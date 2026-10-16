"""Application FastAPI de CyberGuard.

Principes tenus par ce fichier :

- aucun secret dans le code : tout vient de l'environnement ;
- aucune entrée utilisateur renvoyée telle quelle dans une réponse ;
- en-têtes de sécurité posés par un intergiciel, y compris sur les erreurs ;
- documentation interactive fermée en production ;
- un seul rôle pour l'API : dire ce que l'on sait, et jamais rassurer à tort.
"""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .config import Reglages, charger
from .hibp import HibpIndisponible, fuites_pour
from .pwned import FuiteIndisponible, VerificateurFuite
from .schemas import AuditMotDePasse, VerificationEmail
from .security import EnTetesSecurite, LimiteDebit, TailleMaximale

RACINE = Path(__file__).resolve().parent.parent
FRONTEND = RACINE / "frontend"

logger = logging.getLogger("cyberguard")


def creer_application(reglages: Reglages | None = None) -> FastAPI:
    reglages = reglages or charger()
    logging.basicConfig(level=getattr(logging, reglages.journal_niveau.upper(), logging.INFO))

    verificateur = VerificateurFuite(
        delai=reglages.delai_hibp, cache_secondes=reglages.cache_hibp_secondes
    )

    application = FastAPI(
        title="CyberGuard API",
        version="2.0.0",
        description="Vérification de fuites de mots de passe par k-anonymity, et contrôle des fuites d'adresses.",
        # En production, pas de documentation interactive exposée.
        docs_url=None if reglages.production else "/docs",
        redoc_url=None if reglages.production else "/redoc",
        openapi_url=None if reglages.production else "/openapi.json",
    )

    application.state.reglages = reglages

    def reglages_courants() -> Reglages:
        return application.state.reglages

    def verificateur_courant() -> VerificateurFuite:
        return verificateur

    # --- intergiciels (l'ordre compte : le dernier ajouté s'exécute en premier)
    application.add_middleware(
        LimiteDebit, requetes_par_minute=reglages.requetes_par_minute
    )
    application.add_middleware(TailleMaximale, taille_max=reglages.taille_max_corps)
    application.add_middleware(EnTetesSecurite)

    if reglages.origines_autorisees:
        application.add_middleware(
            CORSMiddleware,
            allow_origins=list(reglages.origines_autorisees),
            allow_methods=["GET", "POST"],
            allow_headers=["Content-Type"],
            allow_credentials=False,
        )

    # --- réponses d'erreur assainies : jamais la valeur envoyée par le client
    @application.exception_handler(RequestValidationError)
    async def erreur_de_validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        """Renvoie l'emplacement et la nature du problème, jamais l'entrée reçue.

        Le gestionnaire par défaut de FastAPI recopie la valeur envoyée dans sa
        réponse : sur cette application, cela reviendrait à renvoyer le mot de
        passe ou l'e-mail fautif. On ne garde donc que le champ et le motif.
        """
        problemes = [
            {
                "champ": ".".join(str(partie) for partie in erreur.get("loc", ())),
                "motif": str(erreur.get("msg", "valeur refusée")),
            }
            for erreur in exc.errors()
        ]
        return JSONResponse(
            {"detail": "Requête invalide.", "problemes": problemes}, status_code=422
        )

    # --- interface statique
    if FRONTEND.is_dir():
        application.mount("/static", StaticFiles(directory=str(FRONTEND)), name="static")

    @application.get("/", response_class=HTMLResponse)
    async def accueil() -> HTMLResponse:
        index = FRONTEND / "index.html"
        if not index.is_file():
            raise HTTPException(status_code=500, detail="Interface introuvable.")
        return HTMLResponse(index.read_text(encoding="utf-8"))

    @application.get("/api/health")
    async def sante() -> dict[str, object]:
        return {
            "etat": "ok",
            "environnement": reglages.environnement,
            "verification_fuite_mot_de_passe": True,
            "verification_fuite_email": reglages.verifications_fuite_email_actives,
        }

    # --- audit de mot de passe : le mot de passe reste chez le client
    @application.post("/api/audit")
    async def audit(
        donnees: AuditMotDePasse,
        verificateur: VerificateurFuite = Depends(verificateur_courant),
    ) -> JSONResponse:
        try:
            plage = await verificateur.plage(donnees.prefixe_sha1)
        except FuiteIndisponible:
            logger.warning("Service de vérification de fuite injoignable")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Vérification momentanément indisponible. Réessayez plus tard.",
            )
        # On renvoie toute la famille : le client compare et conclut lui-même.
        return JSONResponse(
            {
                "prefixe": donnees.prefixe_sha1,
                "empreintes": plage,
                "total_empreintes": len(plage),
            }
        )

    # --- vérification d'adresse : réelle si une clé est configurée, sinon refus explicite
    @application.post("/api/breach")
    async def fuite_email(
        donnees: VerificationEmail,
        reglages: Reglages = Depends(reglages_courants),
    ) -> JSONResponse:
        if not reglages.cle_hibp:
            # Rien d'inventé : on dit que le contrôle n'est pas configuré.
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=(
                    "Le contrôle des fuites d'adresses n'est pas configuré sur ce serveur "
                    "(clé HIBP absente). Aucune conclusion ne peut être donnée."
                ),
            )

        try:
            fuites = await fuites_pour(donnees.email, reglages.cle_hibp, delai=reglages.delai_hibp)
        except HibpIndisponible:
            logger.warning("Contrôle HIBP indisponible")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Contrôle des fuites momentanément indisponible. Réessayez plus tard.",
            )

        return JSONResponse(
            {
                "adresse_verifiee": donnees.email,
                "nombre_fuites": len(fuites),
                "fuites": fuites,
                "message": (
                    "Cette adresse apparaît dans des fuites connues."
                    if fuites
                    else "Cette adresse n'apparaît dans aucune fuite connue."
                ),
            }
        )

    return application


app = creer_application()
