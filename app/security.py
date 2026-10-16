"""Durcissement HTTP : en-têtes de sécurité, taille de requête, limite de débit.

Ces trois protections sont indépendantes de la logique métier : elles
s'appliquent à toutes les réponses, y compris aux erreurs — un 404 ou un 500
doit porter les mêmes en-têtes qu'une réponse normale.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

# Contenu autorisé, resserré au maximum :
# - les scripts ne viennent que du site lui-même (aucun script en ligne, aucun
#   script de CDN) : c'est la barrière qui rend un XSS inexploitable ;
# - les styles et les polices viennent du site, de Font Awesome (icônes) et de
#   Google Fonts, qui étaient déjà utilisés par la page ;
# - aucun cadrage (frame-ancestors 'none' + X-Frame-Options) : pas de clickjacking.
CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
    "font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com data:; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)

ENTETES_FIXES = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=(), payment=()",
}


class EnTetesSecurite(BaseHTTPMiddleware):
    """Ajoute les en-têtes de sécurité à chaque réponse."""

    async def dispatch(self, request: Request, call_next) -> Response:
        reponse = await call_next(request)
        for nom, valeur in ENTETES_FIXES.items():
            reponse.headers.setdefault(nom, valeur)
        if request.url.scheme == "https":
            reponse.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        return reponse


class TailleMaximale(BaseHTTPMiddleware):
    """Refuse les corps de requête anormalement gros avant de les lire."""

    def __init__(self, app, taille_max: int) -> None:
        super().__init__(app)
        self.taille_max = taille_max

    async def dispatch(self, request: Request, call_next) -> Response:
        annonce = request.headers.get("content-length")
        if annonce is not None:
            try:
                if int(annonce) > self.taille_max:
                    return JSONResponse(
                        {"detail": "Requête trop volumineuse."}, status_code=413
                    )
            except ValueError:
                return JSONResponse({"detail": "En-tête Content-Length invalide."}, status_code=400)
        return await call_next(request)


class LimiteDebit(BaseHTTPMiddleware):
    """Limite le nombre de requêtes par adresse IP sur une fenêtre glissante.

    Le compteur vit en mémoire : suffisant pour une instance unique et pour
    arrêter le martèlement d'un script. Derrière plusieurs instances, il faut un
    stockage partagé — c'est écrit noir sur blanc dans le README plutôt que
    d'être passé sous silence.
    """

    def __init__(self, app, requetes_par_minute: int, fenetre: float = 60.0) -> None:
        super().__init__(app)
        self.requetes_par_minute = requetes_par_minute
        self.fenetre = fenetre
        self.horodatages: dict[str, deque[float]] = defaultdict(deque)

    def _adresse(self, request: Request) -> str:
        # Derrière un proxy (Render), l'IP réelle est dans X-Forwarded-For.
        transmise = request.headers.get("x-forwarded-for", "")
        if transmise:
            return transmise.split(",")[0].strip()
        return request.client.host if request.client else "inconnue"

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.url.path.startswith(("/static", "/api/health")):
            return await call_next(request)

        maintenant = time.monotonic()
        adresse = self._adresse(request)
        horodatages = self.horodatages[adresse]
        while horodatages and maintenant - horodatages[0] > self.fenetre:
            horodatages.popleft()

        if len(horodatages) >= self.requetes_par_minute:
            return JSONResponse(
                {"detail": "Trop de requêtes. Réessayez dans une minute."},
                status_code=429,
                headers={"Retry-After": "60"},
            )

        horodatages.append(maintenant)
        return await call_next(request)
