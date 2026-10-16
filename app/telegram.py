"""Bot Telegram en mode webhook — la seule forme qui fonctionne sur Vercel.

Vercel n'exécute pas de processus permanent : au lieu que le bot interroge
Telegram en boucle (mode « polling », impossible ici), c'est Telegram qui pousse
chaque message vers notre API. Chaque appel est court, autonome, et rien ne
tourne en arrière-plan.

Ce que le module garantit :

- **le secret du webhook est vérifié** : sans l'en-tête attendu, la requête est
  refusée (403). Sans cette vérification, n'importe qui pourrait faire envoyer
  des messages par le bot ;
- **le mot de passe n'est jamais transmis** : on en calcule l'empreinte SHA-1 et
  seuls les cinq premiers caractères partent vers l'API Pwned Passwords ;
- **le message contenant le mot de passe est supprimé** après l'analyse, quand
  Telegram l'autorise ;
- **aucune promesse invérifiable** : sans clé HIBP, le contrôle d'adresse répond
  « non configuré » au lieu d'annoncer « aucune fuite ».
"""

from __future__ import annotations

import hashlib
import logging

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from .pwned import FuiteIndisponible
from .scoring import evaluer

logger = logging.getLogger("cyberguard.telegram")

API_TELEGRAM = "https://api.telegram.org/bot{jeton}/{methode}"

JAUGE = ["█░░░░", "██░░░", "███░░", "████░", "█████"]
NIVEAUX = ["Très faible", "Faible", "Moyen", "Solide", "Très solide"]

ACCUEIL = (
    "🛡️ CyberGuard\n\n"
    "Envoyez-moi un mot de passe : je vous dis s'il apparaît dans des fuites "
    "connues et j'évalue sa robustesse.\n\n"
    "Envoyez une adresse e-mail : je vérifie si elle figure dans des fuites.\n\n"
    "Votre mot de passe n'est jamais transmis — seuls 5 caractères de son "
    "empreinte partent vers le serveur."
)


async def appeler_telegram(jeton: str, methode: str, charge: dict, delai: float = 10.0) -> dict:
    """Appelle l'API Telegram. Isolée dans une fonction pour rester testable."""
    url = API_TELEGRAM.format(jeton=jeton, methode=methode)
    async with httpx.AsyncClient(timeout=delai) as client:
        reponse = await client.post(url, json=charge)
    try:
        return reponse.json()
    except ValueError:
        return {"ok": False, "description": "réponse illisible"}


async def repondre(jeton: str, conversation: int, texte: str) -> None:
    resultat = await appeler_telegram(
        jeton, "sendMessage", {"chat_id": conversation, "text": texte}
    )
    if not resultat.get("ok"):
        logger.warning("Envoi Telegram refusé : %s", resultat.get("description"))


async def effacer_message(jeton: str, conversation: int, message: int) -> bool:
    """Supprime le message qui contenait le mot de passe, si c'est permis."""
    resultat = await appeler_telegram(
        jeton, "deleteMessage", {"chat_id": conversation, "message_id": message}
    )
    return bool(resultat.get("ok"))


def texte_mot_de_passe(mot_de_passe: str, fuites: int | None) -> str:
    """Rapport d'audit, en texte simple (aucun balisage à échapper)."""
    evaluation = evaluer(mot_de_passe)
    lignes = [
        "🔑 Rapport d'audit",
        "",
        f"Niveau : {NIVEAUX[evaluation.score]}  {JAUGE[evaluation.score]} ({evaluation.score}/4)",
        f"Longueur : {evaluation.longueur} caractères",
        f"Familles de caractères : {evaluation.varietes}/4",
        "",
    ]
    if fuites is None:
        lignes.append("⚠️ Vérification de fuite indisponible pour le moment.")
    elif fuites > 0:
        nombre = f"{fuites:,}".replace(",", " ")
        lignes.append(
            f"🚨 Ce mot de passe apparaît {nombre} fois dans des fuites connues. "
            "Changez-le partout où vous l'utilisez."
        )
    else:
        lignes.append("✅ Aucune trace de ce mot de passe dans les fuites connues.")

    if evaluation.faiblesses:
        lignes += ["", "💡 À corriger :"]
        lignes += [f"• {faiblesse}" for faiblesse in evaluation.faiblesses]
    return "\n".join(lignes)


def creer_routeur_telegram(reglages_courants, verificateur_courant) -> APIRouter:
    """Construit la route de webhook, branchée sur les réglages de l'application."""
    routeur = APIRouter()

    @routeur.post("/api/telegram/webhook")
    async def webhook(request: Request) -> JSONResponse:
        reglages = reglages_courants()
        verificateur = verificateur_courant()

        if not reglages.jeton_telegram:
            return JSONResponse({"detail": "Bot non configuré sur ce serveur."}, status_code=503)
        if not reglages.secret_webhook:
            return JSONResponse(
                {"detail": "Secret de webhook absent : configuration incomplète."},
                status_code=503,
            )

        # Vérification du secret : sans elle, n'importe qui pourrait faire parler
        # le bot à la place de Telegram.
        recu = request.headers.get("x-telegram-bot-api-secret-token", "")
        if not _egal(recu, reglages.secret_webhook):
            return JSONResponse({"detail": "Secret invalide."}, status_code=403)

        try:
            mise_a_jour = await request.json()
        except ValueError:
            return JSONResponse({"detail": "Corps illisible."}, status_code=400)

        message = mise_a_jour.get("message") or mise_a_jour.get("edited_message") or {}
        texte = (message.get("text") or "").strip()
        conversation = (message.get("chat") or {}).get("id")
        identifiant = message.get("message_id")

        if not texte or conversation is None:
            return JSONResponse({"ok": True})   # rien à traiter (photo, sticker…)

        if texte.startswith("/start") or texte.startswith("/aide"):
            await repondre(reglages.jeton_telegram, conversation, ACCUEIL)
            return JSONResponse({"ok": True})

        if "@" in texte and "." in texte:
            await _traiter_email(reglages, conversation, texte)
        else:
            await _traiter_mot_de_passe(reglages, verificateur, conversation, identifiant, texte)

        return JSONResponse({"ok": True})

    async def _traiter_mot_de_passe(reglages, verificateur, conversation, identifiant, mot_de_passe):
        if identifiant is not None:
            await effacer_message(reglages.jeton_telegram, conversation, identifiant)

        empreinte = hashlib.sha1(mot_de_passe.encode("utf-8")).hexdigest()
        prefixe, suffixe = empreinte[:5], empreinte[5:]

        fuites: int | None = None
        try:
            plage = await verificateur.plage(prefixe)
            fuites = int(plage.get(suffixe, 0))
        except FuiteIndisponible:
            fuites = None

        await repondre(
            reglages.jeton_telegram, conversation, texte_mot_de_passe(mot_de_passe, fuites)
        )

    async def _traiter_email(reglages, conversation, adresse):
        if not reglages.cle_hibp:
            await repondre(
                reglages.jeton_telegram,
                conversation,
                "ℹ️ Le contrôle des fuites d'adresses n'est pas configuré sur ce "
                "serveur : aucune conclusion ne peut être donnée.",
            )
            return
        from .hibp import HibpIndisponible, fuites_pour  # import local : module optionnel

        try:
            fuites = await fuites_pour(adresse, reglages.cle_hibp, delai=reglages.delai_hibp)
        except HibpIndisponible:
            await repondre(
                reglages.jeton_telegram,
                conversation,
                "⚠️ Vérification momentanément indisponible. Réessayez plus tard.",
            )
            return

        if fuites:
            lignes = [f"🚨 {len(fuites)} fuite(s) connue(s) pour cette adresse :", ""]
            lignes += [f"• {fuite}" for fuite in fuites]
            lignes.append("")
            lignes.append("Changez le mot de passe de ce compte et activez la double authentification.")
            texte = "\n".join(lignes)
        else:
            texte = "✅ Cette adresse n'apparaît dans aucune fuite connue."
        await repondre(reglages.jeton_telegram, conversation, texte)

    return routeur


def _egal(gauche: str, droite: str) -> bool:
    """Comparaison à temps constant : on ne laisse pas fuir le secret par le temps de réponse."""
    import hmac

    return hmac.compare_digest(gauche.encode("utf-8"), droite.encode("utf-8"))
