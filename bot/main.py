"""Bot Telegram CyberGuard.

Deux choses sont tenues ici, exactement comme côté serveur :

- le mot de passe de l'utilisateur n'est jamais transmis : le bot calcule son
  empreinte SHA-1 et n'envoie que les cinq premiers caractères à l'API ;
- le message contenant le mot de passe est supprimé après l'analyse, quand
  Telegram l'autorise, pour qu'il ne reste pas dans l'historique de la
  conversation.

Aucune promesse qui ne soit vérifiable : si le contrôle des adresses n'est pas
configuré sur le serveur, le bot le dit au lieu d'afficher « aucune fuite ».
"""

from __future__ import annotations

import hashlib
import logging
import os
import sys
from pathlib import Path

import httpx
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import (
    ApplicationBuilder,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

# Le dossier racine du projet doit être dans le chemin pour réutiliser le même
# barème de robustesse que le site (app/scoring.py) : une seule source de vérité.
RACINE = Path(__file__).resolve().parent.parent
if str(RACINE) not in sys.path:
    sys.path.insert(0, str(RACINE))

from app.scoring import evaluer  # noqa: E402  (import après ajustement du chemin)

DELAI_API = 10.0

JAUGE = ["█░░░░", "██░░░", "███░░", "████░", "█████"]
NIVEAUX = ["Très faible", "Faible", "Moyen", "Solide", "Très solide"]


def reglages() -> tuple[str, str]:
    """Récupère le jeton et l'adresse de l'API dans l'environnement."""
    jeton = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    api = os.getenv("CYBERGUARD_API_URL", "").strip().rstrip("/")

    if not jeton:
        raise SystemExit(
            "TELEGRAM_BOT_TOKEN est absent. Créez un jeton avec @BotFather, "
            "puis placez-le dans les variables d'environnement (jamais dans le code)."
        )
    if not api:
        raise SystemExit(
            "CYBERGUARD_API_URL est absent. Indiquez l'adresse publique de l'API "
            "(par exemple https://votre-service.onrender.com). Le bot refuse de "
            "démarrer plutôt que d'appeler une adresse locale par défaut."
        )
    return jeton, api


def menu() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("🔑 Audit de mot de passe", callback_data="menu_mdp"),
                InlineKeyboardButton("🔍 Vérifier une adresse", callback_data="menu_email"),
            ],
            [InlineKeyboardButton("ℹ️ À propos", callback_data="menu_apropos")],
        ]
    )


def bouton_retour() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [[InlineKeyboardButton("⬅️ Retour au menu", callback_data="menu_accueil")]]
    )


async def accueil(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    texte = (
        "🛡️ *CyberGuard*\n\n"
        "Analyse de robustesse et détection de fuites.\n\n"
        "Votre mot de passe n'est *jamais* envoyé : seul un fragment de son "
        "empreinte (5 caractères) part vers le serveur."
    )
    context.user_data["etat"] = None
    if update.message:
        await update.message.reply_text(texte, parse_mode="Markdown", reply_markup=menu())
    elif update.callback_query:
        await update.callback_query.message.edit_text(
            texte, parse_mode="Markdown", reply_markup=menu()
        )


async def boutons(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    requete = update.callback_query
    await requete.answer()

    if requete.data == "menu_mdp":
        context.user_data["etat"] = "attente_mdp"
        await requete.message.edit_text(
            "🔑 *Audit de mot de passe*\n\nEnvoyez le mot de passe à tester. "
            "Je le supprimerai juste après l'analyse.",
            parse_mode="Markdown",
        )
    elif requete.data == "menu_email":
        context.user_data["etat"] = "attente_email"
        await requete.message.edit_text(
            "🔍 *Contrôle d'adresse e-mail*\n\nEnvoyez l'adresse à vérifier.",
            parse_mode="Markdown",
        )
    elif requete.data == "menu_apropos":
        await requete.message.edit_text(
            "🛡️ *CyberGuard*\n\n"
            "• Serveur : FastAPI (Python)\n"
            "• Fuites de mots de passe : API Pwned Passwords, méthode k-anonymity\n"
            "• Score de robustesse : calculé localement\n\n"
            "_Le contrôle des adresses dépend d'une clé HIBP ; sans elle, la "
            "réponse est « non configuré », jamais « aucune fuite »._",
            parse_mode="Markdown",
            reply_markup=bouton_retour(),
        )
    elif requete.data == "menu_accueil":
        await accueil(update, context)


async def message_recu(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    texte = (update.message.text or "").strip()
    etat = context.user_data.get("etat")

    if etat == "attente_mdp":
        await analyser_mot_de_passe(update, texte)
    elif etat == "attente_email":
        await verifier_email(update, texte)
    elif "@" in texte and "." in texte:
        await verifier_email(update, texte)
    else:
        await analyser_mot_de_passe(update, texte)


async def effacer_message_mot_de_passe(update: Update) -> bool:
    """Supprime le message contenant le mot de passe, si Telegram l'autorise."""
    try:
        await update.message.delete()
        return True
    except Exception:  # permission refusée, message trop ancien…
        return False


async def analyser_mot_de_passe(update: Update, mot_de_passe: str) -> None:
    if not mot_de_passe:
        await update.message.reply_text("Envoyez d'abord un mot de passe à tester.")
        return

    attente = await update.message.reply_text("⏳ Analyse en cours…")
    efface = await effacer_message_mot_de_passe(update)

    evaluation = evaluer(mot_de_passe)
    empreinte = hashlib.sha1(mot_de_passe.encode("utf-8")).hexdigest().upper()
    prefixe, suffixe = empreinte[:5], empreinte[5:]

    fuites: int | None = None
    try:
        async with httpx.AsyncClient(timeout=DELAI_API) as client:
            reponse = await client.post(
                f"{API_URL}/api/audit", json={"prefixe_sha1": prefixe}
            )
        if reponse.status_code == 200:
            empreintes = reponse.json().get("empreintes", {})
            fuites = int(empreintes.get(suffixe.lower(), 0))
            # L'API renvoie les suffixes en minuscules.
            if fuites == 0:
                fuites = int(empreintes.get(suffixe, 0))
    except httpx.HTTPError:
        fuites = None

    lignes = [
        "🔑 *Rapport d'audit*",
        "",
        f"*Niveau :* {NIVEAUX[evaluation.score]}  `{JAUGE[evaluation.score]}` ({evaluation.score}/4)",
        f"*Longueur :* {evaluation.longueur} caractères",
        f"*Familles de caractères :* {evaluation.varietes}/4",
        "",
    ]

    if fuites is None:
        lignes.append("⚠️ Vérification de fuite indisponible pour le moment.")
    elif fuites > 0:
        lignes.append(
            f"🚨 *Ce mot de passe apparaît {fuites:,} fois dans des fuites connues.* "
            "Changez-le partout où vous l'utilisez."
        )
    else:
        lignes.append("✅ Aucune trace de ce mot de passe dans les fuites connues.")

    if evaluation.faiblesses:
        lignes += ["", "💡 *À corriger :*"]
        lignes += [f"• {faiblesse}" for faiblesse in evaluation.faiblesses]

    lignes += [
        "",
        "_Seuls 5 caractères de l'empreinte ont été envoyés au serveur ; "
        "le mot de passe lui-même n'a pas quitté Telegram._"
        if efface
        else "_Le mot de passe n'a pas pu être supprimé de la conversation : "
        "pensez à effacer votre message._",
    ]

    await attente.edit_text("\n".join(lignes), parse_mode="Markdown", reply_markup=bouton_retour())


async def verifier_email(update: Update, adresse: str) -> None:
    attente = await update.message.reply_text("⏳ Interrogation en cours…")
    try:
        async with httpx.AsyncClient(timeout=DELAI_API) as client:
            reponse = await client.post(f"{API_URL}/api/breach", json={"email": adresse})
        donnees = reponse.json()
    except (httpx.HTTPError, ValueError):
        await attente.edit_text(
            "⚠️ Serveur injoignable. Réessayez plus tard.", reply_markup=bouton_retour()
        )
        return
    except Exception:
        await attente.edit_text(
            "⚠️ Adresse illisible ou serveur injoignable.", reply_markup=bouton_retour()
        )
        return

    if reponse.status_code == 200:
        fuites = donnees.get("fuites") or []
        if fuites:
            lignes = [f"🚨 *{len(fuites)} fuite(s) connue(s)* pour cette adresse :", ""]
            lignes += [f"• {fuite}" for fuite in fuites]
            lignes += ["", "_Changez le mot de passe de ce compte et activez la double authentification._"]
        else:
            lignes = ["✅ Cette adresse n'apparaît dans aucune fuite connue."]
    elif reponse.status_code == 503:
        lignes = [
            "ℹ️ Contrôle *non configuré* sur ce serveur.",
            "",
            str(donnees.get("detail", "")),
        ]
    else:
        lignes = [f"❌ Analyse impossible (code {reponse.status_code})."]

    await attente.edit_text("\n".join(lignes), parse_mode="Markdown", reply_markup=bouton_retour())


def main() -> None:
    global API_URL
    jeton, API_URL = reglages()
    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s — %(message)s", level=logging.INFO
    )

    application = ApplicationBuilder().token(jeton).build()
    application.add_handler(CommandHandler("start", accueil))
    application.add_handler(CallbackQueryHandler(boutons))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, message_recu))

    logging.getLogger("cyberguard.bot").info("Bot démarré (API : %s)", API_URL)
    application.run_polling()


if __name__ == "__main__":
    main()
