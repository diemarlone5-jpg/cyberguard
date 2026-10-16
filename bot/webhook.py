"""Enregistre le webhook Telegram (ou l'enlève).

Sur Vercel, le bot ne peut pas interroger Telegram en boucle : c'est Telegram qui
pousse les messages vers ``/api/telegram/webhook``. Il faut donc prévenir
Telegram de l'adresse à appeler, une fois — c'est le rôle de ce script.

Usage :

    python -m bot.webhook --statut
    python -m bot.webhook --set https://cyberguard-azure.vercel.app
    python -m bot.webhook --supprimer

Le jeton et le secret sont lus dans l'environnement (ou dans le fichier ``.env``
à la racine). S'il manque, un secret est **généré** et écrit dans ``.env`` :
il ne reste plus qu'à recopier la même valeur dans les variables d'environnement
Vercel. Aucune valeur secrète n'est affichée en entier.
"""

from __future__ import annotations

import argparse
import os
import secrets
import sys
from pathlib import Path

import httpx

RACINE = Path(__file__).resolve().parent.parent
ENV = RACINE / ".env"
API = "https://api.telegram.org/bot{jeton}/{methode}"
CHEMIN_WEBHOOK = "/api/telegram/webhook"


def charger_env() -> None:
    """Charge le fichier .env s'il existe (sans écraser l'environnement)."""
    if not ENV.is_file():
        return
    for ligne in ENV.read_text(encoding="utf-8").splitlines():
        ligne = ligne.strip()
        if not ligne or ligne.startswith("#") or "=" not in ligne:
            continue
        cle, _, valeur = ligne.partition("=")
        os.environ.setdefault(cle.strip(), valeur.strip().strip('"').strip("'"))


def ecrire_env(cle: str, valeur: str) -> None:
    """Ajoute ou remplace une ligne dans .env (fichier ignoré par Git)."""
    lignes: list[str] = []
    if ENV.is_file():
        lignes = [
            ligne
            for ligne in ENV.read_text(encoding="utf-8").splitlines()
            if not ligne.strip().startswith(f"{cle}=")
        ]
    lignes.append(f"{cle}={valeur}")
    ENV.write_text("\n".join(lignes).strip() + "\n", encoding="utf-8")


def masque(valeur: str) -> str:
    return f"{valeur[:4]}…{valeur[-4:]}" if len(valeur) > 10 else "(court)"


def secret_ou_genere() -> tuple[str, bool]:
    secret = os.getenv("TELEGRAM_WEBHOOK_SECRET", "").strip()
    if secret:
        return secret, False
    secret = secrets.token_urlsafe(32)
    ecrire_env("TELEGRAM_WEBHOOK_SECRET", secret)
    return secret, True


def appeler(jeton: str, methode: str, charge: dict | None = None) -> dict:
    with httpx.Client(timeout=20.0) as client:
        if charge is None:
            reponse = client.get(API.format(jeton=jeton, methode=methode))
        else:
            reponse = client.post(API.format(jeton=jeton, methode=methode), json=charge)
    try:
        return reponse.json()
    except ValueError:
        return {"ok": False, "description": f"réponse illisible (HTTP {reponse.status_code})"}


def main() -> int:
    analyseur = argparse.ArgumentParser(description="Gestion du webhook Telegram de CyberGuard")
    groupe = analyseur.add_mutually_exclusive_group(required=True)
    groupe.add_argument("--set", metavar="URL", help="adresse publique du site")
    groupe.add_argument("--statut", action="store_true", help="état du webhook")
    groupe.add_argument("--supprimer", action="store_true", help="retirer le webhook")
    options = analyseur.parse_args()

    charger_env()
    jeton = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    if not jeton:
        print(
            "TELEGRAM_BOT_TOKEN est absent.\n"
            "Créez un jeton avec @BotFather (/mybots → votre bot → API Token),\n"
            "puis ajoutez-le dans le fichier .env à la racine du projet :\n"
            "  TELEGRAM_BOT_TOKEN=votre_jeton\n"
            "(Ne collez jamais un jeton dans le chat ni dans le code.)"
        )
        return 1

    if options.statut:
        infos = appeler(jeton, "getWebhookInfo")
        resultat = infos.get("result", {})
        print("Webhook enregistré :", resultat.get("url") or "(aucun)")
        if resultat.get("last_error_message"):
            print("Dernière erreur :", resultat["last_error_message"])
        print("Mises à jour en attente :", resultat.get("pending_update_count", 0))
        return 0

    if options.supprimer:
        resultat = appeler(jeton, "deleteWebhook", {"drop_pending_updates": False})
        print("Webhook retiré." if resultat.get("ok") else f"Échec : {resultat}")
        return 0 if resultat.get("ok") else 1

    secret, genere = secret_ou_genere()
    base = options.set.rstrip("/")
    resultat = appeler(
        jeton,
        "setWebhook",
        {
            "url": f"{base}{CHEMIN_WEBHOOK}",
            "secret_token": secret,
            "allowed_updates": ["message", "edited_message"],
            "drop_pending_updates": True,
        },
    )

    if not resultat.get("ok"):
        print("Échec de l'enregistrement :", resultat.get("description", resultat))
        return 1

    print("Webhook enregistré :")
    print(f"  adresse : {base}{CHEMIN_WEBHOOK}")
    print(f"  secret  : {masque(secret)}")
    if genere:
        print()
        print("⚠️ Un secret a été généré et écrit dans .env (fichier ignoré par Git).")
        print("   Recopiez cette même valeur dans Vercel : Settings → Environment Variables")
        print("   → ajoutez la variable TELEGRAM_WEBHOOK_SECRET avec la valeur du fichier .env.")
    print()
    print("Ensuite, écrivez à votre bot sur Telegram : il doit répondre.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
