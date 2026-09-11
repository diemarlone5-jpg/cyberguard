import logging
import requests
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    CallbackQueryHandler,
    MessageHandler,
    ContextTypes,
    filters,
)

# 🔑 TON TOKEN TELEGRAM
TELEGRAM_BOT_TOKEN = "8867548816:AAFGPpIadj_dkmuK0ZxBUsBvgzS79_ziXdA"  # Mets ton vrai token ici

# URL de ton API FastAPI
API_URL = "http://127.0.0.1:8000/api"

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO
)

def get_main_menu_keyboard():
    keyboard = [
        [
            InlineKeyboardButton("🔑 Audit Mot de Passe", callback_data="menu_password"),
            InlineKeyboardButton("🔍 Vérifier E-mail", callback_data="menu_email"),
        ],
        [
            InlineKeyboardButton("ℹ️ À propos de CyberGuard", callback_data="menu_about")
        ]
    ]
    return InlineKeyboardMarkup(keyboard)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    welcome_text = (
        "🛡️ *Bienvenue sur CyberGuard Security* 🛡️\n\n"
        "Votre assistant de sécurité B2B en temps réel.\n"
        "Sélectionnez une option ci-dessous ou envoyez directement votre texte :"
    )
    if update.message:
        await update.message.reply_text(welcome_text, parse_mode="Markdown", reply_markup=get_main_menu_keyboard())
    elif update.callback_query:
        await update.callback_query.message.edit_text(welcome_text, parse_mode="Markdown", reply_markup=get_main_menu_keyboard())

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    if query.data == "menu_password":
        context.user_data["state"] = "awaiting_password"
        await query.message.edit_text(
            "🔑 *Audit de Mot de Passe*\n\n"
            "Veuillez envoyer le mot de passe à tester dans le tchat.",
            parse_mode="Markdown"
        )
    elif query.data == "menu_email":
        context.user_data["state"] = "awaiting_email"
        await query.message.edit_text(
            "🔍 *Surveillance des Fuites E-mail*\n\n"
            "Veuillez envoyer l'adresse e-mail professionnelle à analyser.",
            parse_mode="Markdown"
        )
    elif query.data == "menu_about":
        about_text = (
            "🛡️ *CyberGuard Security Suite*\n\n"
            "• *Backend :* FastAPI v0.100+\n"
            "• *Moteur d'analyse :* Real-time entropy & leak check\n"
            "• *Interface :* B2B Corporate Dashboard & Telegram Integration\n\n"
            "💡 _Toutes les requêtes sont chiffrées et aucune donnée sensible n'est enregistrée._"
        )
        back_keyboard = InlineKeyboardMarkup([
            [InlineKeyboardButton("⬅️ Retour au Menu", callback_data="menu_start")]
        ])
        await query.message.edit_text(about_text, parse_mode="Markdown", reply_markup=back_keyboard)
    elif query.data == "menu_start":
        await start(update, context)

async def process_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_input = update.message.text.strip()

    # Détection automatique ou guidée par le menu
    if "@" in user_input and "." in user_input:
        await check_email(update, user_input)
    else:
        await check_password(update, user_input)

async def check_password(update: Update, password: str):
    msg = await update.message.reply_text("⏳ *Analyse du mot de passe en cours...*", parse_mode="Markdown")
    try:
        res = requests.post(f"{API_URL}/check-password", json={"password": password}, timeout=5)
        if res.status_code == 200:
            data = res.json()
            score = data.get("score", 0)
            strength = data.get("strength", "Inconnu")
            warning = data.get("warning")
            suggestions = data.get("suggestions", [])

            status_icons = ["🔴 Extremely Weak", "🟠 Weak", "🟡 Medium", "🟢 Strong", "🔵 Ultra Secure"]
            progress_bars = ["█░░░░", "██░░░", "███░░", "████░", "█████"]
            
            icon = status_icons[score] if score < len(status_icons) else "⚪"
            bar = progress_bars[score] if score < len(progress_bars) else "░░░░░"

            reply = (
                f"🔑 *Rapport d'Audit Mot de Passe*\n\n"
                f"*Niveau :* {icon}\n"
                f"*Jauge :* `{bar}` ({strength})\n\n"
            )

            if warning:
                reply += f"⚠️ *Avertissement :* {warning}\n\n"

            if suggestions:
                reply += "💡 *Recommandations :*\n"
                for s in suggestions:
                    reply += f"• {s}\n"

            reply_markup = InlineKeyboardMarkup([
                [InlineKeyboardButton("⬅️ Retour au Menu", callback_data="menu_start")]
            ])
            await msg.edit_text(reply, parse_mode="Markdown", reply_markup=reply_markup)
        else:
            await msg.edit_text("❌ *Erreur lors de l'analyse du mot de passe.*", parse_mode="Markdown")
    except Exception:
        await msg.edit_text("⚠️ *Impossible de joindre le serveur API. Assurez-vous que FastAPI tourne bien.*", parse_mode="Markdown")

async def check_email(update: Update, email: str):
    msg = await update.message.reply_text("⏳ *Interrogation des bases d'incidents...*", parse_mode="Markdown")
    try:
        res = requests.post(f"{API_URL}/check-email", json={"email": email}, timeout=5)
        if res.status_code == 200:
            data = res.json()
            compromised = data.get("compromised", False)
            breaches = data.get("breaches", [])

            if compromised:
                reply = (
                    f"🚨 *ALERTE SÉCURITÉ : Adresse Compromise !*\n\n"
                    f"L'adresse `{email}` a été détectée dans des fuites de données publiques.\n\n"
                    f"🔻 *Incidents répertoriés :*\n"
                )
                for b in breaches:
                    reply += f"• ⚠️ {b}\n"
                reply += "\n👉 _Nous vous conseillons de changer immédiatement vos mots de passe associés._"
            else:
                reply = (
                    f"✅ *Adresse Conforme*\n\n"
                    f"L'adresse `{email}` n'apparaît dans aucune fuite de données répertoriée."
                )

            reply_markup = InlineKeyboardMarkup([
                [InlineKeyboardButton("⬅️ Retour au Menu", callback_data="menu_start")]
            ])
            await msg.edit_text(reply, parse_mode="Markdown", reply_markup=reply_markup)
        else:
            await msg.edit_text("❌ *Erreur lors de la vérification de l'adresse email.*", parse_mode="Markdown")
    except Exception:
        await msg.edit_text("⚠️ *Impossible de joindre le serveur API. Assurez-vous que FastAPI tourne bien.*", parse_mode="Markdown")

if __name__ == "__main__":
    app = ApplicationBuilder().token(TELEGRAM_BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CallbackQueryHandler(button_handler))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, process_message))
    
    print("🤖 Bot Telegram CyberGuard démarré avec Menu !")
    app.run_polling()