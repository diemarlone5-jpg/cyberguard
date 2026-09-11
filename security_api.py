import re
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from zxcvbn import zxcvbn
import requests

app = FastAPI(title="Security Checker API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class PasswordCheckRequest(BaseModel):
    password: str

class EmailCheckRequest(BaseModel):
    email: EmailStr

@app.post("/api/check-password")
def check_password(data: PasswordCheckRequest):
    password = data.password
    result = zxcvbn(password)
    score = result["score"]
    
    warnings = []
    suggestions = list(result["feedback"]["suggestions"])

    # --- RÈGLES DE SÉCURITÉ PERSONNALISÉES ---
    
    has_letters = bool(re.search(r"[a-zA-Z]", password))
    has_digits = bool(re.search(r"\d", password))
    has_symbols = bool(re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?~`]", password))
    
    # 1. Détection des numéros de téléphone ou suites de chiffres uniquement
    if password.isdigit():
        score = min(score, 1) # Force le score à être "Faible" au maximum
        warnings.append("Ce mot de passe ne contient que des chiffres (style numéro de téléphone ou date).")
        suggestions.append("Ajoutez des lettres (majuscules/minuscules) et des symboles spéciaux.")
    
    # 2. Exigence d'un mélange complet (lettres + chiffres + symboles) pour un score élevé
    elif not (has_letters and has_digits and has_symbols):
        if score > 2:
            score = 2 # Évite qu'un mot de passe sans mélange soit "Fort"
        warnings.append("Il manque de la diversité dans vos caractères.")
        suggestions.append("Combinez à la fois des lettres, des chiffres ET des symboles (!@#...).")

    # Si zxcvbn avait déjà un warning d'origine, on l'ajoute aussi
    if result["feedback"]["warning"]:
        warnings.append(result["feedback"]["warning"])

    levels = {0: "Très faible", 1: "Faible", 2: "Moyen", 3: "Fort", 4: "Très fort"}

    return {
        "score": score,
        "strength": levels[score],
        "warning": " ".join(warnings) if warnings else None,
        "suggestions": list(set(suggestions)) # Supprime les doublons de conseils
    }

@app.post("/api/check-email")
def check_email(data: EmailCheckRequest):
    url = f"https://api.xposedornot.com/v1/check-email/{data.email}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data_res = response.json()
            if "Error" in data_res:
                return {"compromised": False, "breaches": []}
            breaches_list = data_res.get("ExposedBreaches", {}).get("breaches_details", [])
            breaches = [b.get("breach", "Inconnu") for b in breaches_list]
            return {"compromised": True, "breaches": breaches}
        return {"compromised": False, "breaches": []}
    except Exception:
        raise HTTPException(status_code=500, detail="Erreur serveur externe")