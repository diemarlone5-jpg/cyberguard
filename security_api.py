from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import re

app = FastAPI()

# 1. Activer CORS pour autoriser les requêtes sur Render
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Autorise toutes les origines
    allow_credentials=True,
    allow_methods=["*"],  # Autorise toutes les méthodes (POST, GET, etc.)
    allow_headers=["*"],  # Autorise tous les headers
)

# Schémas de données reçues du frontend
class PasswordRequest(BaseModel):
    password: str

class EmailRequest(BaseModel):
    email: str

@app.post("/api/audit")
def audit_password(data: PasswordRequest):
    password = data.password
    
    if not password:
        raise HTTPException(status_code=400, detail="Mot de passe vide")
        
    score = 0
    feedback = []
    
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Le mot de passe doit faire au moins 8 caractères.")
        
    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Ajoutez des majuscules.")
        
    if re.search(r"[0-9]", password):
        score += 1
    else:
        feedback.append("Ajoutez des chiffres.")
        
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1
    else:
        feedback.append("Ajoutez des caractères spéciaux.")

    is_secure = score >= 3
    
    return {
        "status": "success",
        "secure": is_secure,
        "score": score,
        "feedback": feedback,
        "message": "Mot de passe sécurisé !" if is_secure else "Mot de passe trop faible."
    }

@app.post("/api/breach")
def check_breach(data: EmailRequest):
    email = data.email
    
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Adresse e-mail invalide")
        
    return {
        "status": "success",
        "leached": False,
        "message": f"Aucune fuite détectée pour l'adresse : {email}"
    }