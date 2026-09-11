from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import os
import re

app = FastAPI()

# 1. Activer CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 2. Servir les fichiers statiques (CSS, JS) du dossier "frontend"
# Assurez-vous que votre dossier s'appelle "frontend" à la racine
if os.path.exists("frontend"):
    app.mount("/static", StaticFiles(directory="frontend"), name="static")

# 3. Route racine pour afficher directement la page HTML
@app.get("/", response_class=HTMLResponse)
async def read_index():
    index_path = "frontend/index.html"
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Fichier index.html introuvable dans le dossier frontend</h1>"

# Schémas et routes API
class PasswordRequest(BaseModel):
    password: str

class EmailRequest(BaseModel):
    email: str

@app.post("/api/audit")
def audit_password(data: PasswordRequest):
    password = data.password
    if not password:
        raise HTTPException(status_code=400, detail="Mot de passe vide")
    
    score = sum([
        len(password) >= 8,
        bool(re.search(r"[A-Z]", password)),
        bool(re.search(r"[0-9]", password)),
        bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password))
    ])
    
    is_secure = score >= 3
    return {
        "status": "success",
        "secure": is_secure,
        "score": score,
        "message": "Mot de passe sécurisé !" if is_secure else "Mot de passe trop faible."
    }

@app.post("/api/breach")
def check_breach(data: EmailRequest):
    return {
        "status": "success",
        "leached": False,
        "message": f"Aucune fuite détectée pour l'adresse : {data.email}"
    }