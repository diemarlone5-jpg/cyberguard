from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os

app = FastAPI(title="CyberGuard Security API")

# Configuration CORS pour autoriser les requêtes
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- TES ROUTES D'API EXISTANTES ---
# (Laisse tes routes /api/check-password, /api/check-email, etc. ici)


# --- NOUVEAUTÉ : SERVIR LE FRONTEND À LA RACINE ---

# Monte le dossier frontend pour charger les fichiers statiques (CSS, JS, images)
app.mount("/static", StaticFiles(directory="frontend"), name="static")

@app.get("/")
def serve_frontend():
    """Redirige la racine vers l'interface web index.html"""
    return FileResponse(os.path.join("frontend", "index.html"))