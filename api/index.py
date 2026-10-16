"""Point d'entrée Vercel.

Vercel exécute le site comme une fonction Python : il cherche dans ce fichier un
objet ``app`` exposant une application ASGI. Notre application FastAPI est
exactement cela — on la réexporte donc telle quelle, sans la modifier.

Ce fichier n'existe que pour Vercel : en local, c'est ``app.main:app`` qui est
lancé (``uvicorn app.main:app``).
"""

from __future__ import annotations

import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parent.parent
if str(RACINE) not in sys.path:
    sys.path.insert(0, str(RACINE))

from app.main import app  # noqa: E402  (import après ajustement du chemin)

__all__ = ["app"]
