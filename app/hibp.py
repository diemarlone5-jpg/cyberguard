"""Contrôle réel des fuites d'adresses, via l'API Have I Been Pwned.

Ce module n'est actif que si une clé est fournie par l'environnement
(`HIBP_API_KEY`). Sans clé, l'application ne prétend rien : elle refuse la
requête en expliquant pourquoi, au lieu de répondre « aucune fuite ».
"""

from __future__ import annotations

from urllib.parse import quote

import httpx

URL = "https://haveibeenpwned.com/api/v3/breachedaccount/"


class HibpIndisponible(Exception):
    """Clé refusée, quota dépassé ou service injoignable."""


async def fuites_pour(email: str, cle: str, delai: float = 8.0) -> list[str]:
    """Renvoie la liste des fuites connues pour cette adresse (vide si aucune)."""
    try:
        async with httpx.AsyncClient(timeout=delai) as client:
            reponse = await client.get(
                f"{URL}{quote(email)}",
                params={"truncateResponse": "true"},
                headers={
                    "hibp-api-key": cle,
                    "User-Agent": "CyberGuard/2.0 (verification de fuite)",
                },
            )
    except httpx.HTTPError as erreur:
        raise HibpIndisponible(str(erreur)) from erreur

    if reponse.status_code == 404:
        return []                     # adresse absente de toutes les fuites connues
    if reponse.status_code == 401:
        raise HibpIndisponible("clé HIBP refusée")
    if reponse.status_code == 429:
        raise HibpIndisponible("quota HIBP atteint")
    if reponse.status_code >= 500:
        raise HibpIndisponible(f"HIBP a répondu {reponse.status_code}")

    try:
        donnees = reponse.json()
    except ValueError as erreur:
        raise HibpIndisponible("réponse HIBP illisible") from erreur

    if not isinstance(donnees, list):
        raise HibpIndisponible("réponse HIBP inattendue")
    return [str(fuite.get("Name", "inconnue")) for fuite in donnees]
