"""Vérification réelle de fuite de mot de passe, par la méthode k-anonymity.

Principe (celui des professionnels, et celui de l'API Pwned Passwords) :

1. le client calcule le SHA-1 du mot de passe ;
2. il n'envoie que les 5 premiers caractères ;
3. le serveur renvoie toutes les empreintes de cette famille ;
4. le client compare localement et sait si son mot de passe a fuité.

Le mot de passe — et même son empreinte complète — ne transitent jamais.

Un cache mémoire évite de rejouer la même requête pendant quelques minutes.
"""

from __future__ import annotations

import time

import httpx

URL_API = "https://api.pwnedpasswords.com/range/"


class FuiteIndisponible(Exception):
    """Le service de vérification est injoignable ou a répondu une erreur."""


class VerificateurFuite:
    """Interroge Pwned Passwords et mémorise les réponses quelques minutes."""

    def __init__(self, delai: float = 6.0, cache_secondes: int = 300) -> None:
        self.delai = delai
        self.cache_secondes = cache_secondes
        self._cache: dict[str, tuple[float, dict[str, int]]] = {}

    async def plage(self, prefixe: str) -> dict[str, int]:
        """Renvoie {suffixe: nombre de fuites} pour un préfixe de 5 caractères."""
        prefixe = prefixe.strip().lower()
        maintenant = time.monotonic()
        memo = self._cache.get(prefixe)
        if memo and maintenant - memo[0] < self.cache_secondes:
            return memo[1]

        try:
            async with httpx.AsyncClient(timeout=self.delai) as client:
                reponse = await client.get(
                    f"{URL_API}{prefixe.upper()}",
                    headers={"User-Agent": "CyberGuard/2.0 (verification de fuite)"},
                )
                reponse.raise_for_status()
        except httpx.HTTPError as erreur:  # réseau, DNS, 4xx, 5xx
            raise FuiteIndisponible(str(erreur)) from erreur

        resultat: dict[str, int] = {}
        for ligne in reponse.text.splitlines():
            if ":" not in ligne:
                continue
            suffixe, _, compte = ligne.partition(":")
            suffixe = suffixe.strip().lower()
            if len(suffixe) == 35 and suffixe.isalnum():
                try:
                    resultat[suffixe] = int(compte.strip())
                except ValueError:
                    continue

        self._cache[prefixe] = (maintenant, resultat)
        return resultat

    def vider_cache(self) -> None:
        self._cache.clear()
