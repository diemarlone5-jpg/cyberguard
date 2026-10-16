"""Évaluation de la robustesse d'un mot de passe.

Ce module s'exécute LÀ OÙ le mot de passe se trouve : dans le navigateur (la
version JavaScript reprend exactement les mêmes règles) ou dans le bot. Le
serveur web ne reçoit jamais le mot de passe, seulement un préfixe d'empreinte.

Les règles sont volontairement simples et lisibles : longueur, diversité,
absence de motifs répétitifs. Elles sont documentées dans le README.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

LONGUEUR_SOLIDE = 12
LONGUEUR_MINIMALE = 8

# Motifs triviaux : suites classiques, répétitions, clavier.
SUITES = (
    "0123456789", "9876543210", "abcdefghijklmnopqrstuvwxyz",
    "qwertyuiop", "azertyuiop", "motdepasse", "password", "admin",
)
REPETITION = re.compile(r"(.)\1{2,}")

@dataclass(frozen=True)
class Evaluation:
    score: int          # 0 à 4
    longueur: int
    varietes: int       # familles de caractères présentes
    faiblesses: tuple[str, ...]

    @property
    def robuste(self) -> bool:
        return self.score >= 3 and self.longueur >= LONGUEUR_MINIMALE


def evaluer(mot_de_passe: str) -> Evaluation:
    """Évalue un mot de passe et énumère ses faiblesses en clair."""
    minuscule = mot_de_passe.lower()
    faiblesses: list[str] = []

    varietes = sum(
        [
            bool(re.search(r"[a-z]", mot_de_passe)),
            bool(re.search(r"[A-Z]", mot_de_passe)),
            bool(re.search(r"\d", mot_de_passe)),
            bool(re.search(r"[^A-Za-z0-9]", mot_de_passe)),
        ]
    )

    score = 0
    if len(mot_de_passe) >= LONGUEUR_MINIMALE:
        score += 1
    if len(mot_de_passe) >= LONGUEUR_SOLIDE:
        score += 1
    if varietes >= 3:
        score += 1
    if varietes == 4:
        score += 1

    if len(mot_de_passe) < LONGUEUR_MINIMALE:
        faiblesses.append(f"moins de {LONGUEUR_MINIMALE} caractères")
    if varietes < 3:
        faiblesses.append("mélangez majuscules, minuscules, chiffres et symboles")
    if any(suite in minuscule for suite in SUITES):
        faiblesses.append("contient une suite connue (clavier, alphabet, mot courant)")
        score = max(0, score - 1)
    if REPETITION.search(mot_de_passe):
        faiblesses.append("contient un caractère répété trois fois ou plus")
        score = max(0, score - 1)

    return Evaluation(score=min(score, 4), longueur=len(mot_de_passe),
                      varietes=varietes, faiblesses=tuple(faiblesses))
