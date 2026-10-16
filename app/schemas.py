"""Schémas d'entrée : bornés, typés, et volontairement étroits.

Règle de conception : l'API n'accepte jamais un mot de passe en clair. Le
client calcule l'empreinte et n'envoie que les cinq premiers caractères
hexadécimaux (méthode dite « k-anonymity ») : le mot de passe ne quitte jamais
la machine de l'utilisateur.
"""

from __future__ import annotations

from pydantic import BaseModel, EmailStr, Field, field_validator

# Un préfixe SHA-1 fait exactement cinq caractères hexadécimaux.
PREFIXE_SHA1 = r"^[0-9a-fA-F]{5}$"


class AuditMotDePasse(BaseModel):
    """Préfixe SHA-1 d'un mot de passe — jamais le mot de passe lui-même."""

    model_config = {"extra": "forbid"}

    prefixe_sha1: str = Field(
        ...,
        min_length=5,
        max_length=5,
        pattern=PREFIXE_SHA1,
        description="Les 5 premiers caractères hexadécimaux du SHA-1 du mot de passe.",
    )

    @field_validator("prefixe_sha1")
    @classmethod
    def normaliser(cls, valeur: str) -> str:
        return valeur.strip().lower()


class VerificationEmail(BaseModel):
    """Adresse e-mail à vérifier — validée, bornée, sans champ superflu."""

    model_config = {"extra": "forbid"}

    email: EmailStr = Field(..., max_length=254)
