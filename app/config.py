"""Réglages de CyberGuard.

Tout est lu dans l'environnement : aucun secret, aucune adresse en dur dans le
code. Un réglage manquant ne doit jamais rendre l'application silencieusement
dangereuse — d'où les valeurs par défaut restrictives.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

# Plafond du corps des requêtes : un mot de passe ou un e-mail ne pèse jamais
# plus de quelques centaines d'octets. 16 Ko laisse une marge confortable.
TAILLE_MAX_CORPS = 16 * 1024

# Nombre de requêtes autorisées par adresse IP et par minute.
REQUETES_PAR_MINUTE = 40


def _liste(valeur: str) -> tuple[str, ...]:
    return tuple(element.strip() for element in valeur.split(",") if element.strip())


@dataclass(frozen=True)
class Reglages:
    """Configuration effective de l'application."""

    environnement: str = "development"
    origines_autorisees: tuple[str, ...] = ()
    jeton_telegram: str | None = None
    secret_webhook: str | None = None
    cle_hibp: str | None = None
    url_api_bot: str | None = None
    taille_max_corps: int = TAILLE_MAX_CORPS
    requetes_par_minute: int = REQUETES_PAR_MINUTE
    delai_hibp: float = 6.0
    cache_hibp_secondes: int = 300
    journal_niveau: str = "INFO"
    champs_libres: dict = field(default_factory=dict)

    @property
    def production(self) -> bool:
        return self.environnement.strip().lower() in {"production", "prod"}

    @property
    def verifications_fuite_email_actives(self) -> bool:
        return bool(self.cle_hibp)


def charger() -> Reglages:
    """Construit les réglages à partir des variables d'environnement."""
    return Reglages(
        environnement=os.getenv("ENVIRONMENT", "development"),
        origines_autorisees=_liste(os.getenv("ALLOWED_ORIGINS", "")),
        jeton_telegram=os.getenv("TELEGRAM_BOT_TOKEN") or None,
        secret_webhook=os.getenv("TELEGRAM_WEBHOOK_SECRET") or None,
        cle_hibp=os.getenv("HIBP_API_KEY") or None,
        url_api_bot=os.getenv("CYBERGUARD_API_URL") or None,
        taille_max_corps=int(os.getenv("MAX_BODY_BYTES", TAILLE_MAX_CORPS)),
        requetes_par_minute=int(os.getenv("RATE_LIMIT_PER_MINUTE", REQUETES_PAR_MINUTE)),
        journal_niveau=os.getenv("LOG_LEVEL", "INFO"),
    )
