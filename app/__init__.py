"""CyberGuard — service de vérification de fuites.

Le paquet est volontairement petit et lisible :

- ``config``   : réglages lus dans l'environnement ;
- ``schemas``  : entrées validées et bornées ;
- ``security`` : en-têtes, taille de requête, limite de débit ;
- ``pwned``    : fuites de mots de passe (k-anonymity, sans clé) ;
- ``hibp``     : fuites d'adresses (nécessite une clé) ;
- ``scoring``  : robustesse d'un mot de passe, calculée côté client ;
- ``main``     : assemblage FastAPI.
"""

__version__ = "2.0.0"
