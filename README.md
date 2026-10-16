# CyberGuard

Service de vérification de fuites de données : une API en Python, une interface
web et un bot Telegram.

## Ce que fait l'application

- **Audit de mot de passe** — indique si un mot de passe apparaît dans les
  fuites de données connues, et évalue sa robustesse. Le mot de passe **ne
  quitte jamais la machine de l'utilisateur** : le client calcule son empreinte
  SHA-1 et n'envoie que les **cinq premiers caractères** au serveur (méthode
  dite *k-anonymity*, celle qu'utilise l'API Pwned Passwords). Le serveur
  renvoie la famille d'empreintes correspondante, le client compare et conclut.
- **Contrôle d'adresse e-mail** — vérifie si une adresse apparaît dans des
  fuites connues, via l'API Have I Been Pwned. **Ce contrôle exige une clé**
  (`HIBP_API_KEY`). Sans clé, l'application répond « non configuré » : elle ne
  prétend jamais qu'une adresse est saine.
- **Bot Telegram** — les deux mêmes fonctions, avec suppression du message
  contenant le mot de passe après l'analyse.

## Sécurité : les mesures en place

| Mesure | Ce que ça bloque |
|---|---|
| Politique de sécurité du contenu stricte (`script-src 'self'`) | Exécution de script injecté (XSS) |
| Aucun `innerHTML` dans l'interface, tout passe par `textContent` | Injection de balises dans la page |
| Réponses d'erreur assainies (jamais la valeur reçue) | Fuite du mot de passe ou de l'e-mail dans un message d'erreur |
| Validation stricte et bornée des entrées (`extra="forbid"`) | Champs surprise, valeurs géantes |
| Taille maximale du corps (16 Ko par défaut) | Requêtes volumineuses |
| Limite de débit par adresse IP (40/min par défaut) | Martèlement et déni de service simple |
| En-têtes `CSP`, `X-Frame-Options`, `nosniff`, `Referrer-Policy`, `HSTS` | Clickjacking, reniflage de type, fuite d'URL |
| Documentation interactive fermée en production | Cartographie offerte de l'API |
| Aucun secret dans le code : tout par variables d'environnement | Fuite de jeton dans le dépôt |
| Message d'erreur honnête quand un service n'est pas configuré | Fausse assurance de sécurité |

## Installation

```bash
uv venv .venv
uv pip install --python .venv/Scripts/python.exe -r requirements-dev.txt
```

Sur Linux/macOS, remplacez `.venv/Scripts/python.exe` par `.venv/bin/python`.

## Configuration

Copiez `.env.example` en `.env` et remplissez :

| Variable | Rôle |
|---|---|
| `ENVIRONMENT` | `development` ou `production` (ferme la documentation interactive) |
| `ALLOWED_ORIGINS` | Origines autorisées à appeler l'API depuis un autre site. Vide = aucune (le plus sûr) |
| `TELEGRAM_BOT_TOKEN` | Jeton du bot, créé avec @BotFather. Jamais dans le code |
| `CYBERGUARD_API_URL` | Adresse de l'API vue par le bot. **Obligatoire** : sans elle, le bot refuse de démarrer |
| `HIBP_API_KEY` | Facultative : active le contrôle des adresses |
| `RATE_LIMIT_PER_MINUTE`, `MAX_BODY_BYTES` | Réglages des protections |

## Lancer

```bash
# Serveur web — http://127.0.0.1:8000
.venv/Scripts/python.exe -m uvicorn app.main:app --reload

# Bot Telegram (dans un second terminal)
.venv/Scripts/python.exe -m bot.main
```

## Tests

```bash
.venv/Scripts/python.exe -m pytest
```

14 tests couvrent les propriétés de sécurité : en-têtes présents (même sur une
erreur), entrée hostile neutralisée, mot de passe en clair refusé par l'API,
absence de toute fuite d'entrée dans les réponses, corps trop gros refusé,
martèlement bloqué, refus explicite quand le contrôle d'adresse n'est pas
configuré, documentation fermée en production.

## Structure

```
app/
  config.py     réglages lus dans l'environnement
  schemas.py    entrées validées et bornées
  security.py   en-têtes, taille de requête, limite de débit
  pwned.py      fuites de mots de passe (sans clé)
  hibp.py       fuites d'adresses (avec clé)
  scoring.py    robustesse d'un mot de passe (calculée côté client)
  main.py       application FastAPI
bot/
  main.py       bot Telegram
frontend/
  index.html    interface (thème SOC)
  app.js        logique de l'interface (sans innerHTML)
tests/
  test_api.py   tests de sécurité
```

## Déploiement (Vercel)

Le projet est prêt pour Vercel : `vercel.json` déclare un service unique
(`api/index.py`, qui réexporte l'application FastAPI) et route tout le trafic
public vers lui.

```bash
vercel deploy --prod          # depuis la racine du projet
```

Variable d'environnement à définir dans le projet Vercel (Settings →
Environment Variables) :

| Variable | Valeur |
|---|---|
| `ENVIRONMENT` | `production` (ferme `/docs` et `/openapi.json`) |
| `TELEGRAM_BOT_TOKEN` | seulement si vous activez le bot |
| `HIBP_API_KEY` | seulement si vous avez une clé Have I Been Pwned |

Points à connaître sur Vercel :

- **Le bot Telegram ne peut pas y tourner en boucle** : Vercel n'exécute pas de
  processus permanent. Il lui faut soit un webhook (voir ci-dessous), soit un
  autre hébergeur.
- **La limite de débit devient indicative** : chaque instance de fonction est
  éphémère, le compteur repart à zéro — et plusieurs instances peuvent coexister.
  Pour une limite fiable, il faut un stockage partagé (Redis, Upstash…).
- **Le contrôle d'adresse e-mail nécessite une clé HIBP** ; sans elle, la route
  répond « non configuré ».

### Ancien hébergement : Render

Les instructions Render restent valables (Procfile présent) mais **le mode
« service web » ne convient plus** si vous suivez la structure `app/` :
la commande de démarrage doit être
`uvicorn app.main:app --host 0.0.0.0 --port $PORT`.

## Limites connues, écrites noir sur blanc

- La limite de débit est stockée **en mémoire** : elle protège une instance
  unique. Derrière plusieurs instances, il faut un stockage partagé (Redis).
- Le contrôle des adresses e-mail nécessite une clé HIBP payante ; sans elle,
  la fonction répond honnêtement « non configuré ».
- Les empreintes de mots de passe ne sont pas mises en cache côté client.
