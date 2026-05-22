# BOLA-Shield AI — Plateforme d'Audit Intelligent des Failles BOLA/IDOR

**BOLA-Shield AI** est une plateforme **entièrement modulaire** pour détecter et corriger les failles BOLA/IDOR (Broken Object-Level Authorization) dans des architectures API modernes, avec **support du WAF bypass** et **protections anti-bot avancées**.

## 🎯 Vue d'ensemble

BOLA-Shield combine:
- **Scanner multi-moteurs** : moteur HTTP natif rapide + fallback Puppeteer lourd pour contourner les WAF;
- **Full Auto-Discovery Spider** : Fuzzing autonome d'UI et détection intelligente des API REST cachées (capture d'ID dynamique);
- **Module d'Exfiltration & Sabotage** : Data mining automatique (Regex e-mails/téléphones), fuite de masse (ID+1) et simulation d'Attack Chaining (Write Access);
- **Moteur d'évasion anti-bot** : IP spoofing, fausse entropie, gestion des honeypots, support OTP;
- **Gateway instrumentée** : reverse proxy avec observation et modification contrôlée des requêtes/réponses;
- **Tableau de bord en temps réel** : logs SSE, charts, fiches d'audit détaillées;
- **Laboratoire cible e-commerce durci** : protections anti-robot, captcha, honeypots, proof-of-time.

## 🏗️ Architecture Globale

```
┌─────────────────────────────────────────────────────────────┐
│  BOLA-Shield Main Server (server.js)                        │
│  ├─ Static UI (index.html + assets/)                        │
│  ├─ REST API (lib/routes.js)                                │
│  ├─ SSE Broadcast (lib/store.js → pendingOTP relay)         │
│  └─ Gateway Proxy (Observe + Modify-Approved mode)          │
└─────────────────────────────────────────────────────────────┘
         ↓
┌─────────────────────────────────────────────────────────────┐
│  Scanner Core Engine (lib/)                                 │
│  ├─ utils.js (HTTP rapide + bascule automatique)            │
│  ├─ spider.js (Puppeteer + OTP await)                       │
│  ├─ browser-engine.js (3 contextes Incognito pour WAF)      │
│  ├─ evasion.js (IP spoofing + fausse entropie)              │
│  ├─ cache.js (Découverte cachée)                            │
│  └─ store.js (État global + SSE)                            │
└─────────────────────────────────────────────────────────────┘
         ↓
┌─────────────────────────────────────────────────────────────┐
│  Target API (target-api/server.js)                          │
│  ├─ Endpoints protégés (/api/users/:id)                     │
│  ├─ Auth durcie (honeypot, captcha, entropy, PoT)           │
│  └─ Bot detection (headers, timing, behavior analysis)      │
└─────────────────────────────────────────────────────────────┘
```

## 📂 Structure du Projet Détaillée

```
projet X/
├── index.html                    # UI principal (Vue.js style)
├── package.json                  # Dépendances racine (Puppeteer + extras)
├── server.js                     # Serveur principal Node.js
├── README.md                     # Cette documentation
│
├── assets/                       # Frontend statique
│   ├── css/
│   │   └── style.css            # Styles premium (dashboard, charts)
│   └── js/
│       ├── main.js              # Orchestrateur central (init modules)
│       ├── utils/
│       │   └── helpers.js        # Toast, logs, UI utilities
│       └── modules/              # Vue.js components
│           ├── dashboard.js      # Charts + live logs
│           ├── scanner.js        # Audit matrix UI
│           ├── patcher.js        # Vulnerability patch UI
│           ├── mapper.js         # Endpoint mapper graph
│           ├── chat.js           # Real-time chat/notifications
│           ├── firewall.js       # Blacklist/whitelist UI
│           └── state.js          # Global state management
│
├── lib/                          # ⚠️ CORE ENGINE — À comprendre absolument
│   ├── README.md                 # Documentation complète du moteur (LIRE CECI!)
│   ├── routes.js                 # API routes (/api/v1/*)
│   ├── store.js                  # État global + SSE broadcast + save/load
│   ├── utils.js                  # HTTP natif + router vers spider/browser-engine
│   ├── spider.js                 # Puppeteer automation (incognito, stealth)
│   ├── browser-engine.js         # Heavy DAST (3 contextes pour WAF bypass)
│   ├── cache.js                  # Discovery cache persistant
│   └── evasion.js                # IP spoofing + fausse entropie
│
├── data/
│   ├── state.json                # État persistant (gateway config, logs, etc.)
│   ├── credentials.json          # Credentials testées (NE PAS COMMITTER)
│   └── credentials.example.json  # Template de credentials
│
└── target-api/                   # API cible de test (Mock e-commerce)
    ├── package.json              # Express, JWT, bcryptjs, helmet, cors
    ├── server.js                 # API protégée (honeypots, captcha, PoT)
    └── README.md                 # (Voir lib/README.md pour intégration)
```

## 📌 Point d'entrée de Reprise pour un Nouveau Dev

**Point 1 : Lire `lib/README.md` en premier** — C'est la cartographie complète du moteur avec architecture Mermaid et risques de suppression.

**Point 2 : Comprendre le flow d'audit**:
1. L'interface UI envoie une demande d'audit via `POST /api/v1/scanner/audit`
2. `routes.js` reçoit la demande et fait appel à `utils.js` pour l'attaque rapide (HTTP natif)
3. Si la cible bloque (400, 403), `utils.js` bascule automatiquement vers `spider.js` (Puppeteer) ou `browser-engine.js` (3 contextes)
4. `evasion.js` falsifie les en-têtes (IP spoofée, fausse entropie) pour passer les WAF
5. `store.js` relaie les logs via SSE vers le dashboard en temps réel
6. Les credentials testées sont sauvegardées dans `data/state.json`

## ⚙️ Installation

### Prérequis

- Node.js 20+
- npm
- 2 terminaux : un pour le serveur principal, un pour la cible mock

### Étapes

**1. Installer la racine et dépendances**

```bash
cd "c:\Users\Administrator\Desktop\projet X"
npm install
```

**2. Installer la cible de test**

```bash
cd target-api
npm install
```

## 🚀 Lancement

### Terminal 1 : Cible Mock

```bash
cd target-api
node server.js
```

Écoute sur `http://localhost:3000`

### Terminal 2 : BOLA-Shield Principal

```bash
cd "c:\Users\Administrator\Desktop\projet X"
node server.js
```

Écoute sur `http://localhost:8080`

Ouvrez `http://localhost:8080` dans votre navigateur.

## 🔍 Utilisation

### Workflow Simple (UI)

1. Accédez à `http://localhost:8080`
2. Onglet **Scanner** → Entrez la base de la cible (`http://localhost:3000`)
3. Cliquez **Discover** pour enumérer les endpoints
4. Configurez credentials de test ou laissez vide pour l'attaque ano
5. Cliquez **Run Audit** et regardez les logs en temps réel

### Workflow API (curl)

**Découverte des endpoints**

```bash
curl -X POST http://localhost:8080/api/v1/scanner/discover \
  -H 'Content-Type: application/json' \
  -d '{
    "apiBase": "http://localhost:3000"
  }'
```

**Audit BOLA complet**

```bash
curl -X POST http://localhost:8080/api/v1/scanner/audit \
  -H 'Content-Type: application/json' \
  -d '{
    "apiBase": "http://localhost:3000",
    "register": "/api/auth/register",
    "login": "/api/auth/login",
    "target": "/api/users/:id",
    "objectId": "usr_exampleid1234"
  }'
```

**Réponse attendue (BOLA trouvée)**

```json
{
  "isBOLA": true,
  "ownerStatus": 200,
  "ownerData": { "id": "...", "email": "..." },
  "anonStatus": 401,
  "evidence": "Accès possible sans authentification via Header/Cookie manipulation"
}
```

## 🛡️ Variables d'Environnement

### Serveur Principal

| Variable | Défaut | Description |
|----------|--------|-------------|
| `PORT` | `8080` | Port du serveur principal |
| `ALLOWED_ORIGIN` | `*` | Origine CORS autorisée |
| `ENABLE_DEMO_TARGET` | `false` | Active `/api/v1/_discover` (démo locale) |
| `NODE_ENV` | `development` | Mode production/développement |

### Puppeteer & Stealth

| Variable | Défaut | Description |
|----------|--------|-------------|
| `PUPPETEER_ENABLED` | `true` | Active spider.js |
| `PUPPETEER_HEADLESS` | `new` | Mode headless (`new`, `true`, `false`) |
| `PUPPETEER_TIMEOUT_MS` | `15000` | Timeout en millisecondes |
| `PUPPETEER_NO_SANDBOX` | `true` | Ajoute `--no-sandbox` (Linux sans GUI) |
| `PUPPETEER_EXECUTABLE_PATH` | `` | Chemin Chrome/Chromium custom |
| `PUPPETEER_CHANNEL` | `` | Channel (`chrome`, `firefox`) |
| `PUPPETEER_USER_DATA_DIR` | `` | Répertoire profil utilisateur |
| `PUPPETEER_IGNORE_HTTPS_ERRORS` | `false` | Ignore erreurs SSL (test uniquement) |
| `PUPPETEER_BLOCK_ASSETS` | `true` | Bloque images/CSS pour accélérer |

### Limites & Sécurité

| Variable | Défaut | Description |
|----------|--------|-------------|
| `MAX_BODY_BYTES` | `1048576` | Limite taille corps HTTP (1MB) |
| `MAX_AUTH_ATTEMPTS` | `10` | Max tentatives auth par audit |

## 🧪 Comprendre la Target API

La cible (`target-api/server.js`) implémente **4 niveaux de protections anti-bot**:

### 1. **Honeypot Fields** 
Les fields invisibles qui ne doivent JAMAIS être remplies:
- `middleName`, `botField`, `hiddenField`

Si remplis → rejeté comme bot.

### 2. **Captcha Validation**
Attendu l'un des tokens:
- `captchaToken`, `gRecaptchaResponse`, `recaptchaToken`, `humanProof`

BOLA-Shield injecte `captchaToken: 'valid_human_token'` dans les payloads.

### 3. **Proof-of-Time (PoT)**
- Timestamp signée avec HMAC-SHA256 généré par le serveur
- Minimum 2s d'écart (détecte les bots trop rapides)
- Maximum 10min d'écart (session expirée)

### 4. **Browser Headers Stricts**
Chèque la présence de:
- `user-agent` ET `accept-language` REQUIS
- `sec-fetch-mode` OU `origin` REQUIS

Un simple `curl` sans ces headers est rejeté.

**Comment BOLA-Shield contourne**:
- `spider.js` : navigue avec Puppeteer (vrais headers) + attente OTP
- `browser-engine.js` : injecte les requêtes dans le contexte de la page (utilise cookies) via `page.evaluate(fetch)`
- `evasion.js` : spoofie IP et fausse entropie si détecté

## 📚 Pour Continuer le Développement

### Ajouter une nouvelle route API

Modifiez `lib/routes.js` et réferencez `context` pour les helpers:

```javascript
if (url.pathname === '/api/v1/ma-route' && req.method === 'POST') {
    const body = await context.readBody(req);
    context.broadcastEvent({ type: 'info', msg: 'Ma route appelée' });
    return context.sendJSON(res, 200, { ok: true });
}
```

### Ajouter une méthode d'évasion

Modifiez `lib/evasion.js`:

```javascript
export function myNewEvasionMethod() {
    // Retourner des headers falsifiés, cookies, etc.
}
```

Puis utilisez dans `utils.js`:

```javascript
import { myNewEvasionMethod } from './evasion.js';
```

### Tester localement

1. Assurez-vous que `target-api/server.js` écoute sur `:3000`
2. Lancez `server.js` sur `:8080`
3. Utilisez l'UI ou curl pour tester

### Déboguer l'audit

Vérifiez `data/state.json` pour les logs SSE:

```bash
cat data/state.json | jq '.events[-10:]'  # Derniers 10 logs
```

## 🔗 Git & Publication

Le dépôt est configuré pour:

```bash
git remote -v
# origin  https://github.com/ROMI021/projetX.git (fetch)
# origin  https://github.com/ROMI021/projetX.git (push)
```

### Committer & Pousser

**Docs uniquement:**

```bash
git add README.md
git commit -m "Mise à jour documentation"
git push origin main
```

**Code complet:**

```bash
git add .
git commit -m "Mise à jour: refactor modulaire + protections avancées"
git push origin main
```

**Bonnes pratiques:**
- Committer docs séparément du code
- Écrire des messages clairs et en français
- Ne jamais committer `data/credentials.json` (utiliser `.gitignore`)

## ⚠️ Notes Importantes

- **Ne supprimez aucun fichier de `lib/`** — chacun a un rôle critique (voir `lib/README.md`)
- **Target API sur `:3000`** — endpoint figé dans les tests
- **Puppeteer est lourd** — 300MB+ première install, déjà optimisé avec stealth + asset blocking
- **OTP Flow** — Si la cible demande un OTP, le bot se met en pause et relaye via SSE; l'UI envoie le code via `POST /api/v1/otp`
- **Cache de découverte** — Sauvegardée dans `data/discovery_cache.json` pour éviter les re-scans

## 🤝 Contributeurs Futurs

Si vous modifiez ce projet, **mettez à jour `lib/README.md` et `README.md`** en même temps. C'est crucial pour les repreneurs!

---

**Bon hack! 🛡️**
