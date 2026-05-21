# BOLA-Shield AI

BOLA-Shield AI est une plateforme d'audit local et live pour détecter les failles BOLA/IDOR dans des architectures API modernes.

Elle combine :
- un scanner multi-acteurs capable d'enregistrer et de jouer des scénarios d'authentification ;
- un moteur d'audit hybride (actif + passif) ;
- une gateway de mitigation instrumentée ;
- un tableau de bord en temps réel avec flux SSE ;
- un laboratoire cible e-commerce durci pour valider les attaques.

## Objectif du projet

Ce dépôt est conçu pour qu'une autre personne puisse reprendre le développement sans se perdre :
- la logique serveur principale est dans `server.js` et `lib/routes.js` ;
- les helpers partagés sont dans `lib/utils.js` ;
- l'état d'application est stocké dans `lib/store.js` et `data/state.json` ;
- la cible de test est dans `target-api/server.js`.

## Prérequis

- Node.js 20+
- npm
- deux terminaux : un pour le serveur principal, un pour la cible mock

## Installation

### 1. Installer la racine

```bash
cd "c:\Users\Administrator\Desktop\projet X"
npm install
```

### 2. Installer la cible de test

```bash
cd target-api
npm install
```

## Execution

### 1. Lancer la cible mock

```bash
cd target-api
node server.js
```

La cible écoute par défaut sur :
- `http://localhost:3000`

### 2. Lancer le serveur principal

```bash
cd "c:\Users\Administrator\Desktop\projet X"
node server.js
```

Le serveur principal écoute sur :
- `http://localhost:8080`

## Workflow de développement

### Audit de la cible locale

1. Démarrez `target-api/server.js`.
2. Démarrez `server.js`.
3. Ouvrez l'interface : `http://localhost:8080`.
4. Configurez la cible sur `http://localhost:3000`.
5. Lancez l'audit live.

### Tester via API

#### Découverte

```bash
curl -X POST http://localhost:8080/api/v1/scanner/discover \
  -H 'Content-Type: application/json' \
  -d '{"apiBase":"http://localhost:3000"}'
```

#### Audit BOLA

```bash
curl -X POST http://localhost:8080/api/v1/scanner/audit \
  -H 'Content-Type: application/json' \
  -d '{
    "apiBase":"http://localhost:3000",
    "register":"/api/auth/register",
    "login":"/api/auth/login",
    "target":"/api/users/:id",
    "objectId":"usr_exampleid1234"
  }'
```

## Structure du projet

```text
projet X/
├── index.html
├── package.json
├── server.js
├── README.md
├── assets/
│   ├── css/style.css
│   └── js/
│       ├── main.js
│       └── modules/
│           ├── dashboard.js
│           ├── scanner.js
│           ├── patcher.js
│           ├── mapper.js
│           ├── chat.js
│           ├── firewall.js
│           └── state.js
├── lib/
│   ├── routes.js
│   ├── store.js
│   └── utils.js
├── data/
│   ├── state.json
│   └── credentials.example.json
└── target-api/
    ├── package.json
    └── server.js
```

## Composants principaux

- `server.js` : assemble le serveur principal, la gateway proxy et le handler API.
- `lib/routes.js` : implémente les routes du scanner, firewall, patchs et chat.
- `lib/utils.js` : regroupe les outils de découverte, d'appel distant, de parsing, de fingerprinting et de Puppeteer.
- `lib/store.js` : état central persistant et chargement/enregistrement sur disque.
- `target-api/server.js` : API de test e-commerce durcie avec protections anti-robot et endpoint vulnérable contrôlé.

## Variables d'environnement importantes

- `PORT` : port du serveur principal (par défaut `8080`).
- `ALLOWED_ORIGIN` : origine CORS autorisée.
- `ENABLE_DEMO_TARGET` : active le mode démo local uniquement.
- `PUPPETEER_ENABLED` : active l'utilisation de Puppeteer.
- `PUPPETEER_TIMEOUT_MS` : timeout Puppeteer en ms.
- `PUPPETEER_NO_SANDBOX` : ajoute `--no-sandbox` pour les environnements sans GUI.
- `PUPPETEER_BLOCK_ASSETS` : bloque les ressources lourdes pour accélérer la navigation.
- `MAX_BODY_BYTES` : limite de taille des corps HTTP.
- `MAX_AUTH_ATTEMPTS` : limite le nombre de tentatives d'authentification pendant l'audit.

## Conseils pour continuer

- Ajoutez des tests unitaires sur `lib/utils.js` et `lib/routes.js`.
- Documentez chaque nouvelle route API par un exemple `curl`.
- Séparez les logiques d'attaque et de mitigation dans des modules dédiés si la base grossit.
- Ne versionnez jamais `data/credentials.json`.
- Pour une cible réelle, fournissez des tokens ou cookies pré-authentifiés plutôt que de forcer l'authentification.

## Git et publication

Le dépôt est déjà relié à :

- `origin`: `https://github.com/ROMI021/projetX.git`

Pour publier vos modifications :

```bash
git add README.md
git commit -m "Mise à jour de la documentation et des instructions de reprise"
git push origin main
```

Si vous souhaitez pousser toutes les modifications en cours :

```bash
git add .
git commit -m "Mise à jour du projet et de la documentation"
git push origin main
```

> Astuce : conservez un historique clair avec des commits séparés pour le code et la documentation.
