# BOLA-Shield AI

BOLA-Shield AI est une plateforme locale d'audit live pour les failles BOLA/IDOR de niveau professionnel. Elle a été transformée d'une application de démonstration locale en un scanner de sécurité "Production-Ready". 

Elle combine :
- Un scanner multi-acteurs utilisant Puppeteer (Headless Browser) pour simuler des utilisateurs réels.
- Un moteur d'audit hybride : **Audit Actif** pour prouver la vulnérabilité (preuves d'accès croisés) et **Audit Passif** pour la cartographie des surfaces d'attaque lorsque le bot est bloqué par un WAF/Cloudflare.
- Une Gateway (Proxy) de mitigation jouant le rôle d'un pare-feu applicatif de nouvelle génération (IA-Powered Shield).
- La diffusion de journaux d'audit en temps réel dans l'interface utilisateur via la technologie **Server-Sent Events (SSE)**.
- Des métriques dynamiques strictes et réalistes (plus d'estimations factices).

Le mode par défaut est strictement externe ("live-only") : aucune API e-commerce locale vulnérable n'est exposée pour éviter d'ouvrir des failles sur votre propre système.

## Démarrage Rapide

```bash
node server.js
```

- Interface UI : <http://localhost:8080>
- API locale : <http://localhost:8080/api/v1>

## Nouveautés Récentes (Hardening Production)

- **Flux de logs en temps réel (SSE) :** Les étapes d'audit s'affichent instantanément dans le "Journal du bot" au fur et à mesure que Puppeteer exécute les actions. Protection contre la duplication des logs via la norme stricte `Last-Event-ID` lors des reconnexions réseau.
- **Moteur Puppeteer Optimisé :** Blocage automatique des ressources lourdes (images, fonts, css) pour des audits extrêmement rapides. Émulation de User-Agent pour réduire le risque de blocage basique.
- **Métriques Réalistes :** Le tableau de bord affiche des compteurs stricts basés sur le comportement réel du scanner. Si une cible refuse immédiatement la connexion, le système enregistre 0 tentative et passe en cartographie passive.
- **Limitation d'attaques Granulaire :** Intégration de la variable `MAX_AUTH_ATTEMPTS` pour contrôler strictement les itérations des tests d'authentification sans déborder de la mémoire ou être blacklisté (par défaut: 24 tests).

## Préparation pour un Déploiement en Production

Avant de publier ou déployer sur un VPS (ex: Ubuntu/Debian) :

```bash
NODE_ENV=production MAX_AUTH_ATTEMPTS=24 ALLOWED_ORIGIN=https://votre-domaine.example node server.js
```

### Bonnes pratiques :
- Ne versionnez pas `data/credentials.json` et configurez vos identifiants réels en local.
- Sur des cibles fortement protégées (WAF strict), renseignez manuellement un **Token de Session** ou des **Cookies valides** dans l'interface de scan pour court-circuiter l'étape de connexion bloquée par Cloudflare et aller directement tester les vulnérabilités BOLA.
- Exposez le service derrière un reverse proxy HTTPS en production.
- Le serveur refuse nativement la navigation dans les répertoires sensibles (`Directory Traversal` bloqué).

## Architecture

```text
projet X/
|-- index.html
|-- server.js
|-- package.json
|-- package-lock.json
`-- assets/
    |-- css/style.css
    `-- js/
        |-- main.js
        |-- modules/
        |   |-- dashboard.js     (Client SSE & Graphiques)
        |   |-- scanner.js       (Moteur UI d'audit & Logs temps réel)
        |   |-- patcher.js
        |   |-- mapper.js
        |   |-- chat.js
        |   |-- firewall.js      (Configurations du Shield IA)
        |   `-- state.js
        `-- utils/helpers.js
```

## Sécurité Intégrée

Le serveur applique de manière proactive des mesures de sécurité pour s'auto-protéger :

- Nettoyage des en-têtes Hop-by-hop.
- Headers HTTP stricts (HSTS, DENY, Referrer-Policy, Content-Security-Policy).
- CORS configurable via `ALLOWED_ORIGIN`.
- Masquage des erreurs serveur et stacktraces en production via le wrapper `publicError()`.
- Persistance des métriques et configuration dans `data/state.json`.

## Variables d'Environnement

Le serveur est hautement configurable au travers de variables :

- `PORT` : port HTTP, défaut `8080`.
- `MAX_BODY_BYTES` : taille maximale des requêtes JSON, défaut `1000000`.
- `MAX_AUTH_ATTEMPTS` : Nombre limite de combinaisons d'identifiants testées lors de la découverte (défaut `24`).
- `ALLOWED_ORIGIN` : origine CORS autorisée, défaut `*`.
- `ALLOW_PRIVATE_TARGETS` : autorise le scan de cibles réseau privées (localhost, 192.168.x.x) si `true`.
- `ENABLE_DEMO_TARGET` : réactive l'ancienne cible e-commerce locale ("Mboa-Shop") uniquement pour un labo isolé (défaut `false`).
- `PUPPETEER_ENABLED` : force le mode fetch-only HTTP pur si `false`.
- `PUPPETEER_TIMEOUT_MS` : timeout global de Puppeteer, défaut `15000`.
- `PUPPETEER_NO_SANDBOX` : ajoute le flag `--no-sandbox`, indispensable pour Docker ou un VPS sans GUI.
- `PUPPETEER_BLOCK_ASSETS` : accélère les performances en empêchant Puppeteer de charger le design de la page.

## Limites Volontaires

BOLA-Shield AI n'a pas vocation à contourner l'authentification humaine d'un véritable pare-feu (ex: résoudre un Captcha interactif).
Pour effectuer un audit certifiant d'une vraie API en production, vous devez utiliser l'outil en "White Box", en fournissant des Tokens ou Cookies préalablement authentifiés. L'outil passera alors l'étape de connexion et bombardera exclusivement les points de terminaison pour prouver la vulnérabilité d'autorisation.
