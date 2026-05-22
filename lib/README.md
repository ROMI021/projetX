# BOLA-Shield : Bibliothèque Interne (`/lib`)

Ce dossier contient le **Cœur du Moteur Backend** (Core Engine) de BOLA-Shield. C'est ici que toute la logique d'attaque (Pentesting), d'évasion (Stealth) et de gestion d'état est exécutée.

> [!WARNING]
> **Fichiers critiques !** Ne supprimez aucun fichier de ce dossier. La modification d'un de ces fichiers peut casser l'intégralité du moteur d'audit ou les capacités d'évasion du bot.

## 🗂️ Cartographie des Fichiers

| Fichier | Rôle Principal | Risque si suppression |
| :--- | :--- | :--- |
| `cache.js` | Gère la lecture et l'écriture du cache de découverte des cibles (`discovery_cache.json`). Évite les requêtes réseau redondantes. | Le bot perd sa mémoire et relancera Puppeteer à chaque scan, provoquant des lenteurs extrêmes. |
| `evasion.js` | Moteur Anti-Bot. Génère de fausses adresses IP (Spoofing X-Forwarded-For) et simule une entropie comportementale (faux mouvements de souris) pour tromper les WAF (Web Application Firewalls). | Le bot sera instantanément bloqué (Erreur 429) par les protections d'entreprise. |
| `routes.js` | Gère les requêtes HTTP (API Express) venant du Front-End Vue.js. Orchestre le démarrage de l'audit BOLA, du patch, du firewall et **réceptionne le code OTP envoyé par l'UI** (`/api/otp`). | L'interface graphique ne pourra plus communiquer avec le serveur BOLA-Shield. |
| `spider.js` | Moteur DAST. Lance un navigateur invisible (*Puppeteer Stealth*). **Simule de véritables frappes de touches humaines** (Tabulations, Enter, Blur events) pour déjouer les validations front-end strictes (Vue/React). Il se met en **pause asynchrone (max 3 min)** lorsqu'un code OTP est requis. | Incapacité d'auditer des cibles réelles nécessitant une double authentification ou bloquant les saisies DOM instantanées. |
| `spider-engine.js` | **[NEW] Full Auto-Discovery Spider**. Moteur heuristique d'exploration autonome. Clique intelligemment sur la cible pour intercepter et découvrir de vraies requêtes API. | Le bot perd sa capacité à trouver des cibles BOLA de lui-même. |
| `macro-engine.js` | Génération de ressources (Panier d'achat). Clique sur un produit et l'ajoute au panier pour capturer l'ID dynamique. | Incapacité de s'attaquer aux paniers d'achats classiques. |
| `exfiltration-engine.js`| **[NEW] Data Exfiltration & Sabotage Engine**. S'active après une confirmation BOLA. Aspire les données de masse (emails, téléphones) et tente des requêtes de modification (Attack Chaining). | L'outil perd sa capacité de preuve de concept (PoC) post-exploitation. |
| `browser-engine.js` | **Heavy DAST Engine**. Moteur de secours. Lance 3 profils Incognito parallèles (User A, User B, Anon) et y injecte les requêtes BOLA (`page.evaluate(fetch)`) pour utiliser automatiquement les cookies certifiés et contourner les WAF (Cloudflare) bloquant le moteur HTTP natif. Pilote les modules d'exfiltration et d'exploration. | Impossible d'auditer les cibles d'entreprise (Erreur 400 permanente). |
| `store.js` | Gère l'état global de l'application. Contient `broadcastEvent` pour envoyer les logs (SSE) à l'UI et **le pont de communication mémoire (`pendingOTP`)** pour relayer l'OTP saisi par l'utilisateur vers Puppeteer. | Perte totale de la mémoire du programme. Plantage généralisé des flux SSE. |
| `utils.js` | Fonctions utilitaires de base (Requêtes HTTP, cryptographie). Pilote la boucle BOLA rapide. **Bascule automatiquement sur `browser-engine.js` si le moteur HTTP natif reçoit un blocage (Erreur 400/403).** | Dépendance critique pour tous les autres modules. Plantage garanti. |

## 🏗️ Architecture du Moteur (Mermaid)

```mermaid
graph TD
    UI[Front-End UI] -->|Appels API| R(routes.js)
    
    R -->|1. Demande Cache| C(cache.js)
    C -.->|Miss| SP(spider.js)
    
    SP -->|Mode interactif OTP| UI
    SP -->|Intercepte| Target[Serveur Cible]
    
    R -->|2A. Attaque Rapide| U(utils.js)
    U -->|Falsifie IP| E(evasion.js)
    E -->|Requête HTTP Node| Target
    
    Target -.->|Blocage 400/403| R
    R -->|2B. Fallback| B(browser-engine.js)
    B -->|1. Découverte API| SE(spider-engine.js)
    SE -->|Navigue et Intercepte| Target
    B -->|2. Attaque BOLA WAF-Bypass| Target
    B -->|3. Post-Exploitation PoC| EX(exfiltration-engine.js)
    EX -->|Aspiration & Sabotage| Target
    
    R -->|Envoie Logs| ST(store.js)
    ST -->|SSE (Server-Sent Events)| UI
```

## 🛠️ Comment bien l'utiliser

1. **Modularité :** Si vous devez ajouter un nouveau moyen d'évasion (ex: contournement de Captcha), ajoutez-le dans `evasion.js` ou `spider.js`, **pas** dans `utils.js`.
2. **Gestion d'État :** Si une variable doit persister après un redémarrage, elle doit être déclarée dans l'objet global de `store.js` et sauvegardée via `saveStore()`.
3. **Puppeteer :** La configuration de `spider.js` est pilotée par les variables d'environnement (`PUPPETEER_HEADLESS`, etc.). Ne modifiez le code interne que si les sélecteurs CSS des cibles sont très spécifiques.
