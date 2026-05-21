# BOLA-Shield : Bibliothèque Interne (`/lib`)

Ce dossier contient le **Cœur du Moteur Backend** (Core Engine) de BOLA-Shield. C'est ici que toute la logique d'attaque (Pentesting), d'évasion (Stealth) et de gestion d'état est exécutée.

> [!WARNING]
> **Fichiers critiques !** Ne supprimez aucun fichier de ce dossier. La modification d'un de ces fichiers peut casser l'intégralité du moteur d'audit ou les capacités d'évasion du bot.

## 🗂️ Cartographie des Fichiers

| Fichier | Rôle Principal | Risque si suppression |
| :--- | :--- | :--- |
| `cache.js` | Gère la lecture et l'écriture du cache de découverte des cibles (`discovery_cache.json`). Évite les requêtes réseau redondantes. | Le bot perd sa mémoire et relancera Puppeteer à chaque scan, provoquant des lenteurs extrêmes. |
| `evasion.js` | Moteur Anti-Bot. Génère de fausses adresses IP (Spoofing X-Forwarded-For) et simule une entropie comportementale (faux mouvements de souris) pour tromper les WAF (Web Application Firewalls). | Le bot sera instantanément bloqué (Erreur 429) par les protections d'entreprise. |
| `routes.js` | Gère les requêtes HTTP (API Express) venant du Front-End. Orchestre le démarrage de l'audit BOLA et gère la route `POST /api/otp` pour réceptionner l'OTP interactif. | L'interface graphique ne pourra plus communiquer avec le serveur BOLA-Shield. |
| `spider.js` | Moteur DAST (Dynamic Application Security Testing). Lance un navigateur invisible pour extraire les routes. **Désormais équipé d'une simulation de frappe humaine (Puppeteer `type`), d'une gestion intelligente de l'onglet E-mail, et d'un mécanisme de pause/reprise de 3 minutes pour la saisie d'OTP (2FA).** | Incapacité d'auditer des cibles réelles ne possédant pas de documentation API ouverte ou protégées par Anti-Bots. |
| `store.js` | Gère l'état global de l'application (Variables en mémoire RAM). Intègre la variable `pendingOTP` servant de pont de communication asynchrone entre le Frontend et le navigateur fantôme. | Perte totale de la mémoire du programme. Plantage généralisé des flux SSE. |
| `utils.js` | Fonctions utilitaires de base (Requêtes HTTP, cryptographie). Lit dynamiquement les identifiants depuis `credentials.json` et les injecte dans le processus du Spider. | Dépendance critique pour tous les autres modules. Plantage garanti. |

## 🏗️ Architecture du Moteur (Mermaid)

```mermaid
graph TD
    UI[Front-End UI] -->|Appels API| R(routes.js)
    
    R -->|1. Demande Cache| C(cache.js)
    C -.->|Miss| SP(spider.js)
    
    SP -->|Intercepte| Target[Serveur Cible]
    
    R -->|2. Attaque BOLA| U(utils.js)
    U -->|Falsifie IP| E(evasion.js)
    E -->|Requête Attaque| Target
    
    R -->|Envoie Logs| ST(store.js)
    ST -->|SSE (Server-Sent Events)| UI
```

## 🛠️ Comment bien l'utiliser

1. **Modularité :** Si vous devez ajouter un nouveau moyen d'évasion (ex: contournement de Captcha), ajoutez-le dans `evasion.js` ou `spider.js`, **pas** dans `utils.js`.
2. **Gestion d'État :** Si une variable doit persister après un redémarrage, elle doit être déclarée dans l'objet global de `store.js` et sauvegardée via `saveStore()`.
3. **Puppeteer :** La configuration de `spider.js` est pilotée par les variables d'environnement (`PUPPETEER_HEADLESS`, etc.). Ne modifiez le code interne que si les sélecteurs CSS des cibles sont très spécifiques.
