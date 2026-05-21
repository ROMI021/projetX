# BOLA-Shield : Front-End Vue.js (`/assets`)

Ce dossier gère **l'Interface Graphique (UI)** de BOLA-Shield. C'est ici que sont affichés le tableau de bord, la cartographie visuelle des attaques BOLA, et les recommandations du pare-feu.

> [!NOTE]
> Le Front-End a été construit de manière moderne en **Vanilla JavaScript** modulaire (sans build complexe Webpack/Vite). Le code est structuré en différents modules JavaScript ES6 dans `assets/js/modules`.

## 🗂️ Cartographie des Fichiers

| Fichier / Dossier | Rôle Principal | Risque si suppression |
| :--- | :--- | :--- |
| `css/` | Contient les styles visuels (Thème sombre Cyberpunk, animations, design premium). | L'interface graphique perdra son aspect esthétique (mode texte brut). |
| `js/main.js` | Point d'entrée principal. Initialise l'application, gère les interactions des boutons globaux (comme l'activation du pare-feu) et **pilote la fenêtre modale interactive d'OTP**. | L'application entière sera figée. |
| `js/modules/state.js` | Le "Store" réactif du Front-End. Gère la logique de calcul de score de sécurité et la persistance des données. | La page web ne s'actualisera plus et perdra son état. |
| `js/modules/dashboard.js` | Gère l'affichage dynamique (DOM) du tableau de bord. **Écoute le flux SSE et déclenche les événements personnalisés (ex: `bola-otp-required`)** pour communiquer avec les autres modules. | Les statistiques resteront figées à zéro et l'UI ne réagira plus aux événements serveurs. |
| `js/modules/mapper.js` | Gère le dessin du **Graphique des Attaques** (La carte des objets). Dessine les liens entre l'attaquant, la cible et la vulnérabilité détectée. | L'attaque ne sera pas visuellement affichée (écran noir au centre de l'interface). |
| `js/modules/firewall.js` | Affiche l'écran des recommandations de sécurité en temps réel. | Le système défensif ne sera pas visualisable. |
| `js/modules/chat.js` | Composant d'affichage des logs (Journal du Bot). | Vous ne verrez plus les actions du scanner à l'écran. |

## 🏗️ Architecture du Front-End (Mermaid)

```mermaid
graph TD
    index[index.html (Point d'entrée)] --> Main(main.js)
    
    Main --> State(state.js)
    Main --> Dashboard(dashboard.js)
    Dashboard -->|Écoute (SSE)| Backend[Serveur Node.js]
    
    State --> Dashboard(dashboard.js)
    State --> Mapper(mapper.js)
    State --> Firewall(firewall.js)
    State --> Chat(chat.js)
    
    Mapper -->|Génère| UI_Graph[Carte BOLA visuelle]
    Chat -->|Affiche| UI_Terminal[Terminal Cybersécurité]
```

## 🛠️ Comment bien l'utiliser

1. **Pas besoin de compilation :** Vous n'avez pas besoin d'utiliser `npm run build` pour ce front-end. Les modifications dans ces fichiers `.js` ou `.css` sont immédiatement visibles dans votre navigateur si vous rafraîchissez la page (`F5`).
2. **Logique Vanilla JS :** Tous ces modules utilisent des API natives (CustomEvents, DOM Manipulation) et sont assemblés dans le fichier principal `/index.html` à la racine du projet. L'architecture repose sur un couplage lâche via `document.dispatchEvent`.
3. **Graphisme :** Si vous souhaitez modifier l'apparence des bulles d'attaque BOLA (par exemple, pour les rendre plus agressives ou d'une autre couleur), modifiez la logique de rendu SVG dans `mapper.js`.
