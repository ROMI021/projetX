# BOLA-Shield : Front-End Vue.js (`/assets`)

Ce dossier gère **l'Interface Graphique (UI)** de BOLA-Shield. C'est ici que sont affichés le tableau de bord, la cartographie visuelle des attaques BOLA, et les recommandations du pare-feu.

> [!NOTE]
> Le Front-End a été construit de manière moderne via Vue 3 en mode "Petite" (sans build complexe Webpack/Vite). Le code est structuré en différents modules JavaScript ES6 dans `assets/js/modules`.

## 🗂️ Cartographie des Fichiers

| Fichier / Dossier | Rôle Principal | Risque si suppression |
| :--- | :--- | :--- |
| `css/` | Contient les styles visuels (Thème sombre Cyberpunk, animations, design premium). | L'interface graphique perdra son aspect esthétique (mode texte brut). |
| `js/modules/state.js` | Le "Store" réactif du Front-End. Gère la connexion SSE avec le Backend pour recevoir les alertes en temps réel et met à jour l'affichage. | La page web ne s'actualisera plus en temps réel et perdra sa connexion au Backend. |
| `js/modules/dashboard.js` | Gère les composants Vue pour les compteurs (Taux d'exposition, Fuites, Injections). | Les statistiques resteront figées à zéro. |
| `js/modules/mapper.js` | Gère le dessin du **Graphique des Attaques** (La carte des objets). Dessine les liens entre l'attaquant, la cible et la vulnérabilité détectée. | L'attaque ne sera pas visuellement affichée (écran noir au centre de l'interface). |
| `js/modules/firewall.js` | Affiche l'écran des recommandations de sécurité en temps réel. | Le système défensif ne sera pas visualisable. |
| `js/modules/chat.js` | Composant d'affichage des logs (Journal du Bot). | Vous ne verrez plus les actions du scanner à l'écran. |

## 🏗️ Architecture du Front-End (Mermaid)

```mermaid
graph TD
    index[index.html (Point d'entrée)] --> Vue(Instance Vue 3)
    
    Vue --> State(state.js)
    State -->|Écoute (SSE)| Backend[Serveur Node.js]
    
    State --> Dashboard(dashboard.js)
    State --> Mapper(mapper.js)
    State --> Firewall(firewall.js)
    State --> Chat(chat.js)
    
    Mapper -->|Génère| UI_Graph[Carte BOLA visuelle]
    Chat -->|Affiche| UI_Terminal[Terminal Cybersécurité]
```

## 🛠️ Comment bien l'utiliser

1. **Pas besoin de compilation :** Vous n'avez pas besoin d'utiliser `npm run build` pour ce front-end. Les modifications dans ces fichiers `.js` ou `.css` sont immédiatement visibles dans votre navigateur si vous rafraîchissez la page (`F5`).
2. **Logique Vue.js :** Tous ces modules exportent des composants Vue 3 qui sont ensuite assemblés dans le fichier principal `/index.html` à la racine du projet. Ne supprimez pas les imports ES6 dans `index.html`.
3. **Graphisme :** Si vous souhaitez modifier l'apparence des bulles d'attaque BOLA (par exemple, pour les rendre plus agressives ou d'une autre couleur), modifiez la logique de rendu SVG dans `mapper.js`.
