# BOLA-Shield : Front-End Vue.js (`/assets`)

Ce dossier gère **l'Interface Graphique (UI)** de BOLA-Shield. C'est ici que sont affichés le tableau de bord, la cartographie visuelle des attaques BOLA, et les recommandations du pare-feu.

> [!NOTE]
> Le Front-End a été construit de manière moderne en **Vanilla JavaScript ES6** (sans build Webpack/Vite ni framework lourd). Le code est structuré en modules modulaires natifs dans `assets/js/modules`. L'interaction avec le DOM se fait directement via l'API Web standard.

## 🗂️ Cartographie des Fichiers

| Fichier / Dossier | Rôle Principal | Risque si suppression |
| :--- | :--- | :--- |
| `css/` | Contient les styles visuels (Thème sombre Cyberpunk, animations, design premium). | L'interface graphique perdra son aspect esthétique (mode texte brut). |
| `js/main.js` | Point d'entrée principal. Initialise le système et gère la **Modale OTP Interactive** (écoute l'événement de demande d'OTP et expédie la saisie vers le backend). | La modale OTP et d'autres fonctions globales cesseront de fonctionner. |
| `js/modules/state.js` | Le "Store" réactif du Front-End. Gère la connexion SSE avec le Backend pour recevoir les alertes en temps réel et met à jour l'affichage. | La page web ne s'actualisera plus en temps réel et perdra sa connexion au Backend. |
| `js/modules/dashboard.js` | Gère les compteurs de statistiques, le graphique, et écoute le flux SSE pour déclencher l'affichage de la Modale OTP en cas de détection du signal `[OTP_REQUIRED]`. | Les statistiques resteront figées à zéro et l'OTP ne s'affichera pas. |
| `js/modules/scanner.js` | Gère l'interface de lancement de scan, la récupération des paramètres de configuration cibles, et la matrice visuelle des résultats. | Le bouton de scan ne fonctionnera plus. |
| `js/modules/mapper.js` | Gère le dessin du **Graphique des Attaques** (La carte des objets). Dessine les liens entre l'attaquant, la cible et la vulnérabilité détectée. | L'attaque ne sera pas visuellement affichée (écran noir au centre de l'interface). |
| `js/modules/firewall.js` | Affiche l'écran des recommandations de sécurité en temps réel. | Le système défensif ne sera pas visualisable. |
| `js/modules/chat.js` | Composant d'affichage des logs (Journal du Bot). | Vous ne verrez plus les actions du scanner à l'écran. |

## 🏗️ Architecture du Front-End (Mermaid)

```mermaid
graph TD
    index[index.html (Point d'entrée)] --> Main(main.js)
    Main --> State(state.js)
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
2. **Architecture ES6 :** Tous ces modules utilisent les imports ES6 (`import` / `export`) et sont appelés par le fichier principal `index.html`. Ne supprimez pas le type `module` sur les balises de scripts.
3. **Graphisme :** Si vous souhaitez modifier l'apparence des bulles d'attaque BOLA (par exemple, pour les rendre plus agressives ou d'une autre couleur), modifiez la logique de rendu SVG dans `mapper.js`.
