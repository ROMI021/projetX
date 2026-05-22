/* ======================================================================
   BOLA-Shield — Autonomous Macro Engine
   Extrait les comportements automatisés pour la génération de ressources cibles.
   ====================================================================== */

export async function generateResourceAutonomous(page, targetBase, broadcastEvent) {
    let capturedId = null;
    broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[MACRO] Démarrage de la génération autonome de ressource...` });

    // 1. Intercepter le trafic réseau pour capturer les IDs générés
    const responseHandler = async (response) => {
        try {
            const requestUrl = response.url();
            // Filtrer les requêtes statiques pour éviter des erreurs JSON
            if (requestUrl.match(/\.(png|jpg|jpeg|gif|css|js|woff|woff2)$/i)) return;
            
            // On s'intéresse aux requêtes POST ou aux routes API
            if (response.status() >= 200 && response.status() < 300) {
                const contentType = response.headers()['content-type'] || '';
                if (contentType.includes('application/json')) {
                    const json = await response.json().catch(() => null);
                    if (json) {
                        // Chercher récursivement un ID pertinent
                        const id = extractRelevantId(json);
                        if (id && !capturedId) {
                            capturedId = id;
                            broadcastEvent({ origin: 'AUDIT', type: 'success', msg: `[MACRO] Identifiant capturé dans le réseau : ${capturedId}` });
                        }
                    }
                }
            }
        } catch (e) {
            // Ignorer silencieusement les erreurs de parsing
        }
    };

    page.on('response', responseHandler);

    try {
        // 2. Naviguer vers la page d'accueil
        broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[MACRO] Navigation vers ${targetBase}...` });
        await page.goto(targetBase, { waitUntil: 'domcontentloaded', timeout: 15000 }).catch(() => {});
        await new Promise(r => setTimeout(r, 2000));

        // 3. Heuristique : Chercher un produit et cliquer dessus
        // Stratégie : chercher une balise <a> qui contient une image
        const productLinks = await page.$$('a > img');
        if (productLinks.length > 0) {
            // On prend le deuxième ou troisième lien si possible (pour éviter le logo)
            const targetLink = productLinks.length > 2 ? productLinks[2] : productLinks[productLinks.length - 1];
            broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[MACRO] Produit potentiel trouvé, clic en cours...` });
            
            await Promise.all([
                page.waitForNavigation({ waitUntil: 'domcontentloaded', timeout: 10000 }).catch(() => {}),
                targetLink.click().catch(() => {})
            ]);
            await new Promise(r => setTimeout(r, 2500));
        }

        if (capturedId) return capturedId; // Si le clic a déjà généré un ID (ex: ajout rapide)

        // 4. Heuristique : Chercher un bouton "Ajouter au panier"
        const addButtons = await page.$x("//button[contains(translate(., 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'ajout') or contains(translate(., 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'add') or contains(translate(., 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'panier') or contains(translate(., 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'cart')]");
        
        if (addButtons.length > 0) {
            broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[MACRO] Bouton d'ajout identifié, clic en cours...` });
            await addButtons[0].click().catch(() => {});
        } else {
            broadcastEvent({ origin: 'AUDIT', type: 'warning', msg: `[MACRO] Aucun bouton d'ajout au panier trouvé.` });
            // Tentative désespérée : cliquer sur le premier bouton trouvé
            const anyButton = await page.$('button');
            if (anyButton) await anyButton.click().catch(() => {});
        }

        // 5. Attendre la fin des requêtes réseau (3 secondes max)
        let waited = 0;
        while (!capturedId && waited < 4000) {
            await new Promise(r => setTimeout(r, 200));
            waited += 200;
        }

    } catch (e) {
        broadcastEvent({ origin: 'AUDIT', type: 'warning', msg: `[MACRO] Erreur lors de la navigation : ${e.message}` });
    } finally {
        page.off('response', responseHandler);
    }

    if (!capturedId) {
        broadcastEvent({ origin: 'AUDIT', type: 'warning', msg: `[MACRO] Échec de la génération automatique d'identifiant.` });
    }

    return capturedId;
}

// Fonction utilitaire pour trouver un ID dans un JSON imbriqué
function extractRelevantId(obj, depth = 0) {
    if (depth > 5 || !obj || typeof obj !== 'object') return null;
    
    // Vérifier les clés au niveau courant
    for (const key of Object.keys(obj)) {
        const lowerKey = key.toLowerCase();
        if (lowerKey === 'cart_id' || lowerKey === 'order_id' || lowerKey === 'invoice_id' || lowerKey === 'id') {
            const val = obj[key];
            if (val && (typeof val === 'string' || typeof val === 'number')) {
                // On évite les UUID trop longs si ce n'est pas le standard, mais par défaut on prend tout
                return String(val);
            }
        }
    }

    // Chercher récursivement dans les sous-objets
    for (const key of Object.keys(obj)) {
        if (typeof obj[key] === 'object') {
            const found = extractRelevantId(obj[key], depth + 1);
            if (found) return found;
        }
    }
    return null;
}
