/* ======================================================================
   BOLA-Shield — Autonomous Macro Engine
   Extrait les comportements automatisés pour la génération de ressources cibles.
   ====================================================================== */

export async function generateResourceAutonomous(page, targetBase, broadcastEvent) {
    let capturedId = null;
    let capturedEndpoint = null;
    let isListeningForId = false;
    broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[MACRO] Démarrage de la génération autonome de ressource...` });

    const targetUrlObj = new URL(targetBase);
    const targetHostname = targetUrlObj.hostname;

    // 1. Intercepter le trafic réseau pour capturer les IDs générés
    const responseHandler = async (response) => {
        try {
            if (!isListeningForId) return;

            const requestUrl = response.url();
            const requestUrlObj = new URL(requestUrl);
            
            // Ignorer les requêtes vers d'autres domaines (tracking, analytics, pubs)
            if (!requestUrlObj.hostname.includes(targetHostname)) return;

            // Filtrer les requêtes statiques
            if (requestUrl.match(/\.(png|jpg|jpeg|gif|css|js|woff|woff2|svg)$/i)) return;
            
            // On s'intéresse aux requêtes de l'API (POST/GET)
            if (response.status() >= 200 && response.status() < 300) {
                const contentType = response.headers()['content-type'] || '';
                if (contentType.includes('application/json')) {
                    const json = await response.json().catch(() => null);
                    if (json) {
                        // Chercher récursivement un ID pertinent
                        const id = extractRelevantId(json);
                        if (id && !capturedId) {
                            capturedId = id;
                            capturedEndpoint = requestUrlObj.pathname;
                            broadcastEvent({ origin: 'AUDIT', type: 'success', msg: `[MACRO] Véritable identifiant cible capturé : ${capturedId} sur l'endpoint ${capturedEndpoint}` });
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
                page.waitForNavigation({ waitUntil: 'domcontentloaded', timeout: 15000 }).catch(() => {}),
                targetLink.evaluate(b => b.click()).catch(() => {})
            ]);
            await new Promise(r => setTimeout(r, 2500));
        }

        // 4. Heuristique : Chercher un bouton "Ajouter au panier"
        let targetButton = null;
        
        const clickableElements = await page.$$('button, a, input[type="submit"], input[type="button"]');
        for (const el of clickableElements) {
            const text = await el.evaluate(e => (e.innerText || e.value || '').toLowerCase()).catch(() => '');
            if (text.includes('ajout') || text.includes('add') || text.includes('panier') || text.includes('cart')) {
                // Vérifier si l'élément est visible
                const isVisible = await el.evaluate(e => e.offsetWidth > 0 && e.offsetHeight > 0).catch(() => false);
                if (isVisible) {
                    targetButton = el;
                    break;
                }
            }
        }
        
        // Début de l'écoute du trafic UNIQUEMENT au moment de l'ajout
        isListeningForId = true;

        if (targetButton) {
            broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[MACRO] Bouton d'ajout identifié, clic en cours...` });
            await targetButton.evaluate(b => b.click()).catch(() => {});
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
        broadcastEvent({ origin: 'AUDIT', type: 'warning', msg: `[MACRO] Échec de la capture de l'identifiant du produit/panier.` });
    }

    return { objectId: capturedId, endpoint: capturedEndpoint };
}

// Fonction utilitaire pour trouver un ID dans un JSON imbriqué
function extractRelevantId(obj, depth = 0) {
    if (depth > 5 || !obj || typeof obj !== 'object') return null;
    
    // Vérifier les clés au niveau courant
    for (const key of Object.keys(obj)) {
        const lowerKey = key.toLowerCase();
        if (lowerKey === 'cart_id' || lowerKey === 'order_id' || lowerKey === 'invoice_id' || lowerKey === 'id' || lowerKey === 'quote_id' || lowerKey === 'item_id') {
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
