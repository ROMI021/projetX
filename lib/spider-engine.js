/* ======================================================================
   BOLA-Shield — Full Auto-Discovery Spider
   Module heuristique d'exploration pour trouver automatiquement 
   des endpoints API vulnérables (BOLA) de manière furtive (anti-bot).
   ====================================================================== */

export async function runAutoDiscoverySpider(page, targetBase, broadcastEvent) {
    let discoveredApi = null;
    let isListening = false;
    broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[SPIDER] Démarrage de l'exploration heuristique 100% autonome...` });

    const targetUrlObj = new URL(targetBase);
    const targetHostname = targetUrlObj.hostname;

    // 1. Écoute passive du réseau pour attraper les API
    const responseHandler = async (response) => {
        if (!isListening || discoveredApi) return;
        try {
            const request = response.request();
            const requestUrl = request.url();
            const requestUrlObj = new URL(requestUrl);
            
            // Ignore les requêtes externes et les statiques
            if (!requestUrlObj.hostname.includes(targetHostname)) return;
            if (requestUrl.match(/\.(png|jpg|jpeg|gif|css|js|woff|woff2|svg|ico)$/i)) return;
            
            // On s'intéresse aux requêtes AJAX/XHR/Fetch
            const resourceType = request.resourceType();
            if (resourceType === 'xhr' || resourceType === 'fetch') {
                const status = response.status();
                if (status >= 200 && status < 300) {
                    const contentType = response.headers()['content-type'] || '';
                    if (contentType.includes('application/json')) {
                        
                        // Heuristique de détection d'une route API BOLA : 
                        // L'URL contient "api" et se termine par un identifiant numérique ou un UUID.
                        const pathParts = requestUrlObj.pathname.split('/').filter(Boolean);
                        const lastPart = pathParts[pathParts.length - 1];
                        
                        const isNumeric = /^\d+$/.test(lastPart);
                        const isUUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(lastPart);
                        
                        if (isNumeric || isUUID) {
                            // On extrait la base de l'endpoint et l'ID
                            const endpointBase = '/' + pathParts.slice(0, -1).join('/');
                            discoveredApi = {
                                endpoint: endpointBase,
                                objectId: lastPart,
                                fullPath: requestUrlObj.pathname
                            };
                            broadcastEvent({ origin: 'AUDIT', type: 'success', msg: `[SPIDER] 🎯 API Vulnérable potentielle trouvée : ${discoveredApi.endpoint} (ID: ${discoveredApi.objectId})` });
                        }
                    }
                }
            }
        } catch (e) {
            // Ignorer silencieusement
        }
    };

    page.on('response', responseHandler);

    try {
        isListening = true;
        // 2. Navigation initiale vers le profil ou le dashboard (si possible)
        // Les routes courantes d'espaces clients
        const dashboardRoutes = ['/customer/account', '/account', '/profile', '/my-account', '/dashboard'];
        let inDashboard = false;

        for (const route of dashboardRoutes) {
            if (discoveredApi) break;
            const tryUrl = new URL(route, targetBase).toString();
            broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[SPIDER] Navigation furtive vers ${route}...` });
            
            await page.goto(tryUrl, { waitUntil: 'domcontentloaded', timeout: 15000 }).catch(() => {});
            await humanDelay(); // Délai aléatoire pour simuler l'humain
            
            // Si on n'est pas redirigé vers l'accueil ou le login, c'est qu'on y est !
            const currentUrl = page.url();
            if (currentUrl.includes(route)) {
                inDashboard = true;
                break;
            }
        }

        // 3. Fuzzing UI - Clics aléatoires sur les menus sensibles
        if (!discoveredApi) {
            broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[SPIDER] Fuzzing UI : Recherche d'éléments d'interface critiques...` });
            
            // Mots clés sensibles dans les liens
            const keywords = ['address', 'adresse', 'order', 'commande', 'profile', 'profil', 'history', 'historique', 'wishlist', 'favorite'];
            
            const links = await page.$$('a, button');
            let clickedLinks = 0;

            for (const link of links) {
                if (discoveredApi || clickedLinks >= 3) break; // Max 3 clics pour ne pas bloquer le système

                const text = await link.evaluate(e => (e.innerText || e.getAttribute('title') || '').toLowerCase()).catch(() => '');
                const isSensitive = keywords.some(kw => text.includes(kw));

                if (isSensitive) {
                    const isVisible = await link.evaluate(e => e.offsetWidth > 0 && e.offsetHeight > 0).catch(() => false);
                    if (isVisible) {
                        broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[SPIDER] Action humaine : Clic sur l'élément '${text.trim().substring(0, 15)}...'` });
                        
                        await Promise.all([
                            page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 10000 }).catch(() => {}),
                            link.evaluate(b => b.click()).catch(() => {})
                        ]);
                        clickedLinks++;
                        await humanDelay(2000, 4000); // Mouvements lents
                    }
                }
            }
        }

        // 4. Si après tout ça, aucune API n'est découverte dans le réseau, on attend encore un peu
        let waited = 0;
        while (!discoveredApi && waited < 6000) {
            await new Promise(r => setTimeout(r, 500));
            waited += 500;
            // On scroll de manière humaine pendant l'attente
            if (waited % 2000 === 0) {
                await page.evaluate(() => window.scrollBy(0, Math.floor(Math.random() * 300) + 100)).catch(() => {});
            }
        }

    } catch (e) {
        broadcastEvent({ origin: 'AUDIT', type: 'error', msg: `[SPIDER] Erreur lors de l'exploration : ${e.message}` });
    } finally {
        isListening = false;
        page.off('response', responseHandler);
    }

    if (!discoveredApi) {
        broadcastEvent({ origin: 'AUDIT', type: 'warning', msg: `[SPIDER] Exploration terminée. Aucune route API BOLA directe n'a été détectée automatiquement.` });
    }

    return discoveredApi;
}

/**
 * Génère un délai asynchrone aléatoire pour tromper les protections WAF anti-bot.
 */
function humanDelay(min = 1000, max = 2500) {
    const delay = Math.floor(Math.random() * (max - min + 1)) + min;
    return new Promise(resolve => setTimeout(resolve, delay));
}
