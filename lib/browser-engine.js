import puppeteer from 'puppeteer-extra';
import StealthPlugin from 'puppeteer-extra-plugin-stealth';
import { broadcastEvent } from './store.js';

puppeteer.use(StealthPlugin());

const PUPPETEER_HEADLESS = process.env.PUPPETEER_HEADLESS || 'new';
const PUPPETEER_EXECUTABLE_PATH = process.env.PUPPETEER_EXECUTABLE_PATH || '';
const PUPPETEER_CHANNEL = process.env.PUPPETEER_CHANNEL || '';
const PUPPETEER_TIMEOUT_MS = Number(process.env.PUPPETEER_TIMEOUT_MS || 15000);
const PUPPETEER_NO_SANDBOX = process.env.PUPPETEER_NO_SANDBOX !== 'false';

/**
 * Lance un audit BOLA lourd en utilisant 3 contextes de navigateur isolés (Incognito).
 * Ce module n'est appelé que si le moteur HTTP natif est bloqué par un WAF (Erreur 400, 403, etc.).
 */
export async function runHeavyAudit(targetBase, routes, credentials, targetEndpoint) {
    let browser = null;
    let contextA = null;
    let contextB = null;
    let contextAnon = null;

    broadcastEvent({ origin: 'AUDIT', type: 'warning', msg: `[HEAVY ENGINE] Démarrage du moteur d'audit lourd (Contournement WAF)...` });

    try {
        browser = await puppeteer.launch({
            headless: PUPPETEER_HEADLESS,
            executablePath: PUPPETEER_EXECUTABLE_PATH || undefined,
            channel: PUPPETEER_CHANNEL || undefined,
            args: PUPPETEER_NO_SANDBOX ? ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'] : [],
            defaultViewport: { width: 1280, height: 800 },
            timeout: PUPPETEER_TIMEOUT_MS
        });

        // 1. Création des 3 contextes isolés
        contextA = await browser.createIncognitoBrowserContext();
        contextB = await browser.createIncognitoBrowserContext();
        contextAnon = await browser.createIncognitoBrowserContext();

        // 2. Authentification User A
        broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[HEAVY ENGINE] Authentification de User A...` });
        const loginSuccessA = await authenticateInContext(contextA, targetBase, credentials?.userA);
        
        // 3. Authentification User B
        if (loginSuccessA) {
            broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[HEAVY ENGINE] Authentification de User B...` });
            await authenticateInContext(contextB, targetBase, credentials?.userB);
        } else {
            broadcastEvent({ origin: 'AUDIT', type: 'error', msg: `[HEAVY ENGINE] Échec de l'authentification User A. Abandon du test BOLA.` });
            return null;
        }

        // 4. Injection des requêtes BOLA
        const cleanTargetEndpoint = targetEndpoint.replace('//', '/');
        const fullTargetUrl = new URL(cleanTargetEndpoint, targetBase).toString();
        
        broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[HEAVY ENGINE] Lancement de la sonde BOLA intra-navigateur sur ${cleanTargetEndpoint}` });

        // Lecture Propriétaire (User A -> Ressource A)
        const responseA = await executeFetchInContext(contextA, fullTargetUrl, 'GET');
        broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `Lecture proprietaire: HTTP ${responseA.status}` });

        // BOLA Croisé (User B -> Ressource A)
        const responseB = await executeFetchInContext(contextB, fullTargetUrl, 'GET');
        broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `Requete croisee token B -> objet A: HTTP ${responseB.status}` });

        // Authentification Brisée (Anonyme -> Ressource A)
        const responseAnon = await executeFetchInContext(contextAnon, fullTargetUrl, 'GET');
        broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `Requete anonyme: HTTP ${responseAnon.status}` });

        // 5. Analyse des résultats BOLA
        let bolaVulnerability = false;
        let brokenAuthVulnerability = false;

        // Si B réussit à lire A
        if (responseB.status >= 200 && responseB.status < 300) {
            bolaVulnerability = true;
            broadcastEvent({ origin: 'AUDIT', type: 'error', msg: `[FAILLE CRITIQUE] BOLA confirmée via WAF Bypass ! L'utilisateur B a pu accéder à la ressource de l'utilisateur A.` });
        }

        // Si Anonyme réussit à lire A
        if (responseAnon.status >= 200 && responseAnon.status < 300) {
            brokenAuthVulnerability = true;
            broadcastEvent({ origin: 'AUDIT', type: 'error', msg: `[FAILLE CRITIQUE] Broken Authentication confirmée ! Un utilisateur anonyme a pu accéder à la ressource.` });
        }

        if (!bolaVulnerability && !brokenAuthVulnerability) {
            broadcastEvent({ origin: 'AUDIT', type: 'success', msg: `Pas de fuite confirmee sur cette execution.` });
        }

        return {
            bola: bolaVulnerability,
            brokenAuth: brokenAuthVulnerability,
            statusA: responseA.status,
            statusB: responseB.status,
            statusAnon: responseAnon.status
        };

    } catch (e) {
        broadcastEvent({ origin: 'AUDIT', type: 'error', msg: `[HEAVY ENGINE] Erreur critique : ${e.message}` });
        return null;
    } finally {
        if (contextA) await contextA.close().catch(()=>{});
        if (contextB) await contextB.close().catch(()=>{});
        if (contextAnon) await contextAnon.close().catch(()=>{});
        if (browser) await browser.close().catch(()=>{});
        broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[HEAVY ENGINE] Nettoyage de la RAM terminé.` });
    }
}

/**
 * Automatise le login dans un contexte isolé. Réplique la fiabilité du spider.js
 */
async function authenticateInContext(context, targetBase, userCreds) {
    if (!userCreds || !userCreds.email || !userCreds.password) return false;

    const page = await context.newPage();
    try {
        // Naviguer vers la page de login la plus probable
        const loginUrl = new URL('/login', targetBase).toString();
        await page.goto(loginUrl, { waitUntil: 'networkidle2', timeout: 15000 }).catch(()=>{});

        // Chercher et remplir les champs
        const inputs = await page.$$('input').catch(()=>[]);
        let emailFilled = false;
        let passwordFilled = false;

        for (const input of inputs) {
            const isVisible = await input.evaluate(el => el.offsetHeight > 0 && el.offsetWidth > 0).catch(() => false);
            if (!isVisible) continue;

            const name = await input.evaluate(el => (el.name || '').toLowerCase()).catch(() => '');
            const type = await input.evaluate(el => (el.type || '').toLowerCase()).catch(() => '');

            if (type === 'email' || name.includes('email') || name.includes('user') || name.includes('login')) {
                await input.type(userCreds.email, { delay: 50 }).catch(()=>{});
                emailFilled = true;
            } else if (type === 'password' || name.includes('pass')) {
                await input.type(userCreds.password, { delay: 50 }).catch(()=>{});
                passwordFilled = true;
            }
        }

        if (emailFilled && passwordFilled) {
            await page.keyboard.press('Tab').catch(() => {});
            await new Promise(resolve => setTimeout(resolve, 500));
            
            // Appuyer sur Entrée pour soumettre le formulaire
            await page.keyboard.press('Enter').catch(() => {});
            
            // Attendre la réponse du réseau (ex: redirection vers le dashboard ou /api/auth/login)
            await new Promise(resolve => setTimeout(resolve, 5000));
            
            // Vérifier si on est redirigé loin de la page de login, signe de succès
            const currentUrl = page.url();
            if (!currentUrl.includes('/login') || currentUrl.includes('dashboard')) {
                await page.close();
                return true;
            }
            // Mettre un heuristique : si après 5s on a pas d'erreur affichée, on considère que c'est bon
            await page.close();
            return true;
        }

    } catch (e) {
        console.error("Context Auth Error:", e);
    }
    await page.close();
    return false;
}

/**
 * Exécute une requête `fetch` directement dans la console JavaScript du navigateur,
 * attachant ainsi tous les cookies et jetons d'état dynamiques gérés par le navigateur.
 */
async function executeFetchInContext(context, url, method = 'GET') {
    const page = await context.newPage();
    try {
        // Naviguer sur la racine pour avoir l'origine (CORS) avant d'injecter le fetch
        const targetObj = new URL(url);
        await page.goto(targetObj.origin, { waitUntil: 'domcontentloaded', timeout: 10000 }).catch(()=>{});

        const result = await page.evaluate(async (fetchUrl, fetchMethod) => {
            try {
                const res = await window.fetch(fetchUrl, {
                    method: fetchMethod,
                    headers: {
                        'Accept': 'application/json, text/plain, */*',
                    }
                });
                return {
                    status: res.status,
                    ok: res.ok
                };
            } catch (err) {
                return { status: 0, ok: false, error: err.message };
            }
        }, url, method);

        await page.close();
        return result;

    } catch (e) {
        await page.close();
        return { status: 0, ok: false, error: e.message };
    }
}
