import puppeteer from 'puppeteer-extra';
import StealthPlugin from 'puppeteer-extra-plugin-stealth';
import { broadcastEvent } from './store.js';

puppeteer.use(StealthPlugin());

const PUPPETEER_ENABLED = process.env.PUPPETEER_ENABLED !== 'false';
const PUPPETEER_HEADLESS = process.env.PUPPETEER_HEADLESS || 'new';
const PUPPETEER_EXECUTABLE_PATH = process.env.PUPPETEER_EXECUTABLE_PATH || '';
const PUPPETEER_CHANNEL = process.env.PUPPETEER_CHANNEL || '';
const PUPPETEER_USER_DATA_DIR = process.env.PUPPETEER_USER_DATA_DIR || '';
const PUPPETEER_IGNORE_HTTPS_ERRORS = process.env.PUPPETEER_IGNORE_HTTPS_ERRORS === 'true';
const PUPPETEER_TIMEOUT_MS = Number(process.env.PUPPETEER_TIMEOUT_MS || 15000);
const PUPPETEER_BLOCK_ASSETS = process.env.PUPPETEER_BLOCK_ASSETS !== 'false';
const PUPPETEER_NO_SANDBOX = process.env.PUPPETEER_NO_SANDBOX !== 'false';

let browserInstance = null;

export function closeBrowser() {
  if (!browserInstance) return null;
  const browser = browserInstance;
  browserInstance = null;
  return browser.close();
}

async function getBrowser() {
    if (!browserInstance) {
      browserInstance = await puppeteer.launch({
        headless: PUPPETEER_HEADLESS,
        executablePath: PUPPETEER_EXECUTABLE_PATH || undefined,
        channel: PUPPETEER_CHANNEL || undefined,
        userDataDir: PUPPETEER_USER_DATA_DIR || undefined,
        ignoreHTTPSErrors: PUPPETEER_IGNORE_HTTPS_ERRORS,
        args: PUPPETEER_NO_SANDBOX ? ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'] : [],
        defaultViewport: { width: 1280, height: 800 },
        timeout: PUPPETEER_TIMEOUT_MS
      });
    }
    return browserInstance;
}

export async function fetchWithBrowser(url, fallbackFetch, options = {}) {
  if (!PUPPETEER_ENABLED || (options.method && options.method.toUpperCase() !== 'GET')) {
    return fallbackFetch(url, options);
  }

  try {
    const browser = await getBrowser();
    const page = await browser.newPage();
    if (PUPPETEER_BLOCK_ASSETS) {
      await page.setRequestInterception(true);
      page.on('request', request => {
        const resourceType = request.resourceType();
        if (['image', 'stylesheet', 'font', 'media'].includes(resourceType)) {
          request.abort();
        } else {
          request.continue();
        }
      });
    }
    if (options.headers) {
      await page.setExtraHTTPHeaders(options.headers);
    }
    const response = await page.goto(url, { waitUntil: 'domcontentloaded', timeout: PUPPETEER_TIMEOUT_MS });
    const content = await page.content();
    await page.close();
    return { ok: response?.ok() ?? false, status: response?.status() ?? 0, data: content };
  } catch (e) {
    return fallbackFetch(url, options);
  }
}

export async function submitAuthFormWithBrowser(url, candidate, label = 'browser-candidate') {
  if (!PUPPETEER_ENABLED) {
    return { ok: false, status: 0, data: { error: 'Puppeteer disabled' } };
  }

  try {
    const browser = await getBrowser();
    const page = await browser.newPage();
    await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
    await page.setExtraHTTPHeaders({ Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' });
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: PUPPETEER_TIMEOUT_MS });

    const formExists = await page.$('form');
    if (!formExists) {
      await page.close();
      return { ok: false, status: 0, data: { error: 'No form found' } };
    }

    await page.evaluate((payload) => {
      const inputs = document.querySelectorAll('input');
      for (const input of inputs) {
        const name = (input.name || '').toLowerCase();
        const type = (input.type || '').toLowerCase();
        if (type === 'email' || name.includes('email') || name.includes('user')) {
          input.value = payload.email || payload.username || '';
        } else if (type === 'password' || name.includes('pass')) {
          input.value = payload.password || '';
        } else if (type === 'text') {
          input.value = payload[input.name] || 'Test';
        }
      }
      const submit = document.querySelector('button[type="submit"], input[type="submit"]');
      if (submit) {
        submit.click();
      } else {
        const form = document.querySelector('form');
        if (form) form.submit();
      }
    }, candidate);

    const response = await page.waitForNavigation({ waitUntil: 'networkidle0', timeout: 5000 }).catch(() => null);
    let data = '';
    if (response) {
      data = await response.text();
    } else {
      data = await page.content();
    }
    
    const status = response ? response.status() : 200;
    await page.close();
    return {
      ok: status >= 200 && status < 300,
      status,
      data
    };
  } catch (e) {
    return { ok: false, status: 0, data: { error: e.message } };
  }
}

export async function spiderTarget(targetBase, credentials = {}) {
  broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[SPIDER] Début de la reconnaissance DAST via navigateur fantôme (Stealth) sur ${targetBase}...` });
  let discoveredRoutes = { register: null, login: null };
  let discoveredEndpoints = [];

  if (!PUPPETEER_ENABLED) {
    broadcastEvent({ origin: 'AUDIT', type: 'warning', msg: `[SPIDER] Puppeteer est désactivé. Mode aveugle conservé.` });
    return { routes: discoveredRoutes, endpoints: discoveredEndpoints };
  }

  try {
    const browser = await getBrowser();
    const page = await browser.newPage();
    
    await page.setRequestInterception(true);
    page.on('request', request => {
      const type = request.resourceType();
      const url = request.url();
      const method = request.method();
      
      if ((type === 'xhr' || type === 'fetch' || type === 'document') && url.startsWith('http')) {
         try {
           const pathObj = new URL(url);
           const targetObj = new URL(targetBase);
           
           // Ignorer les requêtes vers des domaines tiers (Analytics, Ads, etc.)
           if (pathObj.hostname.includes(targetObj.hostname.replace('www.', ''))) {
             const pathname = pathObj.pathname.toLowerCase();
             
             // Capturer les soumissions de formulaire de connexion
             if (/login|connexion|signin|auth|customer|account|user/i.test(pathname) && method === 'POST') {
                 discoveredRoutes.login = pathObj.pathname;
                 discoveredEndpoints.push({ path: `POST ${pathObj.pathname}`, authRequired: false, resource: 'Connexion (Spider)', risk: 'Moyen' });
                 broadcastEvent({ origin: 'AUDIT', type: 'success', msg: `[SPIDER] 🎯 Route Login interceptée : ${pathObj.pathname}` });
             }
             // Capturer les soumissions de formulaire d'inscription
             else if (/register|inscription|signup|create/i.test(pathname) && method === 'POST') {
                 discoveredRoutes.register = pathObj.pathname;
                 discoveredEndpoints.push({ path: `POST ${pathObj.pathname}`, authRequired: false, resource: 'Inscription (Spider)', risk: 'Moyen' });
                 broadcastEvent({ origin: 'AUDIT', type: 'success', msg: `[SPIDER] 🎯 Route Inscription interceptée : ${pathObj.pathname}` });
             }
           }
         } catch (e) {
           // Ignorer les URL invalides
         }
      }
      request.continue();
    });

    await page.goto(targetBase, { waitUntil: 'networkidle2', timeout: 15000 }).catch(() => {});
    
    const authLinks = await page.$$eval('a', anchors => {
      return anchors.map(a => a.href).filter(href => /login|connexion|register|inscription|signup|signin/i.test(href));
    });

    const uniqueLinks = [...new Set(authLinks)].slice(0, 3);
    if (uniqueLinks.length === 0) {
        broadcastEvent({ origin: 'AUDIT', type: 'warning', msg: `[SPIDER] Aucun lien de connexion détecté sur la page d'accueil.` });
    }

    for (const link of uniqueLinks) {
       broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[SPIDER] Navigation vers la page d'authentification : ${link}` });
       await page.goto(link, { waitUntil: 'networkidle2', timeout: 10000 }).catch(() => {});
       
       // Chercher et cliquer sur un onglet Email si nécessaire (via JS car c'est un simple basculement UI)
       const clickedTabs = await page.evaluate(() => {
          const emailTabs = Array.from(document.querySelectorAll('button, a, div')).filter(el => {
             const t = (el.textContent || '').toLowerCase().trim();
             return (t === 'e-mail' || t === 'email' || t === 'se connecter par e-mail') && el.offsetHeight > 0 && el.offsetWidth > 0;
          });
          for (const tab of emailTabs) {
             tab.click();
          }
          return emailTabs.length;
       }).catch(() => 0);
       
       if (clickedTabs > 0) {
           broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[SPIDER] ${clickedTabs} onglet(s) 'Email' trouvé(s) et cliqué(s).` });
       }

       // Attendre un peu comme un humain qui regarde l'interface
       await new Promise(resolve => setTimeout(resolve, 800));

       const emailToUse = credentials?.userA?.email || 'spider@audit.local';
       const passToUse = credentials?.userA?.password || 'SpiderTest123!';

       const forms = await page.$$('form');
       broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[SPIDER] ${forms.length} formulaire(s) détecté(s) sur la page.` });
       
       let formSubmitted = false;

       for (const form of forms) {
           const inputs = await form.$$('input').catch(() => []);
           let emailFilled = false;
           let passwordFilled = false;
           
           for (const input of inputs) {
               // Filtrer les inputs invisibles
               const isVisible = await input.evaluate(el => el.offsetHeight > 0 && el.offsetWidth > 0).catch(() => false);
               const name = await input.evaluate(el => (el.name || '').toLowerCase()).catch(() => '');
               const type = await input.evaluate(el => (el.type || '').toLowerCase()).catch(() => '');
               
               if (!isVisible) {
                   continue;
               }

               if (type === 'email' || name.includes('email') || name.includes('user') || name.includes('login') || name.includes('identifier')) {
                   await input.click({ delay: Math.random() * 50 + 50 }).catch(() => {});
                   await input.type(emailToUse, { delay: Math.random() * 50 + 30 }).catch(() => {});
                   emailFilled = true;
                   broadcastEvent({ origin: 'AUDIT', type: 'success', msg: `[SPIDER] Rempli champ Email (${name}) avec ${emailToUse}` });
               } else if (type === 'password' || name.includes('pass')) {
                   await input.click({ delay: Math.random() * 50 + 50 }).catch(() => {});
                   await input.type(passToUse, { delay: Math.random() * 50 + 30 }).catch(() => {});
                   passwordFilled = true;
                   broadcastEvent({ origin: 'AUDIT', type: 'success', msg: `[SPIDER] Rempli champ Password (${name})` });
               } else if ((type === 'number' || type === 'tel' || name.includes('tel') || name.includes('phone')) && !emailFilled) {
                   await input.click({ delay: Math.random() * 50 + 50 }).catch(() => {});
                   await input.type('690000000', { delay: Math.random() * 50 + 30 }).catch(() => {});
                   emailFilled = true; // On le considère comme l'identifiant principal
                   broadcastEvent({ origin: 'AUDIT', type: 'success', msg: `[SPIDER] Rempli champ Téléphone (${name}) avec 690000000` });
               } else if (type === 'text' && !['q', 'search', 'query', 'keyword'].includes(name) && !name.includes('search')) {
                   await input.click({ delay: Math.random() * 50 + 50 }).catch(() => {});
                   await input.type(emailToUse, { delay: Math.random() * 50 + 30 }).catch(() => {});
                   emailFilled = true;
                   broadcastEvent({ origin: 'AUDIT', type: 'success', msg: `[SPIDER] Rempli champ Texte (${name}) avec ${emailToUse}` });
               }
           }

           // On soumet uniquement si on a rempli des identifiants (pour éviter de soumettre une barre de recherche)
           if (emailFilled || passwordFilled) {
               // Chercher le bouton de soumission
               const submitBtn = await form.$('button[type="submit"], input[type="submit"]').catch(() => null);
               if (submitBtn) {
                   broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[SPIDER] Bouton Submit trouvé, clic en cours...` });
                   await new Promise(resolve => setTimeout(resolve, Math.random() * 500 + 300));
                   await submitBtn.click({ delay: Math.random() * 50 + 50 }).catch(() => {});
               } else {
                   broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[SPIDER] Pas de bouton submit, force form.submit()` });
                   await form.evaluate(el => el.submit()).catch(() => {});
               }
               
               formSubmitted = true;
               break;
           } else {
               broadcastEvent({ origin: 'AUDIT', type: 'warning', msg: `[SPIDER] Formulaire ignoré (aucun champ identifiant/mot de passe rempli).` });
           }
       }

       if (formSubmitted) {
           broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[SPIDER] Attente de la réponse du serveur (5 secondes)...` });
           await new Promise(resolve => setTimeout(resolve, 5000));

           // Vérification de la présence d'un champ OTP dans le HTML renvoyé
           const pageHTML = await page.content();
           if (/otp|code de vérification|sms|validation|verification code/i.test(pageHTML) && pageHTML.includes('<input')) {
               broadcastEvent({ origin: 'AUDIT', type: 'warning', msg: `[OTP_REQUIRED] La cible ${targetBase} demande un code OTP. En attente de la saisie utilisateur (max 3 minutes)...` });
               
               // Boucle d'attente active de 3 minutes (180 secondes)
               let otpCode = null;
               for (let i = 0; i < 180; i++) {
                   const storeModule = await import('./store.js');
                   if (storeModule.store.pendingOTP) {
                       otpCode = storeModule.store.pendingOTP;
                       storeModule.store.pendingOTP = null; // Reset après lecture
                       break;
                   }
                   await new Promise(r => setTimeout(r, 1000));
               }

               if (otpCode) {
                   broadcastEvent({ origin: 'AUDIT', type: 'success', msg: `[SPIDER] Code OTP récupéré, saisie humaine en cours...` });
                   
                   const inputs = await page.$$('input');
                   for (const input of inputs) {
                       const isVisible = await input.evaluate(el => el.offsetHeight > 0 && el.offsetWidth > 0).catch(() => false);
                       if (!isVisible) continue;

                       const name = await input.evaluate(el => (el.name || '').toLowerCase()).catch(() => '');
                       const type = await input.evaluate(el => (el.type || '').toLowerCase()).catch(() => '');
                       
                       if (type === 'text' || type === 'number' || name.includes('otp') || name.includes('code') || name.includes('verify')) {
                           // Saisie avec rythme humain pour simuler une lecture
                           await input.click({ delay: Math.random() * 50 + 50 }).catch(() => {});
                           await input.type(otpCode, { delay: Math.random() * 100 + 100 }).catch(() => {});
                           
                           const form = await input.evaluateHandle(el => el.closest('form')).catch(() => null);
                           const isForm = form ? await form.evaluate(f => f !== null).catch(() => false) : false;
                           
                           if (isForm) {
                               const submitBtn = await form.$('button[type="submit"], input[type="submit"]').catch(() => null);
                               if (submitBtn) {
                                   await new Promise(resolve => setTimeout(resolve, Math.random() * 500 + 500));
                                   await submitBtn.click({ delay: Math.random() * 50 + 50 }).catch(() => {});
                               } else {
                                   await form.evaluate(f => f.submit()).catch(() => {});
                               }
                           }
                           break;
                       }
                   }
                   await new Promise(resolve => setTimeout(resolve, 3000));
               } else {
                   broadcastEvent({ origin: 'AUDIT', type: 'error', msg: `[SPIDER] Délai d'attente OTP dépassé (3 minutes).` });
               }
           }
           
           // FIN DU FLUX DE CONNEXION PRINCIPAL
           // On a trouvé et soumis le bon formulaire de connexion, inutile de tester les autres URLs de redirection
           break;
       } else {
           await new Promise(resolve => setTimeout(resolve, 2000));
       }
    }
  } catch (error) {
    broadcastEvent({ origin: 'AUDIT', type: 'warning', msg: `[SPIDER] Erreur lors de l'exploration réseau : ${error.message}` });
  }

  return { routes: discoveredRoutes, endpoints: discoveredEndpoints };
}
