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
       
       // Injecter BOLA-Shield dans la page pour faciliter la sélection
       await page.evaluate((creds) => {
          // Chercher et cliquer sur un onglet/bouton Email si existant
          const emailTabs = Array.from(document.querySelectorAll('button, a, div')).filter(el => 
             el.textContent && el.textContent.toLowerCase().includes('e-mail') || el.textContent.toLowerCase().includes('email')
          );
          for (const tab of emailTabs) {
             // on essaie de cliquer sur l'onglet si c'est un bouton de switch
             if(tab.offsetHeight > 0 && tab.offsetWidth > 0) {
                 tab.click();
             }
          }

          const forms = document.querySelectorAll('form');
          const emailToUse = creds?.userA?.email || 'spider@audit.local';
          const passToUse = creds?.userA?.password || 'SpiderTest123!';

          for (const form of forms) {
             const inputs = form.querySelectorAll('input');
             let emailFilled = false;
             
             for (const input of inputs) {
                const name = (input.name || '').toLowerCase();
                const type = (input.type || '').toLowerCase();
                
                if (type === 'email' || name.includes('email') || name.includes('user')) {
                   input.value = emailToUse;
                   input.dispatchEvent(new Event('input', { bubbles: true }));
                   input.dispatchEvent(new Event('change', { bubbles: true }));
                   emailFilled = true;
                } else if (type === 'password' || name.includes('pass')) {
                   input.value = passToUse;
                   input.dispatchEvent(new Event('input', { bubbles: true }));
                   input.dispatchEvent(new Event('change', { bubbles: true }));
                } else if ((type === 'number' || type === 'tel' || name.includes('tel') || name.includes('phone')) && !emailFilled) {
                   // Remplir le numéro uniquement si l'email n'a pas pu être rempli
                   input.value = '690000000';
                   input.dispatchEvent(new Event('input', { bubbles: true }));
                   input.dispatchEvent(new Event('change', { bubbles: true }));
                } else if (type === 'text') {
                   input.value = emailToUse;
                   input.dispatchEvent(new Event('input', { bubbles: true }));
                   input.dispatchEvent(new Event('change', { bubbles: true }));
                }
             }
             const submitBtn = form.querySelector('button[type="submit"], input[type="submit"]');
             if (submitBtn) { submitBtn.click(); } else { form.submit(); }
          }
       }, credentials).catch(() => {});
       
       await new Promise(resolve => setTimeout(resolve, 2500));

       // Vérification de la présence d'un champ OTP dans le HTML renvoyé
       const pageHTML = await page.content();
       if (/otp|code de vérification|sms|validation/i.test(pageHTML) && pageHTML.includes('<form')) {
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
               await new Promise(resolve => setTimeout(resolve, 1000));
           }

           if (otpCode) {
               broadcastEvent({ origin: 'AUDIT', type: 'success', msg: `[SPIDER] Code OTP récupéré, injection en cours...` });
               await page.evaluate((code) => {
                   const inputs = document.querySelectorAll('input');
                   for (const input of inputs) {
                       const name = (input.name || '').toLowerCase();
                       const type = (input.type || '').toLowerCase();
                       if (type === 'text' || type === 'number' || name.includes('otp') || name.includes('code')) {
                           input.value = code;
                           input.dispatchEvent(new Event('input', { bubbles: true }));
                           input.dispatchEvent(new Event('change', { bubbles: true }));
                           const form = input.closest('form');
                           if(form) {
                               const submitBtn = form.querySelector('button[type="submit"], input[type="submit"]');
                               if (submitBtn) { submitBtn.click(); } else { form.submit(); }
                           }
                           break;
                       }
                   }
               }, otpCode).catch(() => {});
               await new Promise(resolve => setTimeout(resolve, 3000));
           } else {
               broadcastEvent({ origin: 'AUDIT', type: 'error', msg: `[SPIDER] Délai d'attente OTP dépassé (3 minutes).` });
           }
       }
    }
  } catch (error) {
    broadcastEvent({ origin: 'AUDIT', type: 'warning', msg: `[SPIDER] Erreur lors de l'exploration réseau : ${error.message}` });
  }

  return { routes: discoveredRoutes, endpoints: discoveredEndpoints };
}
