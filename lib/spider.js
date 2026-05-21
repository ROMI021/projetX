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

export async function spiderTarget(targetBase) {
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
      
      if ((type === 'xhr' || type === 'fetch') && url.startsWith('http')) {
         const summary = url.toLowerCase();
         if (/login|connexion|signin|auth/i.test(summary) && method === 'POST') {
             const pathObj = new URL(url);
             discoveredRoutes.login = pathObj.pathname;
             discoveredEndpoints.push({ path: `POST ${pathObj.pathname}`, authRequired: false, resource: 'Connexion (Spider)', risk: 'Moyen' });
             broadcastEvent({ origin: 'AUDIT', type: 'success', msg: `[SPIDER] 🎯 Route Login interceptée : ${pathObj.pathname}` });
         }
         else if (/register|inscription|signup/i.test(summary) && method === 'POST') {
             const pathObj = new URL(url);
             discoveredRoutes.register = pathObj.pathname;
             discoveredEndpoints.push({ path: `POST ${pathObj.pathname}`, authRequired: false, resource: 'Inscription (Spider)', risk: 'Moyen' });
             broadcastEvent({ origin: 'AUDIT', type: 'success', msg: `[SPIDER] 🎯 Route Inscription interceptée : ${pathObj.pathname}` });
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
       
       await page.evaluate(() => {
          const forms = document.querySelectorAll('form');
          for (const form of forms) {
             const inputs = form.querySelectorAll('input');
             for (const input of inputs) {
                if (input.type === 'email' || input.name.includes('email') || input.name.includes('user')) {
                   input.value = 'spider@audit.local';
                } else if (input.type === 'password' || input.name.includes('pass')) {
                   input.value = 'SpiderTest123!';
                } else if (input.type === 'text') {
                   input.value = 'SpiderTest';
                }
             }
             const submitBtn = form.querySelector('button[type="submit"], input[type="submit"]');
             if (submitBtn) { submitBtn.click(); } else { form.submit(); }
          }
       }).catch(() => {});
       
       await new Promise(resolve => setTimeout(resolve, 2500));
    }
  } catch (error) {
    broadcastEvent({ origin: 'AUDIT', type: 'warning', msg: `[SPIDER] Erreur lors de l'exploration réseau : ${error.message}` });
  }

  return { routes: discoveredRoutes, endpoints: discoveredEndpoints };
}
