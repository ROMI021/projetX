/* ======================================================================
   Server utility helpers for BOLA-Shield
   ====================================================================== */

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import dns from 'dns/promises';
import net from 'net';
import { fileURLToPath } from 'url';
import { store, broadcastEvent } from './store.js';

import { loadDiscoveryCache, saveDiscoveryCache } from './cache.js';
import { generateSpoofedIp, rotateIp, generateFakeEntropy } from './evasion.js';
import { spiderTarget, submitAuthFormWithBrowser, fetchWithBrowser, closeBrowser } from './spider.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DATA_DIR = path.join(__dirname, '..', 'data');
const CREDENTIALS_FILE = path.join(DATA_DIR, 'credentials.json');

const HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'proxy-connection'
]);
const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.txt': 'text/plain; charset=utf-8',
  '.pdf': 'application/pdf'
};

const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*';
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const ENABLE_DEMO_TARGET = process.env.ENABLE_DEMO_TARGET === 'true';
const PUPPETEER_ENABLED = process.env.PUPPETEER_ENABLED !== 'false';
const PUPPETEER_HEADLESS = process.env.PUPPETEER_HEADLESS || 'new';
const PUPPETEER_EXECUTABLE_PATH = process.env.PUPPETEER_EXECUTABLE_PATH || '';
const PUPPETEER_CHANNEL = process.env.PUPPETEER_CHANNEL || '';
const PUPPETEER_USER_DATA_DIR = process.env.PUPPETEER_USER_DATA_DIR || '';
const PUPPETEER_IGNORE_HTTPS_ERRORS = process.env.PUPPETEER_IGNORE_HTTPS_ERRORS === 'true';
const PUPPETEER_TIMEOUT_MS = Number(process.env.PUPPETEER_TIMEOUT_MS || 15_000);
const PUPPETEER_BLOCK_ASSETS = process.env.PUPPETEER_BLOCK_ASSETS !== 'false';
const PUPPETEER_NO_SANDBOX = process.env.PUPPETEER_NO_SANDBOX !== 'false';
const MAX_BODY_BYTES = Number(process.env.MAX_BODY_BYTES || 1_000_000);

function clientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) return String(forwarded).split(',')[0].trim();
  const remote = req.socket?.remoteAddress || '';
  return String(remote).replace(/^::ffff:/, '');
}

async function readRawBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) {
      throw new Error('Payload trop volumineux');
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks, size);
}

async function readBody(req) {
  const raw = await readRawBody(req);
  const contentType = String(req.headers['content-type'] || '').toLowerCase();
  const text = raw.toString('utf8').trim();
  if (!text) return {};

  if (contentType.includes('application/json')) {
    try {
      return JSON.parse(text);
    } catch (e) {
      return { raw: text };
    }
  }

  if (contentType.includes('application/x-www-form-urlencoded')) {
    const params = new URLSearchParams(text);
    const body = {};
    for (const [key, value] of params.entries()) {
      if (body[key] === undefined) {
        body[key] = value;
      } else if (Array.isArray(body[key])) {
        body[key].push(value);
      } else {
        body[key] = [body[key], value];
      }
    }
    return flattenFormPayload(body);
  }

  try {
    return JSON.parse(text);
  } catch (e) {
    return { raw: text };
  }
}

function flattenFormPayload(payload) {
  if (payload && typeof payload === 'object' && !Array.isArray(payload)) {
    const result = {};
    for (const [key, value] of Object.entries(payload)) {
      if (Array.isArray(value)) {
        result[key] = value.length === 1 ? value[0] : value;
      } else if (value && typeof value === 'object') {
        result[key] = flattenFormPayload(value);
      } else {
        result[key] = value;
      }
    }
    return result;
  }
  return payload;
}

function setCorsHeaders(res) {
  res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization,Accept,Origin');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
}

function setSecurityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'interest-cohort=()');
  res.setHeader('X-XSS-Protection', '0');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
}

function sendJSON(res, status, payload) {
  setSecurityHeaders(res);
  setCorsHeaders(res);
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.end(JSON.stringify(payload));
}

function publicError(errorMessage, fallback = 'Erreur interne du serveur') {
  if (IS_PRODUCTION) return fallback;
  if (typeof errorMessage === 'string' && errorMessage.length > 0) return errorMessage;
  return fallback;
}

function sendLiveTargetRequired(res) {
  return sendJSON(res, 400, {
    error: 'apiBase requis pour une cible live',
    hint: 'Configurez apiBase dans la requête ou activez ENABLE_DEMO_TARGET pour utiliser la cible locale de démonstration.'
  });
}

function nowDateStr() {
  return new Date().toISOString();
}

function summarizeGateway() {
  return {
    enabled: store.gateway.enabled,
    targetBase: store.gateway.targetBase,
    mode: store.gateway.mode,
    pendingSuggestions: store.gateway.pendingSuggestions || [],
    transactions: store.gateway.transactions.slice(-10)
  };
}

async function delayMs(ms = 200) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function authHeaderValue(token, scheme = 'Bearer') {
  if (!token) return '';
  return `${scheme} ${token}`;
}

function authHeadersForSession({ token, cookie, scheme = 'Bearer', referer }) {
  const headers = {
    Accept: 'application/json, text/plain, */*'
  };
  if (token) headers.Authorization = authHeaderValue(token, scheme);
  if (cookie) headers.Cookie = cookie;
  if (referer) headers.Referer = referer;
  return headers;
}

function maskToken(token) {
  if (!token || typeof token !== 'string') return '';
  if (token.length <= 8) return '*'.repeat(token.length);
  return `${token.slice(0, 4)}...${token.slice(-4)}`;
}

function parameterizeObjectRoute(route) {
  if (!route || typeof route !== 'string') return route;
  if (route.includes(':id')) return route;
  return route.endsWith('/') ? `${route}:id` : `${route}/:id`;
}

function fillObjectIdRoute(route, objectId) {
  if (!route || !objectId) return route;
  if (route.includes(':id')) return route.replace(/:id/g, encodeURIComponent(objectId));
  return route.endsWith('/') ? `${route}${encodeURIComponent(objectId)}` : `${route}/${encodeURIComponent(objectId)}`;
}

function joinTargetUrl(targetBase, route) {
  if (!route) return targetBase;
  try {
    const origin = new URL(targetBase);
    if (route.startsWith('http://') || route.startsWith('https://')) return route;
    const normalized = route.startsWith('/') ? route.slice(1) : route;
    return new URL(normalized, origin).href;
  } catch (e) {
    return route;
  }
}

function normalizeTargetInput(input) {
  if (!input || typeof input !== 'string') return '';
  let candidate = input.trim();
  if (!candidate.includes('://')) {
    candidate = `http://${candidate}`;
  }
  try {
    const url = new URL(candidate);
    url.pathname = url.pathname.replace(/\/+$|\/{2,}/g, '/');
    return url.href.replace(/\/$/, '');
  } catch (e) {
    return candidate;
  }
}

function isCredentialAuthRoute(route) {
  return typeof route === 'string' && /(login|auth|session)/i.test(route);
}

function extractToken(data) {
  if (!data) return '';
  if (typeof data === 'string') return data;
  if (typeof data === 'object') {
    return data.token || data.accessToken || data.sessionToken || data.tokenA || data.accessTokenA || data.tokenB || data.accessTokenB || '';
  }
  return '';
}

function extractTargetObjectId(data) {
  if (!data) return '';
  if (typeof data === 'string') {
    const match = data.match(/([A-Za-z0-9_-]{8,})/);
    return match?.[1] || '';
  }
  if (typeof data === 'object') {
    if (data.objectId) return data.objectId;
    if (data.id) return data.id;
    if (data.invoiceId) return data.invoiceId;
    if (data.orderId) return data.orderId;
    if (data.userId) return data.userId;
    if (data.data) return extractTargetObjectId(data.data);
    for (const value of Object.values(data)) {
      const candidate = extractTargetObjectId(value);
      if (candidate) return candidate;
    }
  }
  return '';
}

function extractPossibleObjectIds(data, seen = new Set()) {
  if (!data || typeof data !== 'object') return new Set();
  if (seen.has(data)) return new Set();
  seen.add(data);

  const ids = new Set();
  const addCandidate = value => {
    if (typeof value !== 'string') return;
    if (value.length < 8) return;
    if (/token/i.test(value)) return;
    if (/^[A-Za-z0-9_-]{8,}$/.test(value)) {
      ids.add(value);
    }
  };

  if (Array.isArray(data)) {
    for (const item of data) {
      extractPossibleObjectIds(item, seen).forEach(id => ids.add(id));
    }
    return ids;
  }

  for (const [key, value] of Object.entries(data)) {
    if (typeof value === 'string') {
      if (/(?:^|_|\b)(?:id|invoice|order|user|customer|account|profile)\b/i.test(key)) {
        addCandidate(value);
      } else if (/^[A-Za-z0-9_-]{8,}$/.test(value)) {
        addCandidate(value);
      }
    }
    if (typeof value === 'object') {
      extractPossibleObjectIds(value, seen).forEach(id => ids.add(id));
    }
  }
  return ids;
}

async function fetchJSONRemote(url, options = {}) {
  try {
    const fetchOptions = {
      method: options.method || 'GET',
      headers: { ...options.headers },
      body: options.body,
      redirect: 'manual'
    };

    // Injection de la fausse IP (Spoofing) si aucun proxy physique n'est forcé.
    // L'API cible doit avoir `app.set('trust proxy', 1)` pour que cela fonctionne.
    fetchOptions.headers['X-Forwarded-For'] = store.currentSpoofedIp;

    const response = await fetch(url, fetchOptions);
    const text = await response.text();
    let data = text;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      data = text;
    }
    return {
      ok: response.ok,
      status: response.status,
      data,
      headers: Object.fromEntries(response.headers.entries())
    };
  } catch (e) {
    return {
      ok: false,
      status: 0,
      data: { error: e.message }
    };
  }
}

function encodeFormBody(payload) {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(payload || {})) {
    if (value === undefined || value === null) continue;
    params.append(key, typeof value === 'object' ? JSON.stringify(value) : String(value));
  }
  return params.toString();
}




async function postAuthCandidate(url, candidate, label = 'candidate', payloads = []) {
  const attempts = [];
  let potToken = '';
  
  // 1. Evasion: Voler le Proof-of-Time Token (Scraping du formulaire)
  broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[EVASION] Récupération du formulaire ${label} pour extraire le Proof-of-Time...` });
  const getResponse = await fetchJSONRemote(url, { method: 'GET' });
  if (getResponse.ok && typeof getResponse.data === 'string') {
     const potMatch = getResponse.data.match(/name="potToken"[^>]*?value="([^"]+)"/);
     if (potMatch && potMatch[1]) {
         potToken = potMatch[1];
         broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[EVASION] potToken extrait avec succès.` });
     } else {
         broadcastEvent({ origin: 'AUDIT', type: 'warning', msg: `[EVASION] Échec de l'extraction du potToken.` });
     }
  }

  // 2. Evasion: Simuler le temps de frappe d'un humain (Bypass PoT)
  if (potToken) {
      broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[EVASION] Simulation du temps de frappe humain (2.1s)...` });
      await delayMs(2100);
  }

  // 3. Evasion: Injecter l'entropie
  candidate.clientEntropy = generateFakeEntropy();
  if (potToken) candidate.potToken = potToken;

  // Optimisation: Si on a des indices (ex: captchas), on les teste en priorité pour ne pas gâcher
  // nos précieuses tentatives et se faire bloquer par le Rate Limiter agressif (Max 3/heure).
  const payloadQueue = payloads.length > 0 
      ? payloads.map(overlay => ({ ...candidate, ...overlay })) 
      : [candidate];
      
  const contentVariants = ['application/json', 'application/x-www-form-urlencoded'];

  for (const payload of payloadQueue) {
    for (const contentType of contentVariants) {
      const body = contentType === 'application/json'
        ? JSON.stringify(payload)
        : encodeFormBody(payload);

      const attempt = { label, url, payload, contentType, status: 0, ok: false };
      attempts.push(attempt);

      // 4. Evasion: Empreinte Navigateur Stricte
      let response = await fetchJSONRemote(url, {
        method: 'POST',
        headers: {
          'Content-Type': contentType,
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
          'Accept-Language': 'fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7',
          'Sec-Fetch-Mode': 'cors',
          'Sec-Fetch-Site': 'same-origin'
        },
        body
      });

      // 5. Evasion: Si on se fait bloquer par le Rate Limit (429), on déclenche la rotation IP et on réessaye.
      if (response.status === 429) {
          broadcastEvent({ origin: 'AUDIT', type: 'alert', msg: `[BLOCAGE 429] Rate Limit atteint sur la cible !` });
          rotateIp();
          await delayMs(1000); // Petit délai pour laisser souffler la cible
          
          response = await fetchJSONRemote(url, {
             method: 'POST',
             headers: {
               'Content-Type': contentType,
               'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
               'Accept-Language': 'fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7',
               'Sec-Fetch-Mode': 'cors',
               'Sec-Fetch-Site': 'same-origin'
             },
             body
          });
      }
      
      attempt.status = response.status;
      attempt.ok = response.ok;
      attempt.data = response.data;

      if (response.ok) {
        return { ok: true, status: response.status, data: response.data, attempts };
      }
      if (typeof response.data === 'string' && /<form/i.test(response.data) && PUPPETEER_ENABLED) {
        const browserResponse = await submitAuthFormWithBrowser(url, payload, label);
        attempts.push({ label: `${label}-browser`, url, payload, contentType: 'browser' });
        if (browserResponse.ok) {
          return { ok: true, status: browserResponse.status, data: browserResponse.data, attempts };
        }
      }
    }
  }

  const lastResponse = attempts.length ? attempts[attempts.length - 1] : null;
  return {
    ok: false,
    status: lastResponse?.status || 0,
    data: lastResponse?.data || null,
    attempts
  };
}

async function probePublicEndpoints(targetBase, discovery) {
  const list = [];
  if (discovery?.routes) {
    for (const [kind, route] of Object.entries(discovery.routes)) {
      if (route) list.push({ route, kind, reason: 'détection de route' });
    }
  }
  if (Array.isArray(discovery?.endpoints)) {
    for (const endpoint of discovery.endpoints) {
      list.push({ route: endpoint.path || endpoint, kind: 'endpoint', details: endpoint });
    }
  }
  return list;
}

function stableResourceFingerprint(data) {
  const normalized = JSON.stringify(data, Object.keys(data || {}).sort());
  return crypto.createHash('sha256').update(normalized).digest('hex');
}

function buildAuditReport(format = 'json') {
  const report = {
    users: store.users.size,
    invoices: store.invoices.size,
    orders: store.orders.size,
    patched: store.patched,
    metrics: store.metrics,
    lastAudit: store.lastAudit
  };
  if (format === 'markdown') {
    return `# Rapport d'audit BOLA Shield\n\n- Utilisateurs: ${report.users}\n- Factures: ${report.invoices}\n- Commandes: ${report.orders}\n- Attaques bloquées: ${report.metrics.blockedAttacks}\n- Fuites enregistrées: ${report.metrics.dataLeaked}\n- Patchs appliqués: ${JSON.stringify(report.patched)}\n\n## Dernier audit\n\n${report.lastAudit ? JSON.stringify(report.lastAudit, null, 2) : 'Aucun audit enregistre.'}`;
  }
  return report;
}

function buildAuditGraph() {
  const nodes = [];
  const links = [];

  if (store.users.size > 0) {
    const users = [...store.users.values()].slice(0, 4);
    const ySpacing = 360 / Math.max(users.length, 1);
    users.forEach((u, i) => {
      const y = 100 + i * ySpacing;
      const clientNode = { id: `client_${u.id}`, label: u.name || u.email, x: 120, y, type: 'user' };
      const sessionNode = { id: `session_${u.id}`, label: 'Session', x: 300, y, type: 'session' };
      nodes.push(clientNode, sessionNode);
      links.push({ source: clientNode.id, target: sessionNode.id, type: 'secure' });
      const inv = [...store.invoices.values()].find(x => x.userId === u.id);
      const ord = [...store.orders.values()].find(x => x.userId === u.id);
      if (ord) {
        const orderNode = { id: `order_${ord.id}`, label: `Cmd ${ord.id.slice(-4)}`, x: 500, y, type: 'object', owner: u.id };
        nodes.push(orderNode);
        links.push({ source: sessionNode.id, target: orderNode.id, type: 'secure' });
      }
      if (inv) {
        const invoiceNode = { id: `invoice_${inv.id}`, label: `Fact ${inv.id.slice(-4)}`, x: 680, y, type: 'object', owner: u.id };
        nodes.push(invoiceNode);
        if (ord) links.push({ source: `order_${ord.id}`, target: invoiceNode.id, type: 'secure' });
      }
    });
    return { nodes, links, patched: store.patched };
  }

  if (store.lastAudit) {
    const audit = store.lastAudit;
    const clientNodeA = { id: 'client_A', label: 'Audit User A', x: 120, y: 150, type: 'user' };
    const sessionNodeA = { id: 'session_A', label: 'Session A', x: 300, y: 150, type: 'session' };
    const clientNodeB = { id: 'client_B', label: 'Audit User B', x: 120, y: 350, type: 'user' };
    const sessionNodeB = { id: 'session_B', label: 'Session B', x: 300, y: 350, type: 'session' };
    
    nodes.push(clientNodeA, sessionNodeA, clientNodeB, sessionNodeB);
    links.push({ source: clientNodeA.id, target: sessionNodeA.id, type: 'secure' });
    links.push({ source: clientNodeB.id, target: sessionNodeB.id, type: 'secure' });

    if (audit.objectId) {
      const shortId = String(audit.objectId).substring(0, 6) + '..';
      const objectNode = { id: `object_${audit.objectId}`, label: `Cible: ${shortId}`, x: 680, y: 150, type: 'object', owner: 'client_A' };
      nodes.push(objectNode);
      links.push({ source: sessionNodeA.id, target: objectNode.id, type: 'secure' });

      if (audit.isBOLA) {
         links.push({ id: 'bola_link', source: sessionNodeB.id, target: objectNode.id, type: 'bola' });
      } else if (audit.crossStatus >= 400 && audit.crossStatus < 500) {
         links.push({ id: 'blocked_link', source: sessionNodeB.id, target: objectNode.id, type: 'blocked' });
      }
    }
    return { nodes, links, patched: store.patched, audit };
  }

  return null;
}

function firewallRecommendations() {
  return [
    { rule: 'shieldActive', status: store.rules.shieldActive ? 'actif' : 'désactivé' },
    { rule: 'vpnBlock', status: store.rules.vpnBlock ? 'actif' : 'désactivé' },
    { rule: 'emergencyShield', status: store.rules.emergencyShield ? 'actif' : 'désactivé' }
  ];
}

function passiveAuditPayload(targetBase, discovery, message, extras = {}) {
  return {
    targetBase,
    discovery,
    message,
    extras,
    timestamp: new Date().toISOString()
  };
}

function loadTargetCredentials(targetBase) {
  try {
    if (!fs.existsSync(CREDENTIALS_FILE)) return null;
    const payload = JSON.parse(fs.readFileSync(CREDENTIALS_FILE, 'utf8'));
    if (!payload || typeof payload !== 'object') return null;
    const normalizedBase = normalizeTargetInput(targetBase);
    if (payload[normalizedBase]) return payload[normalizedBase];
    if (payload[targetBase]) return payload[targetBase];
    if (payload.default) return payload.default;
    return null;
  } catch (e) {
    return null;
  }
}

function isPrivateIpAddress(address) {
  if (!address) return false;
  const ip = address.replace(/^\[|\]$/g, '');
  if (net.isIP(ip) === 4) {
    return /^10\.|^127\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^192\.168\./.test(ip);
  }
  if (net.isIP(ip) === 6) {
    return ip === '::1' || ip === '::ffff:127.0.0.1' || ip.startsWith('fc') || ip.startsWith('fd');
  }
  return false;
}

async function assertSafeTargetUrl(targetUrl) {
  const url = new URL(targetUrl);
  const hostname = url.hostname;
  if (ENABLE_DEMO_TARGET) return;
  if (LOCAL_TARGETS.has(hostname) || hostname === 'localhost') return;
  if (net.isIP(hostname) && isPrivateIpAddress(hostname)) {
    throw new Error('Cible privee ou locale non autorisee');
  }
  try {
    const addresses = await dns.lookup(hostname, { all: true });
    for (const record of addresses) {
      if (isPrivateIpAddress(record.address)) {
        throw new Error('Cible privee non autorisee');
      }
    }
  } catch (e) {
    if (e.code === 'ENOTFOUND') return;
    throw e;
  }
}

let LOCAL_TARGETS = new Set(['localhost', '127.0.0.1', '::1']);

async function discoverTarget(targetBase) {
  const cache = loadDiscoveryCache();
  if (cache[targetBase]) {
     broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[DISCOVERY] Architecture de la cible chargée depuis le cache local.` });
     return cache[targetBase];
  }

  if (ENABLE_DEMO_TARGET) {
    return {
      base: targetBase,
      authModel: 'demo-target',
      routes: {
        register: '/api/v1/users/register',
        login: '/api/v1/users/login',
        target: '/api/v1/invoices/:id'
      },
      endpoints: [
        { path: 'GET /api/v1/invoices/:id', authRequired: true, resource: 'Factures (Invoice)', risk: store.patched['node-invoice'] ? 'AUCUN' : 'CRITIQUE' },
        { path: 'GET /api/v1/orders/:id/download', authRequired: true, resource: 'Reçus de Commande', risk: store.patched['node-order'] ? 'AUCUN' : 'ÉLEVÉ' },
        { path: 'GET /api/v1/customers/:id/profile', authRequired: true, resource: 'Profil Client', risk: 'AUCUN' },
        { path: 'GET /api/v1/products/:id', authRequired: false, resource: 'Détails Produits', risk: 'AUCUN' }
      ]
    };
  }

  const routes = {
    register: '/api/v1/users/register',
    login: '/api/v1/users/login',
    target: '/api/v1/invoices/:id'
  };
  let authModel = 'no-public-auth-routes-detected';
  const endpoints = [];

  const openApiCandidates = [];
  try {
    const openApiResp = await fetchJSONRemote(joinTargetUrl(targetBase, '/openapi.json'), { method: 'GET' });
    if (openApiResp.ok && openApiResp.data && typeof openApiResp.data === 'object') {
      const paths = openApiResp.data.paths || {};
      for (const [path, details] of Object.entries(paths)) {
        for (const [method, op] of Object.entries(details || {})) {
          const verb = method.toUpperCase();
          if (verb !== 'GET' && verb !== 'POST' && verb !== 'PUT' && verb !== 'DELETE') continue;
          const normalizedPath = path.replace(/\{[^/]+\}/g, ':id');
          const summary = String(op.summary || op.description || '').toLowerCase();

          if (verb === 'POST' && /register|inscription|sign ?up|signup/i.test(summary + path)) {
            routes.register = normalizedPath;
            authModel = authModel === 'login-route-detected' ? 'auth-routes-detected' : 'registration-route-detected';
            endpoints.push({ path: `POST ${normalizedPath}`, authRequired: false, resource: 'Inscription', risk: 'Moyen' });
          }
          if (verb === 'POST' && /login|connexion|auth/i.test(summary + path)) {
            routes.login = normalizedPath;
            authModel = authModel === 'registration-route-detected' ? 'auth-routes-detected' : 'login-route-detected';
            endpoints.push({ path: `POST ${normalizedPath}`, authRequired: false, resource: 'Connexion', risk: 'Moyen' });
          }
          if (verb === 'GET' && /users\/:id|customers\/:id|invoices\/:id|orders\/:id|profiles\/:id/i.test(normalizedPath)) {
            openApiCandidates.push({ path: normalizedPath, method: verb, summary });
          }
          const authRequired = !/public|open/i.test(summary) && !/register|login|auth/i.test(path + summary);
          endpoints.push({ path: `${verb} ${normalizedPath}`, authRequired, resource: summary || normalizedPath, risk: authRequired ? 'Moyen' : 'AUCUN' });
        }
      }
      if (openApiCandidates.length > 0) {
        const targetCandidate = openApiCandidates.find(c => /invoice|order|user|customer|profile/i.test(c.path));
        if (targetCandidate) {
          routes.target = targetCandidate.path;
        }
      }
    }
  } catch {
    // ignore discovery failures
  }

  try {
    const registerProbe = await fetchJSONRemote(joinTargetUrl(targetBase, routes.register), { method: 'OPTIONS' });
    const loginProbe = await fetchJSONRemote(joinTargetUrl(targetBase, routes.login), { method: 'OPTIONS' });
    if (registerProbe.status >= 200 && registerProbe.status < 500) {
      authModel = authModel === 'login-route-detected' ? 'auth-routes-detected' : 'registration-route-detected';
      if (!endpoints.some(e => e.path === `POST ${routes.register}`)) {
        endpoints.push({ path: `POST ${routes.register}`, authRequired: false, resource: 'Inscription', risk: 'Moyen' });
      }
    }
    if (loginProbe.status >= 200 && loginProbe.status < 500) {
      authModel = authModel === 'registration-route-detected' ? 'auth-routes-detected' : 'login-route-detected';
      if (!endpoints.some(e => e.path === `POST ${routes.login}`)) {
        endpoints.push({ path: `POST ${routes.login}`, authRequired: false, resource: 'Connexion', risk: 'Moyen' });
      }
    }
  } catch {
    // probe might fail if CORS is super strict or server drops OPTIONS, we still keep the guessed routes
  }

  // Si l'analyse OpenAPI a échoué et que nous n'avons pas de route login confirmée, on lance le Spider !
  if (!openApiCandidates.length && authModel === 'no-public-auth-routes-detected') {
      const spiderResult = await spiderTarget(targetBase);
      if (spiderResult.routes.login) {
          routes.login = spiderResult.routes.login;
          authModel = 'login-route-detected';
      }
      if (spiderResult.routes.register) {
          routes.register = spiderResult.routes.register;
          authModel = authModel === 'login-route-detected' ? 'auth-routes-detected' : 'registration-route-detected';
      }
      endpoints.push(...spiderResult.endpoints);
  }

  const finalResult = {
    base: targetBase,
    authModel,
    routes,
    endpoints
  };

  cache[targetBase] = finalResult;
  saveDiscoveryCache(cache);

  return finalResult;
}


export {
  clientIp,
  readRawBody,
  readBody,
  sendJSON,
  setCorsHeaders,
  setSecurityHeaders,
  publicError,
  sendLiveTargetRequired,
  nowDateStr,
  broadcastEvent,
  discoverTarget,
  fetchJSONRemote,
  fetchWithBrowser,
  delayMs,
  postAuthCandidate,
  probePublicEndpoints,
  stableResourceFingerprint,
  extractToken,
  extractTargetObjectId,
  extractPossibleObjectIds,
  flattenFormPayload,
  maskToken,
  authHeadersForSession,
  authHeaderValue,
  joinTargetUrl,
  normalizeTargetInput,
  isCredentialAuthRoute,
  parameterizeObjectRoute,
  fillObjectIdRoute,
  buildAuditReport,
  buildAuditGraph,
  firewallRecommendations,
  passiveAuditPayload,
  loadTargetCredentials,
  assertSafeTargetUrl,
  detectGatewaySuggestions,
  applyApprovedResponseModifications,
  summarizeGateway,
  closeBrowser,
  HOP_BY_HOP_HEADERS,
  MIME_TYPES,
  ENABLE_DEMO_TARGET,
  PUPPETEER_ENABLED,
  PUPPETEER_HEADLESS,
  PUPPETEER_EXECUTABLE_PATH,
  PUPPETEER_CHANNEL,
  PUPPETEER_USER_DATA_DIR,
  PUPPETEER_IGNORE_HTTPS_ERRORS,
  PUPPETEER_TIMEOUT_MS,
  PUPPETEER_BLOCK_ASSETS,
  PUPPETEER_NO_SANDBOX,
  MAX_BODY_BYTES
};

function detectGatewaySuggestions(record, requestHeaders, responseHeaders, bodyText) {
  const suggestions = store.gateway.pendingSuggestions || [];
  if (typeof bodyText !== 'string') return;
  if (bodyText.includes('<form') && !suggestions.find(s => s.type === 'form')) {
    suggestions.push({ type: 'form', message: 'La réponse contient un formulaire HTML. Vérifiez les chemins de connexion ou d’inscription.' });
  }
  store.gateway.pendingSuggestions = suggestions.slice(-20);
}

function applyApprovedResponseModifications(responseHeaders, bodyText, contentType) {
  const output = { headers: { ...responseHeaders }, body: bodyText, modified: false };
  if (store.gateway.approvedResponseHeaders) {
    for (const [key, value] of Object.entries(store.gateway.approvedResponseHeaders)) {
      output.headers[key.toLowerCase()] = value;
      output.modified = true;
    }
  }
  if (contentType.includes('application/json') && store.gateway.approvedJsonResponsePatch) {
    try {
      const json = JSON.parse(bodyText);
      const patched = { ...json, ...store.gateway.approvedJsonResponsePatch };
      output.body = JSON.stringify(patched);
      output.modified = true;
    } catch (_) {
      // keep original body
    }
  }
  return output;
}
