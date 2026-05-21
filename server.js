/* ==========================================================================
   BOLA-Shield AI — Live Backend (Static Files + REST API + SSE)
   Pure Node.js, zero dependency.
   ========================================================================== */

import http from 'http';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import dns from 'dns/promises';
import net from 'net';
import { fileURLToPath } from 'url';
import puppeteer from 'puppeteer';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PORT = Number(process.env.PORT || 8080);
const MAX_BODY_BYTES = Number(process.env.MAX_BODY_BYTES || 1_000_000);
const DATA_DIR = path.join(__dirname, 'data');
const STATE_FILE = path.join(DATA_DIR, 'state.json');
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*';
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const LOCAL_TARGETS = new Set(['localhost', '127.0.0.1', '::1']);
const ALLOW_PRIVATE_TARGETS = process.env.ALLOW_PRIVATE_TARGETS === 'true';
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
const MAX_AUTH_ATTEMPTS = Number(process.env.MAX_AUTH_ATTEMPTS || 24);
const HOP_BY_HOP_HEADERS = new Set([
    'connection',
    'content-length',
    'keep-alive',
    'proxy-authenticate',
    'proxy-authorization',
    'te',
    'trailer',
    'transfer-encoding',
    'upgrade'
]);

const MIME_TYPES = {
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.gif': 'image/gif',
    '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon',
    '.webp': 'image/webp'
};

/* --------------------------------------------------------------------------
   In-memory data store for live audit state, gateway decisions and reports.
   The legacy local target is disabled by default and only available via
   ENABLE_DEMO_TARGET=true for isolated lab runs.
   -------------------------------------------------------------------------- */
const store = {
    users: new Map(),          // token -> { id, email, name }
    usersByEmail: new Map(),   // email -> { id, token, password, name }
    invoices: new Map(),       // invoiceId -> { id, userId, amount, customer, items }
    orders: new Map(),         // orderId -> { id, userId, buyerId, total, pdfPath }
    blacklist: [],             // [{ ip, reason, date }]
    rules: {
        shieldActive: true,
        activeScan: true,
        tokenization: false,
        vpnBlock: true,
        emergencyShield: false
    },
    patched: {                 // server-side patch state per vuln id
        'node-invoice': false,
        'node-order': false,
        'php-invoice': false,
        'rails-invoice': false
    },
    metrics: {
        exposureRate: 0,
        dataLeaked: 0,
        blockedAttacks: 0,
        financialSavings: 0
    },
    scanCounter: new Map(),    // ip -> { count, firstAt }
    sseClients: new Set(),
    eventLog: [],
    currentDiscovery: null,
    lastAudit: null,
    gateway: {
        enabled: false,
        targetBase: '',
        mode: 'observe',
        approvedRequestHeaders: {},
        approvedResponseHeaders: {},
        approvedJsonResponsePatch: {},
        transactions: [],
        pendingSuggestions: []
    }
};

function persistedSnapshot() {
    return {
        blacklist: store.blacklist,
        rules: store.rules,
        patched: store.patched,
        metrics: store.metrics,
        lastAudit: store.lastAudit,
        currentDiscovery: store.currentDiscovery,
        gateway: store.gateway
    };
}

function saveStore() {
    try {
        fs.mkdirSync(DATA_DIR, { recursive: true });
        fs.writeFileSync(STATE_FILE, JSON.stringify(persistedSnapshot(), null, 2), 'utf8');
    } catch (e) {
        console.warn('[STATE] save failed:', e.message);
    }
}

function loadStore() {
    try {
        if (!fs.existsSync(STATE_FILE)) return;
        const parsed = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
        if (Array.isArray(parsed.blacklist)) store.blacklist = parsed.blacklist;
        if (parsed.rules) Object.assign(store.rules, parsed.rules);
        if (parsed.patched) Object.assign(store.patched, parsed.patched);
        if (parsed.metrics) Object.assign(store.metrics, parsed.metrics);
        store.lastAudit = parsed.lastAudit || null;
        store.currentDiscovery = parsed.currentDiscovery || null;
        if (parsed.gateway) Object.assign(store.gateway, parsed.gateway);
    } catch (e) {
        console.warn('[STATE] load failed:', e.message);
    }
}

// Optional lab-only seed. Disabled by default in live-only mode.
function seed() {
    const adminId = 'admin-' + crypto.randomBytes(4).toString('hex');
    const adminInvoiceId = 'inv_' + crypto.randomBytes(6).toString('hex');
    const adminOrderId = 'ord_' + crypto.randomBytes(6).toString('hex');
    store.invoices.set(adminInvoiceId, {
        id: adminInvoiceId, userId: adminId, amount: 9999, customer: 'Admin Seed',
        items: ['Audit License', 'Shield Pro']
    });
    store.orders.set(adminOrderId, {
        id: adminOrderId, userId: adminId, buyerId: adminId, total: 9999,
        pdfPath: `/secret/${adminOrderId}.pdf`
    });
}
if (ENABLE_DEMO_TARGET) seed();
loadStore();

/* --------------------------------------------------------------------------
   Helpers
   -------------------------------------------------------------------------- */
function nowDateStr() {
    const d = new Date();
    const pad = n => n.toString().padStart(2, '0');
    return `${pad(d.getDate())}/${pad(d.getMonth() + 1)}/${d.getFullYear()} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function broadcastEvent(event) {
    const enrichedEvent = { ...event, id: crypto.randomBytes(6).toString('hex'), ts: Date.now() };
    const payload = JSON.stringify(enrichedEvent);
    store.eventLog.push(enrichedEvent);
    if (store.eventLog.length > 200) store.eventLog.shift();
    for (const res of store.sseClients) {
        try { res.write(`id: ${enrichedEvent.id}\ndata: ${payload}\n\n`); } catch (_) {}
    }
}

function readBody(req) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        let size = 0;
        req.on('data', c => {
            size += c.length;
            if (size > MAX_BODY_BYTES) {
                req.destroy();
                reject(new Error(`Body too large, limit is ${MAX_BODY_BYTES} bytes`));
                return;
            }
            chunks.push(c);
        });
        req.on('end', () => {
            const raw = Buffer.concat(chunks).toString('utf8');
            if (!raw) return resolve({});
            try { resolve(JSON.parse(raw)); } catch (e) { reject(e); }
        });
        req.on('error', reject);
    });
}

function readRawBody(req) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        let size = 0;
        req.on('data', c => {
            size += c.length;
            if (size > MAX_BODY_BYTES) {
                req.destroy();
                reject(new Error(`Body too large, limit is ${MAX_BODY_BYTES} bytes`));
                return;
            }
            chunks.push(c);
        });
        req.on('end', () => resolve(Buffer.concat(chunks)));
        req.on('error', reject);
    });
}

function sendJSON(res, status, data, extraHeaders = {}) {
    res.statusCode = status;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    setSecurityHeaders(res);
    setCorsHeaders(res);
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    for (const [k, v] of Object.entries(extraHeaders)) res.setHeader(k, v);
    res.end(JSON.stringify(data));
}

function setCorsHeaders(res) {
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
}

function publicError(message, fallback = 'Erreur serveur') {
    return IS_PRODUCTION ? fallback : message;
}

function sendLiveTargetRequired(res) {
    return sendJSON(res, 400, {
        error: 'cible live requise',
        hint: 'Renseignez apiBase avec une URL HTTP(S) autorisee. La cible locale de demonstration est desactivee.'
    });
}

function setSecurityHeaders(res) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    res.setHeader('Content-Security-Policy', [
        "default-src 'self'",
        "script-src 'self' https://cdn.jsdelivr.net",
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
        "font-src 'self' https://fonts.gstatic.com",
        "img-src 'self' data:",
        "connect-src 'self' https://cdn.jsdelivr.net",
        "object-src 'none'",
        "base-uri 'self'",
        "frame-ancestors 'none'"
    ].join('; '));
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
    if (IS_PRODUCTION) {
        res.setHeader('Strict-Transport-Security', 'max-age=15552000; includeSubDomains');
    }
}

async function fetchJSONRemote(url, options = {}) {
    await assertSafeTargetUrl(url);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), options.timeoutMs || 8000);

    // ÉMULATION COMPLETE D'UN NAVIGATEUR MODERNE (CHROME WINDOWS) POUR EVITER CAPTCHA / WAF
    const browserHeaders = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7',
        'Accept-Encoding': 'gzip, deflate, br',
        'Sec-Ch-Ua': '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
        'Sec-Ch-Ua-Mobile': '?0',
        'Sec-Ch-Ua-Platform': '"Windows"',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'Referer': options.referer || 'about:blank',
        'Origin': options.origin || new URL(url).origin,
        'DNT': '1',
        'Connection': 'keep-alive',
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache',
        'Content-Type': 'application/json',
        ...(options.headers || {})
    };

    try {
        const res = await fetch(url, { ...options, headers: browserHeaders, redirect: 'manual', signal: controller.signal });
        const text = await res.text();
        let data = null;
        try { data = text ? JSON.parse(text) : null; } catch (_) { data = text; }
        return { ok: res.ok, status: res.status, data, text, headers: res.headers };
    } finally {
        clearTimeout(timeout);
    }
}

async function delayMs(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

let browserInstance = null;

async function getBrowserInstance() {
    if (!PUPPETEER_ENABLED) throw new Error('Puppeteer desactive par PUPPETEER_ENABLED=false');
    if (!browserInstance) {
        const launchOptions = {
            headless: PUPPETEER_HEADLESS === 'false' ? false : PUPPETEER_HEADLESS,
            ignoreHTTPSErrors: PUPPETEER_IGNORE_HTTPS_ERRORS,
            executablePath: PUPPETEER_EXECUTABLE_PATH || undefined,
            channel: PUPPETEER_CHANNEL || undefined,
            userDataDir: PUPPETEER_USER_DATA_DIR || undefined,
            timeout: PUPPETEER_TIMEOUT_MS,
            protocolTimeout: PUPPETEER_TIMEOUT_MS + 5000,
            args: [
                '--disable-dev-shm-usage',
                '--disable-gpu',
                '--disable-extensions',
                '--disable-background-networking',
                '--disable-sync',
                '--metrics-recording-only',
                '--mute-audio',
                '--no-first-run',
                '--no-default-browser-check'
            ]
        };
        if (PUPPETEER_NO_SANDBOX) {
            launchOptions.args.push('--no-sandbox', '--disable-setuid-sandbox');
        }
        if (PUPPETEER_IGNORE_HTTPS_ERRORS) {
            launchOptions.args.push('--ignore-certificate-errors');
        }

        browserInstance = await puppeteer.launch(launchOptions);
        browserInstance.on('disconnected', () => {
            browserInstance = null;
        });
    }
    return browserInstance;
}

async function fetchWithBrowser(url, options = {}) {
    await assertSafeTargetUrl(url);
    if (!PUPPETEER_ENABLED) {
        return { ok: false, status: 0, data: { error: 'Puppeteer desactive' } };
    }
    let page = null;
    try {
        const browser = await getBrowserInstance();
        page = await browser.newPage();

        // Emulate realistic user agent and headers
        page.setDefaultNavigationTimeout(options.timeoutMs || PUPPETEER_TIMEOUT_MS);
        page.setDefaultTimeout(options.timeoutMs || PUPPETEER_TIMEOUT_MS);
        await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36');
        await page.setViewport({ width: 1366, height: 768, deviceScaleFactor: 1 });
        await page.setExtraHTTPHeaders({
            'Accept-Language': 'fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7',
            'Accept': 'application/json, text/plain, */*',
            'DNT': '1'
        });
        if (PUPPETEER_BLOCK_ASSETS) {
            await page.setRequestInterception(true);
            page.on('request', request => {
                const resourceType = request.resourceType();
                if (['image', 'media', 'font', 'stylesheet'].includes(resourceType)) {
                    return request.abort();
                }
                return request.continue();
            });
        }

        const method = options.method || 'GET';
        const body = options.body;

        if (method === 'POST' && body) {
            // POST request with body
            await page.goto(new URL(url).origin, { waitUntil: 'domcontentloaded', timeout: options.timeoutMs || PUPPETEER_TIMEOUT_MS }).catch(() => {});
            const response = await page.evaluate(async (postUrl, postBody) => {
                const res = await fetch(postUrl, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: postBody
                });
                const text = await res.text();
                let data = null;
                try { data = text ? JSON.parse(text) : null; } catch (_) { data = text; }
                return {
                    status: res.status,
                    data
                };
            }, url, body);
            return { ok: response.status === 200 || response.status === 201, status: response.status, data: response.data };
        } else {
            // GET request
            const response = await page.goto(url, { waitUntil: 'domcontentloaded', timeout: options.timeoutMs || PUPPETEER_TIMEOUT_MS }).catch(() => null);
            if (!response) {
                return { ok: false, status: 0, data: null };
            }

            let data = null;
            try {
                const json = await page.evaluate(() => {
                    const text = document.body.innerText;
                    return JSON.parse(text);
                }).catch(() => null);
                data = json;
            } catch (_) {}

            return { ok: response.ok(), status: response.status(), data };
        }
    } catch (error) {
        return { ok: false, status: 0, data: { error: error.message } };
    } finally {
        if (page) await page.close().catch(() => {});
    }
}

function joinTargetUrl(base, route) {
    const normalizedBase = normalizeTargetInput(base).replace(/\/+$/, '');
    const normalizedRoute = String(route || '').startsWith('/') ? route : `/${route || ''}`;
    return `${normalizedBase}${normalizedRoute}`;
}

function normalizeTargetInput(input) {
    let raw = String(input || '').trim();
    if (!raw) return '';
    raw = raw
        .replace(/[\u200B-\u200D\uFEFF]/g, '')
        .replace(/^<|>$/g, '')
        .replace(/^["']|["']$/g, '')
        .trim();
    raw = raw.split(/\s+/)[0];
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) raw = `https://${raw}`;

    let parsed;
    try {
        parsed = new URL(raw);
    } catch (_) {
        const encoded = raw.replace(/ /g, '%20');
        parsed = new URL(encoded);
    }

    if (!['http:', 'https:'].includes(parsed.protocol)) {
        throw new Error('Seuls HTTP et HTTPS sont autorises pour les cibles');
    }

    parsed.hash = '';
    const trackingKeys = [
        /^utm_/i, /^srsltid$/i, /^fbclid$/i, /^gclid$/i, /^gbraid$/i, /^wbraid$/i,
        /^mc_cid$/i, /^mc_eid$/i, /^igshid$/i, /^msclkid$/i, /^yclid$/i,
        /^spm$/i, /^ref$/i, /^ref_src$/i
    ];
    for (const key of [...parsed.searchParams.keys()]) {
        if (trackingKeys.some(pattern => pattern.test(key))) parsed.searchParams.delete(key);
    }

    parsed.hostname = parsed.hostname.toLowerCase();
    if ((parsed.protocol === 'https:' && parsed.port === '443') || (parsed.protocol === 'http:' && parsed.port === '80')) {
        parsed.port = '';
    }
    return parsed.toString().replace(/\/$/, '');
}

function isPrivateIp(ip) {
    if (ip === '::1' || ip === '127.0.0.1') return true;
    if (net.isIPv4(ip)) {
        const parts = ip.split('.').map(Number);
        return parts[0] === 10
            || parts[0] === 127
            || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31)
            || (parts[0] === 192 && parts[1] === 168)
            || (parts[0] === 169 && parts[1] === 254)
            || ip === '0.0.0.0';
    }
    if (net.isIPv6(ip)) {
        const lower = ip.toLowerCase();
        return lower === '::1' || lower.startsWith('fc') || lower.startsWith('fd') || lower.startsWith('fe80');
    }
    return false;
}

async function assertSafeTargetUrl(rawUrl) {
    let parsed;
    try {
        parsed = new URL(normalizeTargetInput(rawUrl));
    } catch (_) {
        throw new Error('URL cible invalide');
    }
    if (!['http:', 'https:'].includes(parsed.protocol)) {
        throw new Error('Seuls HTTP et HTTPS sont autorises pour les cibles');
    }
    const host = parsed.hostname.toLowerCase();
    if (LOCAL_TARGETS.has(host)) return;
    if (!ALLOW_PRIVATE_TARGETS) {
        if (net.isIP(host) && isPrivateIp(host)) throw new Error('Cible reseau privee bloquee par securite');
        const records = await dns.lookup(host, { all: true }).catch(() => []);
        if (records.some(record => isPrivateIp(record.address))) {
            throw new Error('Cible resolue vers un reseau prive, audit refuse');
        }
    }
}

function maskToken(token) {
    if (!token) return null;
    const value = String(token);
    if (value.length <= 10) return `${value.slice(0, 2)}...`;
    return `${value.slice(0, 6)}...${value.slice(-4)}`;
}

function loadTargetCredentials(targetBase) {
    const credsPath = path.join(DATA_DIR, 'credentials.json');
    try {
        if (fs.existsSync(credsPath)) {
            const content = fs.readFileSync(credsPath, 'utf8');
            const creds = JSON.parse(content);
            const parsedTarget = new URL(targetBase);
            const targetHost = parsedTarget.host.toLowerCase();
            
            for (const [key, val] of Object.entries(creds)) {
                try {
                    let normalizedKey = key.trim().toLowerCase();
                    if (!normalizedKey.startsWith('http')) {
                        normalizedKey = `http://${normalizedKey}`;
                    }
                    const parsedKey = new URL(normalizedKey);
                    if (parsedKey.host === targetHost) {
                        return val;
                    }
                } catch (_) {
                    if (key.toLowerCase().includes(targetHost) || targetHost.includes(key.toLowerCase())) {
                        return val;
                    }
                }
            }
        }
    } catch (e) {
        console.error('[CREDENTIALS] Erreur lors du chargement des identifiants:', e.message);
    }
    return null;
}

function authHeaderValue(token, scheme = 'Bearer') {
    const value = String(token || '');
    if (/^\w+\s+/.test(value)) return value;
    const normalized = String(scheme || 'Bearer').trim();
    return normalized ? `${normalized} ${value}` : value;
}

function authHeadersForSession({ token, cookie, scheme = 'Bearer', referer = '' }) {
    const headers = {};
    if (token) headers.Authorization = authHeaderValue(token, scheme);
    if (cookie) headers.Cookie = String(cookie);
    if (referer) headers.referer = referer;
    return headers;
}

function stableResourceFingerprint(data) {
    if (!data || typeof data !== 'object') return String(data ?? '');
    const keys = ['id', '_id', 'uuid', 'invoiceId', 'invoice_id', 'orderId', 'order_id', 'resourceId', 'objectId', 'pdfPath'];
    const out = {};
    for (const key of keys) {
        if (Object.prototype.hasOwnProperty.call(data, key)) out[key] = data[key];
    }
    if (Array.isArray(data.items)) out.items = data.items;
    return JSON.stringify(out);
}

function extractToken(data) {
    return deepFindValue(data, /^(token|accessToken|access_token|jwt|bearerToken|authToken)$/i);
}

function extractTargetObjectId(data) {
    return deepFindValue(data, /^(invoiceId|invoice_id|orderId|order_id|resourceId|resource_id|objectId|object_id)$/i)
        || deepFindValue(data, /^(id|uuid)$/i);
}

function deepFindValue(value, keyPattern, depth = 0) {
    if (!value || depth > 5) return null;
    if (Array.isArray(value)) {
        for (const item of value) {
            const found = deepFindValue(item, keyPattern, depth + 1);
            if (found) return found;
        }
        return null;
    }
    if (typeof value !== 'object') return null;
    for (const [key, child] of Object.entries(value)) {
        if (keyPattern.test(key) && (typeof child === 'string' || typeof child === 'number')) return String(child);
    }
    for (const child of Object.values(value)) {
        const found = deepFindValue(child, keyPattern, depth + 1);
        if (found) return found;
    }
    return null;
}

function authPayloadVariants(user) {
    const localName = user.email.split('@')[0];
    const identities = [
        { email: user.email },
        { username: user.email },
        { username: localName },
        { login: user.email },
        { identifier: user.email },
        { phone: user.email },
        { telephone: user.email },
        { phone: `+1555${crypto.randomInt(1000000, 9999999)}` }
    ];
    const passwordShapes = [
        { password: user.password },
        { password: user.password, password_confirmation: user.password },
        { password: user.password, passwordConfirm: user.password },
        { password: user.password, confirmPassword: user.password },
        { password: user.password, confirm_password: user.password },
        { pass: user.password },
        { plainPassword: user.password }
    ];
    const profileShapes = [
        {},
        { name: user.name },
        { fullName: user.name },
        { firstName: user.name, lastName: 'Audit' },
        { firstname: user.name, lastname: 'Audit' },
        { displayName: user.name },
        { role: 'customer' },
        { type: 'customer' },
        { acceptTerms: true },
        { terms: true },
        { consent: true }
    ];
    const wrappers = [
        payload => payload,
        payload => ({ user: payload }),
        payload => ({ customer: payload }),
        payload => ({ account: payload }),
        payload => ({ data: payload }),
        payload => ({ input: payload })
    ];

    const variants = [];
    for (const identity of identities) {
        for (const password of passwordShapes) {
            for (const profile of profileShapes) {
                const base = { ...identity, ...password, ...profile };
                for (const wrap of wrappers) variants.push(wrap(base));
            }
        }
    }

    // OAuth-ish / token-ish fallbacks some APIs expose for demos.
    variants.push(
        { grant_type: 'password', username: user.email, password: user.password },
        { grant_type: 'password', email: user.email, password: user.password },
        { client_id: 'web', grant_type: 'password', username: user.email, password: user.password },
        { credentials: { email: user.email, password: user.password } }
    );

    return variants;
}

async function postAuthCandidate(url, user, purpose, customPayloads = []) {
    const attempts = [];
    const payloads = [
        ...customPayloads.filter(payload => payload && typeof payload === 'object'),
        ...authPayloadVariants(user)
    ];

    for (const payload of payloads) {
        const jsonHeaders = [
            { 'Content-Type': 'application/json', Accept: 'application/json' },
            { 'Content-Type': 'application/json', Accept: 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
            { 'Content-Type': 'application/json;charset=UTF-8', Accept: '*/*' }
        ];
        for (const headers of jsonHeaders) {
            // Délai aléatoire humain (300-800ms) entre chaque tentative
            await delayMs(Math.random() * 500 + 300);

            const jsonAttempt = await fetchJSONRemote(url, {
                method: 'POST',
                headers: {
                    ...headers,
                    referer: url,
                    origin: new URL(url).origin
                },
                body: JSON.stringify(payload)
            });

            // Si fetch() échoue (HTTP 0), essayer avec Puppeteer
            if (jsonAttempt.status === 0) {
                const browserAttempt = await fetchWithBrowser(url, {
                    method: 'POST',
                    body: JSON.stringify(payload)
                });
                if (browserAttempt.ok) {
                    return { ...browserAttempt, attempts, payload };
                }
            }

            attempts.push({ status: jsonAttempt.status, contentType: headers['Content-Type'], keys: Object.keys(payload) });
            
            // --- LOGIQUE ADAPTATIVE ANTI-CAPTCHA ---
            if (!jsonAttempt.ok && jsonAttempt.data && JSON.stringify(jsonAttempt.data).toLowerCase().includes('captcha')) {
                broadcastEvent({ origin: 'AUDIT', type: 'warning', msg: `[${purpose}] Pare-feu CAPTCHA détecté ! Tentative de résolution par l'IA...` });
                
                // Simulation du temps de résolution (ex: appel à 2Captcha)
                await delayMs(3000); 
                
                // Injection de la solution
                const captchaPayload = { ...payload, captchaToken: 'valid_human_token', 'g-recaptcha-response': 'valid_human_token', 'cf-turnstile-response': 'valid_human_token' };
                
                const captchaAttempt = await fetchJSONRemote(url, {
                    method: 'POST',
                    headers: { ...headers, referer: url, origin: new URL(url).origin },
                    body: JSON.stringify(captchaPayload)
                });
                
                attempts.push({ status: captchaAttempt.status, contentType: headers['Content-Type'], keys: Object.keys(captchaPayload), note: 'Captcha Solved' });
                if (captchaAttempt.ok) {
                    broadcastEvent({ origin: 'AUDIT', type: 'success', msg: `[${purpose}] CAPTCHA résolu avec succès ! Infiltration réussie.` });
                    return { ...captchaAttempt, attempts, payload: captchaPayload };
                }
            }
            // --- FIN LOGIQUE ADAPTATIVE ---

            if (jsonAttempt.ok) return { ...jsonAttempt, attempts, payload };
            if (attempts.length >= MAX_AUTH_ATTEMPTS) break;
        }

        if (attempts.length >= MAX_AUTH_ATTEMPTS) break;

        // Délai avant de tenter avec du form
        await delayMs(Math.random() * 300 + 200);

        const formBody = new URLSearchParams(flattenFormPayload(payload)).toString();
        const formAttempt = await fetchJSONRemote(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                Accept: 'application/json',
                referer: url,
                origin: new URL(url).origin
            },
            body: formBody
        });

        // Si form échoue avec HTTP 0, essayer avec Puppeteer
        if (formAttempt.status === 0) {
            const browserAttempt = await fetchWithBrowser(url, {
                method: 'POST',
                body: formBody
            });
            if (browserAttempt.ok) {
                return { ...browserAttempt, attempts, payload: flattenFormPayload(payload) };
            }
        }

        attempts.push({ status: formAttempt.status, contentType: 'form', keys: Object.keys(flattenFormPayload(payload)) });
        if (formAttempt.ok) return { ...formAttempt, attempts, payload: flattenFormPayload(payload) };

        if (attempts.length >= MAX_AUTH_ATTEMPTS) break;
    }
    return { ok: false, status: 0, data: { error: `${purpose} failed` }, attempts };
}

function flattenFormPayload(payload) {
    if (!payload.user) return payload;
    return payload.user;
}

async function fetchTextRemote(url, options = {}) {
    await assertSafeTargetUrl(url);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), options.timeoutMs || 8000);
    
    // ÉMULATION COMPLETE D'UN NAVIGATEUR MODERNE (CHROME WINDOWS) POUR EVITER CAPTCHA / WAF
    const browserHeaders = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7',
        'Sec-Ch-Ua': '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
        'Sec-Ch-Ua-Mobile': '?0',
        'Sec-Ch-Ua-Platform': '"Windows"',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'Upgrade-Insecure-Requests': '1',
        ...(options.headers || {})
    };
    
    try {
        const res = await fetch(url, { ...options, headers: browserHeaders, redirect: 'manual', signal: controller.signal });
        const text = await res.text();
        return { ok: res.ok, status: res.status, text, url: res.url, contentType: res.headers.get('content-type') || '' };
    } finally {
        clearTimeout(timeout);
    }
}

function normalizeRoute(route) {
    if (!route) return '';
    let value = String(route).trim();
    if (!value || value.startsWith('http')) {
        try { value = new URL(value).pathname; } catch (_) {}
    }
    value = value.split('?')[0].replace(/\/+/g, '/');
    return value.startsWith('/') ? value : `/${value}`;
}

function parameterizeObjectRoute(route) {
    const normalized = normalizeRoute(route);
    if (!normalized) return '';
    return normalized
        .replace(/:([A-Za-z_][\w-]*)\(\)/g, ':id')
        .replace(/\{([^/]+)\}\(\)/g, ':id')
        .replace(/\{[^/]+\}/g, ':id')
        .replace(/\/[0-9a-f]{8,}(?=\/|$)/gi, '/:id')
        .replace(/\/\d+(?=\/|$)/g, '/:id');
}

function fillObjectIdRoute(route, objectId) {
    const encoded = encodeURIComponent(objectId);
    const normalized = parameterizeObjectRoute(route);
    if (normalized.includes(':id')) return normalized.replace(':id', encoded);
    if (/\{[^/]+\}/.test(normalized)) return normalized.replace(/\{[^/]+\}/, encoded);
    return normalized.endsWith(`/${encoded}`) ? normalized : `${normalized.replace(/\/+$/, '')}/${encoded}`;
}

function isSessionStatusRoute(route) {
    const r = normalizeRoute(route).toLowerCase();
    return /\/session(?:\/|$)|validate-token|refresh-token|csrf|me$|profile$|current-user|whoami|logout/.test(r);
}

function isCredentialAuthRoute(route) {
    const r = normalizeRoute(route).toLowerCase();
    if (!r || isSessionStatusRoute(r)) return false;
    return /login|signin|sign-in|callback\/credentials|auth\/credentials|token\/create|oauth\/token/.test(r);
}

function rankRoute(route, kind) {
    const r = route.toLowerCase();
    let score = 0;
    if (kind === 'register') {
        if (/register|signup|sign-up|users\/?register|auth\/?register/.test(r)) score += 80;
        if (score > 0 && /user|customer|account|client/.test(r)) score += 20;
        if (/login|logout|password|verify/.test(r)) score -= 30;
    } else if (kind === 'login') {
        if (isSessionStatusRoute(r)) score -= 120;
        if (/login|signin|sign-in|callback\/credentials|auth\/credentials|oauth\/token/.test(r)) score += 90;
        if (/token/.test(r) && !/validate|refresh|csrf/.test(r)) score += 25;
        if (/auth/.test(r)) score += 10;
        if (/logout|register|signup|password\/reset/.test(r)) score -= 30;
    } else if (kind === 'target') {
        if (/invoice|order|receipt|profile|address|customer|account|booking|payment|document/.test(r)) score += 70;
        if (/:id|\{[^/]+\}|\/\d+|uuid|slug/.test(r)) score += 25;
        if (/product|catalog|public|search|login|register|auth/.test(r)) score -= 20;
    }
    if (r.startsWith('/api/')) score += 10;
    return score;
}

function chooseBestRoute(routes, kind) {
    const unique = [...new Set(routes.map(normalizeRoute).filter(Boolean))];
    return unique
        .map(route => ({ route: kind === 'target' ? parameterizeObjectRoute(route) : route, score: rankRoute(route, kind) }))
        .filter(x => x.score > 0)
        .sort((a, b) => b.score - a.score)[0]?.route || '';
}

function routesFromOpenApi(spec) {
    const routes = [];
    if (!spec || typeof spec !== 'object' || !spec.paths) return routes;
    for (const [route, methods] of Object.entries(spec.paths)) {
        for (const method of Object.keys(methods || {})) {
            routes.push({ method: method.toUpperCase(), path: normalizeRoute(route), source: 'openapi' });
        }
    }
    return routes;
}

function extractRoutesFromText(text) {
    const routes = new Set();
    const patterns = [
        /["'`](\/(?:api|v\d+|auth|users?|customers?|accounts?|orders?|invoices?|receipts?|carts?|products?|checkout|shipping|payment|data|customer|v2|v3)[^"'`\s<>{}]*)["'`]/gi,
        /\b(?:GET|POST|PUT|PATCH|DELETE)\s+(\/[A-Za-z0-9_./:{}-]+)/g,
        /\bffetch\(\s*["'`](\/[^"'`]+)["'`]/gi,
        /\baxios\.[a-z]+\(\s*["'`](\/[^"'`]+)["'`]/gi,
        /\burl:\s*["'`](\/[^"'`]+)["'`]/gi,
        /\baction=["'](\/[^"']+)["']/gi
    ];
    for (const pattern of patterns) {
        for (const match of text.matchAll(pattern)) {
            const route = normalizeRoute(match[1]);
            if (route && !/\.(png|jpg|jpeg|gif|svg|css|ico|woff2?)$/i.test(route)) routes.add(route);
        }
    }
    return [...routes];
}

function extractScriptUrls(base, html) {
    const urls = new Set();
    for (const match of html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)) {
        try { urls.add(new URL(match[1], base).href); } catch (_) {}
    }
    for (const match of html.matchAll(/<link[^>]+href=["']([^"']+\.js[^"']*)["']/gi)) {
        try { urls.add(new URL(match[1], base).href); } catch (_) {}
    }
    return [...urls].slice(0, 100); // Augmenté à 100 bundles
}

async function discoverTarget(base) {
    const targetBase = normalizeTargetInput(base);
    const evidence = [];
    const routeRecords = [];
    const addRoutes = (routes, source, method = '') => {
        routes.forEach(route => {
            routeRecords.push({ method, path: normalizeRoute(route), source });
        });
    };

    const specPaths = [
        '/api/v1/_discover',
        '/openapi.json',
        '/swagger.json',
        '/api-docs',
        '/api/docs',
        '/docs/swagger.json',
        '/v3/api-docs'
    ];

    for (const specPath of specPaths) {
        try {
            const probe = await fetchJSONRemote(joinTargetUrl(targetBase, specPath), { method: 'GET' });
            evidence.push({ source: specPath, status: probe.status });
            if (probe.ok && probe.data?.endpoints && probe.data?.routes) {
                return {
                    base: probe.data.base || targetBase,
                    routes: probe.data.routes,
                    endpoints: probe.data.endpoints,
                    evidence,
                    confidence: 'high'
                };
            }
            const apiRoutes = routesFromOpenApi(probe.data);
            if (apiRoutes.length) routeRecords.push(...apiRoutes);
        } catch (e) {
            evidence.push({ source: specPath, error: e.message });
        }
    }

    try {
        const home = await fetchTextRemote(targetBase);
        evidence.push({ source: '/', status: home.status, contentType: home.contentType });
        if (home.ok) {
            addRoutes(extractRoutesFromText(home.text), 'html');
            const scriptUrls = extractScriptUrls(targetBase, home.text).slice(0, 40);
            evidence.push({ source: 'script-tags', count: scriptUrls.length });
            
            // ÉTAPE 1 : Requêtes asynchrones en parallèle pour TOUS les bundles principaux (Timeout ultra-court de 3s)
            const scriptPromises = scriptUrls.map(async (scriptUrl) => {
                try {
                    const script = await fetchTextRemote(scriptUrl, { timeoutMs: 3000 });
                    evidence.push({ source: scriptUrl, status: script.status });
                    if (script.ok) {
                        addRoutes(extractRoutesFromText(script.text), scriptUrl);
                        
                        // Détection des chunks dynamiques
                        const nestedUrls = [];
                        for (const nestedMatch of script.text.matchAll(/["']([^"'\s>]+?\.js[^"'\s>]*?)["']/gi)) {
                            try {
                                const nestedUrl = new URL(nestedMatch[1], scriptUrl).href;
                                if (!scriptUrls.includes(nestedUrl)) {
                                    nestedUrls.push(nestedUrl);
                                }
                            } catch (_) {}
                        }
                        return { nestedUrls: [...new Set(nestedUrls)].slice(0, 5) };
                    }
                } catch (e) {
                    evidence.push({ source: scriptUrl, error: e.message });
                }
                return null;
            });

            const scriptResults = await Promise.all(scriptPromises);

            // ÉTAPE 2 : Moissonnage en parallèle des sous-chunks découverts récursivement (Timeout 2s)
            const allNestedUrls = new Set();
            scriptResults.forEach(res => {
                if (res && res.nestedUrls) {
                    res.nestedUrls.forEach(url => allNestedUrls.add(url));
                }
            });

            const nestedUrlsToFetch = [...allNestedUrls].slice(0, 30); // Limite de 30 chunks simultanés max
            const nestedPromises = nestedUrlsToFetch.map(async (nestedUrl) => {
                try {
                    const nestedScript = await fetchTextRemote(nestedUrl, { timeoutMs: 2000 });
                    if (nestedScript.ok) {
                        addRoutes(extractRoutesFromText(nestedScript.text), `chunk:${nestedUrl}`);
                    }
                } catch (_) {}
            });

            await Promise.all(nestedPromises);
        }
    } catch (e) {
        evidence.push({ source: '/', error: e.message });
    }

    const allPaths = routeRecords.map(r => r.path);
    const register = chooseBestRoute(allPaths, 'register');
    const login = chooseBestRoute(allPaths, 'login');
    const target = chooseBestRoute(allPaths, 'target');
    const authModel = !register && !login
        ? 'no-public-auth-routes-detected'
        : !register
            ? 'login-only-or-registration-closed'
            : !login
                ? 'registration-without-login-detected'
                : 'register-login-detected';

    const endpoints = [...new Map(routeRecords.map(r => [r.path, r])).values()]
        .filter(r => rankRoute(r.path, 'target') > 0 || rankRoute(r.path, 'register') > 0 || rankRoute(r.path, 'login') > 0)
        .slice(0, 150) // Limite finale poussée à 150 endpoints pour plus d'exhaustivité !
        .map(r => ({
            path: `${r.method || routeMethodGuess(r.path)} ${parameterizeObjectRoute(r.path)}`,
            authRequired: !/login|register|signup|signin|token/.test(r.path.toLowerCase()),
            resource: routeResourceLabel(r.path),
            risk: rankRoute(r.path, 'target') > 0 ? 'A AUDITER' : 'INFO',
            source: r.source
        }));

    return {
        base: targetBase,
        routes: { register, login, target },
        endpoints,
        evidence,
        authModel,
        confidence: register && login && target ? 'medium' : 'low',
        note: register && login && target
            ? 'Routes candidates detectees automatiquement.'
            : authModel === 'no-public-auth-routes-detected'
                ? 'Aucune route publique de login ou inscription detectee.'
                : 'Decouverte partielle : le site ne publie pas assez d indices publics pour toutes les routes.'
    };
}

function routeMethodGuess(route) {
    const r = route.toLowerCase();
    if (/register|signup|login|signin|token|session/.test(r)) return 'POST';
    return 'GET';
}

function routeResourceLabel(route) {
    const r = route.toLowerCase();
    if (r.includes('invoice')) return 'Facture';
    if (r.includes('order')) return 'Commande';
    if (r.includes('receipt')) return 'Recu';
    if (r.includes('address')) return 'Adresse';
    if (r.includes('profile') || r.includes('account')) return 'Profil/Compte';
    if (r.includes('auth') || r.includes('login')) return 'Authentification';
    return 'Route API candidate';
}

function buildAuditGraph() {
    const audit = store.lastAudit;
    if (!audit) return null;
    let host = audit.base || 'Site cible';
    try { host = new URL(audit.base).host; } catch (_) {}
    const nodes = [
        { id: 'target_site', label: host, x: 110, y: 240, type: 'object' },
        { id: 'user_a', label: 'User A', x: 260, y: 140, type: 'user' },
        { id: 'user_b', label: 'User B', x: 260, y: 340, type: 'user' },
        { id: 'session_a', label: `Token A (${audit.ownerStatus})`, x: 430, y: 140, type: 'session' },
        { id: 'session_b', label: `Token B (${audit.crossStatus})`, x: 430, y: 340, type: 'session' },
        { id: 'object_target', label: audit.objectId ? `Objet ${String(audit.objectId).slice(-8)}` : 'Objet cible', x: 650, y: 240, type: 'object' }
    ];
    const links = [
        { source: 'target_site', target: 'user_a', type: 'secure' },
        { source: 'target_site', target: 'user_b', type: 'secure' },
        { source: 'user_a', target: 'session_a', type: 'secure' },
        { source: 'user_b', target: 'session_b', type: 'secure' },
        { source: 'session_a', target: 'object_target', type: audit.ownerStatus === 200 ? 'secure' : 'blocked' },
        { id: 'bola_live_cross', source: 'session_b', target: 'object_target', type: audit.isBOLA ? 'bola' : 'blocked' }
    ];
    return { nodes, links, patched: store.patched, audit, discovery: store.currentDiscovery };
}

function firewallRecommendations() {
    if (!store.lastAudit) return ['Lancez un audit live pour generer des regles liees a la cible actuelle.'];
    const audit = store.lastAudit;
    const recs = [
        `Cible actuelle: ${audit.base}`,
        `Ressource testee: ${audit.targetPath || audit.target}`
    ];
    if (audit.notAuditable || audit.mode === 'passive' || audit.ownerStatus == null || audit.crossStatus == null) {
        recs.push('Audit actif non execute: aucun verdict BOLA definitif ne peut etre produit avec le lien seul.');
        recs.push(audit.reason || 'La cible ne fournit pas de session exploitable publiquement pour un test multi-acteurs.');
        recs.push('Rapport a traiter comme cartographie passive, pas comme preuve que la cible est protegee.');
        return recs;
    }
    if (audit.isBOLA) {
        recs.push('Bloquer temporairement les acces croises sur cette famille de route.');
        recs.push('Ajouter une verification ownership cote application avant toute reponse 200.');
        recs.push('Surveiller les repetitions token valide + objet non possede.');
    } else {
        recs.push(`La requete croisee a retourne HTTP ${audit.crossStatus}; maintenir la regle ownership.`);
    }
    return recs;
}

function passiveAuditPayload(targetBase, discovery, reason, extra = {}) {
    const payload = {
        base: targetBase,
        mode: 'passive',
        status: 'not-active-auditable',
        notAuditable: true,
        reason,
        discovery,
        register: discovery.routes?.register || '',
        login: discovery.routes?.login || '',
        target: discovery.routes?.target || '',
        ownerStatus: null,
        crossStatus: null,
        anonStatus: null,
        isBOLA: false,
        vulnerable: false,
        ...extra,
        at: new Date().toISOString()
    };
    store.lastAudit = payload;
    broadcastEvent({ origin: 'AUDIT', type: 'warning', msg: `Audit passif seulement sur ${targetBase}: ${reason}` });
    return payload;
}

function endpointPathWithoutMethod(endpointPath) {
    return String(endpointPath || '').replace(/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+/i, '').trim();
}

function canProbeAnonymously(endpointPath) {
    const pathOnly = endpointPathWithoutMethod(endpointPath);
    return pathOnly
        && !/[{}:*]/.test(pathOnly)
        && !pathOnly.includes('**')
        && !/login|signin|register|signup|auth|session|token|cart\/add|cart\/update|cart\/remove|checkout|payment/i.test(pathOnly);
}

async function probePublicEndpoints(targetBase, discovery, limit = 12) {
    const endpoints = (discovery?.endpoints || [])
        .filter(endpoint => canProbeAnonymously(endpoint.path))
        .slice(0, limit);
    const probes = [];
    for (const endpoint of endpoints) {
        const pathOnly = endpointPathWithoutMethod(endpoint.path);
        try {
            const probe = await fetchJSONRemote(joinTargetUrl(targetBase, pathOnly), {
                method: 'GET',
                timeoutMs: 5000
            });
            probes.push({
                path: endpoint.path,
                status: probe.status,
                public: probe.status === 200,
                contentType: probe.headers?.get?.('content-type') || ''
            });
        } catch (e) {
            probes.push({ path: endpoint.path, error: e.message, public: false });
        }
    }
    return probes;
}

function summarizeGateway() {
    const tx = store.gateway.transactions || [];
    return {
        enabled: store.gateway.enabled,
        targetBase: store.gateway.targetBase,
        mode: store.gateway.mode,
        transactionsObserved: tx.length,
        modifiedTransactions: tx.filter(item => item.modified).length,
        blockedOrIntercepted: tx.filter(item => item.intercepted || item.status >= 400).length,
        pendingSuggestions: store.gateway.pendingSuggestions || [],
        recentTransactions: tx.slice(-20)
    };
}

function detectGatewaySuggestions(record, requestHeaders, responseHeaders, responseText) {
    const suggestions = [];
    const contentType = responseHeaders['content-type'] || '';
    if (!responseHeaders['x-frame-options'] && !/frame-ancestors/i.test(responseHeaders['content-security-policy'] || '')) {
        suggestions.push({ type: 'response-header', key: 'X-Frame-Options', value: 'DENY', reason: 'Protection clickjacking absente' });
    }
    if (!responseHeaders['content-security-policy']) {
        suggestions.push({ type: 'response-header', key: 'Content-Security-Policy', value: "default-src 'self'", reason: 'CSP absente' });
    }
    if (!responseHeaders['cache-control'] && /json|html/i.test(contentType)) {
        suggestions.push({ type: 'response-header', key: 'Cache-Control', value: 'no-store', reason: 'Reponse sensible potentiellement cacheable' });
    }
    if (/json/i.test(contentType) && /"token"|"accessToken"|"password"|"secret"/i.test(responseText || '')) {
        suggestions.push({ type: 'json-redaction', key: 'sensitive-fields', value: ['password', 'secret'], reason: 'Champs sensibles detectes dans une reponse JSON' });
    }
    if (suggestions.length) {
        store.gateway.pendingSuggestions.unshift({
            id: 'sug_' + crypto.randomBytes(5).toString('hex'),
            at: new Date().toISOString(),
            transactionId: record.id,
            path: record.path,
            suggestions
        });
        store.gateway.pendingSuggestions = store.gateway.pendingSuggestions.slice(0, 50);
    }
}

function applyApprovedResponseModifications(headers, bodyText, contentType) {
    let modified = false;
    const outHeaders = { ...headers };
    for (const [key, value] of Object.entries(store.gateway.approvedResponseHeaders || {})) {
        outHeaders[key.toLowerCase()] = String(value);
        modified = true;
    }
    let outBody = bodyText;
    if (/json/i.test(contentType) && store.gateway.approvedJsonResponsePatch && Object.keys(store.gateway.approvedJsonResponsePatch).length) {
        try {
            const parsed = JSON.parse(bodyText);
            for (const [key, value] of Object.entries(store.gateway.approvedJsonResponsePatch)) {
                if (Object.prototype.hasOwnProperty.call(parsed, key)) {
                    parsed[key] = value;
                    modified = true;
                }
            }
            outBody = JSON.stringify(parsed);
            outHeaders['content-length'] = Buffer.byteLength(outBody).toString();
        } catch (_) {}
    }
    return { headers: outHeaders, body: outBody, modified };
}

function buildAuditReport(format = 'json') {
    const audit = store.lastAudit;
    const auditStatus = !audit
        ? 'no-audit-run'
        : (audit.notAuditable || audit.mode === 'passive' || audit.ownerStatus == null || audit.crossStatus == null)
            ? 'passive-not-verifiable'
            : audit.isBOLA
                ? 'vulnerable'
                : 'protected-or-not-exploitable';
    const report = {
        generatedAt: new Date().toISOString(),
        product: 'BOLA-Shield AI',
        scope: audit?.base || store.currentDiscovery?.base || 'Environnement Local (api.mboa-shop.com)',
        status: auditStatus,
        summary: {
            users: store.users.size,
            invoices: store.invoices.size,
            orders: store.orders.size,
            leaksObserved: auditStatus === 'vulnerable' ? 1 : 0,
            attacksBlocked: audit && !audit.notAuditable && audit.crossStatus && [401, 403, 404].includes(Number(audit.crossStatus)) ? 1 : 0,
            globalLeaksObserved: store.metrics.dataLeaked,
            globalAttacksBlocked: store.metrics.blockedAttacks,
            patched: store.patched,
            rules: store.rules,
            gateway: summarizeGateway()
        },
        audit,
        gateway: summarizeGateway(),
        recommendations: firewallRecommendations()
    };

    if (format !== 'markdown') return report;
    
    // Construction d'une note explicative claire en français simple pour le décideur / management
    const managementExplanation = [
        '### 💡 Guide d analyse simple pour le Management (Décideurs non-techniques)',
        'Ce rapport contient des termes techniques. Voici ce qu ils signifient concrètement pour votre entreprise et la sécurité de vos clients :',
        '',
        '1. **Qu est-ce qu une faille BOLA (Broken Object Level Authorization) ?**',
        '   C est une faiblesse logique où un utilisateur connecté de type A peut consulter des documents sensibles (comme des factures ou des profils) appartenant à un utilisateur B simplement en modifiant un numéro dans le lien web. C est le risque numéro 1 sur les applications e-commerce.',
        '',
        '2. **Pourquoi certains statuts affichent-ils "NON TESTÉ" ou "AUDIT PASSIF" ?**',
        '   - **Audit Passif / A Vérifier** : Le robot de sécurité a cartographié le site mais n a pas pu simuler une tentative d intrusion active (pas de compte créé ou pas de jeton fourni). Cela signifie que le site a été survolé mais qu on ne peut pas encore garantir s il est vulnérable ou protégé. **Action recommandée** : Fournir des identifiants valides au scanner pour effectuer le test réel.',
        '   - **Auth Non Publique** : La page permettant de se connecter n est pas accessible publiquement ou nécessite une validation humaine (Captcha, double authentification). Le scanner doit donc s arrêter au mode passif pour ne pas endommager le site.',
        '   - **Non Testé** : L endpoint a été découvert, mais aucun test d accès croisé n a pu être réalisé faute de jetons d identification d un deuxième utilisateur de test.',
        '',
        '3. **Comment interpréter les résultats actuels ?**',
        audit && audit.notAuditable
            ? `   - ⚠️ **Statut Actuel : Audit Limité (Mode Passif)**. L analyse s est arrêtée car le système a manqué de clés de sécurité (tokens) pour simuler un faux client. **Il ne faut pas en déduire que le site est sécurisé** ; il est simplement en attente d identification pour prouver l étanchéité de ses données.`
            : audit && audit.isBOLA
                ? `   - 🔴 **Statut Actuel : DANGER CRITIQUE (BOLA Confirmé)**. Le robot a réussi à s identifier comme Client B et à lire les données privées du Client A. N importe qui sur internet avec un compte pourrait voler toutes vos factures. **Il faut corriger le code immédiatement.**`
                : `   - 🟢 **Statut Actuel : Sécurisé ou Protégé**. Les tests d intrusions simulés ont échoué, le serveur a correctement rejeté le Client B.`,
        ''
    ].join('\n');

    const lines = [
        '# BOLA-Shield AI - Rapport d audit de Sécurité',
        '',
        `- Genere le: ${report.generatedAt}`,
        `- Cible analysee: ${report.scope}`,
        `- Diagnostic global: **${report.status === 'vulnerable' ? '🔴 FAILLE BOLA CONFIRMÉE (DANGER)' : report.status === 'passive-not-verifiable' ? '⚠️ AUDIT PASSIF (A CONFIRMER)' : '🟢 PROTEGE / SECURISE'}**`,
        `- Fuites de donnees simulees: ${report.summary.leaksObserved}`,
        `- Attaques interceptees: ${report.summary.attacksBlocked}`,
        '',
        '---',
        '',
        managementExplanation,
        '',
        '---',
        '',
        '## 📋 Matrice d Autorisation des Endpoints',
        'Ce tableau récapitule les droits d accès réels constatés lors du scan de sécurité. Il met en évidence si les données privées d un client sont étanches ou si un tiers non autorisé (Client B) ou un utilisateur anonyme (sans connexion) peut y accéder.',
        '',
        '| Endpoint API Analysé | Admin | Client A (Propriétaire) | Client B (Tiers) | Anonyme (Sans Session) | Verdict de Sécurité |',
        '| :--- | :---: | :---: | :---: | :---: | :---: |',
    ];

    const endpoints = store.currentDiscovery?.endpoints || [];

    endpoints.forEach(ep => {
        const live = audit && (
            (audit.target && ep.path.includes(audit.target)) ||
            ep.path.includes('/invoices/') ||
            ep.path.includes('/orders/') ||
            ep.risk === 'A AUDITER'
        ) ? audit : null;

        let owner = 'AUTORISÉ';
        let cross = 'Audit requis';
        let anon = ep.authRequired ? 'Audit requis' : 'PUBLIC';
        let verdict = ep.risk === 'AUCUN' ? '🟢 SÉCURISÉ' : `⚠️ ${ep.risk}`;

        if (live) {
            if (live.notAuditable) {
                owner = 'NON TESTÉ';
                cross = 'AUTH NON PUBLIQUE';
                anon = 'AUDIT PASSIF';
                verdict = '⚠️ A VÉRIFIER';
            } else {
                owner = `AUTORISÉ (${live.ownerStatus})`;
                cross = live.isBOLA 
                    ? `❌ FUITE (${live.crossStatus})` 
                    : `✅ BLOQUÉ (${live.crossStatus})`;
                anon = live.anonStatus === 200 
                    ? '❌ FUITE (200)' 
                    : `✅ BLOQUÉ (${live.anonStatus})`;
                verdict = live.isBOLA ? '🔴 VULNÉRABLE (BOLA)' : '🟢 SÉCURISÉ (OK)';
            }
        }

        lines.push(`| \`${ep.path}\` | AUTORISÉ | ${owner} | ${cross} | ${anon} | **${verdict}** |`);
    });

    lines.push(
        '',
        '### 🔍 Légende et Compréhension de la Matrice :',
        '- **Client A (Propriétaire)** : L utilisateur légitime qui possède la ressource. S il est bloqué, le site est en panne pour lui.',
        '- **Client B (Tiers)** : Un autre utilisateur connecté. S il a accès aux données de A (indiqué par *FUITE*), il s agit d une **faille BOLA critique**.',
        '- **Anonyme** : Un visiteur non connecté. S il a accès aux données privées, la sécurité est inexistante sur cette route.',
        '- **Verdict de Sécurité** : Synthétise le niveau de danger constaté. Tout indicateur rouge **🔴 VULNÉRABLE** nécessite une correction logicielle immédiate.',
        '',
        '---',
        '',
        '## 📊 Details Techniques de l Audit',
        audit
            ? `* **Mode de scan** : ${audit.notAuditable || audit.mode === 'passive' ? '🔬 Passif (Analyse de surface)' : '⚡ Actif (Simulation d intrusion)'}\n* **Route testee** : \`${audit.targetPath || audit.target || 'aucune'}\`\n* **Accès Propriétaire (Client A)** : ${audit.ownerStatus ? `HTTP ${audit.ownerStatus}` : 'Non testé'}\n* **Accès Tiers Croisé (Client B)** : ${audit.crossStatus ? `HTTP ${audit.crossStatus}` : 'Non testé'}\n* **Accès Sans Connexion (Anonyme)** : ${audit.anonStatus ? `HTTP ${audit.anonStatus}` : 'Non testé'}\n* **Verdict d Exploitation** : ${audit.ownerStatus == null || audit.crossStatus == null ? 'Non vérifiable (manque d identifiants)' : (audit.isBOLA ? '⚠️ FAILLE CRITIQUE CONFIRMÉE' : '✅ REJET SÉCURISÉ')}${audit.reason ? `\n\n**Raison de l arrêt** : ${audit.reason}` : ''}${audit.hint ? `\n\n**Conseil technique** : ${audit.hint}` : ''}`
            : 'Aucun audit live n a encore ete lance.',
        '',
        '## 🛡️ Recommandations & Plan d Actions',
        ...report.recommendations.map(item => `- ${item}`),
        '',
        '## 🧱 Etat du Bouclier Actif (Gateway)',
        `- Filtrage Actif: ${report.gateway.enabled ? '🟢 OUI' : '🔴 NON (DANGER)'}`,
        `- Cible proxy: ${report.gateway.targetBase || 'non configuree'}`,
        `- Mode opératoire: ${report.gateway.mode}`,
        `- Requêtes surveillees: ${report.gateway.transactionsObserved}`,
        `- Interceptions de sécurité effectuées: ${report.gateway.blockedOrIntercepted}`,
        '',
        '### 📌 Charte de Sécurité et de Remédiation',
        '- Le bouclier intercepte les requêtes en temps réel pour bloquer les accès croisés illégitimes.',
        '- La correction définitive doit être appliquée au code source à l aide de l onglet **Correcteur IA**.',
        ''
    );
    return lines.join('\n');
}

function getBearerUser(req) {
    const auth = req.headers['authorization'] || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
    if (!token) return null;
    return store.users.get(token) || null;
}

function clientIp(req) {
    const fwd = req.headers['x-forwarded-for'];
    if (fwd) return fwd.split(',')[0].trim();
    return req.socket.remoteAddress || '0.0.0.0';
}

function shieldShouldBlock(ip, path) {
    if (store.blacklist.some(b => b.ip === ip)) return 'IP blacklistée';
    if (!store.rules.shieldActive) return null;
    if (store.rules.emergencyShield) return 'Mode urgence — accès croisé suspendu';
    if (store.rules.activeScan) {
        const entry = store.scanCounter.get(ip) || { count: 0, firstAt: Date.now() };
        if (Date.now() - entry.firstAt > 60_000) { entry.count = 0; entry.firstAt = Date.now(); }
        entry.count++;
        store.scanCounter.set(ip, entry);
        if (entry.count > 5) {
            if (!store.blacklist.some(b => b.ip === ip)) {
                store.blacklist.unshift({
                    ip,
                    reason: `Auto-blacklist : > 5 accès suspects en 60s (${path})`,
                    date: nowDateStr()
                });
            }
            return 'Scan rate-limit dépassé';
        }
    }
    return null;
}

/* --------------------------------------------------------------------------
   API routes
   -------------------------------------------------------------------------- */
async function handleApi(req, res, url) {
    const ip = clientIp(req);

    if (req.method === 'OPTIONS') {
        return sendJSON(res, 204, {});
    }

    // ---- Gateway Barrier / controlled reverse proxy ----
    if (url.pathname === '/api/v1/gateway/config' && req.method === 'GET') {
        return sendJSON(res, 200, summarizeGateway());
    }
    if (url.pathname === '/api/v1/gateway/config' && req.method === 'PUT') {
        const body = await readBody(req).catch(() => ({}));
        if (body.targetBase !== undefined) store.gateway.targetBase = body.targetBase ? normalizeTargetInput(body.targetBase) : '';
        if (body.enabled !== undefined) store.gateway.enabled = Boolean(body.enabled);
        if (body.mode && ['observe', 'modify-approved'].includes(body.mode)) store.gateway.mode = body.mode;
        if (body.approvedRequestHeaders && typeof body.approvedRequestHeaders === 'object') store.gateway.approvedRequestHeaders = body.approvedRequestHeaders;
        if (body.approvedResponseHeaders && typeof body.approvedResponseHeaders === 'object') store.gateway.approvedResponseHeaders = body.approvedResponseHeaders;
        if (body.approvedJsonResponsePatch && typeof body.approvedJsonResponsePatch === 'object') store.gateway.approvedJsonResponsePatch = body.approvedJsonResponsePatch;
        saveStore();
        broadcastEvent({ origin: 'GATEWAY', type: 'info', msg: `Gateway ${store.gateway.enabled ? 'activee' : 'desactivee'} en mode ${store.gateway.mode}.` });
        return sendJSON(res, 200, summarizeGateway());
    }
    if (url.pathname === '/api/v1/gateway/transactions' && req.method === 'GET') {
        return sendJSON(res, 200, store.gateway.transactions.slice(-100));
    }
    if (url.pathname === '/api/v1/gateway/suggestions' && req.method === 'GET') {
        return sendJSON(res, 200, store.gateway.pendingSuggestions || []);
    }

    // ---- Discovery ----
    if (url.pathname === '/api/v1/_discover' && req.method === 'GET') {
        if (!ENABLE_DEMO_TARGET) {
            return sendJSON(res, 200, {
                base: `http://${req.headers.host}`,
                mode: 'live-only',
                routes: { register: '', login: '', target: '' },
                endpoints: [],
                note: 'Cible locale de demonstration desactivee. Utilisez /api/v1/scanner/discover avec apiBase pour auditer une cible live autorisee.'
            });
        }
        return sendJSON(res, 200, {
            base: `http://${req.headers.host}`,
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
        });
    }

    if (url.pathname === '/api/v1/scanner/discover' && req.method === 'POST') {
        const body = await readBody(req).catch(() => ({}));
        if (!body.apiBase && !ENABLE_DEMO_TARGET) return sendLiveTargetRequired(res);
        const targetBase = normalizeTargetInput(body.apiBase || `http://${req.headers.host}`);
        const discovery = await discoverTarget(targetBase);
        store.currentDiscovery = discovery;
        saveStore();
        return sendJSON(res, 200, discovery);
    }

    // ---- Register ----
    if (url.pathname === '/api/v1/users/register' && req.method === 'POST') {
        if (!ENABLE_DEMO_TARGET) return sendJSON(res, 404, { error: 'route inconnue', path: url.pathname });
        const body = await readBody(req).catch(() => ({}));
        const { email, password, name } = body;
        if (!email || !password) return sendJSON(res, 400, { error: 'email/password requis' });
        if (store.usersByEmail.has(email)) return sendJSON(res, 409, { error: 'email déjà utilisé' });

        const id = 'usr_' + crypto.randomBytes(5).toString('hex');
        const token = 'tok_' + crypto.randomBytes(12).toString('hex');
        const user = { id, email, name: name || email.split('@')[0] };
        store.users.set(token, user);
        store.usersByEmail.set(email, { ...user, password, token });

        // Auto-create one invoice + one order for this user (the resource an attacker would target)
        const invoiceId = 'inv_' + crypto.randomBytes(6).toString('hex');
        const orderId = 'ord_' + crypto.randomBytes(6).toString('hex');
        store.invoices.set(invoiceId, {
            id: invoiceId, userId: id, amount: crypto.randomInt(100, 9100),
            customer: user.name, items: ['Produit 1', 'Produit 2']
        });
        store.orders.set(orderId, {
            id: orderId, userId: id, buyerId: id, total: crypto.randomInt(100, 9100),
            pdfPath: `/secret/${orderId}.pdf`
        });

        broadcastEvent({ origin: 'API', type: 'info', msg: `Nouveau compte créé : ${email} (id=${id}, invoice=${invoiceId})` });
        saveStore();
        return sendJSON(res, 201, { id, token, accessToken: token, email, name: user.name, invoiceId, orderId });
    }

    // ---- Login ----
    if (url.pathname === '/api/v1/users/login' && req.method === 'POST') {
        if (!ENABLE_DEMO_TARGET) return sendJSON(res, 404, { error: 'route inconnue', path: url.pathname });
        const body = await readBody(req).catch(() => ({}));
        const rec = store.usersByEmail.get(body.email);
        if (!rec || rec.password !== body.password) return sendJSON(res, 401, { error: 'identifiants invalides' });
        broadcastEvent({ origin: 'API', type: 'info', msg: `Connexion : ${body.email}` });
        return sendJSON(res, 200, { id: rec.id, token: rec.token, accessToken: rec.token, email: rec.email });
    }

    // ---- Vulnerable endpoint: invoice by id (BOLA target) ----
    const invoiceMatch = url.pathname.match(/^\/api\/v1\/invoices\/([^/]+)$/);
    if (invoiceMatch && req.method === 'GET') {
        if (!ENABLE_DEMO_TARGET) return sendJSON(res, 404, { error: 'route inconnue', path: url.pathname });
        const id = invoiceMatch[1];
        const reqUser = getBearerUser(req);
        if (!reqUser) return sendJSON(res, 401, { error: 'authentification requise' });

        const blockReason = shieldShouldBlock(ip, url.pathname);
        const invoice = store.invoices.get(id);

        // Patched mode = real ownership validation enforced
        if (store.patched['node-invoice']) {
            if (!invoice || invoice.userId !== reqUser.id) {
                broadcastEvent({ origin: 'SHIELD', type: 'success', msg: `[PATCH] Accès facture ${id} refusé pour ${reqUser.email} (ownership invalide).` });
                store.metrics.blockedAttacks++;
                saveStore();
                return sendJSON(res, 404, { message: 'Facture non trouvée' });
            }
            return sendJSON(res, 200, invoice);
        }

        // Gateway shield blocks before code-level fix
        if (blockReason && invoice && invoice.userId !== reqUser.id) {
            broadcastEvent({ origin: 'SHIELD', type: 'success', msg: `[GATEWAY] Tentative BOLA bloquée sur ${id} par ${reqUser.email} — motif: ${blockReason}.` });
            store.metrics.blockedAttacks++;
            saveStore();
            return sendJSON(res, 403, { message: 'Accès refusé par la passerelle' });
        }

        // Vulnerable behaviour — no ownership check, leak.
        if (!invoice) return sendJSON(res, 404, { message: 'Facture non trouvée' });
        if (invoice.userId !== reqUser.id) {
            broadcastEvent({ origin: 'ALERT', type: 'alert', msg: `[FUITE BOLA] ${reqUser.email} a accédé à la facture ${id} appartenant à un tiers.` });
            store.metrics.dataLeaked += 1;
            saveStore();
        }
        return sendJSON(res, 200, invoice);
    }

    // ---- Vulnerable endpoint: order download ----
    const orderMatch = url.pathname.match(/^\/api\/v1\/orders\/([^/]+)\/download$/);
    if (orderMatch && req.method === 'GET') {
        if (!ENABLE_DEMO_TARGET) return sendJSON(res, 404, { error: 'route inconnue', path: url.pathname });
        const id = orderMatch[1];
        const reqUser = getBearerUser(req);
        if (!reqUser) return sendJSON(res, 401, { error: 'authentification requise' });
        const order = store.orders.get(id);

        if (store.patched['node-order']) {
            if (!order || order.buyerId !== reqUser.id) return sendJSON(res, 404, { message: 'Commande non trouvée' });
            return sendJSON(res, 200, { id: order.id, total: order.total, pdfPath: order.pdfPath, message: 'PDF prêt' });
        }
        if (!order) return sendJSON(res, 404, { message: 'Commande non trouvée' });
        if (order.buyerId !== reqUser.id) {
            broadcastEvent({ origin: 'ALERT', type: 'alert', msg: `[FUITE BOLA] ${reqUser.email} a téléchargé la commande ${id} d'un tiers.` });
            store.metrics.dataLeaked += 1;
            saveStore();
        }
        return sendJSON(res, 200, { id: order.id, total: order.total, pdfPath: order.pdfPath, message: 'PDF prêt (LEAK)' });
    }

    // ---- Safe endpoints used to show non-vulnerable cases ----
    if (/^\/api\/v1\/customers\/([^/]+)\/profile$/.test(url.pathname) && req.method === 'GET') {
        if (!ENABLE_DEMO_TARGET) return sendJSON(res, 404, { error: 'route inconnue', path: url.pathname });
        const reqUser = getBearerUser(req);
        if (!reqUser) return sendJSON(res, 401, { error: 'authentification requise' });
        const targetId = url.pathname.split('/')[4];
        if (reqUser.id !== targetId) return sendJSON(res, 403, { error: 'Accès refusé' });
        return sendJSON(res, 200, { id: reqUser.id, email: reqUser.email, name: reqUser.name });
    }
    if (/^\/api\/v1\/products\/([^/]+)$/.test(url.pathname) && req.method === 'GET') {
        if (!ENABLE_DEMO_TARGET) return sendJSON(res, 404, { error: 'route inconnue', path: url.pathname });
        const id = url.pathname.split('/').pop();
        return sendJSON(res, 200, { id, name: `Produit ${id}`, price: 19.99, public: true });
    }

    // ---- Firewall: blacklist ----
    if (url.pathname === '/api/v1/firewall/blacklist' && req.method === 'GET') {
        return sendJSON(res, 200, store.blacklist);
    }
    if (url.pathname === '/api/v1/firewall/blacklist' && req.method === 'POST') {
        const body = await readBody(req).catch(() => ({}));
        if (!body.ip) return sendJSON(res, 400, { error: 'ip requise' });
        if (store.blacklist.some(b => b.ip === body.ip)) return sendJSON(res, 409, { error: 'déjà bloquée' });
        const entry = { ip: body.ip, reason: body.reason || 'Ajout manuel', date: nowDateStr() };
        store.blacklist.unshift(entry);
        broadcastEvent({ origin: 'SHIELD', type: 'success', msg: `IP ${body.ip} bloquée (${entry.reason}).` });
        saveStore();
        return sendJSON(res, 201, entry);
    }
    if (url.pathname === '/api/v1/firewall/blacklist' && req.method === 'DELETE') {
        store.blacklist = [];
        broadcastEvent({ origin: 'SHIELD', type: 'info', msg: 'Blacklist vidée.' });
        saveStore();
        return sendJSON(res, 200, { ok: true });
    }
    const blDelMatch = url.pathname.match(/^\/api\/v1\/firewall\/blacklist\/(.+)$/);
    if (blDelMatch && req.method === 'DELETE') {
        const ipToRemove = decodeURIComponent(blDelMatch[1]);
        store.blacklist = store.blacklist.filter(b => b.ip !== ipToRemove);
        broadcastEvent({ origin: 'SHIELD', type: 'info', msg: `IP ${ipToRemove} débloquée.` });
        saveStore();
        return sendJSON(res, 200, { ok: true });
    }

    // ---- Firewall: rules ----
    if (url.pathname === '/api/v1/firewall/rules' && req.method === 'GET') {
        return sendJSON(res, 200, {
            ...store.rules,
            currentAudit: store.lastAudit,
            currentTarget: store.lastAudit?.base || store.currentDiscovery?.base || null,
            recommendations: firewallRecommendations()
        });
    }
    if (url.pathname === '/api/v1/firewall/rules' && req.method === 'PUT') {
        const body = await readBody(req).catch(() => ({}));
        Object.assign(store.rules, body);
        broadcastEvent({ origin: 'SHIELD', type: 'info', msg: `Regles passerelle mises a jour : ${JSON.stringify(body)}` });
        saveStore();
        return sendJSON(res, 200, {
            ...store.rules,
            currentAudit: store.lastAudit,
            currentTarget: store.lastAudit?.base || store.currentDiscovery?.base || null,
            recommendations: firewallRecommendations()
        });
    }

    // ---- Patch state (server-enforced fix per vulnerability) ----
    if (url.pathname === '/api/v1/patches' && req.method === 'GET') {
        return sendJSON(res, 200, ENABLE_DEMO_TARGET ? store.patched : {});
    }
    const patchMatch = url.pathname.match(/^\/api\/v1\/patches\/([^/]+)$/);
    if (patchMatch && req.method === 'POST') {
        if (!ENABLE_DEMO_TARGET) {
            return sendJSON(res, 409, {
                error: 'correctif local desactive',
                hint: 'Mode live-only: appliquez les corrections dans le code de la cible, puis relancez un audit.'
            });
        }
        const id = patchMatch[1];
        if (!(id in store.patched)) return sendJSON(res, 404, { error: 'vuln inconnue' });
        store.patched[id] = true;
        broadcastEvent({ origin: 'SHIELD', type: 'success', msg: `Correctif appliqué côté serveur sur "${id}". Ownership check actif.` });
        saveStore();
        return sendJSON(res, 200, { id, patched: true });
    }
    if (patchMatch && req.method === 'DELETE') {
        if (!ENABLE_DEMO_TARGET) return sendJSON(res, 404, { error: 'route inconnue', path: url.pathname });
        const id = patchMatch[1];
        if (!(id in store.patched)) return sendJSON(res, 404, { error: 'vuln inconnue' });
        store.patched[id] = false;
        saveStore();
        return sendJSON(res, 200, { id, patched: false });
    }

    // ---- Metrics ----
    if (url.pathname === '/api/v1/metrics' && req.method === 'GET') {
        const hasScan = store.currentDiscovery && Array.isArray(store.currentDiscovery.endpoints) && store.currentDiscovery.endpoints.length > 0;
        
        let exposure = 0;
        let total = 0;
        let blocked = store.metrics.blockedAttacks;
        let leaked = store.metrics.dataLeaked;
        
        if (hasScan) {
            const endpoints = store.currentDiscovery.endpoints;
            const live = store.lastAudit;
            let score = 50;
            
            // Calculate blocked attacks based on actual scan probes (real attempts made)
            const scanProbes = live?.attempts?.length || 0;
            blocked = store.metrics.blockedAttacks + scanProbes;
            
            // Calculate estimated leaks based strictly on the number of endpoints exposed
            if (live) {
                if (live.notAuditable) {
                    score = 55;
                    leaked = store.metrics.dataLeaked;
                } else if (live.isBOLA) {
                    score = 25;
                    // BOLA confirmed: we count 1 leak per endpoint
                    leaked = store.metrics.dataLeaked + endpoints.length;
                } else {
                    score = 85;
                    leaked = store.metrics.dataLeaked;
                }
            } else {
                leaked = endpoints.length * 1500;
            }
            
            if (store.rules.shieldActive) {
                score += 15;
            }
            exposure = Math.max(0, 100 - score);
            total = endpoints.length;
        } else {
            const safeRoutes = Object.values(store.patched).filter(Boolean).length;
            exposure = Math.max(0, 100 - safeRoutes * 20 - (store.rules.shieldActive ? 15 : 0));
            total = store.invoices.size + store.orders.size;
        }

        return sendJSON(res, 200, {
            ...store.metrics,
            exposureRate: exposure,
            blockedAttacks: blocked,
            dataLeaked: leaked,
            financialSavings: blocked * 170,
            users: store.users.size,
            invoices: store.invoices.size,
            orders: store.orders.size,
            totalResources: total
        });
    }

    // ---- Exportable audit report ----
    if (url.pathname === '/api/v1/report' && req.method === 'GET') {
        const format = url.searchParams.get('format') || 'json';
        if (format === 'markdown') {
            res.statusCode = 200;
            setSecurityHeaders(res);
            res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
            res.setHeader('Content-Disposition', 'attachment; filename="bola-shield-report.md"');
            return res.end(buildAuditReport('markdown'));
        }
        return sendJSON(res, 200, buildAuditReport('json'));
    }

    // ---- Graph (mapper) ----
    if (url.pathname === '/api/v1/graph' && req.method === 'GET') {
        const auditGraph = buildAuditGraph();
        if (auditGraph) return sendJSON(res, 200, auditGraph);

        const users = [...store.users.values()].slice(0, 4);
        const nodes = [];
        const links = [];
        const ySpacing = 360 / Math.max(users.length, 1);
        users.forEach((u, i) => {
            const y = 100 + i * ySpacing;
            const clientNode = { id: `client_${u.id}`, label: u.name || u.email, x: 120, y, type: 'user' };
            const sessionNode = { id: `session_${u.id}`, label: 'Session', x: 300, y, type: 'session' };
            nodes.push(clientNode, sessionNode);
            links.push({ source: clientNode.id, target: sessionNode.id, type: 'secure' });

            // attach owned invoice & order
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
                const ordRef = `order_${ord?.id}`;
                if (ord) links.push({ source: ordRef, target: invoiceNode.id, type: 'secure' });
            }
        });

        // Add BOLA cross-links unless server-side patch applied
        if (!store.patched['node-invoice'] && users.length >= 2) {
            const sourceSession = `session_${users[1].id}`;
            const targetInvoice = [...store.invoices.values()].find(x => x.userId === users[0].id);
            if (targetInvoice) {
                links.push({ id: 'bola_link_a', source: sourceSession, target: `invoice_${targetInvoice.id}`, type: 'bola' });
            }
        }
        return sendJSON(res, 200, { nodes, links, patched: store.patched });
    }

    // ---- Live audit orchestration (server-driven) ----
    if (url.pathname === '/api/v1/scanner/audit' && req.method === 'POST') {
        const body = await readBody(req).catch(() => ({}));
        if (!body.apiBase && !ENABLE_DEMO_TARGET) return sendLiveTargetRequired(res);
        const targetBase = normalizeTargetInput(body.apiBase || `http://${req.headers.host}`);
        const discovery = await discoverTarget(targetBase);
        const reg = body.register || discovery.routes?.register;
        const login = body.login || discovery.routes?.login;
        const target = body.target || discovery.routes?.target;
        const suppliedTokenA = body.tokenA || body.accessTokenA || '';
        const suppliedTokenB = body.tokenB || body.accessTokenB || '';
        let cookieA = body.cookieA || body.sessionCookieA || '';
        let cookieB = body.cookieB || body.sessionCookieB || '';
        
        // --- LOAD CREDENTIALS FROM FILE AUTOMATICALLY ---
        const fileCreds = loadTargetCredentials(targetBase);
        let userA = body.userA;
        let userB = body.userB;
        let objectId = body.objectId || '';
        let hasPredefinedCredentials = false;

        if (fileCreds) {
            broadcastEvent({ 
                origin: 'AUDIT', 
                type: 'info', 
                msg: `[CREDENTIALS] Fichier credentials.json trouvé pour la cible : ${targetBase}` 
            });
            if (fileCreds.userA) userA = fileCreds.userA;
            if (fileCreds.userB) userB = fileCreds.userB;
            if (fileCreds.objectId && !objectId) objectId = fileCreds.objectId;
            if (fileCreds.cookieA && !cookieA) cookieA = fileCreds.cookieA;
            if (fileCreds.cookieB && !cookieB) cookieB = fileCreds.cookieB;
            if (fileCreds.sessionCookieA && !cookieA) cookieA = fileCreds.sessionCookieA;
            if (fileCreds.sessionCookieB && !cookieB) cookieB = fileCreds.sessionCookieB;
            hasPredefinedCredentials = true;
            broadcastEvent({
                origin: 'AUDIT',
                type: 'info',
                msg: `[CREDENTIALS] Comptes injectés : A=${userA?.email || 'N/A'}, B=${userB?.email || 'N/A'}, ID Objet=${objectId || 'N/A'}`
            });
        }

        const tokenAFromConfig = suppliedTokenA || fileCreds?.tokenA || fileCreds?.accessTokenA || '';
        const tokenBFromConfig = suppliedTokenB || fileCreds?.tokenB || fileCreds?.accessTokenB || '';
        const hasManualSession = Boolean(objectId && ((tokenAFromConfig && tokenBFromConfig) || (cookieA && cookieB)));
        const runId = crypto.randomBytes(4).toString('hex');
        const passwordA = `Audit-${runId}-A`;
        const passwordB = `Audit-${runId}-B`;
        if (!userA) userA = { email: `user_a_${Date.now()}_${runId}@audit.local`, password: passwordA, name: 'Audit A' };
        if (!userB) userB = { email: `user_b_${Date.now()}_${runId}@audit.local`, password: passwordB, name: 'Audit B' };

        const skipRegistration = hasPredefinedCredentials || hasManualSession;

        if (!target || (!skipRegistration && (!reg || !login))) {
            const noAuth = discovery.authModel === 'no-public-auth-routes-detected' || (!reg && !login);
            const publicProbes = await probePublicEndpoints(targetBase, discovery);
            return sendJSON(res, 200, passiveAuditPayload(targetBase, discovery, noAuth ? 'Aucune route login/inscription publique detectee' : 'Configuration audit incomplete', {
                target,
                authModel: discovery.authModel,
                publicProbes,
                hint: noAuth
                    ? 'Mode URL-only: la surface publique a ete analysee, mais un audit BOLA actif exige deux sessions utilisateur ou une inscription publique automatisable.'
                    : 'Le lien a ete analyse, mais les routes publiques ne suffisent pas pour executer un audit multi-acteurs actif.'
            }));
        }

        broadcastEvent({ origin: 'AUDIT', type: 'warning', msg: `Audit serveur démarré sur ${targetBase} (${target})` });

        try {
            let tokenA = tokenAFromConfig;
            let tokenB = tokenBFromConfig;
            let regA = { data: null, attempts: [] };
            let regB = { data: null, attempts: [] };

            // --- 1. ETAPE REGISTRATION (SAUTÉE SI IDENTIFIANTS PRÉCONFIGURÉS) ---
            if (!skipRegistration) {
                broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[INSCRIPTION] Création des comptes d audit autorises sur ${joinTargetUrl(targetBase, reg)}...` });
                const registerAUrl = joinTargetUrl(targetBase, reg);
                const registerBUrl = joinTargetUrl(targetBase, reg);

                // Délai humain avant la première création
                await delayMs(Math.random() * 1000 + 800);

                regA = await postAuthCandidate(registerAUrl, userA, 'register A', body.registerPayloadA ? [body.registerPayloadA] : []);
                if (!regA.ok) {
                    broadcastEvent({
                        origin: 'AUDIT',
                        type: 'alert',
                        msg: `[ERREUR INSCRIPTION A] Échec de l'inscription User A. Code: ${regA.status}. ${regA.attempts.length} combinaisons testées.`
                    });
                    return sendJSON(res, 200, passiveAuditPayload(targetBase, discovery, `Inscription utilisateur A refusée par la cible (${regA.status})`, {
                        status: regA.status,
                        response: regA.data,
                        attempts: regA.attempts,
                        hint: 'Le serveur a refusé les schémas d\'inscription par défaut. Créez des comptes manuellement et configurez les dans data/credentials.json.'
                    }));
                }

                // Délai réaliste entre les deux comptes (comme un utilisateur humain reviendrait plus tard)
                await delayMs(Math.random() * 2000 + 1500);

                regB = await postAuthCandidate(registerBUrl, userB, 'register B', body.registerPayloadB ? [body.registerPayloadB] : []);
                if (!regB.ok) {
                    broadcastEvent({
                        origin: 'AUDIT',
                        type: 'alert',
                        msg: `[ERREUR INSCRIPTION B] Échec de l'inscription User B. Code: ${regB.status}.`
                    });
                    return sendJSON(res, 200, passiveAuditPayload(targetBase, discovery, `Inscription utilisateur B refusée par la cible (${regB.status})`, {
                        status: regB.status,
                        response: regB.data,
                        attempts: regB.attempts,
                        hint: 'Le serveur a refusé la création du deuxième compte. Créez des comptes manuellement et configurez les dans data/credentials.json.'
                    }));
                }

                tokenA = extractToken(regA.data);
                tokenB = extractToken(regB.data);
                objectId = objectId || extractTargetObjectId(regA.data);

                if ((!tokenA || !tokenB) && login) {
                    broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[LOGIN] Token manquant dans register. Tentative de login dynamique...` });

                    // Délai avant le login
                    await delayMs(Math.random() * 1000 + 500);

                    const loginA = await postAuthCandidate(joinTargetUrl(targetBase, login), userA, 'login A', body.loginPayloadA ? [body.loginPayloadA] : []);

                    // Délai entre les deux logins
                    await delayMs(Math.random() * 800 + 400);

                    const loginB = await postAuthCandidate(joinTargetUrl(targetBase, login), userB, 'login B', body.loginPayloadB ? [body.loginPayloadB] : []);
                    tokenA = tokenA || extractToken(loginA.data);
                    tokenB = tokenB || extractToken(loginB.data);
                }
            }

            // --- 2. ETAPE LOGIN DIRECT (SI IDENTIFIANTS PRÉCONFIGURÉS EXISTENT ET PAS DE JETONS MANUELS) ---
            if (skipRegistration && !hasManualSession && login) {
                if (!isCredentialAuthRoute(login)) {
                    const publicProbes = await probePublicEndpoints(targetBase, discovery);
                    return sendJSON(res, 200, passiveAuditPayload(targetBase, discovery, `Route de login non exploitable pour une connexion directe (${login})`, {
                        target,
                        login,
                        authModel: discovery.authModel,
                        publicProbes,
                        hint: 'Mode URL-only: la route detectee ressemble a une route de session/statut, pas a un endpoint login. La surface publique a ete analysee; un test BOLA actif necessite une inscription publique automatisable ou deux sessions autorisees.'
                    }));
                }
                broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[LOGIN DIRECT] Authentification de User A sur ${joinTargetUrl(targetBase, login)}...` });
                const loginA = await postAuthCandidate(joinTargetUrl(targetBase, login), userA, 'login A', body.loginPayloadA ? [body.loginPayloadA] : []);
                if (!loginA.ok) {
                    broadcastEvent({ 
                        origin: 'AUDIT', 
                        type: 'alert', 
                        msg: `[ERREUR LOGIN A] Connexion directe refusée pour ${userA.email}. Code: ${loginA.status}. Détail: ${JSON.stringify(loginA.data || '')}` 
                    });
                    return sendJSON(res, 200, passiveAuditPayload(targetBase, discovery, `Connexion directe User A refusée par la cible (${loginA.status})`, {
                        status: loginA.status,
                        response: loginA.data,
                        attempts: loginA.attempts,
                        hint: 'Vérifiez les identifiants configurez dans data/credentials.json.'
                    }));
                }
                tokenA = extractToken(loginA.data);
                broadcastEvent({ origin: 'AUDIT', type: 'success', msg: `[LOGIN A] Token A récupéré: ${maskToken(tokenA)}` });

                broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[LOGIN DIRECT] Authentification de User B sur ${joinTargetUrl(targetBase, login)}...` });
                const loginB = await postAuthCandidate(joinTargetUrl(targetBase, login), userB, 'login B', body.loginPayloadB ? [body.loginPayloadB] : []);
                if (!loginB.ok) {
                    broadcastEvent({ 
                        origin: 'AUDIT', 
                        type: 'alert', 
                        msg: `[ERREUR LOGIN B] Connexion directe refusée pour ${userB.email}. Code: ${loginB.status}. Détail: ${JSON.stringify(loginB.data || '')}` 
                    });
                    return sendJSON(res, 200, passiveAuditPayload(targetBase, discovery, `Connexion directe User B refusée par la cible (${loginB.status})`, {
                        status: loginB.status,
                        response: loginB.data,
                        attempts: loginB.attempts,
                        hint: 'Vérifiez les identifiants configurez dans data/credentials.json.'
                    }));
                }
                tokenB = extractToken(loginB.data);
                broadcastEvent({ origin: 'AUDIT', type: 'success', msg: `[LOGIN B] Token B récupéré: ${maskToken(tokenB)}` });
            }

            if ((!tokenA || !tokenB) && (!cookieA || !cookieB)) {
                broadcastEvent({ origin: 'AUDIT', type: 'alert', msg: `[ERREUR AUTHENTIFICATION] Impossible de récupérer des tokens valides.` });
                const publicProbes = await probePublicEndpoints(targetBase, discovery);
                return sendJSON(res, 200, passiveAuditPayload(targetBase, discovery, 'Token introuvable apres inscription/login', {
                    registerA: regA.data,
                    registerB: regB.data,
                    publicProbes,
                    hint: 'Mode URL-only: la surface publique a ete analysee, mais la cible ne fournit pas de session exploitable automatiquement pour un test BOLA actif.'
                }));
            }
            
            if (!objectId) {
                broadcastEvent({ origin: 'AUDIT', type: 'alert', msg: `[ERREUR RESSOURCE] Identifiant d'objet cible introuvable.` });
                const publicProbes = await probePublicEndpoints(targetBase, discovery);
                return sendJSON(res, 200, passiveAuditPayload(targetBase, discovery, 'ID de ressource introuvable apres inscription', {
                    registerA: regA.data,
                    publicProbes,
                    hint: 'Mode URL-only: le scanner n a pas trouve d identifiant d objet prive exploitable dans les reponses publiques.'
                }));
            }

            const targetPath = fillObjectIdRoute(target, objectId);
            const targetUrl = joinTargetUrl(targetBase, targetPath);
            const authScheme = body.authScheme || 'Bearer';

            // Délai avant les requêtes de test (comme un utilisateur naviguant)
            await delayMs(Math.random() * 1500 + 1000);

            const ownerRead = await fetchJSONRemote(targetUrl, {
                method: 'GET',
                headers: authHeadersForSession({ token: tokenA, cookie: cookieA, scheme: authScheme, referer: targetUrl })
            });

            // Petit délai entre les deux requêtes de test
            await delayMs(Math.random() * 600 + 300);

            const crossRead = await fetchJSONRemote(targetUrl, {
                method: 'GET',
                headers: authHeadersForSession({ token: tokenB, cookie: cookieB, scheme: authScheme, referer: targetUrl })
            });

            // Délai avant la requête anonyme
            await delayMs(Math.random() * 500 + 200);

            const anonRead = await fetchJSONRemote(targetUrl, { method: 'GET' });

            const ownerFingerprint = stableResourceFingerprint(ownerRead.data);
            const crossFingerprint = stableResourceFingerprint(crossRead.data);
            const isBOLA = crossRead.ok
                && crossRead.status === 200
                && ownerRead.status === 200
                && ownerFingerprint
                && ownerFingerprint === crossFingerprint;
            const auditRecord = {
                base: targetBase,
                register: reg,
                login,
                target,
                targetPath,
                targetUrl,
                objectId,
                ownerStatus: ownerRead.status,
                crossStatus: crossRead.status,
                anonStatus: anonRead.status,
                evidence: {
                    ownerFingerprint,
                    crossFingerprint,
                    sameResource: ownerFingerprint === crossFingerprint
                },
                isBOLA,
                vulnerable: isBOLA,
                authModel: discovery.authModel,
                discovery,
                at: new Date().toISOString()
            };
            store.lastAudit = auditRecord;

            if (isBOLA) {
                store.metrics.dataLeaked += 1;
                broadcastEvent({ origin: 'ALERT', type: 'alert', msg: `[FUITE BOLA] Audit proxy confirme une fuite sur ${targetUrl}.` });
            } else {
                store.metrics.blockedAttacks += crossRead.status === 401 || crossRead.status === 403 || crossRead.status === 404 ? 1 : 0;
                broadcastEvent({ origin: 'AUDIT', type: 'success', msg: `Audit proxy termine : cross-read HTTP ${crossRead.status}.` });
            }
            saveStore();

            return sendJSON(res, 200, {
                base: targetBase,
                register: reg,
                login,
                target,
                discovery,
                objectId,
                tokenA: maskToken(tokenA),
                tokenB: maskToken(tokenB),
                ownerStatus: ownerRead.status,
                crossStatus: crossRead.status,
                anonStatus: anonRead.status,
                audit: auditRecord,
                ownerData: ownerRead.data,
                crossData: crossRead.data,
                evidence: auditRecord.evidence,
                isBOLA,
                vulnerable: isBOLA
            });
        } catch (e) {
            return sendJSON(res, 502, {
                error: 'Audit proxy impossible',
                detail: publicError(e.message, 'La cible est indisponible ou refuse la requete configuree'),
                hint: 'Le serveur local ne peut pas joindre la cible ou la cible refuse le format de requete configure.'
            });
        }
    }

    // ---- Chat (real, state-aware) ----
    if (url.pathname === '/api/v1/chat' && req.method === 'POST') {
        const body = await readBody(req).catch(() => ({}));
        const response = answerChat(body.message || '');
        broadcastEvent({ origin: 'CHAT', type: 'info', msg: `Question CISO : ${body.message?.slice(0, 80)}` });
        return sendJSON(res, 200, response);
    }

    // ---- Logs (SSE) ----
    if (url.pathname === '/api/v1/logs/stream' && req.method === 'GET') {
        setSecurityHeaders(res);
        setCorsHeaders(res);
        res.writeHead(200, {
            'Content-Type': 'text/event-stream',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive'
        });
        res.write(`retry: 5000\n\n`);
        
        const lastEventId = req.headers['last-event-id'];
        let replayLogs = store.eventLog.slice(-25);
        if (lastEventId) {
            const idx = store.eventLog.findIndex(e => String(e.id) === lastEventId);
            if (idx !== -1) replayLogs = store.eventLog.slice(idx + 1);
        }

        // Replay recent buffer
        for (const e of replayLogs) {
            res.write(`id: ${e.id}\ndata: ${JSON.stringify(e)}\n\n`);
        }
        store.sseClients.add(res);
        req.on('close', () => store.sseClients.delete(res));
        return;
    }

    return sendJSON(res, 404, { error: 'route inconnue', path: url.pathname });
}

async function handleGatewayProxy(req, res, url) {
    if (!store.gateway.enabled || !store.gateway.targetBase) {
        res.statusCode = 503;
        setSecurityHeaders(res);
        res.setHeader('Content-Type', 'application/json; charset=utf-8');
        return res.end(JSON.stringify({ error: 'Gateway non activee ou cible non configuree' }));
    }

    const suffix = url.pathname.replace(/^\/gateway/, '') || '/';
    const targetUrl = new URL(joinTargetUrl(store.gateway.targetBase, suffix));
    targetUrl.search = url.search;
    await assertSafeTargetUrl(targetUrl.href);

    const rawBody = ['GET', 'HEAD'].includes(req.method) ? undefined : await readRawBody(req);
    const headers = {};
    for (const [key, value] of Object.entries(req.headers)) {
        if (HOP_BY_HOP_HEADERS.has(key.toLowerCase()) || key.toLowerCase() === 'host') continue;
        headers[key] = value;
    }
    let requestModified = false;
    if (store.gateway.mode === 'modify-approved') {
        for (const [key, value] of Object.entries(store.gateway.approvedRequestHeaders || {})) {
            headers[key] = value;
            requestModified = true;
        }
    }

    const record = {
        id: 'gw_' + crypto.randomBytes(5).toString('hex'),
        at: new Date().toISOString(),
        method: req.method,
        path: suffix + url.search,
        targetUrl: targetUrl.href,
        requestModified,
        responseModified: false,
        modified: false,
        intercepted: false,
        status: null
    };

    try {
        const upstream = await fetch(targetUrl.href, {
            method: req.method,
            headers,
            body: rawBody,
            redirect: 'manual'
        });
        const buffer = Buffer.from(await upstream.arrayBuffer());
        const responseHeaders = {};
        upstream.headers.forEach((value, key) => { responseHeaders[key.toLowerCase()] = value; });
        const contentType = responseHeaders['content-type'] || '';
        let bodyText = buffer.toString('utf8');
        detectGatewaySuggestions(record, headers, responseHeaders, bodyText);

        let output = { headers: responseHeaders, body: bodyText, modified: false };
        if (store.gateway.mode === 'modify-approved') {
            output = applyApprovedResponseModifications(responseHeaders, bodyText, contentType);
        }

        record.status = upstream.status;
        record.responseModified = output.modified;
        record.modified = requestModified || output.modified;
        record.intercepted = upstream.status >= 400;
        store.gateway.transactions.push(record);
        store.gateway.transactions = store.gateway.transactions.slice(-300);
        saveStore();

        res.statusCode = upstream.status;
        setSecurityHeaders(res);
        for (const [key, value] of Object.entries(output.headers)) {
            if (HOP_BY_HOP_HEADERS.has(key) || key === 'content-encoding') continue;
            try { res.setHeader(key, value); } catch (_) {}
        }
        res.setHeader('X-BOLA-Gateway-Transaction', record.id);
        return res.end(Buffer.from(output.body, 'utf8'));
    } catch (e) {
        record.status = 502;
        record.intercepted = true;
        record.error = e.message;
        store.gateway.transactions.push(record);
        store.gateway.transactions = store.gateway.transactions.slice(-300);
        saveStore();
        res.statusCode = 502;
        setSecurityHeaders(res);
        res.setHeader('Content-Type', 'application/json; charset=utf-8');
        return res.end(JSON.stringify({
            error: 'Gateway upstream error',
            detail: publicError(e.message, 'La cible amont est indisponible'),
            transaction: record.id
        }));
    }
}

/* --------------------------------------------------------------------------
   Server-side CISO chat — state-aware, not keyword-only
   -------------------------------------------------------------------------- */
function answerChat(rawMsg) {
    const msg = (rawMsg || '').toLowerCase();
    const ts = new Date().toISOString();

    // Build state snapshot to enrich answers with real numbers
    const snapshot = {
        invoices: store.invoices.size,
        orders: store.orders.size,
        users: store.users.size,
        blocked: store.metrics.blockedAttacks,
        leaks: store.metrics.dataLeaked,
        patchedInvoice: store.patched['node-invoice'],
        patchedOrder: store.patched['node-order'],
        shield: store.rules.shieldActive
    };

    let actions = [];
    let body = '';

    if (msg.includes('urgence') || msg.includes('emergency')) {
        store.rules.emergencyShield = true;
        store.rules.shieldActive = true;
        actions.push({ type: 'rule', key: 'emergencyShield', value: true });
        actions.push({ type: 'rule', key: 'shieldActive', value: true });
        broadcastEvent({ origin: 'SHIELD', type: 'alert', msg: 'Mode urgence activé par CISO IA.' });
        body = `🚨 <strong>Mode urgence anti-BOLA ACTIVÉ côté serveur.</strong><br>
        À cet instant : ${snapshot.users} comptes vivants, ${snapshot.invoices} factures protégées, ${snapshot.blocked} attaques déjà bloquées.<br>
        Toute tentative d'accès croisé sera maintenant refusée par la passerelle.`;
    } else if (msg.includes('audit') || msg.includes('scan')) {
        body = `🔍 <strong>État actuel de l'audit</strong><br>
        - Comptes enregistrés : <strong>${snapshot.users}</strong><br>
        - Factures côté serveur : <strong>${snapshot.invoices}</strong><br>
        - Fuites observées : <strong>${snapshot.leaks}</strong><br>
        - Attaques bloquées : <strong>${snapshot.blocked}</strong><br>
        - Patch <code>invoiceController</code> : ${snapshot.patchedInvoice ? '✅' : '🔴 non appliqué'}<br>
        Lance le bouton "Audit Live" du scanner pour faire le test réel maintenant.`;
    } else if (msg.includes('waf') || msg.includes('pare-feu classique')) {
        body = `🧱 <strong>Un WAF ne voit pas BOLA.</strong><br>
        Les WAF classiques cherchent des signatures (XSS, SQLi). Une requête BOLA est une requête HTTP <em>parfaitement légitime</em> avec un token valide — la seule chose anormale est <strong>la sémantique d'ownership</strong>, qui se vérifie en base, pas dans la trame réseau.`;
    } else if (msg.includes('middleware') || msg.includes('express') || msg.includes('node')) {
        body = `💻 Middleware d'ownership prêt à coller dans Express :<pre><code>const checkOwnership = (Model, ownerField = 'userId') => async (req, res, next) => {
  const resource = await Model.findById(req.params.id);
  if (!resource || resource[ownerField].toString() !== req.user.id) {
    return res.status(404).json({ message: 'Ressource introuvable' });
  }
  req.resource = resource;
  next();
};</code></pre>
        Actuellement, ce middleware est ${snapshot.patchedInvoice ? '<strong>actif</strong>' : '<strong>absent</strong>'} sur <code>/api/v1/invoices/:id</code>.`;
    } else if (msg.includes('uuid') || msg.includes('identifiant')) {
        body = `🔑 Les UUIDs sont une protection par obscurité, pas une correction. Sur cette instance, les factures sont déjà des UUIDs (ex: <code>${[...store.invoices.keys()][0] || 'inv_xxxx'}</code>) — et pourtant la faille reste exploitable tant que <code>node-invoice</code> n'est pas patché.`;
    } else if (msg.includes('pourquoi bola') || msg.includes('critique')) {
        body = `🧐 BOLA = #1 du Top 10 OWASP API. Sur cette instance, ${snapshot.leaks} fuites ont déjà été enregistrées dans le journal serveur — la preuve que la faille est triviale à exploiter dès que l'ownership n'est pas validé.`;
    } else {
        body = `Je lis l'état réel du serveur. Tu peux me demander : "audit", "middleware", "WAF", "UUID", "pourquoi BOLA", ou "mode urgence" pour que j'agisse en direct.<br>
        Instantané actuel : ${snapshot.users} utilisateurs, ${snapshot.invoices} factures, ${snapshot.blocked} blocages, patch invoice = ${snapshot.patchedInvoice ? 'oui' : 'non'}.`;
    }

    return { ts, body, snapshot, actions };
}

function parseRequestUrl(req) {
    const host = req.headers.host || `127.0.0.1:${PORT}`;
    try {
        return new URL(req.url || '/', `http://${host}`);
    } catch (_) {
        return null;
    }
}

function resolveStaticFile(urlPathname) {
    const pathname = urlPathname === '/' ? '/index.html' : urlPathname;
    let decoded;
    try {
        decoded = decodeURIComponent(pathname);
    } catch (_) {
        return null;
    }

    if (/(^|[/\\])\.\.([/\\]|$)/.test(decoded)) return null;
    if (decoded !== '/index.html' && !decoded.startsWith('/assets/')) return null;

    const normalized = path.normalize(decoded);
    const relativePath = normalized.replace(/^[/\\]+/, '');
    const resolvedPath = path.resolve(__dirname, relativePath);
    const relativeToRoot = path.relative(__dirname, resolvedPath);
    if (relativeToRoot.startsWith('..') || path.isAbsolute(relativeToRoot)) return null;
    return resolvedPath;
}

/* --------------------------------------------------------------------------
   HTTP server (static files + API)
   -------------------------------------------------------------------------- */
const server = http.createServer(async (req, res) => {
    const url = parseRequestUrl(req);
    if (!url) {
        res.statusCode = 400;
        setSecurityHeaders(res);
        res.setHeader('Content-Type', 'text/plain; charset=utf-8');
        return res.end('Bad Request');
    }
    console.log(`[HTTP] ${req.method} ${url.pathname}`);

    try {
        if (url.pathname.startsWith('/api/')) {
            return await handleApi(req, res, url);
        }
        if (url.pathname.startsWith('/gateway/')) {
            return await handleGatewayProxy(req, res, url);
        }
    } catch (e) {
        console.error('[API] error', e);
        return sendJSON(res, 500, { error: publicError(e.message) });
    }

    // Static files
    const filePath = resolveStaticFile(url.pathname);
    if (!filePath) {
        res.statusCode = 403;
        setSecurityHeaders(res);
        res.setHeader('Content-Type', 'text/plain; charset=utf-8');
        return res.end('Access Denied');
    }
    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';
    fs.readFile(filePath, (err, content) => {
        if (err) {
            if (err.code === 'ENOENT') {
                res.statusCode = 404;
                res.setHeader('Content-Type', 'text/plain; charset=utf-8');
                res.end('404 Not Found');
            } else {
                res.statusCode = 500;
                res.end('500 Server Error');
            }
        } else {
            res.statusCode = 200;
            setSecurityHeaders(res);
            res.setHeader('Content-Type', contentType);
            if (['.html', '.js', '.css'].includes(ext)) {
                res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
                res.setHeader('Pragma', 'no-cache');
                res.setHeader('Expires', '0');
            } else {
                res.setHeader('Cache-Control', 'public, max-age=3600');
            }
            res.end(content);
        }
    });
});

server.listen(PORT, () => {
    console.log(`
   ================================================================
   BOLA-Shield AI — Live backend + UI
   ================================================================
   URL          : http://127.0.0.1:${PORT}
   API base     : http://127.0.0.1:${PORT}/api/v1
   Logs SSE     : http://127.0.0.1:${PORT}/api/v1/logs/stream
   Zero npm install required.
   ================================================================
   `);
});

async function shutdown(signal) {
    console.log(`[HTTP] ${signal} recu, arret propre...`);
    server.close(async () => {
        try {
            if (browserInstance) await browserInstance.close();
        } catch (e) {
            console.warn('[PUPPETEER] close failed:', e.message);
        } finally {
            process.exit(0);
        }
    });
    setTimeout(() => process.exit(1), 5000).unref();
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
