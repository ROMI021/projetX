/* ==========================================================================
   BOLA-Shield AI — Live Backend (Static Files + REST API + SSE)
   Pure Node.js, zero dependency.
   ========================================================================== */

import http from 'http';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import { store, loadStore, saveStore, seed } from './lib/store.js';
import { makeHandleApi } from './lib/routes.js';
import * as utils from './lib/utils.js';

loadStore();
if (store.invoices.size === 0 && store.orders.size === 0) seed();
const {
    HOP_BY_HOP_HEADERS,
    MIME_TYPES,
    assertSafeTargetUrl,
    detectGatewaySuggestions,
    applyApprovedResponseModifications,
    setSecurityHeaders,
    sendJSON,
    publicError,
    readRawBody,
    setCorsHeaders,
    joinTargetUrl
} = utils;
const ENABLE_DEMO_TARGET = utils.ENABLE_DEMO_TARGET;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PORT = Number(process.env.PORT || 8080);
let handleApi = null;

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
// Build context and wire external route handler
const _context = {
    ...utils,
    store,
    saveStore,
    ENABLE_DEMO_TARGET,
    crypto,
    answerChat
};
handleApi = makeHandleApi(_context);
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
            await utils.closeBrowser();
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
