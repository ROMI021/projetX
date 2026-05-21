/* ======================================================================
   BOLA-Shield — Store & Persistence extracted from server.js
   ====================================================================== */

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DATA_DIR = path.join(__dirname, '..', 'data');
const STATE_FILE = path.join(DATA_DIR, 'state.json');

export const store = {
    users: new Map(),
    usersByEmail: new Map(),
    invoices: new Map(),
    orders: new Map(),
    blacklist: [],
    rules: {
        shieldActive: true,
        activeScan: true,
        tokenization: false,
        vpnBlock: true,
        emergencyShield: false
    },
    patched: {
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
    scanCounter: new Map(),
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

export function saveStore() {
    try {
        fs.mkdirSync(DATA_DIR, { recursive: true });
        fs.writeFileSync(STATE_FILE, JSON.stringify(persistedSnapshot(), null, 2), 'utf8');
    } catch (e) {
        console.warn('[STATE] save failed:', e.message);
    }
}

export function loadStore() {
    try {
        if (!fs.existsSync(STATE_FILE)) return;
        const raw = fs.readFileSync(STATE_FILE, 'utf8');
        const parsed = JSON.parse(raw);
        if (parsed.blacklist) store.blacklist = parsed.blacklist;
        if (parsed.rules) Object.assign(store.rules, parsed.rules);
        if (parsed.patched) store.patched = parsed.patched;
        if (parsed.metrics) store.metrics = parsed.metrics;
        if (parsed.lastAudit) store.lastAudit = parsed.lastAudit;
        if (parsed.currentDiscovery) store.currentDiscovery = parsed.currentDiscovery;
        if (parsed.gateway) store.gateway = parsed.gateway;
    } catch (e) {
        console.warn('[STATE] load failed:', e.message);
    }
}

export function broadcastEvent(event) {
  event.id = Date.now();
  if (!event.origin) event.origin = 'SYSTEM';
  
  if (event.origin === 'AUDIT' && event.type === 'info') {
     console.log(`\x1b[90m${new Date(event.id).toLocaleTimeString()} [${event.origin}] ${event.msg}\x1b[0m`);
  } else if (event.type === 'error' || event.type === 'alert') {
     console.log(`\x1b[31m${new Date(event.id).toLocaleTimeString()} [${event.origin}] ${event.msg}\x1b[0m`);
  } else {
     console.log(`\x1b[36m${new Date(event.id).toLocaleTimeString()} [${event.origin}] ${event.msg}\x1b[0m`);
  }

  store.eventLog.push(event);
  if (store.eventLog.length > 500) store.eventLog.shift();
  const payload = `data: ${JSON.stringify(event)}\n\n`;
  for (const client of [...store.sseClients]) {
    try {
      client.write(payload);
    } catch (e) {
      store.sseClients.delete(client);
    }
  }
}

export function seed() {
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

// Exports: store, saveStore, loadStore, seed
