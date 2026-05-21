/* ==========================================================================
   BOLA-Shield AI — Live Firewall Module
   Blacklist + rules are persisted server-side; toggles call the API.
   ========================================================================== */

import { state, savePersistedState } from './state.js';
import { logToConsole, showToast } from '../utils/helpers.js';

const apiBase = () => window.location.origin;

const RULE_IDS = {
    'toggle-active-scan': 'activeScan',
    'toggle-tokenization': 'tokenization',
    'toggle-vpn-block': 'vpnBlock',
    'toggle-emergency-shield': 'emergencyShield'
};

function escapeHTML(value) {
    return String(value ?? '').replace(/[&<>"']/g, char => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    }[char]));
}

export function initFirewall() {
    const btnAdd = document.getElementById('btn-add-blacklist');
    const btnClear = document.getElementById('btn-clear-blacklist');
    const ipInput = document.getElementById('blacklist-ip-input');
    const gatewayToggle = document.getElementById('toggle-gateway-barrier');
    const gatewayTarget = document.getElementById('gateway-target-input');
    const gatewayMode = document.getElementById('gateway-mode-select');
    const btnGateway = document.getElementById('btn-save-gateway');
    const gatewayUrl = document.getElementById('gateway-local-url');

    btnAdd?.addEventListener('click', () => {
        const ip = ipInput?.value.trim();
        if (ip) {
            blacklistIP(ip, 'Ajout manuel par l\'administrateur');
            if (ipInput) ipInput.value = '';
        }
    });

    btnClear?.addEventListener('click', async () => {
        try {
            const res = await fetch(`${apiBase()}/api/v1/firewall/blacklist`, { method: 'DELETE' });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            state.blacklist = [];
            renderBlacklistTable();
            showToast('🗑️ Blacklist vidée');
            logToConsole('SHIELD', 'Blacklist vidée côté serveur.', 'info');
            document.dispatchEvent(new CustomEvent('bola-score-update'));
        } catch (e) {
            showToast('❌ ' + e.message);
        }
    });

    Object.entries(RULE_IDS).forEach(([elId, key]) => {
        const el = document.getElementById(elId);
        if (!el) return;
        el.addEventListener('change', async () => {
            try {
                const res = await fetch(`${apiBase()}/api/v1/firewall/rules`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ [key]: el.checked })
                });
                if (!res.ok) throw new Error(`HTTP ${res.status}`);
                document.dispatchEvent(new CustomEvent('bola-score-update'));
                savePersistedState();

                const label = el.closest('.toggle-card')?.querySelector('.toggle-title')?.innerText;
                if (el.checked) {
                    showToast(`✅ ${label}`);
                    logToConsole('SHIELD', `Règle activée serveur : ${label}`, 'success');
                } else {
                    showToast(`ℹ️ ${label} désactivée`);
                    logToConsole('SYSTEM', `Règle désactivée serveur : ${label}`, 'warning');
                }
            } catch (e) {
                showToast('❌ Règle non sauvegardée : ' + e.message);
                el.checked = !el.checked;
            }
        });
    });

    btnGateway?.addEventListener('click', async () => {
        try {
            const res = await fetch(`${apiBase()}/api/v1/gateway/config`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    enabled: gatewayToggle?.checked || false,
                    targetBase: gatewayTarget?.value || '',
                    mode: gatewayMode?.value || 'observe'
                })
            });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const config = await res.json();
            applyGatewayToUI(config);
            showToast('Gateway sauvegardee');
            logToConsole('GATEWAY', `Barrier ${config.enabled ? 'activee' : 'desactivee'} vers ${config.targetBase || 'aucune cible'} en mode ${config.mode}.`, 'success');
        } catch (e) {
            showToast('Gateway non sauvegardee : ' + e.message);
        }
    });

    syncFromServer();
}

async function syncFromServer() {
    try {
        const [rulesRes, listRes] = await Promise.all([
            fetch(`${apiBase()}/api/v1/firewall/rules`),
            fetch(`${apiBase()}/api/v1/firewall/blacklist`)
        ]);
        if (rulesRes.ok) {
            const rules = await rulesRes.json();
            applyRulesToUI(rules);
            if (rules.currentTarget) {
                logToConsole('SHIELD', `Regles synchronisees avec la cible actuelle : ${rules.currentTarget}`, 'info');
            }
            if (Array.isArray(rules.recommendations)) {
                rules.recommendations.slice(0, 3).forEach(r => logToConsole('SHIELD', r, 'info'));
            }
        }
        const gatewayRes = await fetch(`${apiBase()}/api/v1/gateway/config`);
        if (gatewayRes.ok) applyGatewayToUI(await gatewayRes.json());
        if (listRes.ok) {
            state.blacklist = await listRes.json();
            renderBlacklistTable();
        }
    } catch (e) {
        logToConsole('SYSTEM', `Sync firewall hors-ligne : ${e.message}`, 'warning');
    }
}

function applyGatewayToUI(config) {
    const gatewayToggle = document.getElementById('toggle-gateway-barrier');
    const gatewayTarget = document.getElementById('gateway-target-input');
    const gatewayMode = document.getElementById('gateway-mode-select');
    const gatewayUrl = document.getElementById('gateway-local-url');
    if (gatewayToggle) gatewayToggle.checked = Boolean(config.enabled);
    if (gatewayTarget) gatewayTarget.value = config.targetBase || '';
    if (gatewayMode) gatewayMode.value = config.mode || 'observe';
    if (gatewayUrl) gatewayUrl.innerText = `${apiBase()}/gateway/*`;
}

function applyRulesToUI(rules) {
    Object.entries(RULE_IDS).forEach(([elId, key]) => {
        const el = document.getElementById(elId);
        if (el && typeof rules[key] === 'boolean') el.checked = rules[key];
    });
    state.shieldActive = rules.shieldActive !== false;
}

export async function blacklistIP(ip, reason) {
    try {
        const res = await fetch(`${apiBase()}/api/v1/firewall/blacklist`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, reason })
        });
        if (res.status === 409) { showToast('ℹ️ IP déjà bloquée'); return; }
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const entry = await res.json();
        state.blacklist.unshift(entry);
        renderBlacklistTable();
        showToast(`🚫 IP ${ip} bloquée`);
        logToConsole('SHIELD', `[BLACKLIST] ${ip} — ${reason}`, 'success');
        document.dispatchEvent(new CustomEvent('bola-score-update'));
    } catch (e) {
        showToast('❌ ' + e.message);
    }
}

export function renderBlacklistTable() {
    const tbody = document.getElementById('blacklist-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';

    if (!state.blacklist.length) {
        tbody.innerHTML = `<tr><td colspan="4" class="text-center py-4 text-secondary">Aucune adresse IP bloquée pour le moment.</td></tr>`;
        return;
    }

    state.blacklist.forEach(item => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td class="font-semibold text-danger">${escapeHTML(item.ip)}</td>
            <td>${escapeHTML(item.reason)}</td>
            <td class="text-muted font-semibold">${escapeHTML(item.date)}</td>
            <td><button class="cyber-btn btn-secondary text-sm py-1 px-2 btn-deblock">Débloquer</button></td>
        `;
        row.querySelector('.btn-deblock')?.addEventListener('click', async () => {
            try {
                const res = await fetch(`${apiBase()}/api/v1/firewall/blacklist/${encodeURIComponent(item.ip)}`, { method: 'DELETE' });
                if (!res.ok) throw new Error(`HTTP ${res.status}`);
                state.blacklist = state.blacklist.filter(b => b.ip !== item.ip);
                renderBlacklistTable();
                showToast(`🔓 IP ${item.ip} débloquée`);
                logToConsole('SHIELD', `IP ${item.ip} retirée serveur.`, 'info');
                document.dispatchEvent(new CustomEvent('bola-score-update'));
            } catch (e) { showToast('❌ ' + e.message); }
        });
        tbody.appendChild(row);
    });
}
