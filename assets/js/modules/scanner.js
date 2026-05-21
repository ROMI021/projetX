/* ==========================================================================
   BOLA-Shield AI - Live Multi-Actor Scanner
   Browser calls the local backend only; backend proxies the target site.
   ========================================================================== */

import { state, savePersistedState } from './state.js';
import { logToConsole, showToast } from '../utils/helpers.js';

const localApiBase = () => window.location.origin;

function normalizeUrlInput(input) {
    let raw = String(input || '').trim()
        .replace(/[\u200B-\u200D\uFEFF]/g, '')
        .replace(/^<|>$/g, '')
        .replace(/^["']|["']$/g, '')
        .trim();
    raw = raw.split(/\s+/)[0];
    if (!raw) return '';
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) raw = `https://${raw}`;
    const url = new URL(raw);
    url.hash = '';
    const tracking = [/^utm_/i, /^srsltid$/i, /^fbclid$/i, /^gclid$/i, /^gbraid$/i, /^wbraid$/i, /^mc_cid$/i, /^mc_eid$/i, /^igshid$/i, /^msclkid$/i, /^yclid$/i, /^ref$/i, /^ref_src$/i];
    [...url.searchParams.keys()].forEach(key => {
        if (tracking.some(pattern => pattern.test(key))) url.searchParams.delete(key);
    });
    return url.toString().replace(/\/$/, '');
}

async function fetchJSON(url, options = {}) {
    const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
    const res = await fetch(url, { ...options, headers });
    const text = await res.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch (_) { data = text; }
    return { ok: res.ok, status: res.status, data };
}

function getScannerConfig() {
    const baseInput = document.getElementById('live-api-base');
    const config = { apiBase: normalizeUrlInput(baseInput?.value || '') };
    if (baseInput) baseInput.value = config.apiBase;
    const register = document.getElementById('live-api-register')?.value.trim();
    const login = document.getElementById('live-api-login')?.value.trim();
    const target = document.getElementById('live-api-target')?.value.trim();
    const objectId = document.getElementById('live-api-object-id')?.value.trim();
    const tokenA = document.getElementById('live-api-token-a')?.value.trim();
    const tokenB = document.getElementById('live-api-token-b')?.value.trim();
    const authScheme = document.getElementById('live-api-auth-scheme')?.value.trim();
    if (register) config.register = register;
    if (login) config.login = login;
    if (target) config.target = target;
    if (objectId) config.objectId = objectId;
    if (tokenA) config.tokenA = tokenA;
    if (tokenB) config.tokenB = tokenB;
    if (authScheme) config.authScheme = authScheme;
    addJSONField(config, 'userA', 'live-api-user-a');
    addJSONField(config, 'userB', 'live-api-user-b');
    addJSONField(config, 'registerPayloadA', 'live-api-register-payload-a');
    addJSONField(config, 'registerPayloadB', 'live-api-register-payload-b');
    addJSONField(config, 'loginPayloadA', 'live-api-login-payload-a');
    addJSONField(config, 'loginPayloadB', 'live-api-login-payload-b');
    return config;
}

function addJSONField(config, key, elementId) {
    const raw = document.getElementById(elementId)?.value.trim();
    if (!raw) return;
    try {
        config[key] = JSON.parse(raw);
    } catch (_) {
        throw new Error(`JSON invalide dans ${elementId}`);
    }
}

function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.innerText = value;
}

function escapeHTML(value) {
    return String(value ?? '').replace(/[&<>"']/g, char => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    }[char]));
}

function resetBotFeed(message = 'Initialisation du bot de scan...') {
    const box = document.getElementById('scan-bot-feed-list');
    if (!box) return;
    box.innerHTML = '';
    appendBotStep(message, 'info');
}

function appendBotStep(message, type = 'info') {
    const list = document.getElementById('scan-bot-feed-list');
    const container = document.getElementById('scan-bot-feed');
    if (!list) return;
    const now = new Date();
    const time = now.toTimeString().split(' ')[0];
    const entry = document.createElement('div');
    entry.className = `scan-bot-entry ${type}`;
    entry.innerHTML = `<span class="bot-time">${time}</span><span>${escapeHTML(message)}</span>`;
    list.appendChild(entry);
    while (list.children.length > 80) list.removeChild(list.firstChild);
    if (container) {
        container.scrollTop = container.scrollHeight;
    }
}

function appendDiscoveryEvidence(discovery) {
    if (!discovery) return;
    appendBotStep(`Mode auth detecte: ${discovery.authModel || 'inconnu'} | confiance: ${discovery.confidence || 'n/a'}`, 'info');
    const routes = discovery.routes || {};
    if (routes.register || routes.login || routes.target) {
        appendBotStep(`Routes candidates: register=${routes.register || 'introuvable'}, login=${routes.login || 'introuvable'}, target=${routes.target || 'introuvable'}`, 'success');
    }
    if (Array.isArray(discovery.evidence)) {
        discovery.evidence.slice(0, 8).forEach(item => {
            const status = item.status ? `HTTP ${item.status}` : (item.error || 'inspecte');
            appendBotStep(`Preuve inspectee: ${item.source} -> ${status}`, item.error ? 'warning' : 'info');
        });
    }
}

function appendAuditOutcome(data) {
    if (data.notAuditable) {
        appendBotStep(`Audit actif non executable: ${data.reason}`, 'warning');
        if (data.attempts?.length) appendBotStep(`${data.attempts.length} tentative(s) auth essayee(s) avant interception/refus.`, 'warning');
        if (Array.isArray(data.publicProbes) && data.publicProbes.length) {
            const publicCount = data.publicProbes.filter(item => item.public).length;
            appendBotStep(`Controle URL-only: ${data.publicProbes.length} endpoint(s) public(s) sondes, ${publicCount} reponse(s) HTTP 200.`, publicCount ? 'info' : 'warning');
        }
        if (data.hint) appendBotStep(data.hint, 'warning');
        return;
    }
    appendBotStep(`Lecture proprietaire: HTTP ${data.ownerStatus}`, data.ownerStatus === 200 ? 'success' : 'warning');
    appendBotStep(`Requete croisee token B -> objet A: HTTP ${data.crossStatus}`, data.crossStatus === 200 ? 'danger' : 'success');
    appendBotStep(`Requete anonyme: HTTP ${data.anonStatus}`, data.anonStatus === 200 ? 'danger' : 'info');
    appendBotStep(data.isBOLA ? 'BOLA CONFIRMEE: le bot a recu la meme ressource avec le token B.' : 'Pas de fuite confirmee sur cette execution.', data.isBOLA ? 'danger' : 'success');
}

export function initScanner() {
    document.addEventListener('bola-audit-log', ev => {
        if (ev.detail && ev.detail.msg) {
            appendBotStep(ev.detail.msg, ev.detail.type || 'info');
        }
    });

    const btn = document.getElementById('btn-start-scan');
    const radar = document.getElementById('scanner-radar');
    const radarText = document.getElementById('radar-overlay-text');
    const badge = document.getElementById('scan-status-badge');
    const toggleLiveMode = document.getElementById('toggle-live-scan-mode');
    const liveConfig = document.getElementById('live-scan-config');

    if (toggleLiveMode) {
        toggleLiveMode.checked = true;
        if (liveConfig) liveConfig.style.display = 'flex';
        toggleLiveMode.addEventListener('change', () => {
            if (!toggleLiveMode.checked) {
                showToast('Mode Live obligatoire - simulation supprimee');
                toggleLiveMode.checked = true;
            }
        });
    }

    const baseInput = document.getElementById('live-api-base');
    resetBotFeed('Pret. Collez un lien puis lancez le scan.');

    // RÉSISTANCE AU RAFRAÎCHISSEMENT : Restaurer la matrice et l'état visuel du radar
    if (state.discoveredEndpoints && state.discoveredEndpoints.length) {
        renderScannerMatrix();
        const live = state.lastAuditResult;
        if (live) {
            if (radarText) radarText.innerText = live.notAuditable ? 'Audit passif' : (live.isBOLA ? 'BOLA detectee' : 'Audit termine');
            if (badge) {
                badge.innerText = live.notAuditable ? 'Audit Passif' : (live.isBOLA ? 'BOLA Confirmee' : 'Endpoint Securise');
                badge.className = live.notAuditable ? 'cyber-badge badge-primary-glow' : (live.isBOLA ? 'cyber-badge badge-danger-glow' : 'cyber-badge badge-success-glow');
            }
        }
    }

    const btnDiscover = document.getElementById('btn-discover-routes');
    const discoveryBadge = document.getElementById('discovery-status-badge');

    btnDiscover?.addEventListener('click', async () => {
        let config;
        try {
            config = getScannerConfig();
            if (!config.apiBase) throw new Error('Renseignez une URL de cible live avant la decouverte.');
            resetBotFeed('Decouverte manuelle lancee.');
            appendBotStep(`URL normalisee: ${config.apiBase}`, 'info');
        } catch (err) {
            showToast(err.message);
            logToConsole('SYSTEM', err.message, 'danger');
            appendBotStep(err.message, 'danger');
            return;
        }
        if (discoveryBadge) {
            discoveryBadge.style.display = 'inline';
            discoveryBadge.innerText = 'Exploration...';
        }
        btnDiscover.disabled = true;

        try {
            logToConsole('DISCOVERY', `Proxy local -> decouverte de ${config.apiBase}`, 'info');
            const { ok, status, data } = await fetchJSON(`${localApiBase()}/api/v1/scanner/discover`, {
                method: 'POST',
                body: JSON.stringify(config)
            });
            if (!ok) throw new Error(data?.error || `HTTP ${status}`);

            if (data.base) document.getElementById('live-api-base').value = data.base;
            if (data.routes?.register) document.getElementById('live-api-register').value = data.routes.register;
            if (data.routes?.login) document.getElementById('live-api-login').value = data.routes.login;
            if (data.routes?.target) document.getElementById('live-api-target').value = data.routes.target;

            state.discoveredEndpoints = data.endpoints || [];
            appendDiscoveryEvidence(data);
            appendBotStep(`${state.discoveredEndpoints.length} endpoint(s) candidat(s) listes.`, state.discoveredEndpoints.length ? 'success' : 'warning');
            state.discoveredEndpoints.forEach(ep => logToConsole('DISCOVERY', `${ep.path} [${ep.risk}]`, 'info'));
            if (data.note) logToConsole('DISCOVERY', data.note, 'warning');

            showToast('Routes chargees via proxy local');
            if (discoveryBadge) {
                discoveryBadge.innerText = 'Decouverte OK';
                discoveryBadge.className = 'text-success font-semibold';
                setTimeout(() => { discoveryBadge.style.display = 'none'; }, 2500);
            }
            savePersistedState();
            renderScannerMatrix();
            document.dispatchEvent(new CustomEvent('bola-score-update'));
        } catch (err) {
            logToConsole('SYSTEM', `Echec decouverte : ${err.message}`, 'danger');
            showToast('Decouverte impossible : ' + err.message);
            appendBotStep(`Decouverte interrompue: ${err.message}`, 'danger');
            if (discoveryBadge) discoveryBadge.style.display = 'none';
        } finally {
            btnDiscover.disabled = false;
        }
    });

    btn?.addEventListener('click', async () => {
        if (state.scanning) {
            appendBotStep('Scan deja en cours, nouvelle demande ignoree.', 'warning');
            return;
        }

        let config;
        try {
            config = getScannerConfig();
            if (!config.apiBase) throw new Error('Renseignez une URL de cible live avant de lancer le scan.');
            resetBotFeed('Scan lance.');
            appendBotStep(`URL recue puis normalisee: ${config.apiBase}`, 'info');
            appendBotStep('Le navigateur appelle uniquement le proxy local pour eviter CORS.', 'info');
        } catch (err) {
            showToast(err.message);
            logToConsole('SYSTEM', err.message, 'danger');
            appendBotStep(err.message, 'danger');
            return;
        }
        try { new URL(config.apiBase); }
        catch (_) {
            showToast('URL de base invalide');
            logToConsole('SYSTEM', `URL invalide : ${config.apiBase}`, 'danger');
            appendBotStep(`URL invalide: ${config.apiBase}`, 'danger');
            return;
        }

        state.scanning = true;
        radar?.classList.add('scanning');
        if (radarText) radarText.innerText = 'Audit proxy en cours...';
        btn.disabled = true;
        if (badge) {
            badge.innerText = 'Audit en cours...';
            badge.className = 'cyber-badge badge-primary-glow animate-pulse';
        }

        const tbody = document.getElementById('matrix-tbody');
        if (tbody) {
            tbody.innerHTML = `<tr><td colspan="6" class="text-center py-12"><span class="text-primary font-semibold animate-pulse" id="scan-progress-step-text">Audit execute cote serveur local...</span></td></tr>`;
        }

        try {
            logToConsole('AUDIT LIVE', `Proxy local -> decouverte + audit automatique de ${config.apiBase}`, 'warning');
            appendBotStep('Demande envoyee au backend local: decouverte + audit automatique.', 'info');
            const { ok, status, data } = await fetchJSON(`${localApiBase()}/api/v1/scanner/audit`, {
                method: 'POST',
                body: JSON.stringify(config)
            });
            if (!ok) {
                const hint = data?.hint ? ` | ${data.hint}` : '';
                const found = data?.discovered ? ` | trouve: ${JSON.stringify(data.discovered)}` : '';
                const attempts = data?.attempts ? ` | ${data.attempts.length} combinaisons essayees` : '';
                throw new Error(`${data?.error || 'Audit refuse'} (${status})${hint}${found}${attempts}`);
            }
            appendDiscoveryEvidence(data.discovery);
            appendAuditOutcome(data);

            state.lastAuditResult = {
                base: data.base,
                target: data.target || data.discovery?.routes?.target,
                ownerStatus: data.ownerStatus,
                crossStatus: data.crossStatus,
                anonStatus: data.anonStatus,
                isBOLA: data.isBOLA,
                vulnerable: data.vulnerable,
                notAuditable: data.notAuditable,
                reason: data.reason
            };

            if (document.getElementById('token-display-a')) {
                setText('token-display-a', data.tokenA ? data.tokenA.substring(0, 15) + '...' : 'n/a');
            }
            if (document.getElementById('token-display-b')) {
                setText('token-display-b', data.tokenB ? data.tokenB.substring(0, 15) + '...' : 'n/a');
            }

            if (data.notAuditable) {
                logToConsole('AUDIT LIVE', `Audit passif termine : ${data.reason}. ${data.hint || ''}`, 'warning');
                showToast('Audit passif termine : auth active non disponible');
            } else if (data.isBOLA) {
                logToConsole('AUDIT LIVE', `BOLA CONFIRMEE via proxy : owner=${data.ownerStatus}, cross=${data.crossStatus}, anon=${data.anonStatus}`, 'alert');
                showToast('Faille BOLA confirmee en direct');
            } else {
                logToConsole('AUDIT LIVE', `Pas de fuite via proxy : owner=${data.ownerStatus}, cross=${data.crossStatus}, anon=${data.anonStatus}`, 'success');
                showToast('Endpoint protege ou non exploitable');
            }

            state.scanned = true;
            await refreshDiscoveryFromServer(config);
            renderScannerMatrix();

            if (radarText) radarText.innerText = data.notAuditable ? 'Audit passif' : (data.isBOLA ? 'BOLA detectee' : 'Audit termine');
            if (badge) {
                badge.innerText = data.notAuditable ? 'Audit Passif' : (data.isBOLA ? 'BOLA Confirmee' : 'Endpoint Securise');
                badge.className = data.notAuditable ? 'cyber-badge badge-primary-glow' : (data.isBOLA ? 'cyber-badge badge-danger-glow' : 'cyber-badge badge-success-glow');
            }
            savePersistedState();
            document.dispatchEvent(new CustomEvent('bola-score-update'));
        } catch (err) {
            logToConsole('SYSTEM', `Echec audit : ${err.message}`, 'danger');
            showToast(err.message);
            appendBotStep(`Scan arrete: ${err.message}`, 'danger');
            if (badge) {
                badge.innerText = 'Audit Echoue';
                badge.className = 'cyber-badge badge-danger-glow';
            }
            if (tbody) {
                tbody.innerHTML = '';
                const row = document.createElement('tr');
                const cell = document.createElement('td');
                cell.colSpan = 6;
                cell.className = 'text-center text-danger py-8';
                cell.textContent = err.message;
                row.appendChild(cell);
                tbody.appendChild(row);
            }
        } finally {
            state.scanning = false;
            radar?.classList.remove('scanning');
            btn.disabled = false;
            savePersistedState();
        }
    });

    const initialConfig = getScannerConfig();
    if (initialConfig.apiBase) refreshDiscoveryFromServer(initialConfig);
}

async function refreshDiscoveryFromServer(config) {
    try {
        const { ok, data } = await fetchJSON(`${localApiBase()}/api/v1/scanner/discover`, {
            method: 'POST',
            body: JSON.stringify(config)
        });
        if (ok && Array.isArray(data.endpoints)) {
            state.discoveredEndpoints = data.endpoints;
            savePersistedState();
        }
    } catch (_) {}
}

export function renderScannerMatrix() {
    const tbody = document.getElementById('matrix-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';

    const endpoints = state.discoveredEndpoints || [];
    if (!endpoints.length) {
        tbody.innerHTML = `<tr><td colspan="6" class="text-center text-secondary py-8">Saisissez l URL cible puis lancez la decouverte ou l audit live.</td></tr>`;
        return;
    }

    const lastResult = state.lastAuditResult;

    endpoints.forEach(ep => {
        const live = lastResult && (
            (lastResult.target && ep.path.includes(lastResult.target)) ||
            ep.path.includes('/invoices/') ||
            ep.path.includes('/orders/') ||
            ep.risk === 'A AUDITER'
        ) ? lastResult : null;

        let userOwnerAccess = `<span class="status-allowed">AUTORISE${live ? ` (${live.ownerStatus})` : ''}</span>`;
        let userCrossAccess;
        let guestAccess;
        let riskBadge;

        if (live) {
            if (live.notAuditable) {
                userOwnerAccess = `<span class="text-muted">NON TESTE</span>`;
                userCrossAccess = `<span class="text-muted">AUTH NON PUBLIQUE</span>`;
                guestAccess = `<span class="text-muted">AUDIT PASSIF</span>`;
                riskBadge = `<span class="badge-warning">A VERIFIER</span>`;
            } else {
                userCrossAccess = live.isBOLA
                    ? `<span class="status-allowed">FUITE (${live.crossStatus})</span>`
                    : `<span class="status-denied">BLOQUE (${live.crossStatus})</span>`;
                guestAccess = live.anonStatus === 200
                    ? `<span class="status-allowed">FUITE (200)</span>`
                    : `<span class="status-denied">BLOQUE (${live.anonStatus})</span>`;
                riskBadge = live.isBOLA ? `<span class="badge-danger">CRITIQUE</span>` : `<span class="badge-success">RESOLU</span>`;
            }
        } else {
            userCrossAccess = `<span class="text-muted">Audit requis</span>`;
            guestAccess = ep.authRequired ? `<span class="text-muted">Audit requis</span>` : `<span class="status-allowed">PUBLIC</span>`;
            riskBadge = ep.risk === 'AUCUN'
                ? `<span class="badge-success">SECURISE</span>`
                : `<span class="badge-warning">${escapeHTML(ep.risk)}</span>`;
        }

        const row = document.createElement('tr');
        row.innerHTML = `
            <td class="endpoint-code font-semibold">${escapeHTML(ep.path)}</td>
            <td class="text-center"><span class="status-allowed">AUTORISE</span></td>
            <td class="text-center">${userOwnerAccess}</td>
            <td class="text-center">${userCrossAccess}</td>
            <td class="text-center">${guestAccess}</td>
            <td class="text-center">${riskBadge}</td>
        `;
        tbody.appendChild(row);
    });
}
