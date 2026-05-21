/* ==========================================================================
   BOLA-Shield AI - Live Code Patcher Module
   ========================================================================== */

import { state, savePersistedState } from './state.js';
import { logToConsole, showToast } from '../utils/helpers.js';
import { renderScannerMatrix } from './scanner.js';
import { renderMapperGraph } from './mapper.js';

const apiBase = () => window.location.origin;
let livePatchingEnabled = false;

function escapeHTML(value) {
    return String(value ?? '').replace(/[&<>"']/g, char => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    }[char]));
}

export function initPatcher() {
    document.querySelectorAll('.tech-pill').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.tech-pill').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            state.selectedTech = btn.getAttribute('data-tech');
            state.activeVulnId = null;

            const vulnContent = document.getElementById('code-vuln-content');
            const repContent = document.getElementById('code-repaired-content');
            if (vulnContent) vulnContent.innerText = '// Selectionnez une faille dans la liste de gauche';
            if (repContent) repContent.innerText = '// Le correctif live de validation semantique s affichera ici';

            const btnPatch = document.getElementById('btn-apply-patch');
            if (btnPatch) btnPatch.disabled = true;
            renderVulnList();
        });
    });

    const btnPatch = document.getElementById('btn-apply-patch');
    btnPatch?.addEventListener('click', () => applyLivePatch());

    syncPatchStateFromServer().finally(renderVulnList);
}

async function syncPatchStateFromServer() {
    try {
        const res = await fetch(`${apiBase()}/api/v1/patches`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const patches = await res.json();
        livePatchingEnabled = Object.keys(patches || {}).length > 0;
        Object.values(state.vulnerabilities).forEach(list => {
            list.forEach(v => {
                if (typeof patches[v.id] === 'boolean') v.patched = patches[v.id];
            });
        });
    } catch (e) {
        logToConsole('PATCH', `Etat patch serveur indisponible : ${e.message}`, 'warning');
    }
}

export function renderVulnList() {
    const listContainer = document.getElementById('patcher-vuln-list');
    if (!listContainer) return;

    listContainer.innerHTML = '';
    const list = state.vulnerabilities[state.selectedTech];

    if (!list || list.length === 0) {
        listContainer.innerHTML = `<div class="text-secondary text-sm p-4">Aucune faille enregistree pour cette stack.</div>`;
        return;
    }

    list.forEach(v => {
        const item = document.createElement('button');
        item.className = `vuln-item-btn ${v.id === state.activeVulnId ? 'active' : ''}`;
        const statusBadge = !livePatchingEnabled
            ? `<span class="badge-warning">GUIDE</span>`
            : v.patched
            ? `<span class="badge-success">RESOLU</span>`
            : `<span class="badge-danger">${v.difficulty}</span>`;

        item.innerHTML = `
            <div class="vuln-item-title">${v.title}</div>
            <div class="vuln-item-meta">
                <span class="vuln-item-route">${v.route}</span>
                ${statusBadge}
            </div>
        `;

        item.addEventListener('click', () => {
            document.querySelectorAll('.vuln-item-btn').forEach(b => b.classList.remove('active'));
            item.classList.add('active');
            selectVulnerability(v.id);
        });

        listContainer.appendChild(item);
    });
}

export function selectVulnerability(id) {
    state.activeVulnId = id;
    const v = state.vulnerabilities[state.selectedTech].find(item => item.id === id);
    if (!v) return;

    const vulnPath = document.getElementById('vuln-file-path');
    const repPath = document.getElementById('repaired-file-path');
    if (vulnPath) vulnPath.innerText = v.file;
    if (repPath) repPath.innerText = `${v.file} (Patched)`;

    const vulnContent = document.getElementById('code-vuln-content');
    if (vulnContent) vulnContent.innerHTML = v.vulnCode;

    const btnPatch = document.getElementById('btn-apply-patch');
    const patchedBadge = document.getElementById('patched-status-badge');
    const explanationText = document.getElementById('patch-explanation-text');
    const repContent = document.getElementById('code-repaired-content');

    if (!livePatchingEnabled) {
        if (repContent) repContent.innerHTML = v.repairedCode;
        if (btnPatch) btnPatch.disabled = true;
        if (patchedBadge) {
            patchedBadge.className = 'editor-status badge-warning';
            patchedBadge.innerText = 'GUIDE LIVE';
        }
        if (explanationText) {
            explanationText.innerHTML = `<strong>Mode live-only :</strong> ${v.explanation} Appliquez ce principe directement dans le code de la cible autorisee, puis relancez l audit.`;
        }
    } else if (v.patched) {
        if (repContent) repContent.innerHTML = v.repairedCode;
        if (btnPatch) btnPatch.disabled = true;
        if (patchedBadge) {
            patchedBadge.className = 'editor-status badge-success';
            patchedBadge.innerText = 'SECURISE';
        }
        if (explanationText) explanationText.innerHTML = `<strong>Correctif serveur actif :</strong> ${v.explanation}`;
    } else {
        if (repContent) {
            repContent.innerHTML = `// Pret pour le correctif logique live.
// Cliquez sur "Generer & Appliquer le Correctif IA" ci-dessus.`;
        }
        if (btnPatch) btnPatch.disabled = false;
        if (patchedBadge) {
            patchedBadge.className = 'editor-status badge-warning';
            patchedBadge.innerText = 'EN ATTENTE';
        }
        if (explanationText) explanationText.innerHTML = `<strong>Description du probleme :</strong> ${v.explanation}`;
    }
}

async function applyLivePatch() {
    const v = state.vulnerabilities[state.selectedTech].find(item => item.id === state.activeVulnId);
    if (!v || v.patched) return;
    if (!livePatchingEnabled) {
        showToast('Mode live-only: correction a appliquer dans la cible');
        return;
    }

    const btnPatch = document.getElementById('btn-apply-patch');
    const repairedCodeBlock = document.getElementById('code-repaired-content');
    const explanationText = document.getElementById('patch-explanation-text');

    if (btnPatch) btnPatch.disabled = true;
    if (repairedCodeBlock) repairedCodeBlock.innerHTML = '';
    if (explanationText) {
        explanationText.innerHTML = `<span class="text-primary font-semibold animate-pulse">Application du correctif sur le backend live...</span>`;
    }

    try {
        const res = await fetch(`${apiBase()}/api/v1/patches/${encodeURIComponent(v.id)}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });
        const result = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(result.hint || result.error || `HTTP ${res.status}`);

        v.patched = Boolean(result.patched);
        if (repairedCodeBlock) repairedCodeBlock.innerHTML = v.repairedCode;

        logToConsole('SHIELD', `[PATCH LIVE] ${v.file} protege cote serveur sur ${v.route}.`, 'success');
        showToast(`Correctif live applique sur ${v.file}`);

        renderVulnList();
        if (state.scanned) renderScannerMatrix();
        renderMapperGraph();
        document.dispatchEvent(new CustomEvent('bola-score-update'));

        const patchedBadge = document.getElementById('patched-status-badge');
        if (patchedBadge) {
            patchedBadge.className = 'editor-status badge-success';
            patchedBadge.innerText = 'SECURISE';
        }
        if (explanationText) {
            explanationText.innerHTML = `<strong>Correctif live confirme :</strong> le backend impose maintenant la validation d ownership pour cet endpoint. Relancez l audit pour verifier le HTTP 404/403 sur la requete croisee.`;
        }

        savePersistedState();
    } catch (e) {
        if (btnPatch) btnPatch.disabled = false;
        if (explanationText) explanationText.innerHTML = `<strong>Patch refuse :</strong> ${escapeHTML(e.message)}`;
        logToConsole('PATCH', `Echec du patch live ${v.id} : ${e.message}`, 'warning');
        showToast(`Patch live impossible : ${e.message}`);
    }
}
