/* ==========================================================================
   BOLA-Shield AI - Live CISO Chat Module
   ========================================================================== */

import { logToConsole } from '../utils/helpers.js';

const apiBase = () => window.location.origin;

export function initChat() {
    const input = document.getElementById('chat-message-input');
    const btnSend = document.getElementById('btn-chat-send');

    if (!input || !btnSend) return;

    appendChatMessage('ai', `<strong>BOLA-Shield Analyst connecte au backend live.</strong><br>
    Les reponses utilisent maintenant l'etat reel du serveur : scans, patchs, blocages, fuites observees et regles firewall.`, { html: true });

    btnSend.addEventListener('click', () => handleUserMessage());
    input.addEventListener('keypress', e => {
        if (e.key === 'Enter') handleUserMessage();
    });

    document.querySelectorAll('.cmd-pill').forEach(btn => {
        btn.addEventListener('click', () => {
            const msg = btn.getAttribute('data-msg');
            if (msg) {
                input.value = msg;
                handleUserMessage();
            }
        });
    });
}

export function appendChatMessage(sender, text, { html = false } = {}) {
    const box = document.getElementById('chat-messages-box');
    if (!box) return;

    const bubble = document.createElement('div');
    bubble.className = `chat-bubble bubble-${sender}`;
    if (html) bubble.innerHTML = text;
    else bubble.textContent = text;
    box.appendChild(bubble);
    box.scrollTop = box.scrollHeight;
}

async function handleUserMessage() {
    const input = document.getElementById('chat-message-input');
    if (!input) return;

    const query = input.value.trim();
    if (!query) return;

    appendChatMessage('user', query);
    input.value = '';

    const box = document.getElementById('chat-messages-box');
    const pending = document.createElement('div');
    pending.className = 'chat-bubble bubble-ai font-semibold animate-pulse';
    pending.innerText = 'Analyse backend live...';
    box?.appendChild(pending);
    if (box) box.scrollTop = box.scrollHeight;

    try {
        const res = await fetch(`${apiBase()}/api/v1/chat`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message: query })
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();

        pending.remove();
        appendChatMessage('ai', data.body || 'Aucune reponse serveur.', { html: true });

        if (Array.isArray(data.actions)) {
            data.actions.forEach(action => applyServerAction(action));
        }
        document.dispatchEvent(new CustomEvent('bola-score-update'));
    } catch (e) {
        pending.remove();
        logToConsole('CHAT', `Erreur chat live : ${e.message}`, 'warning');
        appendChatMessage('ai', `Impossible de joindre le backend live pour cette question. ${e.message}`);
    }
}

function applyServerAction(action) {
    if (action.type !== 'rule') return;
    const byRule = {
        activeScan: 'toggle-active-scan',
        tokenization: 'toggle-tokenization',
        vpnBlock: 'toggle-vpn-block',
        emergencyShield: 'toggle-emergency-shield'
    };
    const el = document.getElementById(byRule[action.key]);
    if (el) el.checked = Boolean(action.value);
}
