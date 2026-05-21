/* ==========================================================================
   BOLA-Shield AI - Live Object Relation Map Module
   ========================================================================== */

import { state } from './state.js';
import { showToast } from '../utils/helpers.js';

const apiBase = () => window.location.origin;
let liveGraph = { nodes: [], links: [], patched: {} };

function escapeHTML(value) {
    return String(value ?? '').replace(/[&<>"']/g, char => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    }[char]));
}

export function initMapper() {
    const btnRefresh = document.getElementById('btn-refresh-map');
    btnRefresh?.addEventListener('click', async () => {
        showToast('Recartographie live du graphe');
        await loadGraphFromServer();
        drawGraph();
    });

    loadGraphFromServer().then(drawGraph);
}

export async function renderMapperGraph() {
    await loadGraphFromServer();
    drawGraph();
}

async function loadGraphFromServer() {
    try {
        const res = await fetch(`${apiBase()}/api/v1/graph`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        liveGraph = await res.json();
        syncPatchState(liveGraph.patched || {});
    } catch (e) {
        liveGraph = { nodes: [], links: [], patched: {} };
        const criticalAlert = document.getElementById('map-critical-info');
        if (criticalAlert) {
            criticalAlert.className = 'alert-box alert-danger-style';
            criticalAlert.querySelector('.alert-heading').innerText = 'Graphe live indisponible';
            criticalAlert.querySelector('p').innerHTML = `Le backend n'a pas repondu : <code>${e.message}</code>`;
        }
    }
}

function syncPatchState(patched) {
    Object.values(state.vulnerabilities).forEach(list => {
        list.forEach(v => {
            if (typeof patched[v.id] === 'boolean') v.patched = patched[v.id];
        });
    });
}

function drawGraph() {
    const svg = document.getElementById('network-graph-svg');
    if (!svg) return;
    svg.innerHTML = '';

    const nodes = liveGraph.nodes || [];
    const links = liveGraph.links || [];
    const hasBola = links.some(link => link.type === 'bola');

    updateAlert(hasBola, nodes.length);

    if (!nodes.length) {
        const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        text.setAttribute('x', '400');
        text.setAttribute('y', '245');
        text.setAttribute('text-anchor', 'middle');
        text.setAttribute('class', 'node-text');
        text.textContent = 'Lancez un audit live pour creer des objets reels.';
        svg.appendChild(text);
        return;
    }

    const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
    const userGradient = document.createElementNS('http://www.w3.org/2000/svg', 'radialGradient');
    userGradient.setAttribute('id', 'userGradient');
    userGradient.innerHTML = '<stop offset="0%" style="stop-color:#22d3ee;stop-opacity:1" /><stop offset="100%" style="stop-color:#06b6d4;stop-opacity:0.8" />';
    defs.appendChild(userGradient);

    const objectGradient = document.createElementNS('http://www.w3.org/2000/svg', 'radialGradient');
    objectGradient.setAttribute('id', 'objectGradient');
    objectGradient.innerHTML = '<stop offset="0%" style="stop-color:#34d399;stop-opacity:1" /><stop offset="100%" style="stop-color:#10b981;stop-opacity:0.8" />';
    defs.appendChild(objectGradient);

    const bolaGradient = document.createElementNS('http://www.w3.org/2000/svg', 'radialGradient');
    bolaGradient.setAttribute('id', 'bolaGradient');
    bolaGradient.innerHTML = '<stop offset="0%" style="stop-color:#fca5a5;stop-opacity:1" /><stop offset="100%" style="stop-color:#ef4444;stop-opacity:0.8" />';
    defs.appendChild(bolaGradient);

    svg.appendChild(defs);

    links.forEach(link => {
        const sourceNode = nodes.find(n => n.id === link.source);
        const targetNode = nodes.find(n => n.id === link.target);
        if (!sourceNode || !targetNode) return;

        const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
        line.setAttribute('x1', sourceNode.x);
        line.setAttribute('y1', sourceNode.y);
        line.setAttribute('x2', targetNode.x);
        line.setAttribute('y2', targetNode.y);
        line.setAttribute('class', link.type === 'bola' ? 'link-line link-bola' : 'link-line link-secure');
        if (link.type === 'blocked') {
            line.setAttribute('stroke-dasharray', '6 5');
            line.setAttribute('opacity', '0.45');
        }
        svg.appendChild(line);

        if (link.type) {
            const midX = (sourceNode.x + targetNode.x) / 2;
            const midY = (sourceNode.y + targetNode.y) / 2;
            const labelText = document.createElementNS('http://www.w3.org/2000/svg', 'text');
            labelText.setAttribute('x', midX);
            labelText.setAttribute('y', midY - 8);
            labelText.setAttribute('class', 'link-label');
            labelText.textContent = link.type === 'bola' ? 'BOLA' : link.type === 'secure' ? 'Sécurisé' : 'Bloqué';
            svg.appendChild(labelText);
        }
    });

    nodes.forEach(node => {
        const group = document.createElementNS('http://www.w3.org/2000/svg', 'g');
        const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        circle.setAttribute('cx', node.x);
        circle.setAttribute('cy', node.y);

        let radius = 25;
        let fill = '#8b5cf6';
        let stroke = '#a78bfa';
        let icon = '🔐';

        if (node.type === 'user') {
            radius = 28;
            fill = 'url(#userGradient)';
            stroke = '#22d3ee';
            icon = '👤';
        } else if (node.type === 'session') {
            radius = 24;
            fill = '#8b5cf6';
            stroke = '#a78bfa';
            icon = '🔑';
        } else {
            const exposed = links.some(link => link.type === 'bola' && link.target === node.id);
            radius = exposed ? 32 : 28;
            fill = exposed ? 'url(#bolaGradient)' : 'url(#objectGradient)';
            stroke = exposed ? '#f87171' : '#34d399';
            icon = exposed ? '⚠️' : '📦';
        }

        circle.setAttribute('r', radius);
        circle.setAttribute('class', 'node-circle');
        circle.setAttribute('fill', fill);
        circle.setAttribute('stroke', stroke);
        circle.setAttribute('stroke-width', '2');

        const bgRect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
        bgRect.setAttribute('x', node.x - 38);
        bgRect.setAttribute('y', node.y + radius + 6);
        bgRect.setAttribute('width', '76');
        bgRect.setAttribute('height', '22');
        bgRect.setAttribute('rx', '4');
        bgRect.setAttribute('class', 'node-label-bg');

        const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        text.setAttribute('x', node.x);
        text.setAttribute('y', node.y - 8);
        text.setAttribute('class', 'node-text');
        text.textContent = icon;

        const label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        label.setAttribute('x', node.x);
        label.setAttribute('y', node.y + radius + 18);
        label.setAttribute('class', 'node-detail-text');
        label.setAttribute('font-weight', '600');
        label.textContent = node.label;

        group.appendChild(circle);
        group.appendChild(bgRect);
        group.appendChild(text);
        group.appendChild(label);

        group.addEventListener('mouseenter', () => {
            circle.setAttribute('r', radius + 6);
        });
        group.addEventListener('mouseleave', () => {
            circle.setAttribute('r', radius);
        });

        svg.appendChild(group);
    });
}

function updateAlert(hasBola, nodeCount) {
    const criticalAlert = document.getElementById('map-critical-info');
    if (!criticalAlert) return;

    const alertIcon = criticalAlert.querySelector('.alert-icon');
    const alertHeading = criticalAlert.querySelector('.alert-heading');
    const alertDesc = criticalAlert.querySelector('p');

    if (hasBola) {
        criticalAlert.className = 'alert-box alert-danger-style';
        if (alertIcon) alertIcon.innerText = '!';
        if (alertHeading) alertHeading.innerText = 'Fuite transversale live';
        if (alertDesc) alertDesc.innerHTML = liveGraph.audit
            ? `Audit actuel : <code>${escapeHTML(liveGraph.audit.targetUrl || liveGraph.audit.base)}</code>. Le token B atteint l objet de A en HTTP ${escapeHTML(liveGraph.audit.crossStatus)}.`
            : 'Le graphe vient du backend : une session peut encore atteindre une facture appartenant a un autre utilisateur.';
    } else {
        criticalAlert.className = 'alert-box alert-success-style';
        if (alertIcon) alertIcon.innerText = 'OK';
        if (alertHeading) alertHeading.innerText = 'Graphe live securise';
        if (alertDesc) alertDesc.innerHTML = nodeCount
            ? (liveGraph.audit
                ? `Audit actuel : <code>${escapeHTML(liveGraph.audit.targetUrl || liveGraph.audit.base)}</code>. Requete croisee ${liveGraph.audit.crossStatus ? `HTTP ${escapeHTML(liveGraph.audit.crossStatus)}` : 'non executable avec les routes publiques detectees'}.`
                : 'Aucun lien BOLA actif n est expose dans la cartographie serveur actuelle.')
            : 'Aucun objet live n a encore ete cree par le scanner.';
    }
}
