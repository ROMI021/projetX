/* ==========================================================================
   BOLA-Shield AI — Live Dashboard
   Real backend metrics + Server-Sent Events for the threat feed.
   ========================================================================== */

import { state, savePersistedState } from './state.js';
import { logToConsole } from '../utils/helpers.js';

let bolaChart = null;
let sseSource = null;

// Rolling buckets used to draw the chart from real backend events.
const buckets = {
    hourly: { labels: [], data: Array(7).fill(0), cursor: 0 },
    daily: { labels: [], data: Array(7).fill(0) }
};

function apiBase() {
    return window.location.origin;
}

function initBuckets() {
    const now = new Date();
    buckets.hourly.labels = [];
    for (let i = 6; i >= 0; i--) {
        const d = new Date(now.getTime() - i * 60 * 60 * 1000);
        buckets.hourly.labels.push(`${d.getHours().toString().padStart(2, '0')}:00`);
    }
    const dayNames = ['Dim', 'Lun', 'Mar', 'Mer', 'Jeu', 'Ven', 'Sam'];
    buckets.daily.labels = [];
    for (let i = 6; i >= 0; i--) {
        const d = new Date(now.getTime() - i * 24 * 60 * 60 * 1000);
        buckets.daily.labels.push(dayNames[d.getDay()]);
    }
}

export function initChart() {
    const canvas = document.getElementById('bolaChart');
    if (!canvas) return;
    if (typeof Chart === 'undefined') {
        const fallback = document.createElement('div');
        fallback.className = 'text-secondary text-center py-12';
        fallback.textContent = 'Graphique indisponible hors ligne. Les métriques restent synchronisées.';
        canvas.replaceWith(fallback);
        refreshMetrics();
        return;
    }
    initBuckets();

    const ctx = canvas.getContext('2d');
    const gradient = ctx.createLinearGradient(0, 0, 0, 240);
    gradient.addColorStop(0, 'rgba(139, 92, 246, 0.4)');
    gradient.addColorStop(1, 'rgba(139, 92, 246, 0.0)');

    bolaChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: buckets.hourly.labels,
            datasets: [{
                label: 'Événements observés',
                data: buckets.hourly.data,
                borderColor: '#8b5cf6',
                borderWidth: 3,
                pointBackgroundColor: '#8b5cf6',
                pointHoverRadius: 7,
                backgroundColor: gradient,
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#6b7280', font: { family: 'Fira Code' } } },
                x: { grid: { display: false }, ticks: { color: '#6b7280', font: { family: 'Fira Code' } } }
            }
        }
    });

    document.getElementById('chart-timeframe')?.addEventListener('change', e => {
        const isDaily = e.target.value === '7d';
        bolaChart.data.labels = isDaily ? buckets.daily.labels : buckets.hourly.labels;
        bolaChart.data.datasets[0].data = isDaily ? buckets.daily.data : buckets.hourly.data;
        bolaChart.update();
    });
}

function bumpChart(eventType) {
    const weight = eventType === 'alert' ? 5 : eventType === 'success' ? 2 : 1;
    const lastIndex = buckets.hourly.data.length - 1;
    buckets.hourly.data[lastIndex] += weight;
    buckets.daily.data[buckets.daily.data.length - 1] += weight;
    if (bolaChart) bolaChart.update('none');
}

function applyMetricsToUI(m) {
    state.metrics.blockedAttacks = m.blockedAttacks ?? state.metrics.blockedAttacks;
    state.metrics.dataLeaked = m.dataLeaked ?? state.metrics.dataLeaked;
    state.metrics.exposureRate = m.exposureRate ?? state.metrics.exposureRate;
    state.metrics.financialSavings = m.financialSavings ?? state.metrics.financialSavings;

    const blockedEl = document.getElementById('metric-blocked-attacks');
    if (blockedEl) blockedEl.innerText = state.metrics.blockedAttacks.toLocaleString();
    const leakEl = document.getElementById('metric-data-leaked');
    if (leakEl) leakEl.innerText = state.metrics.dataLeaked.toLocaleString();
    const savingsEl = document.getElementById('metric-financial-savings');
    if (savingsEl) savingsEl.innerText = state.metrics.financialSavings.toLocaleString() + ' €';
    const expEl = document.getElementById('metric-exposure-rate');
    if (expEl) expEl.innerText = `${state.metrics.exposureRate}%`;

    document.dispatchEvent(new CustomEvent('bola-score-update'));
}

async function refreshMetrics() {
    try {
        const res = await fetch(`${apiBase()}/api/v1/metrics`);
        if (!res.ok) return;
        const m = await res.json();
        applyMetricsToUI(m);
    } catch (e) { /* offline */ }
}

export function initLiveLogs() {
    logToConsole('SYSTEM', `BOLA-Shield UI connectée à ${apiBase()}`, 'info');

    refreshMetrics();
    setInterval(refreshMetrics, 5000);

    if (sseSource) sseSource.close();
    try {
        sseSource = new EventSource(`${apiBase()}/api/v1/logs/stream`);
        sseSource.onopen = () => logToConsole('SYSTEM', 'Flux de logs serveur connecté (SSE).', 'success');
        sseSource.onerror = () => logToConsole('SYSTEM', 'Flux de logs interrompu — tentative de reconnexion automatique...', 'warning');
        sseSource.onmessage = ev => {
            try {
                const e = JSON.parse(ev.data);
                logToConsole(e.origin || 'EVENT', e.msg || '(no message)', e.type || 'info');
                bumpChart(e.type);
                if (e.origin === 'ALERT' || e.origin === 'SHIELD') refreshMetrics();
                if (e.origin === 'AUDIT') {
                    document.dispatchEvent(new CustomEvent('bola-audit-log', { detail: e }));
                    // Vérification de la demande d'OTP
                    if (e.msg && e.msg.includes('[OTP_REQUIRED]')) {
                        document.dispatchEvent(new CustomEvent('bola-otp-required'));
                    }
                }
            } catch (_) {}
        };
    } catch (e) {
        logToConsole('SYSTEM', `EventSource non disponible : ${e.message}`, 'danger');
    }
}

export function refreshChart() {
    if (bolaChart) bolaChart.update();
}
