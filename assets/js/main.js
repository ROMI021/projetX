/* ==========================================================================
   BOLA-Shield AI — Central Entrypoint & Module Orchestrator
   ========================================================================== */

import { state, loadPersistedState, savePersistedState } from './modules/state.js';
import { initChart, initLiveLogs, refreshChart } from './modules/dashboard.js';
import { initScanner, renderScannerMatrix } from './modules/scanner.js';
import { initPatcher, renderVulnList } from './modules/patcher.js';
import { initMapper, renderMapperGraph } from './modules/mapper.js';
import { initChat } from './modules/chat.js';
import { initFirewall, renderBlacklistTable } from './modules/firewall.js';
import { showToast, logToConsole } from './utils/helpers.js';

// DOM Elements for Rating Sync
const widget = document.getElementById('header-health-badge');
const valueText = document.getElementById('health-value-text');
const statusText = document.getElementById('health-status-text');
const circle = document.getElementById('health-circle');

// Initialize Main Application Loop on DOM Load
document.addEventListener('DOMContentLoaded', () => {
    // 1. Initialise all modules and bindings
    initChart();
    initLiveLogs();
    initScanner();
    initPatcher();
    initMapper();
    initChat();
    initFirewall();

    // Bind Sidebar Tab Navigation Clicking
    const navItems = document.querySelectorAll('.nav-item');
    const tabPanes = document.querySelectorAll('.tab-pane');
    const tabNameBreadcrumb = document.getElementById('current-tab-name');
    const pageMainTitle = document.getElementById('page-main-title');

    const navigateToTab = (tabId) => {
        const targetNav = document.querySelector(`.nav-item[data-tab="${tabId}"]`);
        if (targetNav) targetNav.click();
    };

    navItems.forEach(item => {
        item.addEventListener('click', () => {
            const tabId = item.getAttribute('data-tab');
            state.activeTab = tabId;

            navItems.forEach(nav => nav.classList.remove('active'));
            item.classList.add('active');

            tabPanes.forEach(pane => {
                pane.classList.remove('active');
                if (pane.id === `tab-${tabId}`) {
                    pane.classList.add('active');
                }
            });

            // Update Breadcrumb & Page Title
            if (tabNameBreadcrumb) {
                tabNameBreadcrumb.innerText = item.querySelector('span').innerText;
            }
            if (pageMainTitle) {
                if (tabId === 'dashboard') pageMainTitle.innerText = 'Aperçu de Sécurité API';
                else if (tabId === 'scanner') pageMainTitle.innerText = 'Multi-Actor Authorization Auditor';
                else if (tabId === 'patcher') pageMainTitle.innerText = 'IA Vulnerability Remediation';
                else if (tabId === 'mapper') pageMainTitle.innerText = 'API Object Relational Cartography';
                else if (tabId === 'chat') pageMainTitle.innerText = 'CISO Cybersecurity Copilot';
                else if (tabId === 'firewall') pageMainTitle.innerText = 'IA API Gateway Firewall';
            }

            // Refresh specific components
            if (tabId === 'dashboard') {
                refreshChart();
            } else if (tabId === 'mapper') {
                renderMapperGraph();
            }

            savePersistedState();
        });
    });

    // Bind Quick Action Buttons
    const actionBtns = document.querySelectorAll('.action-btn[data-navigate]');
    actionBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const tabId = btn.getAttribute('data-navigate');
            navigateToTab(tabId);
        });
    });

    // Bind Main Shield Active Toggle
    const btnShield = document.getElementById('btn-toggle-shield');
    const shieldLabel = btnShield?.querySelector('span');
    btnShield?.addEventListener('click', async () => {
        state.shieldActive = !state.shieldActive;
        try {
            await fetch(`${window.location.origin}/api/v1/firewall/rules`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ shieldActive: state.shieldActive })
            });
        } catch (e) {
            logToConsole('SYSTEM', `Sauvegarde serveur du bouclier impossible : ${e.message}`, 'warning');
        }
        if (state.shieldActive) {
            btnShield.classList.add('active');
            if (shieldLabel) shieldLabel.innerText = 'Bouclier Actif';
            logToConsole('SHIELD', 'Bouclier de filtrage sémantique BOLA de la passerelle ACTIVÉ.', 'success');
            showToast('🛡️ Passerelle de protection active');
        } else {
            btnShield.classList.remove('active');
            if (shieldLabel) shieldLabel.innerText = 'Bouclier Inactif';
            logToConsole('SYSTEM', 'ATTENTION : Bouclier de filtrage sémantique DÉSACTIVÉ.', 'alert');
            showToast('⚠️ Protection de la passerelle désactivée !');
        }
        recalculateSecurityScore();
    });

    // 2. Load previous session state
    const hasStoredState = loadPersistedState();

    if (hasStoredState) {
        // Sync UI widgets with restored state metrics
        const blockedMetric = document.getElementById('metric-blocked-attacks');
        if (blockedMetric) blockedMetric.innerText = state.metrics.blockedAttacks;
        
        const leakedMetric = document.getElementById('metric-data-leaked');
        if (leakedMetric) leakedMetric.innerText = state.metrics.dataLeaked.toLocaleString();
        
        const savingsMetric = document.getElementById('metric-financial-savings');
        if (savingsMetric) savingsMetric.innerText = state.metrics.financialSavings.toLocaleString() + ' €';

        // Shield active button state
        const btnShield = document.getElementById('btn-toggle-shield');
        const shieldLabel = btnShield?.querySelector('span');
        if (btnShield && shieldLabel) {
            if (state.shieldActive) {
                btnShield.classList.add('active');
                shieldLabel.innerText = 'Bouclier Actif';
            } else {
                btnShield.classList.remove('active');
                shieldLabel.innerText = 'Bouclier Inactif';
            }
        }

        // Selected tech framework pill active state
        document.querySelectorAll('.tech-pill').forEach(btn => {
            btn.classList.remove('active');
            if (btn.getAttribute('data-tech') === state.selectedTech) {
                btn.classList.add('active');
            }
        });

        // If previously audited, display matrix
        if (state.scanned) {
            const badge = document.getElementById('scan-status-badge');
            if (badge) {
                badge.innerText = 'Rapport Généré';
                badge.className = 'cyber-badge badge-danger-glow';
            }
            renderScannerMatrix();
        }

        // Re-render vuln lists and tables
        renderVulnList();
        renderBlacklistTable();

        const restoredNav = document.querySelector(`.nav-item[data-tab="${state.activeTab}"]`);
        if (restoredNav && state.activeTab !== 'dashboard') {
            restoredNav.click();
        }
    }

    // 3. Recalculate score and sync UI ratings
    recalculateSecurityScore();
    
    // 4. Bind Custom Event listener for decoupled modules score updates (like patcher and firewall)
    document.addEventListener('bola-score-update', () => {
        recalculateSecurityScore();
    });
});

/**
 * Update the global security score gauge based on patched vulnerabilities count and firewall rules status.
 */
function recalculateSecurityScore() {
    const hasScan = state.scanned && state.discoveredEndpoints && state.discoveredEndpoints.length > 0;
    
    let score = 30;
    let exposureRate = 72;
    let patchedVulns = 0;
    let totalVulns = 0;
    
    // Default or fallback sandbox variables
    Object.keys(state.vulnerabilities).forEach(tech => {
        state.vulnerabilities[tech].forEach(v => {
            totalVulns++;
            if (v.patched) patchedVulns++;
        });
    });

    if (hasScan) {
        // --- 1. SCAN MODE ACTIVE ---
        let baseScore = 50;
        const live = state.lastAuditResult;
        if (live) {
            if (live.notAuditable) {
                baseScore = 55; // Passive audit
            } else if (live.isBOLA) {
                baseScore = 25; // Confirmed BOLA!
            } else {
                baseScore = 85; // Clean scan!
            }
        }
        if (state.shieldActive) baseScore += 15;
        score = Math.min(baseScore, 100);
        exposureRate = Math.max(100 - score, 0);
    } else {
        // --- 2. SANDBOX MODE (FALLBACK) ---
        let localScore = 30;
        const patchWeight = 40;
        if (totalVulns > 0) {
            localScore += Math.round((patchedVulns / totalVulns) * patchWeight);
        }
        if (state.shieldActive) localScore += 15;
        if (document.getElementById('toggle-active-scan')?.checked) localScore += 5;
        if (document.getElementById('toggle-tokenization')?.checked) localScore += 10;
        if (document.getElementById('toggle-vpn-block')?.checked) localScore += 5;
        if (document.getElementById('toggle-emergency-shield')?.checked) localScore += 10;

        score = Math.min(localScore, 100);
        exposureRate = Math.max(100 - score - 10, 0);
        if (exposureRate === 0 && patchedVulns === totalVulns) {
            exposureRate = 0;
        }
    }

    state.securityScore = score;
    state.metrics.exposureRate = exposureRate;

    // Sync dashboard card metrics: Exposure Rate Value & Glow
    const expRateElement = document.getElementById('metric-exposure-rate');
    if (expRateElement) {
        expRateElement.innerText = `${state.metrics.exposureRate}%`;
        const metricCard = expRateElement.closest('.metric-card');
        
        if (state.metrics.exposureRate < 20) {
            if (metricCard) metricCard.className = 'metric-card card-glow-success';
            expRateElement.className = 'metric-value text-success';
        } else if (state.metrics.exposureRate < 50) {
            if (metricCard) metricCard.className = 'metric-card card-glow-warning';
            expRateElement.className = 'metric-value text-warning';
        } else {
            if (metricCard) metricCard.className = 'metric-card card-glow-danger';
            expRateElement.className = 'metric-value text-danger';
        }
    }

    // Sync other metric values to avoid discrepancies
    const blockedMetric = document.getElementById('metric-blocked-attacks');
    if (blockedMetric) blockedMetric.innerText = state.metrics.blockedAttacks.toLocaleString();
    
    const leakedMetric = document.getElementById('metric-data-leaked');
    if (leakedMetric) leakedMetric.innerText = state.metrics.dataLeaked.toLocaleString();
    
    const savingsMetric = document.getElementById('metric-financial-savings');
    if (savingsMetric) savingsMetric.innerText = `${state.metrics.financialSavings.toLocaleString()} €`;

    // --- DYNAMICALLY UPDATE FOOTERS ---
    const footerExposure = document.getElementById('footer-exposure-rate');
    const footerLeaked = document.getElementById('footer-data-leaked');
    const footerBlocked = document.getElementById('footer-blocked-attacks');
    const footerSavings = document.getElementById('footer-financial-savings');

    if (hasScan) {
        const live = state.lastAuditResult;
        let host = 'Cible';
        try {
            if (live && live.base) {
                host = new URL(live.base).hostname;
            } else if (state.discoveredEndpoints && state.discoveredEndpoints.length > 0) {
                host = new URL(state.discoveredEndpoints[0].path).hostname;
            }
        } catch (_) {}

        if (footerExposure) {
            if (live) {
                if (live.notAuditable) {
                    footerExposure.innerHTML = `<span class="text-warning">⚠️ Audit passif</span> &bull; ${state.discoveredEndpoints.length} routes à vérifier sur ${host}`;
                } else if (live.isBOLA) {
                    footerExposure.innerHTML = `<span class="text-danger">🔴 Critique BOLA</span> &bull; Brèche confirmée sur ${host}`;
                } else {
                    footerExposure.innerHTML = `<span class="text-success">🟢 Sécurisé</span> &bull; ${state.discoveredEndpoints.length} routes validées sur ${host}`;
                }
            } else {
                footerExposure.innerHTML = `<span class="text-warning">🔍 Découvert</span> &bull; ${state.discoveredEndpoints.length} routes identifiées sur ${host}`;
            }
        }

        if (footerLeaked) {
            if (live && live.isBOLA) {
                footerLeaked.innerHTML = `<span class="text-danger">Fuites actives</span> de ressources sur ${host}`;
            } else {
                footerLeaked.innerHTML = `<span class="text-success">Zéro fuite</span> de données détectée sur ${host}`;
            }
        }

        if (footerBlocked) {
            footerBlocked.innerHTML = `<span class="text-success">Auditeur Live actif</span> &bull; Cible : ${host}`;
        }

        if (footerSavings) {
            footerSavings.innerHTML = `Économies estimées d'exposition aux risques sur ${host}`;
        }
    } else {
        // Sandbox fallbacks
        if (footerExposure) {
            const left = totalVulns - patchedVulns;
            if (left > 0) {
                footerExposure.innerHTML = `<span class="text-danger">Élevé</span> &bull; ${left} endpoints sur ${totalVulns} vulnérables`;
            } else {
                footerExposure.innerHTML = `<span class="text-success">Excellent</span> &bull; ${totalVulns} endpoints sandbox sécurisés`;
            }
        }
        if (footerLeaked) {
            footerLeaked.innerHTML = `<span class="text-warning">Invoices / Customer files</span> à haut risque`;
        }
        if (footerBlocked) {
            footerBlocked.innerHTML = `<span class="text-success">+18% aujourd'hui</span> &bull; Pare-feu IA actif`;
        }
        if (footerSavings) {
            footerSavings.innerHTML = `Basé sur le coût moyen RGPD & Rétrofacturations`;
        }
    }

    // Sync header visual rating badge
    if (widget && valueText && statusText && circle) {
        widget.className = 'security-health-widget';
        let status = '';
        
        if (state.securityScore < 50) {
            widget.classList.add('danger');
            status = 'CRITIQUE';
            statusText.className = 'health-status text-danger animate-pulse';
        } else if (state.securityScore < 85) {
            widget.classList.add('warning');
            status = 'VULNÉRABLE';
            statusText.className = 'health-status text-warning';
        } else {
            widget.classList.add('success');
            status = 'SÉCURISÉ';
            statusText.className = 'health-status text-success';
        }

        valueText.innerText = `${state.securityScore}%`;
        statusText.innerText = status;
        circle.setAttribute('stroke-dasharray', `${state.securityScore}, 100`);
    }

    savePersistedState();
}
