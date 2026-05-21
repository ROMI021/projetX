/* ==========================================================================
   BOLA-Shield AI — Central Entrypoint & Module Orchestrator
   ========================================================================== */

import { state, loadPersistedState, savePersistedState, recalculateSecurityScore } from './modules/state.js';
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

    // 5. Bind OTP Modal Logic
    const otpModal = document.getElementById('otp-modal');
    const btnCloseOtp = document.getElementById('btn-close-otp');
    const btnSubmitOtp = document.getElementById('btn-submit-otp');
    const otpInputField = document.getElementById('otp-input-field');

    document.addEventListener('bola-otp-required', () => {
        if (otpModal) {
            otpModal.style.display = 'flex';
            if (otpInputField) {
                otpInputField.value = '';
                otpInputField.focus();
            }
        }
    });

    if (btnCloseOtp && otpModal) {
        btnCloseOtp.addEventListener('click', () => {
            otpModal.style.display = 'none';
        });
    }

    if (btnSubmitOtp && otpInputField) {
        btnSubmitOtp.addEventListener('click', async () => {
            const code = otpInputField.value.trim();
            if (!code) {
                showToast('Veuillez entrer le code OTP.');
                return;
            }
            
            try {
                btnSubmitOtp.innerText = 'Envoi...';
                btnSubmitOtp.disabled = true;
                
                const res = await fetch(`${window.location.origin}/api/otp`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ code })
                });
                
                if (!res.ok) throw new Error('Erreur lors de l\'envoi');
                
                showToast('OTP envoyé avec succès ! Le navigateur fantôme reprend...');
                otpModal.style.display = 'none';
            } catch (err) {
                showToast('Erreur : ' + err.message);
            } finally {
                btnSubmitOtp.innerText = 'Envoyer le Code';
                btnSubmitOtp.disabled = false;
            }
        });
    }
});

/**
 * Update the global security score gauge based on patched vulnerabilities count and firewall rules status.
 */

