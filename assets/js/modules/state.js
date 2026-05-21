/* ==========================================================================
   BOLA-Shield AI — Global State & Persistence Manager
   ========================================================================== */

import { showToast } from '../utils/helpers.js';

// Centralised Reactive Application State
export const state = {
    activeTab: 'dashboard',
    shieldActive: true,
    securityScore: 45,
    metrics: {
        exposureRate: 0,
        dataLeaked: 0,
        blockedAttacks: 0,
        financialSavings: 0
    },
    scanned: false,
    scanning: false,
    selectedTech: 'nodejs',
    activeVulnId: null,
    blacklist: [],
    // Propriétés persistantes du scanneur
    discoveredEndpoints: [],
    lastAuditResult: null,
    // Vulnerability database across multiple stacks
    vulnerabilities: {
        nodejs: [
            {
                id: 'node-invoice',
                title: 'Accès Facture sans Validation d\'Ownership',
                route: 'GET /api/v1/invoices/:id',
                file: 'invoiceController.js',
                difficulty: 'Critique',
                explanation: 'La route récupère l\'ID de facture fourni dans la requête (req.params.id) et effectue une requête en base de données directe sans vérifier si l\'ID utilisateur de la session correspond à la colonne user_id de la facture. Un attaquant peut énumérer les IDs séquentiels.',
                vulnCode: `// GET /api/v1/invoices/:id
exports.getInvoice = async (req, res) => {
    try {
        const invoiceId = req.params.id;
        
        // 🔴 ERREUR CRITIQUE BOLA : Requête directe sans contrôle d'ownership
<span class="code-hl-danger">        const invoice = await Invoice.findById(invoiceId);</span>
        
        if (!invoice) {
            return res.status(404).json({ message: 'Facture non trouvée' });
        }
        
        res.status(200).json(invoice);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};`,
                repairedCode: `// GET /api/v1/invoices/:id
exports.getInvoice = async (req, res) => {
    try {
        const invoiceId = req.params.id;
        const currentUserId = req.user.id; // Récupéré du token JWT validé
        
        // 🟢 SÉCURISÉ : Jointure d'autorisation sémantique
<span class="code-hl-success">        const invoice = await Invoice.findOne({ 
            _id: invoiceId, 
            userId: currentUserId // Force la vérification d'appartenance
        });</span>
        
        if (!invoice) {
            // Renvoyer 404 au lieu de 403 pour éviter la découverte d'IDs
            return res.status(404).json({ message: 'Facture non trouvée' });
        }
        
        res.status(200).json(invoice);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};`,
                patched: false
            },
            {
                id: 'node-order',
                title: 'Téléchargement de Commande non Sécurisé',
                route: 'GET /api/v1/orders/:id/download',
                file: 'orderController.js',
                difficulty: 'Élevé',
                explanation: 'Aucune vérification sémantique n\'est faite pour valider si l\'acheteur connecté est bien l\'initiateur de la commande. Un utilisateur connecté lambda peut récupérer n\'importe quel reçu.',
                vulnCode: `// GET /api/v1/orders/:id/download
exports.downloadOrderReceipt = async (req, res) => {
    const orderId = req.params.id;
    
    // 🔴 VULNÉRABILITÉ : Pas de validation de droits d'accès
<span class="code-hl-danger">    const order = await Order.getById(orderId);</span>
    
    const fileStream = fs.createReadStream(order.pdfPath);
    fileStream.pipe(res);
};`,
                repairedCode: `// GET /api/v1/orders/:id/download
exports.downloadOrderReceipt = async (req, res) => {
    const orderId = req.params.id;
    const currentUserId = req.user.id;
    
    // 🟢 SÉCURISÉ : L'IA valide l'ownership de la commande
<span class="code-hl-success">    const order = await Order.findOne({ 
        id: orderId, 
        buyerId: currentUserId 
    });</span>
    
    if (!order) {
        return res.status(403).json({ error: 'Accès non autorisé' });
    }
    
    const fileStream = fs.createReadStream(order.pdfPath);
    fileStream.pipe(res);
};`,
                patched: false
            }
        ],
        php: [
            {
                id: 'php-invoice',
                title: 'Visualisation Facture WooCommerce IDOR',
                route: 'GET /wc-api/v3/invoices/?id=X',
                file: 'class-wc-invoice-api.php',
                difficulty: 'Critique',
                explanation: 'L\'extension utilise une requête globale wp_query basée uniquement sur l\'argument GET "id". Elle omet de vérifier si l\'ID de l\'utilisateur connecté correspond à l\'attribut de commande associé à la facture.',
                vulnCode: `public function get_invoice( $data ) {
    $invoice_id = $data['id'];
    
    // 🔴 ERREUR LOGIQUE : Pas de vérification de l'acheteur connecté
<span class="code-hl-danger">    $invoice = get_post( $invoice_id );</span>
    
    if ( ! $invoice ) {
        return new WP_Error( 'not_found', 'Invoice error', array( 'status' => 404 ) );
    }
    return $invoice;
}`,
                repairedCode: `public function get_invoice( $data ) {
    $invoice_id = $data['id'];
    $current_user_id = get_current_user_id();
    
    $invoice = get_post( $invoice_id );
    
    // 🟢 SÉCURISÉ : On s'assure que la facture appartient à l'utilisateur connecté
<span class="code-hl-success">    $associated_order = get_post_meta( $invoice_id, '_order_id', true );
    $order = wc_get_order( $associated_order );
    
    if ( ! $invoice || $order->get_customer_id() !== $current_user_id ) {</span>
        return new WP_Error( 'forbidden', 'Accès non autorisé', array( 'status' => 403 ) );
    }
    return $invoice;
}`,
                patched: false
            }
        ],
        rails: [
            {
                id: 'rails-invoice',
                title: 'Shopify Custom App Invoice Leak',
                route: 'GET /invoices/:id.json',
                file: 'invoices_controller.rb',
                difficulty: 'Critique',
                explanation: 'Le contrôleur utilise directement l\'index de la base de données. Un attaquant peut manipuler le format .json pour bypasser les filtres d\'affichage HTML habituels.',
                vulnCode: `class InvoicesController < ApplicationController
  def show
    # 🔴 ERREUR BOLA : Récupération directe sur la base de l'index
<span class="code-hl-danger">    @invoice = Invoice.find(params[:id])</span>
    render json: @invoice
  end
end`,
                repairedCode: `class InvoicesController < ApplicationController
  before_action :authenticate_customer!

  def show
    # 🟢 SÉCURISÉ : Scope de recherche limité aux factures du client connecté
<span class="code-hl-success">    @invoice = current_customer.invoices.find_by(id: params[:id])</span>
    
    if @invoice.nil?
      render json: { error: "Facture introuvable ou non autorisée" }, status: :not_found
    else
      render json: @invoice
    end
  end
end`,
                patched: false
            }
        ]
    }
};

/**
 * Persist the current reactive state back to localStorage.
 */
export function savePersistedState() {
    try {
        const serialized = JSON.stringify({
            activeTab: state.activeTab,
            securityScore: state.securityScore,
            metrics: state.metrics,
            scanned: state.scanned,
            blacklist: state.blacklist,
            selectedTech: state.selectedTech,
            shieldActive: state.shieldActive,
            vulnerabilities: state.vulnerabilities,
            // Persistence du scanneur pour éviter que l'actualisation ne tue le scan
            discoveredEndpoints: state.discoveredEndpoints || [],
            lastAuditResult: state.lastAuditResult || null
        });
        localStorage.setItem('bola_shield_state', serialized);
    } catch (e) {
        console.error('Failed to save state to localStorage', e);
    }
}

/**
 * Load previous session state if stored in localStorage.
 */
export function loadPersistedState() {
    try {
        const serialized = localStorage.getItem('bola_shield_state');
        if (!serialized) return false;

        const parsed = JSON.parse(serialized);
        
        // Restore vulnerabilities patched states
        if (parsed.vulnerabilities) {
            Object.keys(parsed.vulnerabilities).forEach(tech => {
                parsed.vulnerabilities[tech].forEach(pv => {
                    const localVuln = state.vulnerabilities[tech].find(v => v.id === pv.id);
                    if (localVuln) localVuln.patched = pv.patched;
                });
            });
        }

        state.securityScore = parsed.securityScore ?? state.securityScore;
        state.activeTab = parsed.activeTab ?? state.activeTab;
        state.metrics = parsed.metrics ?? state.metrics;
        state.scanned = parsed.scanned ?? state.scanned;
        state.blacklist = parsed.blacklist ?? state.blacklist;
        state.selectedTech = parsed.selectedTech ?? state.selectedTech;
        state.shieldActive = parsed.shieldActive ?? state.shieldActive;
        
        // Restauration de l'état du scanneur
        state.discoveredEndpoints = parsed.discoveredEndpoints ?? [];
        state.lastAuditResult = parsed.lastAuditResult ?? null;

        return true;
    } catch (e) {
        console.error('Failed to load state from localStorage', e);
        return false;
    }
}

/**
 * Recalculate the global security score and sync UI widgets.
 */
export function recalculateSecurityScore() {
    const hasScan = state.scanned && state.discoveredEndpoints && state.discoveredEndpoints.length > 0;
    
    let score = 30;
    let exposureRate = 72;
    let patchedVulns = 0;
    let totalVulns = 0;
    
    Object.keys(state.vulnerabilities).forEach(tech => {
        state.vulnerabilities[tech].forEach(v => {
            totalVulns++;
            if (v.patched) patchedVulns++;
        });
    });

    if (hasScan) {
        let baseScore = 50;
        const live = state.lastAuditResult;
        if (live) {
            if (live.notAuditable) {
                baseScore = 55;
            } else if (live.isBOLA) {
                baseScore = 25;
            } else {
                baseScore = 85;
            }
        }
        if (state.shieldActive) baseScore += 15;
        score = Math.min(baseScore, 100);
        exposureRate = Math.max(100 - score, 0);
    } else {
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

    const blockedMetric = document.getElementById('metric-blocked-attacks');
    if (blockedMetric) blockedMetric.innerText = state.metrics.blockedAttacks.toLocaleString();
    
    const leakedMetric = document.getElementById('metric-data-leaked');
    if (leakedMetric) leakedMetric.innerText = state.metrics.dataLeaked.toLocaleString();
    
    const savingsMetric = document.getElementById('metric-financial-savings');
    if (savingsMetric) savingsMetric.innerText = `${state.metrics.financialSavings.toLocaleString()} €`;

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

    const widget = document.getElementById('security-health-widget');
    const valueText = document.getElementById('security-health-value');
    const statusText = document.getElementById('security-health-status');
    const circle = document.querySelector('.progress-ring-circle');

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
