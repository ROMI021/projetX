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
