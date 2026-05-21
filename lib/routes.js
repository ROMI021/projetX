/* ======================================================================
   API routes moved from server.js — uses injected context for helpers
   ====================================================================== */

export function makeHandleApi(context) {
    return async function handleApi(req, res, url) {
        const ip = context.clientIp(req);

        if (req.method === 'OPTIONS') {
            return context.sendJSON(res, 204, {});
        }

        // ---- Gateway Barrier / controlled reverse proxy ----
        if (url.pathname === '/api/v1/gateway/config' && req.method === 'GET') {
            return context.sendJSON(res, 200, context.summarizeGateway());
        }
        if (url.pathname === '/api/v1/gateway/config' && req.method === 'PUT') {
            const body = await context.readBody(req).catch(() => ({}));
            if (body.targetBase !== undefined) context.store.gateway.targetBase = body.targetBase ? context.normalizeTargetInput(body.targetBase) : '';
            if (body.enabled !== undefined) context.store.gateway.enabled = Boolean(body.enabled);
            if (body.mode && ['observe', 'modify-approved'].includes(body.mode)) context.store.gateway.mode = body.mode;
            if (body.approvedRequestHeaders && typeof body.approvedRequestHeaders === 'object') context.store.gateway.approvedRequestHeaders = body.approvedRequestHeaders;
            if (body.approvedResponseHeaders && typeof body.approvedResponseHeaders === 'object') context.store.gateway.approvedResponseHeaders = body.approvedResponseHeaders;
            if (body.approvedJsonResponsePatch && typeof body.approvedJsonResponsePatch === 'object') context.store.gateway.approvedJsonResponsePatch = body.approvedJsonResponsePatch;
            context.saveStore();
            context.broadcastEvent({ origin: 'GATEWAY', type: 'info', msg: `Gateway ${context.store.gateway.enabled ? 'activee' : 'desactivee'} en mode ${context.store.gateway.mode}.` });
            return context.sendJSON(res, 200, context.summarizeGateway());
        }
        if (url.pathname === '/api/v1/gateway/transactions' && req.method === 'GET') {
            return context.sendJSON(res, 200, context.store.gateway.transactions.slice(-100));
        }
        if (url.pathname === '/api/v1/gateway/suggestions' && req.method === 'GET') {
            return context.sendJSON(res, 200, context.store.gateway.pendingSuggestions || []);
        }

        // ---- Discovery ----
        if (url.pathname === '/api/v1/_discover' && req.method === 'GET') {
            if (!context.ENABLE_DEMO_TARGET) {
                return context.sendJSON(res, 200, {
                    base: `http://${req.headers.host}`,
                    mode: 'live-only',
                    routes: { register: '', login: '', target: '' },
                    endpoints: [],
                    note: 'Cible locale de demonstration desactivee. Utilisez /api/v1/scanner/discover avec apiBase pour auditer une cible live autorisee.'
                });
            }
            return context.sendJSON(res, 200, {
                base: `http://${req.headers.host}`,
                routes: {
                    register: '/api/v1/users/register',
                    login: '/api/v1/users/login',
                    target: '/api/v1/invoices/:id'
                },
                endpoints: [
                    { path: 'GET /api/v1/invoices/:id', authRequired: true, resource: 'Factures (Invoice)', risk: context.store.patched['node-invoice'] ? 'AUCUN' : 'CRITIQUE' },
                    { path: 'GET /api/v1/orders/:id/download', authRequired: true, resource: 'Reçus de Commande', risk: context.store.patched['node-order'] ? 'AUCUN' : 'ÉLEVÉ' },
                    { path: 'GET /api/v1/customers/:id/profile', authRequired: true, resource: 'Profil Client', risk: 'AUCUN' },
                    { path: 'GET /api/v1/products/:id', authRequired: false, resource: 'Détails Produits', risk: 'AUCUN' }
                ]
            });
        }

        if (url.pathname === '/api/v1/scanner/discover' && req.method === 'POST') {
            const body = await context.readBody(req).catch(() => ({}));
            if (!body.apiBase && !context.ENABLE_DEMO_TARGET) return context.sendLiveTargetRequired(res);
            const targetBase = context.normalizeTargetInput(body.apiBase || `http://${req.headers.host}`);
            const discovery = await context.discoverTarget(targetBase);
            context.store.currentDiscovery = discovery;
            context.saveStore();
            return context.sendJSON(res, 200, discovery);
        }

        // ---- Register ----
        if (url.pathname === '/api/v1/users/register' && req.method === 'POST') {
            if (!context.ENABLE_DEMO_TARGET) return context.sendJSON(res, 404, { error: 'route inconnue', path: url.pathname });
            const body = await context.readBody(req).catch(() => ({}));
            const { email, password, name } = body;
            if (!email || !password) return context.sendJSON(res, 400, { error: 'email/password requis' });
            if (context.store.usersByEmail.has(email)) return context.sendJSON(res, 409, { error: 'email déjà utilisé' });

            const id = 'usr_' + context.crypto.randomBytes(5).toString('hex');
            const token = 'tok_' + context.crypto.randomBytes(12).toString('hex');
            const user = { id, email, name: name || email.split('@')[0] };
            context.store.users.set(token, user);
            context.store.usersByEmail.set(email, { ...user, password, token });

            const invoiceId = 'inv_' + context.crypto.randomBytes(6).toString('hex');
            const orderId = 'ord_' + context.crypto.randomBytes(6).toString('hex');
            context.store.invoices.set(invoiceId, {
                id: invoiceId, userId: id, amount: context.crypto.randomInt(100, 9100),
                customer: user.name, items: ['Produit 1', 'Produit 2']
            });
            context.store.orders.set(orderId, {
                id: orderId, userId: id, buyerId: id, total: context.crypto.randomInt(100, 9100),
                pdfPath: `/secret/${orderId}.pdf`
            });

            context.broadcastEvent({ origin: 'API', type: 'info', msg: `Nouveau compte créé : ${email} (id=${id}, invoice=${invoiceId})` });
            context.saveStore();
            return context.sendJSON(res, 201, { id, token, accessToken: token, email, name: user.name, invoiceId, orderId });
        }

        // ---- Login ----
        if (url.pathname === '/api/v1/users/login' && req.method === 'POST') {
            if (!context.ENABLE_DEMO_TARGET) return context.sendJSON(res, 404, { error: 'route inconnue', path: url.pathname });
            const body = await context.readBody(req).catch(() => ({}));
            const rec = context.store.usersByEmail.get(body.email);
            if (!rec || rec.password !== body.password) return context.sendJSON(res, 401, { error: 'identifiants invalides' });
            context.broadcastEvent({ origin: 'API', type: 'info', msg: `Connexion : ${body.email}` });
            return context.sendJSON(res, 200, { id: rec.id, token: rec.token, accessToken: rec.token, email: rec.email });
        }

        // ---- Vulnerable endpoint: invoice by id (BOLA target) ----
        const invoiceMatch = url.pathname.match(/^\/api\/v1\/invoices\/([^/]+)$/);
        if (invoiceMatch && req.method === 'GET') {
            if (!context.ENABLE_DEMO_TARGET) return context.sendJSON(res, 404, { error: 'route inconnue', path: url.pathname });
            const id = invoiceMatch[1];
            const reqUser = context.getBearerUser(req);
            if (!reqUser) return context.sendJSON(res, 401, { error: 'authentification requise' });

            const blockReason = context.shieldShouldBlock(ip, url.pathname);
            const invoice = context.store.invoices.get(id);

            if (context.store.patched['node-invoice']) {
                if (!invoice || invoice.userId !== reqUser.id) {
                    context.broadcastEvent({ origin: 'SHIELD', type: 'success', msg: `[PATCH] Accès facture ${id} refusé pour ${reqUser.email} (ownership invalide).` });
                    context.store.metrics.blockedAttacks++;
                    context.saveStore();
                    return context.sendJSON(res, 404, { message: 'Facture non trouvée' });
                }
                return context.sendJSON(res, 200, invoice);
            }

            if (blockReason && invoice && invoice.userId !== reqUser.id) {
                context.broadcastEvent({ origin: 'SHIELD', type: 'success', msg: `[GATEWAY] Tentative BOLA bloquée sur ${id} par ${reqUser.email} — motif: ${blockReason}.` });
                context.store.metrics.blockedAttacks++;
                context.saveStore();
                return context.sendJSON(res, 403, { message: 'Accès refusé par la passerelle' });
            }

            if (!invoice) return context.sendJSON(res, 404, { message: 'Facture non trouvée' });
            if (invoice.userId !== reqUser.id) {
                context.broadcastEvent({ origin: 'ALERT', type: 'alert', msg: `[FUITE BOLA] ${reqUser.email} a accédé à la facture ${id} appartenant à un tiers.` });
                context.store.metrics.dataLeaked += 1;
                context.saveStore();
            }
            return context.sendJSON(res, 200, invoice);
        }

        // ---- Vulnerable endpoint: order download ----
        const orderMatch = url.pathname.match(/^\/api\/v1\/orders\/([^/]+)\/download$/);
        if (orderMatch && req.method === 'GET') {
            if (!context.ENABLE_DEMO_TARGET) return context.sendJSON(res, 404, { error: 'route inconnue', path: url.pathname });
            const id = orderMatch[1];
            const reqUser = context.getBearerUser(req);
            if (!reqUser) return context.sendJSON(res, 401, { error: 'authentification requise' });
            const order = context.store.orders.get(id);

            if (context.store.patched['node-order']) {
                if (!order || order.buyerId !== reqUser.id) return context.sendJSON(res, 404, { message: 'Commande non trouvée' });
                return context.sendJSON(res, 200, { id: order.id, total: order.total, pdfPath: order.pdfPath, message: 'PDF prêt' });
            }
            if (!order) return context.sendJSON(res, 404, { message: 'Commande non trouvée' });
            if (order.buyerId !== reqUser.id) {
                context.broadcastEvent({ origin: 'ALERT', type: 'alert', msg: `[FUITE BOLA] ${reqUser.email} a téléchargé la commande ${id} d'un tiers.` });
                context.store.metrics.dataLeaked += 1;
                context.saveStore();
            }
            return context.sendJSON(res, 200, { id: order.id, total: order.total, pdfPath: order.pdfPath, message: 'PDF prêt (LEAK)' });
        }

        // ---- Safe endpoints used to show non-vulnerable cases ----
        if (/^\/api\/v1\/customers\/([^/]+)\/profile$/.test(url.pathname) && req.method === 'GET') {
            if (!context.ENABLE_DEMO_TARGET) return context.sendJSON(res, 404, { error: 'route inconnue', path: url.pathname });
            const reqUser = context.getBearerUser(req);
            if (!reqUser) return context.sendJSON(res, 401, { error: 'authentification requise' });
            const targetId = url.pathname.split('/')[4];
            if (reqUser.id !== targetId) return context.sendJSON(res, 403, { error: 'Accès refusé' });
            return context.sendJSON(res, 200, { id: reqUser.id, email: reqUser.email, name: reqUser.name });
        }
        if (/^\/api\/v1\/products\/([^/]+)$/.test(url.pathname) && req.method === 'GET') {
            if (!context.ENABLE_DEMO_TARGET) return context.sendJSON(res, 404, { error: 'route inconnue', path: url.pathname });
            const id = url.pathname.split('/').pop();
            return context.sendJSON(res, 200, { id, name: `Produit ${id}`, price: 19.99, public: true });
        }

        // ---- Firewall: blacklist ----
        if (url.pathname === '/api/v1/firewall/blacklist' && req.method === 'GET') {
            return context.sendJSON(res, 200, context.store.blacklist);
        }
        if (url.pathname === '/api/v1/firewall/blacklist' && req.method === 'POST') {
            const body = await context.readBody(req).catch(() => ({}));
            if (!body.ip) return context.sendJSON(res, 400, { error: 'ip requise' });
            if (context.store.blacklist.some(b => b.ip === body.ip)) return context.sendJSON(res, 409, { error: 'déjà bloquée' });
            const entry = { ip: body.ip, reason: body.reason || 'Ajout manuel', date: context.nowDateStr() };
            context.store.blacklist.unshift(entry);
            context.broadcastEvent({ origin: 'SHIELD', type: 'success', msg: `IP ${body.ip} bloquée (${entry.reason}).` });
            context.saveStore();
            return context.sendJSON(res, 201, entry);
        }
        if (url.pathname === '/api/v1/firewall/blacklist' && req.method === 'DELETE') {
            context.store.blacklist = [];
            context.broadcastEvent({ origin: 'SHIELD', type: 'info', msg: 'Blacklist vidée.' });
            context.saveStore();
            return context.sendJSON(res, 200, { ok: true });
        }
        const blDelMatch = url.pathname.match(/^\/api\/v1\/firewall\/blacklist\/(.+)$/);
        if (blDelMatch && req.method === 'DELETE') {
            const ipToRemove = decodeURIComponent(blDelMatch[1]);
            context.store.blacklist = context.store.blacklist.filter(b => b.ip !== ipToRemove);
            context.broadcastEvent({ origin: 'SHIELD', type: 'info', msg: `IP ${ipToRemove} débloquée.` });
            context.saveStore();
            return context.sendJSON(res, 200, { ok: true });
        }

        // ---- Firewall: rules ----
        if (url.pathname === '/api/v1/firewall/rules' && req.method === 'GET') {
            return context.sendJSON(res, 200, {
                ...context.store.rules,
                currentAudit: context.store.lastAudit,
                currentTarget: context.store.lastAudit?.base || context.store.currentDiscovery?.base || null,
                recommendations: context.firewallRecommendations()
            });
        }
        if (url.pathname === '/api/v1/firewall/rules' && req.method === 'PUT') {
            const body = await context.readBody(req).catch(() => ({}));
            Object.assign(context.store.rules, body);
            context.broadcastEvent({ origin: 'SHIELD', type: 'info', msg: `Regles passerelle mises a jour : ${JSON.stringify(body)}` });
            context.saveStore();
            return context.sendJSON(res, 200, {
                ...context.store.rules,
                currentAudit: context.store.lastAudit,
                currentTarget: context.store.lastAudit?.base || context.store.currentDiscovery?.base || null,
                recommendations: context.firewallRecommendations()
            });
        }

        // ---- Patch state (server-enforced fix per vulnerability) ----
        if (url.pathname === '/api/v1/patches' && req.method === 'GET') {
            return context.sendJSON(res, 200, context.ENABLE_DEMO_TARGET ? context.store.patched : {});
        }
        const patchMatch = url.pathname.match(/^\/api\/v1\/patches\/([^/]+)$/);
        if (patchMatch && req.method === 'POST') {
            if (!context.ENABLE_DEMO_TARGET) {
                return context.sendJSON(res, 409, {
                    error: 'correctif local desactive',
                    hint: 'Mode live-only: appliquez les corrections dans le code de la cible, puis relancez un audit.'
                });
            }
            const id = patchMatch[1];
            if (!(id in context.store.patched)) return context.sendJSON(res, 404, { error: 'vuln inconnue' });
            context.store.patched[id] = true;
            context.broadcastEvent({ origin: 'SHIELD', type: 'success', msg: `Correctif appliqué côté serveur sur "${id}". Ownership check actif.` });
            context.saveStore();
            return context.sendJSON(res, 200, { id, patched: true });
        }
        if (patchMatch && req.method === 'DELETE') {
            if (!context.ENABLE_DEMO_TARGET) return context.sendJSON(res, 404, { error: 'route inconnue', path: url.pathname });
            const id = patchMatch[1];
            if (!(id in context.store.patched)) return context.sendJSON(res, 404, { error: 'vuln inconnue' });
            context.store.patched[id] = false;
            context.saveStore();
            return context.sendJSON(res, 200, { id, patched: false });
        }

        // ---- Metrics ----
        if (url.pathname === '/api/v1/metrics' && req.method === 'GET') {
            const hasScan = context.store.currentDiscovery && Array.isArray(context.store.currentDiscovery.endpoints) && context.store.currentDiscovery.endpoints.length > 0;
            
            let exposure = 0;
            let total = 0;
            let blocked = context.store.metrics.blockedAttacks;
            let leaked = context.store.metrics.dataLeaked;
            
            if (hasScan) {
                const endpoints = context.store.currentDiscovery.endpoints;
                const live = context.store.lastAudit;
                let score = 50;
                
                const scanProbes = live?.attempts?.length || 0;
                blocked = context.store.metrics.blockedAttacks + scanProbes;
                
                if (live) {
                    if (live.notAuditable) {
                        score = 55;
                        leaked = context.store.metrics.dataLeaked;
                    } else if (live.isBOLA) {
                        score = 25;
                        leaked = context.store.metrics.dataLeaked + endpoints.length;
                    } else {
                        score = 85;
                        leaked = context.store.metrics.dataLeaked;
                    }
                } else {
                    leaked = endpoints.length * 1500;
                }
                
                if (context.store.rules.shieldActive) {
                    score += 15;
                }
                exposure = Math.max(0, 100 - score);
                total = endpoints.length;
            } else {
                const safeRoutes = Object.values(context.store.patched).filter(Boolean).length;
                exposure = Math.max(0, 100 - safeRoutes * 20 - (context.store.rules.shieldActive ? 15 : 0));
                total = context.store.invoices.size + context.store.orders.size;
            }

            return context.sendJSON(res, 200, {
                ...context.store.metrics,
                exposureRate: exposure,
                blockedAttacks: blocked,
                dataLeaked: leaked,
                financialSavings: blocked * 170,
                users: context.store.users.size,
                invoices: context.store.invoices.size,
                orders: context.store.orders.size,
                totalResources: total
            });
        }

        // ---- Exportable audit report ----
        if (url.pathname === '/api/v1/report' && req.method === 'GET') {
            const format = url.searchParams.get('format') || 'json';
            if (format === 'markdown') {
                res.statusCode = 200;
                context.setSecurityHeaders(res);
                res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
                res.setHeader('Content-Disposition', 'attachment; filename="bola-shield-report.md"');
                return res.end(context.buildAuditReport('markdown'));
            }
            return context.sendJSON(res, 200, context.buildAuditReport('json'));
        }

        // ---- Graph (mapper) ----
        if (url.pathname === '/api/v1/graph' && req.method === 'GET') {
            const auditGraph = context.buildAuditGraph();
            if (auditGraph) return context.sendJSON(res, 200, auditGraph);

            const users = [...context.store.users.values()].slice(0, 4);
            const nodes = [];
            const links = [];
            const ySpacing = 360 / Math.max(users.length, 1);
            users.forEach((u, i) => {
                const y = 100 + i * ySpacing;
                const clientNode = { id: `client_${u.id}`, label: u.name || u.email, x: 120, y, type: 'user' };
                const sessionNode = { id: `session_${u.id}`, label: 'Session', x: 300, y, type: 'session' };
                nodes.push(clientNode, sessionNode);
                links.push({ source: clientNode.id, target: sessionNode.id, type: 'secure' });

                const inv = [...context.store.invoices.values()].find(x => x.userId === u.id);
                const ord = [...context.store.orders.values()].find(x => x.userId === u.id);
                if (ord) {
                    const orderNode = { id: `order_${ord.id}`, label: `Cmd ${ord.id.slice(-4)}`, x: 500, y, type: 'object', owner: u.id };
                    nodes.push(orderNode);
                    links.push({ source: sessionNode.id, target: orderNode.id, type: 'secure' });
                }
                if (inv) {
                    const invoiceNode = { id: `invoice_${inv.id}`, label: `Fact ${inv.id.slice(-4)}`, x: 680, y, type: 'object', owner: u.id };
                    nodes.push(invoiceNode);
                    const ordRef = `order_${ord?.id}`;
                    if (ord) links.push({ source: ordRef, target: invoiceNode.id, type: 'secure' });
                }
            });

            if (!context.store.patched['node-invoice'] && users.length >= 2) {
                const sourceSession = `session_${users[1].id}`;
                const targetInvoice = [...context.store.invoices.values()].find(x => x.userId === users[0].id);
                if (targetInvoice) {
                    links.push({ id: 'bola_link_a', source: sourceSession, target: `invoice_${targetInvoice.id}`, type: 'bola' });
                }
            }
            return context.sendJSON(res, 200, { nodes, links, patched: context.store.patched });
        }

        // ---- Live audit orchestration (server-driven) ----
        if (url.pathname === '/api/v1/scanner/audit' && req.method === 'POST') {
            const body = await context.readBody(req).catch(() => ({}));
            if (!body.apiBase && !context.ENABLE_DEMO_TARGET) return context.sendLiveTargetRequired(res);
            const targetBase = context.normalizeTargetInput(body.apiBase || `http://${req.headers.host}`);
            const discovery = await context.discoverTarget(targetBase);
            const reg = body.register || discovery.routes?.register;
            const login = body.login || discovery.routes?.login;
            const target = body.target || discovery.routes?.target;
            const suppliedTokenA = body.tokenA || body.accessTokenA || '';
            const suppliedTokenB = body.tokenB || body.accessTokenB || '';
            let cookieA = body.cookieA || body.sessionCookieA || '';
            let cookieB = body.cookieB || body.sessionCookieB || '';
            
            const fileCreds = context.loadTargetCredentials(targetBase);
            let userA = body.userA;
            let userB = body.userB;
            let objectId = body.objectId || '';
            let hasPredefinedCredentials = false;

            if (fileCreds) {
                context.broadcastEvent({ 
                    origin: 'AUDIT', 
                    type: 'info', 
                    msg: `[CREDENTIALS] Fichier credentials.json trouvé pour la cible : ${targetBase}` 
                });
                if (fileCreds.userA) userA = fileCreds.userA;
                if (fileCreds.userB) userB = fileCreds.userB;
                if (fileCreds.objectId && !objectId) objectId = fileCreds.objectId;
                if (fileCreds.cookieA && !cookieA) cookieA = fileCreds.cookieA;
                if (fileCreds.cookieB && !cookieB) cookieB = fileCreds.cookieB;
                if (fileCreds.sessionCookieA && !cookieA) cookieA = fileCreds.sessionCookieA;
                if (fileCreds.sessionCookieB && !cookieB) cookieB = fileCreds.sessionCookieB;
                hasPredefinedCredentials = true;
                context.broadcastEvent({
                    origin: 'AUDIT',
                    type: 'info',
                    msg: `[CREDENTIALS] Comptes injectés : A=${userA?.email || 'N/A'}, B=${userB?.email || 'N/A'}, ID Objet=${objectId || 'N/A'}`
                });
            }

            const tokenAFromConfig = suppliedTokenA || fileCreds?.tokenA || fileCreds?.accessTokenA || '';
            const tokenBFromConfig = suppliedTokenB || fileCreds?.tokenB || fileCreds?.accessTokenB || '';
            const hasManualSession = Boolean(objectId && ((tokenAFromConfig && tokenBFromConfig) || (cookieA && cookieB)));
            const runId = context.crypto.randomBytes(4).toString('hex');
            const passwordA = `Audit-${runId}-A`;
            const passwordB = `Audit-${runId}-B`;
            if (!userA) userA = { email: `user_a_${Date.now()}_${runId}@audit.local`, password: passwordA, name: 'Audit A' };
            if (!userB) userB = { email: `user_b_${Date.now()}_${runId}@audit.local`, password: passwordB, name: 'Audit B' };

            const skipRegistration = hasPredefinedCredentials || hasManualSession;

            if (!target || (!skipRegistration && (!reg || !login))) {
                const noAuth = discovery.authModel === 'no-public-auth-routes-detected' || (!reg && !login);
                const publicProbes = await context.probePublicEndpoints(targetBase, discovery);
                return context.sendJSON(res, 200, context.passiveAuditPayload(targetBase, discovery, noAuth ? 'Aucune route login/inscription publique detectee' : 'Configuration audit incomplete', {
                    target,
                    authModel: discovery.authModel,
                    publicProbes,
                    hint: noAuth
                        ? 'Mode URL-only: la surface publique a ete analysee, mais un audit BOLA actif exige deux sessions utilisateur ou une inscription publique automatisable.'
                        : 'Le lien a ete analyse, mais les routes publiques ne suffisent pas pour executer un audit multi-acteurs actif.'
                }));
            }

            context.broadcastEvent({ origin: 'AUDIT', type: 'warning', msg: `Audit serveur démarré sur ${targetBase} (${target})` });

            try {
                let tokenA = tokenAFromConfig;
                let tokenB = tokenBFromConfig;
                let regA = { data: null, attempts: [] };
                let regB = { data: null, attempts: [] };

                if (!skipRegistration) {
                    context.broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[INSCRIPTION] Création des comptes d audit autorises sur ${context.joinTargetUrl(targetBase, reg)}...` });
                    const registerAUrl = context.joinTargetUrl(targetBase, reg);
                    const registerBUrl = context.joinTargetUrl(targetBase, reg);
                    const registerHints = [
                        { captchaToken: 'valid_human_token', termsAccepted: true, middleName: '' },
                        { gRecaptchaResponse: 'valid_human_token', termsAccepted: true, middleName: '' },
                        { recaptchaToken: 'valid_human_token', termsAccepted: true, middleName: '' },
                        { captchaToken: 'valid_human_token', honeypot: '' }
                    ];
                    const registerPayloadsA = [...(body.registerPayloadA ? [body.registerPayloadA] : []), ...registerHints];
                    const registerPayloadsB = [...(body.registerPayloadB ? [body.registerPayloadB] : []), ...registerHints];

                    await context.delayMs(Math.random() * 1000 + 800);

                    regA = await context.postAuthCandidate(registerAUrl, userA, 'register A', registerPayloadsA);
                    if (!regA.ok) {
                        context.broadcastEvent({
                            origin: 'AUDIT',
                            type: 'alert',
                            msg: `[ERREUR INSCRIPTION A] Échec de l'inscription User A. Code: ${regA.status}. ${regA.attempts.length} combinaisons testées.`
                        });
                        return context.sendJSON(res, 200, context.passiveAuditPayload(targetBase, discovery, `Inscription utilisateur A refusée par la cible (${regA.status})`, {
                            status: regA.status,
                            response: regA.data,
                            attempts: regA.attempts,
                            hint: 'Le serveur a refusé les schémas d\'inscription par défaut. Créez des comptes manuellement et configurez les dans data/credentials.json.'
                        }));
                    }

                    await context.delayMs(Math.random() * 2000 + 1500);

                    regB = await context.postAuthCandidate(registerBUrl, userB, 'register B', registerPayloadsB);
                    if (!regB.ok) {
                        context.broadcastEvent({
                            origin: 'AUDIT',
                            type: 'alert',
                            msg: `[ERREUR INSCRIPTION B] Échec de l'inscription User B. Code: ${regB.status}.`
                        });
                        return context.sendJSON(res, 200, context.passiveAuditPayload(targetBase, discovery, `Inscription utilisateur B refusée par la cible (${regB.status})`, {
                            status: regB.status,
                            response: regB.data,
                            attempts: regB.attempts,
                            hint: 'Le serveur a refusé la création du deuxième compte. Créez des comptes manuellement et configurez les dans data/credentials.json.'
                        }));
                    }

                    tokenA = context.extractToken(regA.data);
                    tokenB = context.extractToken(regB.data);
                    objectId = objectId || context.extractTargetObjectId(regA.data);

                    if ((!tokenA || !tokenB) && login) {
                        context.broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[LOGIN] Token manquant dans register. Tentative de login dynamique...` });

                        await context.delayMs(Math.random() * 1000 + 500);
                    const loginHints = [
                        { captchaToken: 'valid_human_token', middleName: '' },
                        { gRecaptchaResponse: 'valid_human_token', middleName: '' },
                        { recaptchaToken: 'valid_human_token', middleName: '' },
                        { captchaToken: 'valid_human_token', honeypot: '' }
                    ];
                    const loginPayloadsA = [...(body.loginPayloadA ? [body.loginPayloadA] : []), ...loginHints];
                    const loginPayloadsB = [...(body.loginPayloadB ? [body.loginPayloadB] : []), ...loginHints];

                    const loginA = await context.postAuthCandidate(context.joinTargetUrl(targetBase, login), userA, 'login A', loginPayloadsA);

                    await context.delayMs(Math.random() * 800 + 400);

                    const loginB = await context.postAuthCandidate(context.joinTargetUrl(targetBase, login), userB, 'login B', loginPayloadsB);
                    tokenA = tokenA || context.extractToken(loginA.data);
                    tokenB = tokenB || context.extractToken(loginB.data);
                    }
                }

                if (skipRegistration && !hasManualSession && login) {
                    if (!context.isCredentialAuthRoute(login)) {
                        const publicProbes = await context.probePublicEndpoints(targetBase, discovery);
                        return context.sendJSON(res, 200, context.passiveAuditPayload(targetBase, discovery, `Route de login non exploitable pour une connexion directe (${login})`, {
                            target,
                            login,
                            authModel: discovery.authModel,
                            publicProbes,
                            hint: 'Mode URL-only: la route detectee ressemble a une route de session/statut, pas a un endpoint login. La surface publique a ete analysee; un test BOLA actif necessite une inscription publique automatisable ou deux sessions autorisees.'
                        }));
                    }
                    context.broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[LOGIN DIRECT] Authentification de User A sur ${context.joinTargetUrl(targetBase, login)}...` });
                    const loginHints = [
                        { captchaToken: 'valid_human_token', middleName: '' },
                        { gRecaptchaResponse: 'valid_human_token', middleName: '' },
                        { recaptchaToken: 'valid_human_token', middleName: '' },
                        { captchaToken: 'valid_human_token', honeypot: '' }
                    ];
                    const loginPayloadsA = [...(body.loginPayloadA ? [body.loginPayloadA] : []), ...loginHints];
                    const loginA = await context.postAuthCandidate(context.joinTargetUrl(targetBase, login), userA, 'login A', loginPayloadsA);
                    if (!loginA.ok) {
                        context.broadcastEvent({ 
                            origin: 'AUDIT', 
                            type: 'alert', 
                            msg: `[ERREUR LOGIN A] Connexion directe refusée pour ${userA.email}. Code: ${loginA.status}. Détail: ${JSON.stringify(loginA.data || '')}` 
                        });
                        return context.sendJSON(res, 200, context.passiveAuditPayload(targetBase, discovery, `Connexion directe User A refusée par la cible (${loginA.status})`, {
                            status: loginA.status,
                            response: loginA.data,
                            attempts: loginA.attempts,
                            hint: 'Vérifiez les identifiants configurez dans data/credentials.json.'
                        }));
                    }
                    tokenA = context.extractToken(loginA.data);
                    context.broadcastEvent({ origin: 'AUDIT', type: 'success', msg: `[LOGIN A] Token A récupéré: ${context.maskToken(tokenA)}` });

                    context.broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[LOGIN DIRECT] Authentification de User B sur ${context.joinTargetUrl(targetBase, login)}...` });
                    const loginPayloadsB = [...(body.loginPayloadB ? [body.loginPayloadB] : []), ...loginHints];
                    const loginB = await context.postAuthCandidate(context.joinTargetUrl(targetBase, login), userB, 'login B', loginPayloadsB);
                    if (!loginB.ok) {
                        context.broadcastEvent({ 
                            origin: 'AUDIT', 
                            type: 'alert', 
                            msg: `[ERREUR LOGIN B] Connexion directe refusée pour ${userB.email}. Code: ${loginB.status}. Détail: ${JSON.stringify(loginB.data || '')}` 
                        });
                        return context.sendJSON(res, 200, context.passiveAuditPayload(targetBase, discovery, `Connexion directe User B refusée par la cible (${loginB.status})`, {
                            status: loginB.status,
                            response: loginB.data,
                            attempts: loginB.attempts,
                            hint: 'Vérifiez les identifiants configurez dans data/credentials.json.'
                        }));
                    }
                    tokenB = context.extractToken(loginB.data);
                    context.broadcastEvent({ origin: 'AUDIT', type: 'success', msg: `[LOGIN B] Token B récupéré: ${context.maskToken(tokenB)}` });
                }

                if ((!tokenA || !tokenB) && (!cookieA || !cookieB)) {
                    context.broadcastEvent({ origin: 'AUDIT', type: 'alert', msg: `[ERREUR AUTHENTIFICATION] Impossible de récupérer des tokens valides.` });
                    const publicProbes = await context.probePublicEndpoints(targetBase, discovery);
                    return context.sendJSON(res, 200, context.passiveAuditPayload(targetBase, discovery, 'Token introuvable apres inscription/login', {
                        registerA: regA.data,
                        registerB: regB.data,
                        publicProbes,
                        hint: 'Mode URL-only: la surface publique a ete analysee, mais la cible ne fournit pas de session exploitable automatiquement pour un test BOLA actif.'
                    }));
                }
                
                if (!objectId) {
                    const candidateIds = new Set();
                    [regA.data, regB.data].forEach(payload => {
                        context.extractPossibleObjectIds(payload).forEach(id => candidateIds.add(id));
                    });
                    if (candidateIds.size === 0 && typeof userA.id === 'string') {
                        candidateIds.add(userA.id);
                    }
                    if (candidateIds.size === 0 && typeof userB.id === 'string') {
                        candidateIds.add(userB.id);
                    }
                    if (candidateIds.size > 0) {
                        objectId = [...candidateIds][0];
                        context.broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[ID CANDIDAT] Identifiant d objet trouvé automatiquement : ${objectId}` });
                    }
                }

                if (!objectId) {
                    context.broadcastEvent({ origin: 'AUDIT', type: 'alert', msg: `[ERREUR RESSOURCE] Identifiant d'objet cible introuvable.` });
                    const publicProbes = await context.probePublicEndpoints(targetBase, discovery);
                    return context.sendJSON(res, 200, context.passiveAuditPayload(targetBase, discovery, 'ID de ressource introuvable apres inscription', {
                        registerA: regA.data,
                        publicProbes,
                        hint: 'Mode URL-only: le scanner n a pas trouve d identifiant d objet prive exploitable dans les reponses publiques.'
                    }));
                }

                const targetPath = context.fillObjectIdRoute(target, objectId);
                const targetUrl = context.joinTargetUrl(targetBase, targetPath);
                const authScheme = body.authScheme || 'Bearer';

                await context.delayMs(Math.random() * 1500 + 1000);

                const ownerRead = await context.fetchJSONRemote(targetUrl, {
                    method: 'GET',
                    headers: context.authHeadersForSession({ token: tokenA, cookie: cookieA, scheme: authScheme, referer: targetUrl })
                });

                await context.delayMs(Math.random() * 600 + 300);

                const crossRead = await context.fetchJSONRemote(targetUrl, {
                    method: 'GET',
                    headers: context.authHeadersForSession({ token: tokenB, cookie: cookieB, scheme: authScheme, referer: targetUrl })
                });

                await context.delayMs(Math.random() * 500 + 200);

                const anonRead = await context.fetchJSONRemote(targetUrl, { method: 'GET' });

                const ownerFingerprint = context.stableResourceFingerprint(ownerRead.data);
                const crossFingerprint = context.stableResourceFingerprint(crossRead.data);
                const isBOLA = crossRead.ok
                    && crossRead.status === 200
                    && ownerRead.status === 200
                    && ownerFingerprint
                    && ownerFingerprint === crossFingerprint;
                const auditRecord = {
                    base: targetBase,
                    register: reg,
                    login,
                    target,
                    targetPath,
                    targetUrl,
                    objectId,
                    ownerStatus: ownerRead.status,
                    crossStatus: crossRead.status,
                    anonStatus: anonRead.status,
                    evidence: {
                        ownerFingerprint,
                        crossFingerprint,
                        sameResource: ownerFingerprint === crossFingerprint
                    },
                    isBOLA,
                    vulnerable: isBOLA,
                    authModel: discovery.authModel,
                    discovery,
                    at: new Date().toISOString()
                };
                context.store.lastAudit = auditRecord;

                if (isBOLA) {
                    context.store.metrics.dataLeaked += 1;
                    context.broadcastEvent({ origin: 'ALERT', type: 'alert', msg: `[FUITE BOLA] Audit proxy confirme une fuite sur ${targetUrl}.` });
                } else {
                    context.store.metrics.blockedAttacks += crossRead.status === 401 || crossRead.status === 403 || crossRead.status === 404 ? 1 : 0;
                    context.broadcastEvent({ origin: 'AUDIT', type: 'success', msg: `Audit proxy termine : cross-read HTTP ${crossRead.status}.` });
                }
                context.saveStore();

                return context.sendJSON(res, 200, {
                    base: targetBase,
                    register: reg,
                    login,
                    target,
                    discovery,
                    objectId,
                    tokenA: context.maskToken(tokenA),
                    tokenB: context.maskToken(tokenB),
                    ownerStatus: ownerRead.status,
                    crossStatus: crossRead.status,
                    anonStatus: anonRead.status,
                    audit: auditRecord,
                    ownerData: ownerRead.data,
                    crossData: crossRead.data,
                    evidence: auditRecord.evidence,
                    isBOLA,
                    vulnerable: isBOLA
                });
            } catch (e) {
                return context.sendJSON(res, 502, {
                    error: 'Audit proxy impossible',
                    detail: context.publicError(e.message, 'La cible est indisponible ou refuse la requete configuree'),
                    hint: 'Le serveur local ne peut pas joindre la cible ou la cible refuse le format de requete configure.'
                });
            }
        }

        // ---- Chat (real, state-aware) ----
        if (url.pathname === '/api/v1/chat' && req.method === 'POST') {
            const body = await context.readBody(req).catch(() => ({}));
            const response = context.answerChat(body.message || '');
            context.broadcastEvent({ origin: 'CHAT', type: 'info', msg: `Question CISO : ${body.message?.slice(0, 80)}` });
            return context.sendJSON(res, 200, response);
        }

        // ---- Logs (SSE) ----
        if (url.pathname === '/api/v1/logs/stream' && req.method === 'GET') {
            context.setSecurityHeaders(res);
            context.setCorsHeaders(res);
            res.writeHead(200, {
                'Content-Type': 'text/event-stream',
                'Cache-Control': 'no-cache',
                'Connection': 'keep-alive'
            });
            res.write(`retry: 5000\n\n`);
            
            const lastEventId = req.headers['last-event-id'];
            let replayLogs = context.store.eventLog.slice(-25);
            if (lastEventId) {
                const idx = context.store.eventLog.findIndex(e => String(e.id) === lastEventId);
                if (idx !== -1) replayLogs = context.store.eventLog.slice(idx + 1);
            }

            for (const e of replayLogs) {
                res.write(`id: ${e.id}\ndata: ${JSON.stringify(e)}\n\n`);
            }
            context.store.sseClients.add(res);
            req.on('close', () => context.store.sseClients.delete(res));
            return;
        }

        return context.sendJSON(res, 404, { error: 'route inconnue', path: url.pathname });
    };
}
