const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 3000;
const JWT_SECRET = 's3cr3t_k3y_for_b0la_sh13ld_t3st1ng_0nly';

// Bases de données simulées
const users = new Map(); // email -> { id, email, role }
const orders = new Map(); // id -> { id, userId, items, total }

// Peuplement initial de commandes pour tester
const seedData = () => {
    // Faux IDs complexes
    orders.set('ord_9f8a7b6c5d4e3f2a1', { id: 'ord_9f8a7b6c5d4e3f2a1', userId: 'user_admin', items: ['Server Rack'], total: 4500 });
    orders.set('ord_1a2b3c4d5e6f7g8h9', { id: 'ord_1a2b3c4d5e6f7g8h9', userId: 'user_arthur', items: ['Laptop', 'Mouse'], total: 1250 });
};
seedData();

// Middlewares
app.use(cors());
app.use(express.json());

// Simulation de latence réseau (100ms - 300ms) pour tester les timeouts du scanner
app.use((req, res, next) => {
    const delay = Math.floor(Math.random() * 200) + 100;
    setTimeout(next, delay);
});

// ==========================================
// ROUTES
// ==========================================

// Découverte OpenAPI
app.get('/openapi.json', (req, res) => {
    res.json({
        openapi: "3.0.0",
        info: { title: "Robust Mock Target API", version: "2.0.0" },
        paths: {
            "/api/auth/register": { post: { summary: "Inscription utilisateur" } },
            "/api/auth/login": { post: { summary: "Connexion utilisateur" } },
            "/api/orders/{id}": { get: { summary: "Récupération d'une commande" } }
        }
    });
});

// Inscription
app.post('/api/auth/register', (req, res) => {
    const { email, password } = req.body;
    
    // Input validation robuste
    if (!email || !password) {
        return res.status(422).json({ status: 'error', code: 'ERR_MISSING_FIELDS', message: 'Email and password are required' });
    }
    if (password.length < 6) {
        return res.status(422).json({ status: 'error', code: 'ERR_WEAK_PASSWORD', message: 'Password must be at least 6 characters long' });
    }

    const userId = 'usr_' + Buffer.from(email).toString('base64').substring(0, 10);
    const user = { id: userId, email, role: 'customer' };
    users.set(email, user);

    // Génération d'un vrai JWT
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
    
    res.status(201).json({ status: 'success', token, user });
});

// Connexion
app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(422).json({ status: 'error', code: 'ERR_MISSING_FIELDS', message: 'Email and password are required' });
    }

    const user = users.get(email);
    if (!user) {
        return res.status(401).json({ status: 'error', code: 'ERR_INVALID_CREDENTIALS', message: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ status: 'success', token, user });
});

// Middleware d'authentification stricte
const authenticateJWT = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.split(' ')[1];
        jwt.verify(token, JWT_SECRET, (err, user) => {
            if (err) return res.status(403).json({ status: 'error', code: 'ERR_INVALID_TOKEN', message: 'Token is invalid or expired' });
            req.user = user;
            next();
        });
    } else {
        res.status(401).json({ status: 'error', code: 'ERR_MISSING_TOKEN', message: 'Authorization header is required' });
    }
};

// Endpoint vulnérable au BOLA
app.get('/api/orders/:id', authenticateJWT, (req, res) => {
    const orderId = req.params.id;
    const order = orders.get(orderId);

    if (!order) {
        return res.status(404).json({ status: 'error', code: 'ERR_NOT_FOUND', message: 'Order not found' });
    }

    // ==========================================
    // VULNERABILITÉ BOLA (IDOR) :
    // L'API vérifie si l'utilisateur est bien connecté (authenticateJWT passe),
    // MAIS elle ne vérifie pas si la commande lui appartient réellement !
    // Code manquant : if (order.userId !== req.user.id) return res.status(403).json(...);
    // ==========================================

    res.json({ status: 'success', data: order });
});

// Gestion des erreurs 404 globales
app.use((req, res) => {
    res.status(404).json({ status: 'error', code: 'ERR_NOT_FOUND', message: 'Route not found' });
});

// Lancement du serveur
app.listen(PORT, () => {
    console.log(`[TARGET API ROBUSTE] Serveur Express + JWT démarré sur http://localhost:${PORT}`);
    console.log(`[TARGET API ROBUSTE] Moteur OpenAPI: http://localhost:${PORT}/openapi.json`);
});
