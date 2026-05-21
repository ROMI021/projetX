const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = 3000;
const JWT_SECRET = 's3cr3t_k3y_for_b0la_sh13ld_t3st1ng_0nly';

// Bases de données simulées
const users = new Map(); // id -> { id, email, passwordHash, role, sensitiveData }
const usersByEmail = new Map(); // email -> id

// Peuplement initial
const seedData = () => {
    const adminId = 'usr_admin_' + Date.now();
    users.set(adminId, {
        id: adminId,
        email: 'admin@glotelho.cm',
        passwordHash: bcrypt.hashSync('SuperSecret123!', 10),
        role: 'admin',
        sensitiveData: { creditCard: '****-****-****-1234', address: '123 Admin Ave, Yaoundé' }
    });
    usersByEmail.set('admin@glotelho.cm', adminId);
};
seedData();

// ==========================================
// MIDDLEWARES DE SÉCURITÉ INDUSTRIELS
// ==========================================

// 1. Headers de sécurité (Helmet)
app.use(helmet());
app.use(helmet.hidePoweredBy());

// 2. CORS Restrictif (Ouvert pour le test, mais avec headers stricts)
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// 3. Parsing JSON sécurisé (limite de taille)
app.use(express.json({ limit: '100kb' }));

// 4. Rate Limiting (Anti-Bruteforce)
const apiLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 60, // Limite à 60 requêtes par minute (tolérant pour BOLA-Shield)
    message: { status: 'error', code: 'ERR_RATE_LIMIT', message: 'Too many requests, please try again later.' }
});
app.use('/api/', apiLimiter);

// 5. Simulation de latence réseau réaliste (50ms - 150ms)
app.use((req, res, next) => {
    const delay = Math.floor(Math.random() * 100) + 50;
    setTimeout(next, delay);
});

// ==========================================
// ROUTES
// ==========================================

// Accueil
app.get('/', (req, res) => {
    res.json({
        status: "success",
        message: "E-Commerce Secure API is online. Highly protected environment.",
        docs: "http://localhost:3000/openapi.json"
    });
});

// Découverte OpenAPI
app.get('/openapi.json', (req, res) => {
    res.json({
        openapi: "3.0.0",
        info: { title: "Secure E-Commerce API", version: "3.0.0" },
        paths: {
            "/api/auth/register": { post: { summary: "Inscription utilisateur" } },
            "/api/auth/login": { post: { summary: "Connexion utilisateur" } },
            "/api/users/me": { get: { summary: "Mon profil" } },
            "/api/users/{id}": { get: { summary: "Profil détaillé (Admin/Support only)" } }
        }
    });
});

// Inscription
app.post('/api/auth/register', async (req, res) => {
    const { email, password, captchaToken } = req.body;
    
    // Simulation d'un Anti-Bot robuste (CAPTCHA)
    if (!captchaToken || captchaToken !== 'valid_human_token') {
        return res.status(403).json({ 
            status: 'error', 
            code: 'ERR_BOT_DETECTED', 
            message: 'Captcha validation failed. Automated bot activity suspected.' 
        });
    }

    // Input validation stricte
    if (!email || !password || typeof email !== 'string' || typeof password !== 'string') {
        return res.status(422).json({ status: 'error', code: 'ERR_MISSING_FIELDS', message: 'Valid email and password are required' });
    }
    if (password.length < 8) {
        return res.status(422).json({ status: 'error', code: 'ERR_WEAK_PASSWORD', message: 'Password must be at least 8 characters long' });
    }

    if (usersByEmail.has(email)) {
        return res.status(409).json({ status: 'error', code: 'ERR_EMAIL_EXISTS', message: 'Email already registered' });
    }

    const userId = 'usr_' + Buffer.from(email).toString('base64').substring(0, 15) + Math.floor(Math.random() * 1000);
    const passwordHash = await bcrypt.hash(password, 10);
    
    const user = { 
        id: userId, 
        email, 
        passwordHash, 
        role: 'customer',
        sensitiveData: { creditCard: 'No card on file', address: 'No address' }
    };
    
    users.set(userId, user);
    usersByEmail.set(email, userId);

    // JWT (sans données sensibles)
    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
    
    // Retourne l'ID et l'email uniquement. AUCUN orderId truqué.
    res.status(201).json({ status: 'success', token, user: { id: user.id, email: user.email } });
});

// Connexion
app.post('/api/auth/login', async (req, res) => {
    const { email, password, captchaToken } = req.body;

    // Simulation d'un Anti-Bot robuste (CAPTCHA)
    if (!captchaToken || captchaToken !== 'valid_human_token') {
        return res.status(403).json({ 
            status: 'error', 
            code: 'ERR_BOT_DETECTED', 
            message: 'Captcha validation failed. Automated bot activity suspected.' 
        });
    }

    if (!email || !password) {
        return res.status(422).json({ status: 'error', code: 'ERR_MISSING_FIELDS', message: 'Email and password are required' });
    }

    const userId = usersByEmail.get(email);
    if (!userId) {
        return res.status(401).json({ status: 'error', code: 'ERR_INVALID_CREDENTIALS', message: 'Invalid credentials' });
    }

    const user = users.get(userId);
    const isMatch = await bcrypt.compare(password, user.passwordHash);
    
    if (!isMatch) {
        return res.status(401).json({ status: 'error', code: 'ERR_INVALID_CREDENTIALS', message: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ status: 'success', token, user: { id: user.id, email: user.email } });
});

// Middleware d'authentification cryptographique
const authenticateJWT = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.split(' ')[1];
        jwt.verify(token, JWT_SECRET, (err, decodedUser) => {
            if (err) return res.status(401).json({ status: 'error', code: 'ERR_INVALID_TOKEN', message: 'Token is invalid or expired' });
            req.user = decodedUser;
            next();
        });
    } else {
        res.status(401).json({ status: 'error', code: 'ERR_MISSING_TOKEN', message: 'Authorization header is required' });
    }
};

// Endpoint sécurisé (Mon profil)
app.get('/api/users/me', authenticateJWT, (req, res) => {
    const user = users.get(req.user.id);
    if (!user) return res.status(404).json({ status: 'error', message: 'User not found' });
    
    res.json({ status: 'success', data: { id: user.id, email: user.email, sensitiveData: user.sensitiveData } });
});

// Endpoint vulnérable au BOLA (Lecture de profil d'un autre utilisateur)
app.get('/api/users/:id', authenticateJWT, (req, res) => {
    const targetUserId = req.params.id;
    const targetUser = users.get(targetUserId);

    if (!targetUser) {
        return res.status(404).json({ status: 'error', code: 'ERR_NOT_FOUND', message: 'User profile not found' });
    }

    // ==========================================
    // VULNERABILITÉ BOLA (IDOR) :
    // L'API vérifie si le token est valide, mais "oublie" de vérifier si 
    // l'utilisateur demande SON PROPRE profil ou s'il est Administrateur.
    // Faille : N'importe quel client connecté peut lire les cartes bancaires des autres.
    // ==========================================

    // On masque juste le mot de passe, mais on fuitite les données sensibles
    const leakedProfile = {
        id: targetUser.id,
        email: targetUser.email,
        role: targetUser.role,
        sensitiveData: targetUser.sensitiveData // BOUM ! Fuite BOLA.
    };

    res.json({ status: 'success', data: leakedProfile });
});

// 404
app.use((req, res) => res.status(404).json({ status: 'error', code: 'ERR_NOT_FOUND', message: 'Route not found' }));

app.listen(PORT, () => {
    console.log(`[SECURE E-COMMERCE API] Serveur demarré sur http://localhost:${PORT}`);
});
