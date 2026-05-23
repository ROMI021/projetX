const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = 3000;
const JWT_SECRET = 's3cr3t_k3y_for_b0la_sh13ld_t3st1ng_0nly';

const crypto = require('crypto');

const SERVER_SECRET = crypto.randomBytes(32).toString('hex');

// Bases de données simulées
const users = new Map(); // id -> { id, email, passwordHash, role, sensitiveData }
const usersByEmail = new Map(); // email -> id

const BOT_HONEYPOT_FIELDS = ['middleName', 'botField', 'hiddenField'];
const VALID_CAPTCHA_TOKENS = new Set(['valid_human_token', 'human_passed', 'captcha_ok', 'robot_check_passed']);
// Headers stricts : Un bot omet souvent ces en-têtes complexes
const AUTH_HEADERS_REQUIREMENT = ['user-agent', 'accept-language'];

function isValidCaptcha(body) {
    return body && typeof body === 'object' && (VALID_CAPTCHA_TOKENS.has(body.captchaToken) || VALID_CAPTCHA_TOKENS.has(body.gRecaptchaResponse) || VALID_CAPTCHA_TOKENS.has(body.recaptchaToken) || VALID_CAPTCHA_TOKENS.has(body.humanProof));
}

function hasHoneypotTaint(body) {
    return body && typeof body === 'object' && BOT_HONEYPOT_FIELDS.some(field => body[field] !== undefined && body[field] !== '');
}

function mustHaveBrowserHeaders(req) {
    for (const header of AUTH_HEADERS_REQUIREMENT) {
        if (!req.headers[header]) return false;
    }
    // Sec-Fetch-Dest is often 'empty' for fetch/XHR, 'document' for navigation. 
    // We check if it's completely missing (which happens in basic HTTP clients)
    if (!req.headers['sec-fetch-mode'] && !req.headers['origin']) {
        return false;
    }
    return true;
}

function generateProofOfTime() {
    const timestamp = Date.now();
    const hash = crypto.createHmac('sha256', SERVER_SECRET).update(timestamp.toString()).digest('hex');
    return `${timestamp}.${hash}`;
}

function verifyProofOfTime(token) {
    if (!token) return { valid: false, reason: 'Missing PoT token' };
    const [ts, hash] = token.split('.');
    if (!ts || !hash) return { valid: false, reason: 'Malformed PoT token' };
    
    const expectedHash = crypto.createHmac('sha256', SERVER_SECRET).update(ts).digest('hex');
    if (hash !== expectedHash) return { valid: false, reason: 'Invalid PoT signature' };
    
    const timePassed = Date.now() - parseInt(ts, 10);
    if (timePassed < 2000) return { valid: false, reason: `Too fast: ${timePassed}ms (Bot detected)` };
    if (timePassed > 600000) return { valid: false, reason: `Too slow: ${timePassed}ms (Session expired)` };
    
    return { valid: true };
}

function hasValidEntropy(entropy) {
    if (!entropy || typeof entropy !== 'string') return false;
    // Les vrais sites vérifient les coordonnées de la souris
    return entropy.length > 10 && entropy.includes('m:');
}

function buildFormHtml(action, fields = []) {
    const inputs = fields.map(field => {
        const attrs = Object.entries(field)
            .map(([key, value]) => `${key}="${String(value).replace(/"/g, '&quot;')}"`)
            .join(' ');
        return `<div style="margin-bottom:12px;"><label>${field.label || field.name}: <input ${attrs} /></label></div>`;
    }).join('');
    return `<!doctype html><html><head><meta charset="utf-8"><title>Auth Form</title></head><body><h1>${action}</h1><form method="POST" action="${action}">${inputs}<button type="submit">Submit</button></form></body></html>`;
}

// ==========================================
// PEUPLEMENT DE DONNÉES ET FAILLE BOLA
// ==========================================
let globalUserId = 1000;

const seedData = () => {
    // 1. Admin
    const adminId = (globalUserId++).toString();
    users.set(adminId, {
        id: adminId,
        email: 'admin@glotelho.cm',
        passwordHash: bcrypt.hashSync('SuperSecret123!', 10),
        role: 'admin',
        sensitiveData: { creditCard: '****-****-****-1234', address: '123 Admin Ave, Yaoundé', phone: '+237 655 44 33 22' }
    });
    usersByEmail.set('admin@glotelho.cm', adminId);

    // 2. Utilisateurs Cibles (Victimes Potentielles)
    const victimes = [
        { email: 'jean.dupont@gmail.com', phone: '+237 677 88 99 00', address: 'Bastos, Yaoundé' },
        { email: 'marie.claire@yahoo.fr', phone: '+237 699 11 22 33', address: 'Akwa, Douala' },
        { email: 'arthurngalamo@gmail.com', phone: '+237 650 00 11 22', address: 'Bonamoussadi, Douala' }, // User A
        { email: 'nkarromi7@gmail.com', phone: '+237 690 99 88 77', address: 'Mvan, Yaoundé' } // User B
    ];

    for (const v of victimes) {
        const id = (globalUserId++).toString();
        users.set(id, {
            id: id,
            email: v.email,
            passwordHash: bcrypt.hashSync('TestPassword123!', 10),
            role: 'customer',
            sensitiveData: { creditCard: `****-****-****-${Math.floor(Math.random() * 9000 + 1000)}`, address: v.address, phone: v.phone }
        });
        usersByEmail.set(v.email, id);
    }
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

// Rate Limit Agressif spécifique pour l'inscription
const registerLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 heure
    max: 3, // Strict : max 3 inscriptions par IP par heure
    message: { status: 'error', code: 'ERR_RATE_LIMIT_STRICT', message: 'Too many registration attempts. IP blocked for 1 hour.' }
});

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

// Inscription (formulaire HTML et API)
app.get('/api/auth/register', (req, res) => {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    const potToken = generateProofOfTime();
    res.send(buildFormHtml('/api/auth/register', [
        { name: 'email', type: 'email', placeholder: 'user@example.com', label: 'Email' },
        { name: 'username', type: 'text', placeholder: 'username', label: 'Username' },
        { name: 'password', type: 'password', placeholder: 'password', label: 'Password' },
        { name: 'captchaToken', type: 'text', placeholder: 'valid_human_token', label: 'Captcha Token' },
        { name: 'termsAccepted', type: 'checkbox', label: 'Terms accepted' },
        { name: 'middleName', type: 'text', value: '', style: 'display:none;' },
        { name: 'clientEntropy', type: 'hidden', value: '' }, // Rempli par le JS du client
        { name: 'potToken', type: 'hidden', value: potToken } // Jeton de temps
    ]));
});
app.post('/api/auth/register', registerLimiter, async (req, res) => {
    const { email, username, password, captchaToken, gRecaptchaResponse, recaptchaToken, humanProof, termsAccepted, clientEntropy, potToken } = req.body;

    console.log(`[TARGET-API] Tentative d'inscription depuis l'IP ${req.ip}`);

    // 1. Vérification des Headers
    if (!mustHaveBrowserHeaders(req) || hasHoneypotTaint(req.body)) {
        console.warn(`[TARGET-API] Bot bloqué (Headers manquants ou Honeypot touché)`);
        return res.status(403).json({ status: 'error', code: 'ERR_BOT_DETECTED', message: 'Bot-like authentication pattern detected.' });
    }

    // 2. Vérification de l'entropie (Souris/Clavier)
    if (!hasValidEntropy(clientEntropy)) {
        console.warn(`[TARGET-API] Bot bloqué (Entropie client invalide)`);
        return res.status(403).json({ status: 'error', code: 'ERR_BOT_DETECTED', message: 'Missing client interaction entropy.' });
    }

    // 3. Vérification du Temps de Soumission (PoT)
    const potVerification = verifyProofOfTime(potToken);
    if (!potVerification.valid) {
        console.warn(`[TARGET-API] Bot bloqué (PoT invalide: ${potVerification.reason})`);
        return res.status(403).json({ status: 'error', code: 'ERR_BOT_DETECTED', message: `Behavioral timing verification failed: ${potVerification.reason}` });
    }

    // 4. Captcha classique
    if (!isValidCaptcha(req.body)) {
        console.warn(`[TARGET-API] Bot bloqué (Captcha invalide)`);
        return res.status(403).json({ status: 'error', code: 'ERR_BOT_DETECTED', message: 'Captcha validation failed. Automated bot activity suspected.' });
    }

    if (!email || !password || typeof email !== 'string' || typeof password !== 'string') {
        return res.status(422).json({ status: 'error', code: 'ERR_MISSING_FIELDS', message: 'Valid email and password are required.' });
    }
    if (password.length < 8) {
        return res.status(422).json({ status: 'error', code: 'ERR_WEAK_PASSWORD', message: 'Password must be at least 8 characters long.' });
    }
    if (termsAccepted !== true && termsAccepted !== 'true' && termsAccepted !== 'on') {
        return res.status(422).json({ status: 'error', code: 'ERR_TERMS_REQUIRED', message: 'Terms must be accepted.' });
    }

    const normalizedEmail = email.toLowerCase().trim();
    if (usersByEmail.has(normalizedEmail)) {
        return res.status(409).json({ status: 'error', code: 'ERR_EMAIL_EXISTS', message: 'Email already registered.' });
    }

    const userId = (globalUserId++).toString();
    const passwordHash = await bcrypt.hash(password, 10);
    const user = {
        id: userId,
        email: normalizedEmail,
        username: username ? String(username).trim() : normalizedEmail.split('@')[0],
        passwordHash,
        role: 'customer',
        sensitiveData: { creditCard: 'No card on file', address: 'No address' }
    };

    users.set(userId, user);
    usersByEmail.set(normalizedEmail, userId);

    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
    res.status(201).json({ status: 'success', token, user: { id: user.id, email: user.email, username: user.username } });
});

// Connexion (formulaire HTML et API)
app.get('/api/auth/login', (req, res) => {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(buildFormHtml('/api/auth/login', [
        { name: 'email', type: 'email', placeholder: 'user@example.com', label: 'Email' },
        { name: 'username', type: 'text', placeholder: 'username', label: 'Username' },
        { name: 'password', type: 'password', placeholder: 'password', label: 'Password' },
        { name: 'captchaToken', type: 'text', placeholder: 'valid_human_token', label: 'Captcha Token' },
        { name: 'middleName', type: 'text', value: '', style: 'display:none;' }
    ]));
});
app.post('/api/auth/login', async (req, res) => {
    const { email, username, password } = req.body;

    if (!mustHaveBrowserHeaders(req) || hasHoneypotTaint(req.body)) {
        return res.status(403).json({ status: 'error', code: 'ERR_BOT_DETECTED', message: 'Bot-like authentication pattern detected.' });
    }

    if (!isValidCaptcha(req.body)) {
        return res.status(403).json({ status: 'error', code: 'ERR_BOT_DETECTED', message: 'Captcha validation failed. Automated bot activity suspected.' });
    }

    if (!password || typeof password !== 'string' || (!email && !username)) {
        return res.status(422).json({ status: 'error', code: 'ERR_MISSING_FIELDS', message: 'Email or username and password are required.' });
    }

    const normalizedEmail = email ? String(email).toLowerCase().trim() : null;
    const normalizedUsername = username ? String(username).trim() : null;
    let userId = normalizedEmail ? usersByEmail.get(normalizedEmail) : null;
    if (!userId && normalizedUsername) {
        userId = [...users.values()].find(u => u.username === normalizedUsername)?.id || null;
    }
    if (!userId) {
        return res.status(401).json({ status: 'error', code: 'ERR_INVALID_CREDENTIALS', message: 'Invalid credentials.' });
    }

    const user = users.get(userId);
    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
        return res.status(401).json({ status: 'error', code: 'ERR_INVALID_CREDENTIALS', message: 'Invalid credentials.' });
    }

    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ status: 'success', token, user: { id: user.id, email: user.email, username: user.username } });
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

// Endpoint protégé : profil utilisateur par ID
app.get('/api/users/:id', authenticateJWT, (req, res) => {
    const targetUserId = req.params.id;
    const targetUser = users.get(targetUserId);

    if (!targetUser) {
        return res.status(404).json({ status: 'error', code: 'ERR_NOT_FOUND', message: 'User profile not found' });
    }

    // [BOLA VULNERABILITY INTENTIONALLY OPENED]
    // if (req.user.id !== targetUserId && req.user.role !== 'admin') {
    //     return res.status(404).json({ status: 'error', code: 'ERR_NOT_FOUND', message: 'User profile not found' });
    // }

    const profile = {
        id: targetUser.id,
        email: targetUser.email,
        role: targetUser.role
    };
    // Puisque BOLA est ouvert, tout le monde accède aux données sensibles
    profile.sensitiveData = targetUser.sensitiveData;

    res.json({ status: 'success', data: profile });
});

// Endpoint de Sabotage (Faille BOLA en écriture)
app.put('/api/users/:id', authenticateJWT, (req, res) => {
    const targetUserId = req.params.id;
    const targetUser = users.get(targetUserId);

    if (!targetUser) {
        return res.status(404).json({ status: 'error', message: 'User not found' });
    }

    // [BOLA VULNERABILITY INTENTIONALLY OPENED - WRITE ACCESS]
    // Aucune vérification d'autorisation ! N'importe qui peut modifier les données.
    
    if (req.body.bola_shield_poc) {
        targetUser.sensitiveData.sabotage = req.body.bola_shield_poc;
        targetUser.sensitiveData.poc_status = "Hacked by BOLA-Shield";
    }

    res.json({ status: 'success', message: 'User profile successfully sabotaged (BOLA Write-Access)', updatedData: targetUser });
});

// 404
app.use((req, res) => res.status(404).json({ status: 'error', code: 'ERR_NOT_FOUND', message: 'Route not found' }));

app.listen(PORT, () => {
    console.log(`[SECURE E-COMMERCE API] Serveur demarré sur http://localhost:${PORT}`);
});
