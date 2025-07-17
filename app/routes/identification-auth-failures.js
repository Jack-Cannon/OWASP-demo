// routes/identification-auth-failures.js
// Handles A07:2021-Identification and Authentication Failures vulnerabilities

const express = require('express');
const router = express.Router();
const crypto = require('crypto');

// In-memory storage for login attempts (in a real app, this would be in a database)
const loginAttempts = new Map();
const userSessions = new Map();

// --- Identification and Authentication Failures Routes ---

// VULNERABLE: Weak password policy
router.post('/auth/register', (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }
    
    // --- VULNERABLE LOGIC: No password strength requirements ---
    // This endpoint accepts any password, no matter how weak
    
    res.json({
        success: true,
        message: 'User registered successfully (VULNERABLE: No password requirements)',
        warning: 'Weak passwords are easily guessed or brute-forced'
    });
});

// SECURE: Strong password policy
router.post('/auth/register-secure', (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }
    
    // --- SECURE LOGIC: Password strength requirements ---
    if (password.length < 12) {
        return res.status(400).json({ message: 'Password must be at least 12 characters long' });
    }
    
    // Check for complexity requirements
    const hasUppercase = /[A-Z]/.test(password);
    const hasLowercase = /[a-z]/.test(password);
    const hasNumbers = /[0-9]/.test(password);
    const hasSpecialChars = /[^A-Za-z0-9]/.test(password);
    
    if (!(hasUppercase && hasLowercase && hasNumbers && hasSpecialChars)) {
        return res.status(400).json({
            message: 'Password must include uppercase and lowercase letters, numbers, and special characters'
        });
    }
    
    res.json({
        success: true,
        message: 'User registered successfully (SECURE: Strong password requirements)',
        note: 'Strong passwords help prevent brute force attacks'
    });
});

// VULNERABLE: No brute force protection
router.post('/auth/login', (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }
    
    // --- VULNERABLE LOGIC: No brute force protection ---
    // This endpoint allows unlimited login attempts
    
    // Simulated authentication (in a real app, this would check against a database)
    const isValidLogin = (username === 'user' && password === 'password') ||
                         (username === 'admin' && password === 'adminpass');
    
    if (isValidLogin) {
        // Generate a simple session token (vulnerable)
        const sessionToken = `session-${username}-${Date.now()}`;
        
        res.json({
            success: true,
            message: 'Login successful (VULNERABLE: No brute force protection)',
            sessionToken,
            warning: 'This endpoint allows unlimited login attempts'
        });
    } else {
        res.status(401).json({
            success: false,
            message: 'Invalid credentials'
        });
    }
});

// SECURE: Brute force protection
router.post('/auth/login-secure', (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }
    
    // --- SECURE LOGIC: Brute force protection ---
    // Track login attempts by IP address (in a real app) or username (simplified here)
    const attempts = loginAttempts.get(username) || 0;
    
    // Check if account is temporarily locked
    if (attempts >= 5) {
        return res.status(429).json({
            success: false,
            message: 'Too many failed login attempts. Please try again later.',
            note: 'SECURE: Brute force protection implemented'
        });
    }
    
    // Simulated authentication (in a real app, this would check against a database)
    const isValidLogin = (username === 'user' && password === 'password') ||
                         (username === 'admin' && password === 'adminpass');
    
    if (isValidLogin) {
        // Reset login attempts on successful login
        loginAttempts.delete(username);
        
        // Generate a secure session token
        const sessionToken = crypto.randomBytes(32).toString('hex');
        
        // Store session with expiration (in a real app, this would be in a database)
        userSessions.set(sessionToken, {
            username,
            created: Date.now(),
            expires: Date.now() + 3600000 // 1 hour from now
        });
        
        res.json({
            success: true,
            message: 'Login successful (SECURE: With brute force protection)',
            sessionToken
        });
    } else {
        // Increment login attempts
        loginAttempts.set(username, attempts + 1);
        
        res.status(401).json({
            success: false,
            message: 'Invalid credentials',
            attemptsRemaining: 5 - (attempts + 1)
        });
    }
});

// VULNERABLE: Insecure session management
router.get('/auth/profile', (req, res) => {
    const { sessionToken } = req.query;
    
    if (!sessionToken) {
        return res.status(401).json({ message: 'Session token is required' });
    }
    
    // --- VULNERABLE LOGIC: Weak session validation ---
    // This endpoint only checks if the token starts with 'session-'
    if (sessionToken.startsWith('session-')) {
        // Extract username from token (vulnerable)
        const username = sessionToken.split('-')[1];
        
        res.json({
            username,
            profile: {
                name: 'Test User',
                email: `${username}@example.com`
            },
            warning: 'VULNERABLE: Weak session validation'
        });
    } else {
        res.status(401).json({ message: 'Invalid session token' });
    }
});

// SECURE: Secure session management
router.get('/auth/profile-secure', (req, res) => {
    const { sessionToken } = req.query;
    
    if (!sessionToken) {
        return res.status(401).json({ message: 'Session token is required' });
    }
    
    // --- SECURE LOGIC: Proper session validation ---
    const session = userSessions.get(sessionToken);
    
    if (!session) {
        return res.status(401).json({ message: 'Invalid session token' });
    }
    
    // Check if session has expired
    if (session.expires < Date.now()) {
        userSessions.delete(sessionToken);
        return res.status(401).json({ message: 'Session has expired. Please log in again.' });
    }
    
    res.json({
        username: session.username,
        profile: {
            name: 'Test User',
            email: `${session.username}@example.com`
        },
        note: 'SECURE: Proper session validation with expiration'
    });
});

// VULNERABLE: No multi-factor authentication
router.post('/auth/mfa', (req, res) => {
    const { username } = req.body;
    
    if (!username) {
        return res.status(400).json({ message: 'Username is required' });
    }
    
    // --- VULNERABLE LOGIC: No MFA option ---
    res.json({
        success: true,
        message: 'Login successful without MFA (VULNERABLE)',
        warning: 'No multi-factor authentication is available'
    });
});

// SECURE: Multi-factor authentication
router.post('/auth/mfa-secure', (req, res) => {
    const { username, mfaCode } = req.body;
    
    if (!username) {
        return res.status(400).json({ message: 'Username is required' });
    }
    
    // --- SECURE LOGIC: MFA required ---
    if (!mfaCode) {
        // Generate a simulated MFA code (in a real app, this would be sent via SMS/email/app)
        const simulatedMfaCode = '123456';
        
        return res.json({
            success: false,
            requiresMfa: true,
            message: 'MFA code required',
            note: 'SECURE: Multi-factor authentication is required',
            // In a real app, we wouldn't return the code in the response
            simulatedCode: simulatedMfaCode
        });
    }
    
    // Verify MFA code (simplified)
    if (mfaCode === '123456') {
        res.json({
            success: true,
            message: 'Login successful with MFA (SECURE)',
            note: 'Multi-factor authentication provides an additional layer of security'
        });
    } else {
        res.status(401).json({
            success: false,
            message: 'Invalid MFA code'
        });
    }
});

module.exports = router;
