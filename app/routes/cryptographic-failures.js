// routes/cryptographic-failures.js
// Handles A02:2021-Cryptographic Failures vulnerabilities

const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const { userCredentials, secureUserCredentials } = require('../models/db');

// --- Cryptographic Failures Routes ---

// VULNERABLE: Login with plaintext password storage
router.post('/crypto/login', (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }
    
    // --- VULNERABLE LOGIC: Plaintext password comparison ---
    const user = userCredentials.find(u => 
        u.username === username && u.password === password
    );
    
    if (user) {
        // Don't send the password back in the response
        res.json({ 
            success: true, 
            message: 'Login successful (INSECURE: Plaintext passwords)',
            username: user.username
        });
    } else {
        res.status(401).json({ 
            success: false, 
            message: 'Invalid credentials' 
        });
    }
});

// SECURE: Login with hashed password
router.post('/crypto/login-secure', (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }
    
    // --- SECURE LOGIC: Password hashing (simulated) ---
    // In a real app, you'd use bcrypt.compare() or similar
    const user = secureUserCredentials.find(u => u.username === username);
    
    if (!user) {
        // Use constant-time comparison to prevent timing attacks
        return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    
    // Simulate bcrypt.compare() - in a real app, this would actually compare the hash
    const simulateSecureCompare = () => {
        // This is just a simulation - in a real app you'd use proper password hashing
        return username === 'user' && password === 'password' || 
               username === 'admin' && password === 'adminpass';
    };
    
    if (simulateSecureCompare()) {
        res.json({ 
            success: true, 
            message: 'Login successful (SECURE: Password hashing)',
            username: user.username
        });
    } else {
        res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
});

// VULNERABLE: Insecure data transmission (simulated)
router.post('/crypto/send-data', (req, res) => {
    const { creditCard, ssn } = req.body;
    
    // --- VULNERABLE LOGIC: Sensitive data transmitted without encryption ---
    // In a real app, this would be sending data over HTTP instead of HTTPS
    
    res.json({
        success: true,
        message: 'Data transmitted (INSECURE: Unencrypted transmission)',
        warning: 'This simulates sending sensitive data over an unencrypted connection',
        // Echoing back partial data to demonstrate it was sent in the clear
        dataSent: {
            creditCardLastFour: creditCard ? creditCard.slice(-4) : null,
            ssnLastFour: ssn ? ssn.slice(-4) : null
        }
    });
});

// SECURE: Secure data transmission (simulated)
router.post('/crypto/send-data-secure', (req, res) => {
    const { creditCard, ssn } = req.body;
    
    // --- SECURE LOGIC: Sensitive data transmitted with encryption ---
    // In a real app, this would be sending data over HTTPS
    // We're simulating the encryption process here
    
    // Simulate encryption (in a real app, the transport layer would handle this)
    const simulateEncryption = (data) => {
        if (!data) return null;
        // This is just a simulation - not actual encryption
        return `${data.slice(-4)} (Remaining digits encrypted)`;
    };
    
    res.json({
        success: true,
        message: 'Data transmitted securely (SECURE: Encrypted transmission)',
        note: 'This simulates sending sensitive data over an encrypted connection',
        encryptedData: {
            creditCard: simulateEncryption(creditCard),
            ssn: simulateEncryption(ssn)
        }
    });
});

// VULNERABLE: Weak encryption (simulated)
router.post('/crypto/encrypt', (req, res) => {
    const { data } = req.body;
    
    if (!data) {
        return res.status(400).json({ message: 'Data is required' });
    }
    
    // --- VULNERABLE LOGIC: Weak encryption ---
    // Using MD5 (which is not an encryption algorithm, but a hash function)
    // MD5 is cryptographically broken and unsuitable for further use
    const weakHash = crypto.createHash('md5').update(data).digest('hex');
    
    res.json({
        original: data,
        encrypted: weakHash,
        algorithm: 'MD5 (INSECURE: Cryptographically broken)',
        warning: 'MD5 is not secure and should not be used for sensitive data'
    });
});

// SECURE: Strong encryption (simulated)
router.post('/crypto/encrypt-secure', (req, res) => {
    const { data } = req.body;
    
    if (!data) {
        return res.status(400).json({ message: 'Data is required' });
    }
    
    // --- SECURE LOGIC: Strong encryption ---
    // Using AES-256-GCM with a proper key and IV
    // In a real app, you'd store the key securely, not hardcode it
    const algorithm = 'aes-256-gcm';
    const key = crypto.randomBytes(32); // 256 bits
    const iv = crypto.randomBytes(16); // 128 bits for AES
    
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');
    
    // In a real app, you'd need to store the key, IV, and authTag securely
    // to decrypt the data later
    
    res.json({
        original: data,
        encrypted: encrypted,
        algorithm: 'AES-256-GCM (SECURE: Strong encryption)',
        note: 'Key, IV, and authentication tag would be securely stored in a real application'
    });
});

// VULNERABLE: Hardcoded secrets (simulated)
router.get('/crypto/config', (req, res) => {
    // --- VULNERABLE LOGIC: Hardcoded secrets in code ---
    const insecureConfig = {
        apiKey: 'a1b2c3d4e5f6g7h8i9j0',
        dbPassword: 'super_secret_password',
        jwtSecret: 'nobody_will_guess_this',
        environment: 'production'
    };
    
    res.json({
        config: insecureConfig,
        warning: 'INSECURE: Hardcoded secrets in application code'
    });
});

// SECURE: Environment-based secrets (simulated)
router.get('/crypto/config-secure', (req, res) => {
    // --- SECURE LOGIC: Secrets from environment variables ---
    // In a real app, these would come from process.env
    const secureConfig = {
        apiKey: '[REDACTED]',
        dbPassword: '[REDACTED]',
        jwtSecret: '[REDACTED]',
        environment: 'production'
    };
    
    res.json({
        config: secureConfig,
        note: 'SECURE: Secrets stored in environment variables, not in code'
    });
});

// VULNERABLE: Store password insecurely (plaintext)
router.post('/store-password', (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }
    
    // --- VULNERABLE LOGIC: Plaintext password storage ---
    // Check if user already exists
    const existingUserIndex = userCredentials.findIndex(u => u.username === username);
    
    if (existingUserIndex >= 0) {
        // Update existing user
        userCredentials[existingUserIndex].password = password;
    } else {
        // Add new user
        userCredentials.push({ username, password });
    }
    
    res.json({
        success: true,
        message: 'Password stored (INSECURE: Plaintext storage)',
        warning: 'This password is stored in plaintext and is vulnerable to data breaches'
    });
});

// SECURE: Store password securely (hashed)
router.post('/store-password-secure', (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }
    
    // --- SECURE LOGIC: Password hashing ---
    // In a real app, you'd use bcrypt or Argon2
    // This is a simplified simulation using SHA-256 with a salt
    // (Note: SHA-256 is not recommended for password hashing in production)
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.createHash('sha256').update(password + salt).digest('hex');
    const passwordHash = `${salt}:${hash}`;
    
    // Check if user already exists
    const existingUserIndex = secureUserCredentials.findIndex(u => u.username === username);
    
    if (existingUserIndex >= 0) {
        // Update existing user
        secureUserCredentials[existingUserIndex].passwordHash = passwordHash;
    } else {
        // Add new user
        secureUserCredentials.push({ username, passwordHash });
    }
    
    res.json({
        success: true,
        message: 'Password stored securely (SECURE: Hashed with salt)',
        note: 'This password is properly hashed and salted to protect against data breaches'
    });
});

// Get stored passwords (for demonstration)
router.get('/stored-passwords', (req, res) => {
    // Return both insecure and secure stored passwords for comparison
    res.json({
        insecurePasswords: userCredentials.map(u => ({ 
            username: u.username, 
            password: u.password,
            warning: 'VULNERABLE: Plaintext password exposed'
        })),
        securePasswords: secureUserCredentials.map(u => ({ 
            username: u.username, 
            passwordHash: u.passwordHash,
            note: 'SECURE: Only the hash is stored'
        }))
    });
});

module.exports = router;
