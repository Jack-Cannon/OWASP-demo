// routes/broken-access-control.js
// Handles A01:2021-Broken Access Control vulnerabilities

const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const { dbUsers } = require('../models/db');

// CSRF Protection - Generate tokens
const csrfTokens = new Map();
function generateCSRFToken(userId) {
    const token = crypto.randomBytes(32).toString('hex');
    csrfTokens.set(userId, token);
    return token;
}

// Broken Access Control - Simulated Session
let loggedInUser = null; // Stores { id, username, role }

// --- Broken Access Control Routes ---

// Simulated Login
router.post('/login', (req, res) => {
    const { username, password } = req.body;
    // In a real app, you'd hash passwords and check against a DB
    if (username === 'user' && password === 'password') {
        loggedInUser = { id: 101, username: 'user', role: 'user' };
        // Generate CSRF token for this user
        const csrfToken = generateCSRFToken(loggedInUser.id);
        return res.json({ 
            success: true, 
            message: 'Logged in as regular user', 
            user: loggedInUser,
            csrfToken: csrfToken
        });
    } else if (username === 'admin' && password === 'adminpass') {
        loggedInUser = { id: 4, username: 'admin', role: 'admin' };
        // Generate CSRF token for this user
        const csrfToken = generateCSRFToken(loggedInUser.id);
        return res.json({ 
            success: true, 
            message: 'Logged in as admin', 
            user: loggedInUser,
            csrfToken: csrfToken
        });
    } else {
        loggedInUser = null; // Clear any previous login
        return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
});

// Get current logged-in user (for frontend display)
router.get('/current-user', (req, res) => {
    if (loggedInUser) {
        // Refresh CSRF token
        const csrfToken = generateCSRFToken(loggedInUser.id);
        res.json({ ...loggedInUser, csrfToken });
    } else {
        res.json(null);
    }
});

// Logout
router.post('/logout', (req, res) => {
    if (loggedInUser) {
        csrfTokens.delete(loggedInUser.id); // Remove CSRF token
    }
    loggedInUser = null;
    res.json({ success: true, message: 'Logged out' });
});

// VULNERABLE BAC (IDOR): Get user profile by ID without authorization check
router.get('/user-profile/:id', (req, res) => {
    const requestedId = parseInt(req.params.id, 10);
    console.log(`[DEBUG] Searching for user profile with ID: ${requestedId}, type: ${typeof requestedId}`);
    console.log(`[DEBUG] Current logged in user:`, loggedInUser);
    console.log(`[DEBUG] Available users:`, dbUsers.map(u => ({ id: u.id, username: u.username, idType: typeof u.id })));

    // --- VULNERABLE LOGIC: No check if loggedInUser is authorized to view requestedId ---
    // In a secure app, you'd check:
    // if (!loggedInUser || (loggedInUser.id !== requestedId && loggedInUser.role !== 'admin')) {
    //     return res.status(403).json({ message: 'Forbidden: You are not authorized to view this profile.' });
    // }

    // Explicitly log each user and whether they match the requested ID
    dbUsers.forEach(u => {
        console.log(`User ID ${u.id} (${typeof u.id}) === Requested ID ${requestedId} (${typeof requestedId})? ${u.id === requestedId}`);
    });

    const user = dbUsers.find(u => u.id === requestedId);
    console.log(`[DEBUG] Found user:`, user);
    
    if (user) {
        // Only return non-sensitive public data for demo
        res.json({ id: user.id, username: user.username, email: user.email });
    } else {
        res.status(404).json({ message: 'User not found' });
    }
});

// SECURE BAC (IDOR): Get user profile by ID with proper authorization check
router.get('/user-profile-secure/:id', (req, res) => {
    const requestedId = parseInt(req.params.id, 10);
    console.log(`[DEBUG] SECURE - Searching for user profile with ID: ${requestedId}, type: ${typeof requestedId}`);

    // --- SECURE LOGIC: Check if loggedInUser is authorized to view requestedId ---
    if (!loggedInUser) {
        return res.status(401).json({ message: 'Unauthorized: Please log in first.' });
    }
    
    console.log(`[DEBUG] SECURE - Comparing loggedInUser.id (${loggedInUser.id}, ${typeof loggedInUser.id}) with requestedId (${requestedId}, ${typeof requestedId})`);
    console.log(`[DEBUG] SECURE - Comparison result: ${loggedInUser.id === requestedId}`);
    
    if (loggedInUser.id !== requestedId && loggedInUser.role !== 'admin') {
        return res.status(403).json({ message: 'Forbidden: You are not authorized to view this profile.' });
    }

    const user = dbUsers.find(u => u.id === requestedId);
    console.log(`[DEBUG] SECURE - Found user:`, user);
    
    if (user) {
        // Only return non-sensitive public data for demo
        res.json({ id: user.id, username: user.username, email: user.email });
    } else {
        res.status(404).json({ message: 'User not found' });
    }
});

// VULNERABLE BAC (Role Check): Admin-only data without role check
router.get('/admin-data', (req, res) => {
    // --- VULNERABLE LOGIC: No server-side role check ---
    // This endpoint should only be accessible to admins, but it doesn't check!
    // The UI might hide the button for non-admins, but the API is still accessible.
    
    // Return "sensitive" admin data
    res.json({
        message: 'Welcome to the Admin Panel!',
        secret_data: 'This is sensitive data that should only be visible to admins.',
        user_count: dbUsers.length
    });
});

// SECURE BAC (Role Check): Admin-only data with proper role check
router.get('/admin-data-secure', (req, res) => {
    // --- SECURE LOGIC: Proper server-side role check ---
    if (!loggedInUser) {
        return res.status(401).json({ message: 'Unauthorized: Please log in first.' });
    }
    
    if (loggedInUser.role !== 'admin') {
        return res.status(403).json({ message: 'Forbidden: Admin access required.' });
    }
    
    // Return "sensitive" admin data only to admins
    res.json({
        message: 'Welcome to the Admin Panel!',
        secret_data: 'This is sensitive data that should only be visible to admins.',
        user_count: dbUsers.length
    });
});

// --- CSRF Vulnerability Routes ---

// CSRF Protection - Validate token
function validateCSRFToken(userId, token) {
    const storedToken = csrfTokens.get(userId);
    return storedToken && storedToken === token;
}

// Get bank balance
router.get('/balance', (req, res) => {
    if (!loggedInUser) {
        return res.status(401).json({ message: 'Unauthorized: Please log in first.' });
    }
    
    const userAccount = loggedInUser.username === 'admin' ? 'admin' : 'user';
    const balance = bankAccounts[userAccount]?.balance || 0;
    
    res.json({ 
        username: loggedInUser.username,
        balance: balance
    });
});

// VULNERABLE CSRF: Transfer money without CSRF protection
router.post('/transfer', (req, res) => {
    if (!loggedInUser) {
        return res.status(401).json({ message: 'Unauthorized: Please log in first.' });
    }
    
    const { to, amount } = req.body;
    const parsedAmount = parseInt(amount, 10);
    
    if (!to || isNaN(parsedAmount) || parsedAmount <= 0) {
        return res.status(400).json({ message: 'Invalid transfer details.' });
    }
    
    // --- VULNERABLE LOGIC: No CSRF token validation ---
    // This endpoint doesn't validate any CSRF token, making it vulnerable to CSRF attacks
    
    const fromAccount = loggedInUser.username === 'admin' ? 'admin' : 'user';
    
    // Check if user has enough balance
    if (bankAccounts[fromAccount].balance < parsedAmount) {
        return res.status(400).json({ message: 'Insufficient funds.' });
    }
    
    // Process transfer
    bankAccounts[fromAccount].balance -= parsedAmount;
    bankAccounts[to] = bankAccounts[to] || { balance: 0 };
    bankAccounts[to].balance += parsedAmount;
    
    res.json({ 
        message: `Successfully transferred $${parsedAmount} to ${to}`,
        newBalance: bankAccounts[fromAccount].balance
    });
});

// SECURE CSRF: Transfer money with CSRF protection
router.post('/transfer-secure', (req, res) => {
    if (!loggedInUser) {
        return res.status(401).json({ message: 'Unauthorized: Please log in first.' });
    }
    
    const { to, amount, csrf_token } = req.body;
    const parsedAmount = parseInt(amount, 10);
    
    if (!to || isNaN(parsedAmount) || parsedAmount <= 0) {
        return res.status(400).json({ message: 'Invalid transfer details.' });
    }
    
    // --- SECURE LOGIC: CSRF token validation ---
    if (!validateCSRFToken(loggedInUser.id, csrf_token)) {
        return res.status(403).json({ message: 'Invalid CSRF token.' });
    }
    
    const fromAccount = loggedInUser.username === 'admin' ? 'admin' : 'user';
    
    // Check if user has enough balance
    if (bankAccounts[fromAccount].balance < parsedAmount) {
        return res.status(400).json({ message: 'Insufficient funds.' });
    }
    
    // Process transfer
    bankAccounts[fromAccount].balance -= parsedAmount;
    bankAccounts[to] = bankAccounts[to] || { balance: 0 };
    bankAccounts[to].balance += parsedAmount;
    
    // Generate new CSRF token after sensitive action
    const newCsrfToken = generateCSRFToken(loggedInUser.id);
    
    res.json({ 
        message: `Successfully transferred $${parsedAmount} to ${to}`,
        newBalance: bankAccounts[fromAccount].balance,
        csrf_token: newCsrfToken
    });
});

// Export the router and the loggedInUser for use in other routes
module.exports = { 
    router,
    getLoggedInUser: () => loggedInUser,
    csrfTokens,
    validateCSRFToken
};
