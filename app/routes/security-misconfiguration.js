// routes/security-misconfiguration.js
// Handles A05:2021-Security Misconfiguration vulnerabilities

const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const { defaultCredentials } = require('../models/db');

// --- Security Misconfiguration Routes ---

// VULNERABLE: Default credentials
router.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }
    
    // --- VULNERABLE LOGIC: Default credentials still active ---
    if (username === defaultCredentials.username && password === defaultCredentials.password) {
        return res.json({
            success: true,
            username: 'admin',
            role: 'administrator',
            message: 'Logged in with default credentials (VULNERABLE)',
            warning: 'Default credentials should be changed after installation'
        });
    }
    
    // Regular login logic (simplified)
    if (username === 'user' && password === 'password') {
        return res.json({
            success: true,
            username: 'user',
            role: 'standard',
            message: 'Logged in as regular user'
        });
    }
    
    res.status(401).json({ success: false, message: 'Invalid credentials' });
});

// SECURE: No default credentials
router.post('/login-secure', (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }
    
    // --- SECURE LOGIC: Default credentials disabled ---
    if (username === defaultCredentials.username && password === defaultCredentials.password) {
        return res.status(401).json({
            success: false,
            message: 'Default credentials have been disabled (SECURE)',
            note: 'System requires unique credentials to be set during installation'
        });
    }
    
    // Regular login logic (simplified)
    if (username === 'user' && password === 'password') {
        return res.json({
            success: true,
            username: 'user',
            role: 'standard',
            message: 'Logged in as regular user',
            note: 'SECURE: Strong authentication implemented'
        });
    }
    
    res.status(401).json({ success: false, message: 'Invalid credentials' });
});

// VULNERABLE: Error handling with stack traces
router.get('/error', (req, res) => {
    try {
        // Deliberately cause an error
        const obj = null;
        const result = obj.nonExistentProperty;
        
        res.json({ result });
    } catch (error) {
        // --- VULNERABLE LOGIC: Detailed error with stack trace exposed ---
        res.status(500).json({
            message: 'An error occurred',
            error: error.message,
            stack: error.stack,
            warning: 'VULNERABLE: Exposing detailed error information and stack traces'
        });
    }
});

// SECURE: Error handling without sensitive details
router.get('/error-secure', (req, res) => {
    try {
        // Deliberately cause an error
        const obj = null;
        const result = obj.nonExistentProperty;
        
        res.json({ result });
    } catch (error) {
        // --- SECURE LOGIC: Generic error message without details ---
        console.error('Internal server error:', error); // Log for debugging, but don't expose
        
        res.status(500).json({
            message: 'An internal server error occurred',
            requestId: crypto.randomUUID(), // Reference ID for server logs
            note: 'SECURE: No sensitive error details exposed to client'
        });
    }
});

// VULNERABLE: Directory listing (simulated)
router.get('/files', (req, res) => {
    // --- VULNERABLE LOGIC: Directory listing enabled ---
    // In a real server, this would be equivalent to having directory listing enabled
    
    const files = [
        { name: 'index.html', type: 'file', size: '2.3 KB' },
        { name: 'config.json', type: 'file', size: '1.7 KB' },
        { name: 'database.sqlite', type: 'file', size: '4.2 MB' },
        { name: '.env', type: 'file', size: '0.4 KB' },
        { name: 'backup/', type: 'directory' },
        { name: 'admin/', type: 'directory' }
    ];
    
    res.json({
        path: '/var/www/html/',
        files: files,
        warning: 'VULNERABLE: Directory listing enabled, exposing sensitive files'
    });
});

// SECURE: Directory listing disabled (simulated)
router.get('/files-secure', (req, res) => {
    // --- SECURE LOGIC: Directory listing disabled ---
    res.status(403).json({
        message: 'Forbidden',
        note: 'SECURE: Directory listing is disabled'
    });
});

// VULNERABLE: Unnecessary features enabled (simulated)
router.get('/server-info', (req, res) => {
    // --- VULNERABLE LOGIC: Detailed server information exposed ---
    // In a real server, this would be equivalent to having detailed server headers
    // or phpinfo() enabled
    
    const serverInfo = {
        server: 'Apache/2.4.41 (Ubuntu)',
        phpVersion: '7.4.3',
        modules: [
            'mod_rewrite',
            'mod_ssl',
            'mod_php',
            'mod_cgi' // Potentially dangerous if misconfigured
        ],
        osVersion: 'Ubuntu 20.04.3 LTS',
        databaseVersion: 'MySQL 8.0.27',
        paths: {
            documentRoot: '/var/www/html',
            configFile: '/etc/apache2/apache2.conf',
            logsDirectory: '/var/log/apache2'
        }
    };
    
    res.json({
        serverInfo,
        warning: 'VULNERABLE: Detailed server information exposed'
    });
});

// SECURE: Minimal server information (simulated)
router.get('/server-info-secure', (req, res) => {
    // --- SECURE LOGIC: Minimal server information ---
    res.setHeader('Server', 'Server'); // Generic server header
    
    res.json({
        message: 'Limited information available',
        note: 'SECURE: Detailed server information is hidden'
    });
});

// VULNERABLE: Insecure HTTP headers (simulated)
router.get('/headers', (req, res) => {
    // --- VULNERABLE LOGIC: Missing security headers ---
    // In a real app, this would be a response without important security headers
    
    res.json({
        message: 'Response with insecure headers',
        warning: 'VULNERABLE: Missing security headers like Content-Security-Policy, X-Content-Type-Options, etc.'
    });
});

// SECURE: Secure HTTP headers (simulated)
router.get('/headers-secure', (req, res) => {
    // --- SECURE LOGIC: Proper security headers ---
    res.setHeader('Content-Security-Policy', "default-src 'self'");
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'no-referrer');
    
    res.json({
        message: 'Response with secure headers',
        note: 'SECURE: Proper security headers implemented'
    });
});

// VULNERABLE: XML External Entity (XXE) processing (simulated)
router.post('/parse-xml', (req, res) => {
    const { xml } = req.body;
    
    if (!xml) {
        return res.status(400).json({ message: 'XML content is required' });
    }
    
    // --- VULNERABLE LOGIC: XXE processing enabled (simulated) ---
    // In a real app, this would use an XML parser with external entities enabled
    
    // Check for XXE attack pattern
    if (xml.includes('<!ENTITY') && xml.includes('SYSTEM')) {
        return res.json({
            warning: 'VULNERABLE: XXE attack detected!',
            explanation: 'This endpoint simulates an XML parser with external entities enabled',
            impact: 'An attacker could read local files, cause denial of service, or perform server-side request forgery'
        });
    }
    
    // Simulate parsing (in a real app, this would use a vulnerable XML parser)
    res.json({
        message: 'XML parsed successfully (VULNERABLE: XXE processing enabled)',
        parsedContent: 'Simulated parsed content'
    });
});

// SECURE: XML External Entity (XXE) processing disabled (simulated)
router.post('/parse-xml-secure', (req, res) => {
    const { xml } = req.body;
    
    if (!xml) {
        return res.status(400).json({ message: 'XML content is required' });
    }
    
    // --- SECURE LOGIC: XXE processing disabled (simulated) ---
    // In a real app, this would use an XML parser with external entities disabled
    
    // Check for XXE attack pattern and reject it
    if (xml.includes('<!ENTITY') && xml.includes('SYSTEM')) {
        return res.status(400).json({
            message: 'XML parsing rejected',
            reason: 'External entities are not allowed',
            note: 'SECURE: XXE processing is disabled'
        });
    }
    
    // Simulate parsing (in a real app, this would use a secure XML parser)
    res.json({
        message: 'XML parsed successfully (SECURE: XXE processing disabled)',
        parsedContent: 'Simulated parsed content'
    });
});

module.exports = router;
