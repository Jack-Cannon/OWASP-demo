// routes/injection.js
// Handles A03:2021-Injection vulnerabilities (including XSS)

const express = require('express');
const router = express.Router();
const { xssComments, xssSecureComments, dbUsers } = require('../models/db');
const DOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const window = new JSDOM('').window;
const purify = DOMPurify(window);

// --- XSS Vulnerability Routes ---

// VULNERABLE XSS: Endpoint to add a comment without sanitization
router.post('/xss/add-comment', (req, res) => {
    const { comment } = req.body;
    if (comment) {
        xssComments.push(comment);
        console.log('XSS Comment added (VULNERABLE):', comment);
        res.status(201).json({ message: 'Comment added (VULNERABLE)', comment });
    } else {
        res.status(400).json({ message: 'Comment is required' });
    }
});

// VULNERABLE XSS: Endpoint to get all comments as-is
router.get('/xss/get-comments', (req, res) => {
    res.json(xssComments);
});

// SECURE XSS: Endpoint to add a comment with sanitization
router.post('/xss/add-comment-secure', (req, res) => {
    const { comment } = req.body;
    if (comment) {
        // --- SECURE LOGIC: Sanitize input to remove any malicious code ---
        const sanitizedComment = purify.sanitize(comment);
        xssSecureComments.push(sanitizedComment);
        console.log('XSS Comment added (SECURE):', sanitizedComment);
        res.status(201).json({ message: 'Comment added (SECURE)', comment: sanitizedComment });
    } else {
        res.status(400).json({ message: 'Comment is required' });
    }
});

// SECURE XSS: Endpoint to get all sanitized comments
router.get('/xss/get-comments-secure', (req, res) => {
    res.json(xssSecureComments);
});

// Clear all comments (for demo reset)
router.post('/xss/clear-comments', (req, res) => {
    xssComments.length = 0;
    xssSecureComments.length = 0;
    res.json({ message: 'All comments cleared' });
});

// --- SQL Injection Vulnerability Routes (Simulated) ---

// VULNERABLE INJECTION: Endpoint to search users by username (simulated SQL injection)
router.get('/search-user', (req, res) => {
    const { username } = req.query; // User input directly used in "query"

    if (!username) {
        return res.status(400).json({ message: 'Username parameter is required' });
    }

    console.log(`Simulating search for username: "${username}"`);

    // --- VULNERABLE LOGIC: Direct string concatenation (simulating SQL injection) ---
    // Imagine this is part of a real SQL query:
    // SELECT * FROM users WHERE username = '${username}'
    // An attacker could input: ' OR '1'='1 --
    // Which would make the query: SELECT * FROM users WHERE username = '' OR '1'='1 --'
    // This makes the WHERE clause always true, returning all users.

    // For this demo, we simulate the filtering logic
    const filteredUsers = dbUsers.filter(user => {
        // This is the vulnerable part: directly checking if the username matches or if the "injection" works
        // In a real DB, the DB engine would parse the malicious string.
        // Here, we simulate by checking if the input contains common injection patterns.
        const simulatedQuery = `username = '${username}'`; // The "SQL" string being built

        // Simple simulation of injection bypass:
        if (username.includes("' OR '1'='1")) {
            console.warn('INJECTION DETECTED (SIMULATED): Returning all users due to bypass.');
            return true; // Simulate returning all users
        }
        if (username.includes("' OR 1=1")) {
            console.warn('INJECTION DETECTED (SIMULATED): Returning all users due to bypass.');
            return true; // Simulate returning all users
        }

        // Normal (but still vulnerable if not parameterized) comparison
        return user.username === username;
    }).map(user => ({ id: user.id, username: user.username, email: user.email })); // Don't expose role

    res.json(filteredUsers);
});

// SECURE INJECTION: Endpoint to search users by username (simulated parameterized query)
router.get('/search-user-secure', (req, res) => {
    const { username } = req.query;

    if (!username) {
        return res.status(400).json({ message: 'Username parameter is required' });
    }

    console.log(`Secure search for username: "${username}"`);

    // --- SECURE LOGIC: Simulating parameterized query ---
    // In a real app with a DB, you'd use parameterized queries like:
    // db.query('SELECT * FROM users WHERE username = ?', [username]);
    
    // For this demo, we simulate the secure filtering logic
    const filteredUsers = dbUsers.filter(user => {
        // Simple exact match - no injection possible
        return user.username === username;
    }).map(user => ({ id: user.id, username: user.username, email: user.email }));

    res.json(filteredUsers);
});

// Command Injection (simulated)
router.get('/command', (req, res) => {
    const { filename } = req.query;
    
    if (!filename) {
        return res.status(400).json({ message: 'Filename parameter is required' });
    }
    
    // VULNERABLE: Command injection simulation
    // In a real vulnerable app, this might execute: exec(`cat ${filename}`)
    // An attacker could input: "file.txt; rm -rf /"
    
    // We'll simulate the vulnerability without actually executing commands
    if (filename.includes(';') || filename.includes('|') || filename.includes('&&')) {
        return res.json({
            vulnerable: true,
            message: 'COMMAND INJECTION DETECTED!',
            simulatedCommand: `cat ${filename}`,
            explanation: 'In a vulnerable application, this would execute arbitrary commands on the server.'
        });
    }
    
    // Normal response for "safe" input
    res.json({
        content: `Simulated content of file: ${filename}`,
        note: 'This is a simulation. No actual files are being read.'
    });
});

// Secure version of command handling
router.get('/command-secure', (req, res) => {
    const { filename } = req.query;
    
    if (!filename) {
        return res.status(400).json({ message: 'Filename parameter is required' });
    }
    
    // SECURE: Validate input against a whitelist of allowed patterns
    const validFilenamePattern = /^[a-zA-Z0-9_\-\.]+$/;
    
    if (!validFilenamePattern.test(filename)) {
        return res.status(400).json({ 
            message: 'Invalid filename. Only alphanumeric characters, underscores, hyphens, and periods are allowed.',
            secure: true
        });
    }
    
    // Proceed with "safe" operation
    res.json({
        content: `Simulated content of file: ${filename}`,
        secure: true,
        note: 'Input was properly validated before use.'
    });
});

module.exports = router;
