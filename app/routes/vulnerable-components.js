// routes/vulnerable-components.js
// Handles A06:2021-Vulnerable and Outdated Components vulnerabilities

const express = require('express');
const router = express.Router();
const { softwarePackages } = require('../models/db');

// --- Vulnerable and Outdated Components Routes ---

// VULNERABLE: Display dependency information with vulnerabilities
router.get('/components/dependencies', (req, res) => {
    // --- VULNERABLE LOGIC: Using outdated components with known vulnerabilities ---
    const dependencies = [
        {
            name: 'jquery',
            version: '1.8.3', // Outdated with known XSS vulnerabilities
            vulnerabilities: [
                {
                    id: 'CVE-2020-11023',
                    severity: 'high',
                    description: 'XSS vulnerability in jQuery.htmlPrefilter()'
                }
            ]
        },
        {
            name: 'bootstrap',
            version: '3.0.0', // Outdated with known XSS vulnerabilities
            vulnerabilities: [
                {
                    id: 'CVE-2018-14041',
                    severity: 'medium',
                    description: 'XSS vulnerability in tooltip or popover'
                }
            ]
        },
        {
            name: 'log4j',
            version: '2.14.0', // Vulnerable to Log4Shell
            vulnerabilities: [
                {
                    id: 'CVE-2021-44228',
                    severity: 'critical',
                    description: 'Remote code execution vulnerability in Log4j'
                }
            ]
        },
        {
            name: 'express',
            version: '4.17.1', // Up to date (at time of writing)
            vulnerabilities: []
        }
    ];
    
    res.json({
        dependencies,
        warning: 'VULNERABLE: Using components with known vulnerabilities'
    });
});

// SECURE: Display updated dependency information
router.get('/components/dependencies-secure', (req, res) => {
    // --- SECURE LOGIC: Using updated components without known vulnerabilities ---
    const dependencies = [
        {
            name: 'jquery',
            version: '3.6.0', // Updated version
            vulnerabilities: []
        },
        {
            name: 'bootstrap',
            version: '5.1.3', // Updated version
            vulnerabilities: []
        },
        {
            name: 'log4j',
            version: '2.17.1', // Updated version that fixes Log4Shell
            vulnerabilities: []
        },
        {
            name: 'express',
            version: '4.17.1', // Up to date (at time of writing)
            vulnerabilities: []
        }
    ];
    
    res.json({
        dependencies,
        note: 'SECURE: Using updated components without known vulnerabilities'
    });
});

// VULNERABLE: Simulated package installation without verification
router.post('/components/install', (req, res) => {
    const { packageName, version } = req.body;
    
    if (!packageName || !version) {
        return res.status(400).json({ message: 'Package name and version are required' });
    }
    
    // --- VULNERABLE LOGIC: Installing packages without integrity verification ---
    // In a real app, this would be equivalent to npm install without integrity checks
    
    // Simulate adding the package to our list
    softwarePackages.push({
        name: packageName,
        version: version,
        integrity: null, // No integrity check
        verified: false
    });
    
    res.json({
        success: true,
        message: `Package ${packageName}@${version} installed (VULNERABLE: No integrity verification)`,
        warning: 'Installing packages without integrity verification can lead to supply chain attacks'
    });
});

// SECURE: Simulated package installation with verification
router.post('/components/install-secure', (req, res) => {
    const { packageName, version, integrity } = req.body;
    
    if (!packageName || !version || !integrity) {
        return res.status(400).json({ message: 'Package name, version, and integrity hash are required' });
    }
    
    // --- SECURE LOGIC: Installing packages with integrity verification ---
    // In a real app, this would be equivalent to npm install with integrity checks
    
    // Simulate verifying the package integrity
    const isIntegrityValid = integrity.startsWith('sha256-') || integrity.startsWith('sha384-');
    
    if (!isIntegrityValid) {
        return res.status(400).json({
            success: false,
            message: 'Invalid integrity hash format',
            note: 'Integrity hash should be in SRI format (e.g., sha256-...)'
        });
    }
    
    // Simulate adding the package to our list
    softwarePackages.push({
        name: packageName,
        version: version,
        integrity: integrity,
        verified: true
    });
    
    res.json({
        success: true,
        message: `Package ${packageName}@${version} installed (SECURE: With integrity verification)`,
        note: 'Installing packages with integrity verification helps prevent supply chain attacks'
    });
});

// VULNERABLE: Using a vulnerable component (simulated)
router.get('/components/render', (req, res) => {
    const { input } = req.query;
    
    if (!input) {
        return res.status(400).json({ message: 'Input parameter is required' });
    }
    
    // --- VULNERABLE LOGIC: Using a vulnerable component (simulated) ---
    // Imagine this is using an outdated library with an XSS vulnerability
    
    res.json({
        input: input,
        rendered: `<div>${input}</div>`, // Simulated vulnerable rendering
        warning: 'VULNERABLE: Using a component with known XSS vulnerability',
        explanation: 'This simulates using an outdated component that does not properly escape user input'
    });
});

// SECURE: Using an updated component (simulated)
router.get('/components/render-secure', (req, res) => {
    const { input } = req.query;
    
    if (!input) {
        return res.status(400).json({ message: 'Input parameter is required' });
    }
    
    // --- SECURE LOGIC: Using an updated component (simulated) ---
    // Imagine this is using an updated library that properly escapes input
    
    // Simple HTML escaping function (in a real app, you'd use a proper library)
    const escapeHtml = (unsafe) => {
        return unsafe
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    };
    
    res.json({
        input: input,
        rendered: `<div>${escapeHtml(input)}</div>`, // Simulated secure rendering
        note: 'SECURE: Using an updated component that properly escapes user input'
    });
});

module.exports = router;
