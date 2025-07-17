// routes/integrity-failures.js
// Handles A08:2021-Software and Data Integrity Failures vulnerabilities

const express = require('express');
const router = express.Router();
const crypto = require('crypto');

// --- Software and Data Integrity Failures Routes ---

// VULNERABLE: Insecure deserialization
router.post('/integrity/deserialize', (req, res) => {
    const { serializedData } = req.body;
    
    if (!serializedData) {
        return res.status(400).json({ message: 'Serialized data is required' });
    }
    
    try {
        // --- VULNERABLE LOGIC: Unsafe deserialization ---
        // In a real app, this would be equivalent to using eval() or unsafe JSON.parse
        
        // Simulate unsafe deserialization by checking for dangerous patterns
        if (serializedData.includes('__proto__') || 
            serializedData.includes('constructor') || 
            serializedData.includes('prototype')) {
            
            return res.json({
                warning: 'VULNERABLE: Potentially dangerous deserialization detected!',
                explanation: 'This endpoint simulates unsafe deserialization that could lead to remote code execution',
                impact: 'An attacker could execute arbitrary code on the server'
            });
        }
        
        // Simulate deserialization (in a real app, this would use an unsafe method)
        const data = JSON.parse(serializedData);
        
        res.json({
            message: 'Data deserialized (VULNERABLE: Unsafe deserialization)',
            data: data
        });
    } catch (error) {
        res.status(400).json({ message: 'Invalid serialized data' });
    }
});

// SECURE: Safe deserialization
router.post('/integrity/deserialize-secure', (req, res) => {
    const { serializedData } = req.body;
    
    if (!serializedData) {
        return res.status(400).json({ message: 'Serialized data is required' });
    }
    
    try {
        // --- SECURE LOGIC: Safe deserialization with validation ---
        
        // Parse the JSON data
        const data = JSON.parse(serializedData);
        
        // Validate the structure (in a real app, you'd use a schema validator)
        const isValid = typeof data === 'object' && data !== null && !Array.isArray(data);
        
        if (!isValid) {
            return res.status(400).json({ message: 'Invalid data structure' });
        }
        
        // Check for dangerous properties
        const hasDangerousProps = Object.keys(data).some(key => 
            key.includes('__proto__') || 
            key.includes('constructor') || 
            key === 'prototype'
        );
        
        if (hasDangerousProps) {
            return res.status(400).json({ message: 'Potentially dangerous data rejected' });
        }
        
        res.json({
            message: 'Data deserialized (SECURE: With validation)',
            data: data
        });
    } catch (error) {
        res.status(400).json({ message: 'Invalid serialized data' });
    }
});

// VULNERABLE: Unsigned code execution
router.post('/integrity/execute-update', (req, res) => {
    const { updateScript } = req.body;
    
    if (!updateScript) {
        return res.status(400).json({ message: 'Update script is required' });
    }
    
    // --- VULNERABLE LOGIC: Executing unsigned code ---
    // In a real app, this would be equivalent to downloading and running
    // updates without verifying their integrity
    
    res.json({
        message: 'Update executed (VULNERABLE: No integrity verification)',
        warning: 'This simulates executing code without verifying its integrity',
        impact: 'An attacker could inject malicious code into the update process'
    });
});

// SECURE: Signed code execution
router.post('/integrity/execute-update-secure', (req, res) => {
    const { updateScript, signature, publicKey } = req.body;
    
    if (!updateScript || !signature || !publicKey) {
        return res.status(400).json({ 
            message: 'Update script, signature, and public key are required' 
        });
    }
    
    // --- SECURE LOGIC: Verifying code signature before execution ---
    // In a real app, this would verify the signature using the public key
    
    // Simulate signature verification
    const isSignatureValid = signature.startsWith('valid-signature-');
    
    if (!isSignatureValid) {
        return res.status(400).json({
            message: 'Invalid signature',
            note: 'SECURE: Update rejected due to signature verification failure'
        });
    }
    
    res.json({
        message: 'Update executed (SECURE: With integrity verification)',
        note: 'This simulates executing code after verifying its signature'
    });
});

// VULNERABLE: Insecure CI/CD pipeline (simulated)
router.get('/integrity/ci-cd-status', (req, res) => {
    // --- VULNERABLE LOGIC: Insecure CI/CD pipeline ---
    // In a real app, this would be a CI/CD pipeline without proper security controls
    
    const buildStatus = {
        repository: 'example/app',
        branch: 'main',
        lastBuild: {
            id: 'build-123',
            status: 'success',
            timestamp: new Date().toISOString()
        },
        securityControls: {
            dependencyScan: false,
            codeScan: false,
            signedCommits: false,
            buildIntegrity: false
        }
    };
    
    res.json({
        buildStatus,
        warning: 'VULNERABLE: Insecure CI/CD pipeline without proper security controls',
        impact: 'An attacker could inject malicious code into the build process'
    });
});

// SECURE: Secure CI/CD pipeline (simulated)
router.get('/integrity/ci-cd-status-secure', (req, res) => {
    // --- SECURE LOGIC: Secure CI/CD pipeline ---
    // In a real app, this would be a CI/CD pipeline with proper security controls
    
    const buildStatus = {
        repository: 'example/app',
        branch: 'main',
        lastBuild: {
            id: 'build-123',
            status: 'success',
            timestamp: new Date().toISOString()
        },
        securityControls: {
            dependencyScan: true,
            codeScan: true,
            signedCommits: true,
            buildIntegrity: true
        },
        integrityVerification: {
            hashAlgorithm: 'SHA-256',
            buildHash: crypto.randomBytes(32).toString('hex')
        }
    };
    
    res.json({
        buildStatus,
        note: 'SECURE: CI/CD pipeline with proper security controls',
        explanation: 'This includes dependency scanning, code scanning, signed commits, and build integrity verification'
    });
});

// VULNERABLE: Untrusted data in object graph
router.post('/integrity/process-data', (req, res) => {
    const { data } = req.body;
    
    if (!data) {
        return res.status(400).json({ message: 'Data is required' });
    }
    
    // --- VULNERABLE LOGIC: No validation of object graph ---
    // In a real app, this would process data without validating its structure
    
    try {
        // Simulate processing the data
        const result = {
            processed: true,
            source: data,
            timestamp: new Date().toISOString()
        };
        
        res.json({
            result,
            warning: 'VULNERABLE: No validation of object graph',
            impact: 'An attacker could inject malicious data into the object graph'
        });
    } catch (error) {
        res.status(500).json({ message: 'Error processing data' });
    }
});

// SECURE: Validated data in object graph
router.post('/integrity/process-data-secure', (req, res) => {
    const { data } = req.body;
    
    if (!data) {
        return res.status(400).json({ message: 'Data is required' });
    }
    
    // --- SECURE LOGIC: Validation of object graph ---
    // In a real app, this would validate the data structure before processing
    
    try {
        // Validate the data structure (simplified)
        if (typeof data !== 'object' || data === null) {
            return res.status(400).json({ message: 'Invalid data structure' });
        }
        
        // Check for required fields
        if (!data.id || !data.name) {
            return res.status(400).json({ message: 'Missing required fields' });
        }
        
        // Validate field types
        if (typeof data.id !== 'string' || typeof data.name !== 'string') {
            return res.status(400).json({ message: 'Invalid field types' });
        }
        
        // Simulate processing the data
        const result = {
            processed: true,
            source: {
                id: data.id,
                name: data.name
            },
            timestamp: new Date().toISOString()
        };
        
        res.json({
            result,
            note: 'SECURE: With validation of object graph',
            explanation: 'This validates the data structure before processing'
        });
    } catch (error) {
        res.status(500).json({ message: 'Error processing data' });
    }
});

module.exports = router;
