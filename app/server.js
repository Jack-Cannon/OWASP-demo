// OWASP Security Demo App
// A vulnerable Node.js application for security education

const express = require('express');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Ensure uploads directory exists
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, uploadsDir);
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname);
    }
});
const upload = multer({ storage: storage });

// Import database model
const db = require('./models/db');
const { uploadedFiles, bankAccounts, loggedInUser, csrfTokens, dbUsers } = require('./models/db');

// Import routes
const injectionRoutes = require('./routes/injection');
const brokenAccessControlRoutes = require('./routes/broken-access-control');
const cryptoRoutes = require('./routes/cryptographic-failures');
const designRoutes = require('./routes/insecure-design');
const misconfigRoutes = require('./routes/security-misconfiguration');
const componentsRoutes = require('./routes/vulnerable-components');
const authRoutes = require('./routes/identification-auth-failures');
const integrityRoutes = require('./routes/integrity-failures');
const loggingRoutes = require('./routes/logging-monitoring');
const ssrfRoutes = require('./routes/ssrf');
const fileUploadRoutes = require('./routes/file-upload');

// Mount routes
app.use('/api/injection', injectionRoutes);
app.use('/api/bac', brokenAccessControlRoutes.router);
app.use('/api/crypto', cryptoRoutes);
app.use('/api/design', designRoutes);
app.use('/api/misconfig', misconfigRoutes);
app.use('/api/components', componentsRoutes);
app.use('/api/auth', authRoutes);
app.use('/api/integrity', integrityRoutes);
app.use('/api/logging', loggingRoutes);
app.use('/api/ssrf', ssrfRoutes);
app.use('/api/upload', fileUploadRoutes);

// API endpoint to get information about all vulnerabilities
app.get('/api/vulnerabilities', (req, res) => {
    const vulnerabilities = [
        {
            id: 'A01:2021',
            name: 'Broken Access Control',
            description: 'Restrictions on authenticated users are not properly enforced, allowing attackers to access unauthorized functionality.',
            examples: [
                '/api/bac/user-profile/:id - Insecure Direct Object Reference (IDOR)',
                '/api/bac/admin-data - Missing role-based access control',
                '/api/bac/transfer - Cross-Site Request Forgery (CSRF)'
            ]
        },
        {
            id: 'A02:2021',
            name: 'Cryptographic Failures',
            description: 'Failures related to cryptography that often lead to sensitive data exposure or system compromise.',
            examples: [
                '/api/crypto/login - Plaintext password storage',
                '/api/crypto/send-data - Insecure data transmission',
                '/api/crypto/encrypt - Weak encryption algorithms'
            ]
        },
        {
            id: 'A03:2021',
            name: 'Injection',
            description: 'User-supplied data is not validated, filtered, or sanitized by the application.',
            examples: [
                '/api/injection/xss/add-comment - Cross-Site Scripting (XSS)',
                '/api/injection/search-user - SQL Injection (simulated)',
                '/api/injection/command - Command Injection (simulated)'
            ]
        },
        {
            id: 'A04:2021',
            name: 'Insecure Design',
            description: 'Flaws in the design and architecture of applications that cannot be fixed by proper implementation.',
            examples: [
                '/api/design/forgot-password - Predictable password reset tokens',
                '/api/design/check-username - Account enumeration',
                '/api/design/create-user - Missing input validation'
            ]
        },
        {
            id: 'A05:2021',
            name: 'Security Misconfiguration',
            description: 'Improper implementation of controls intended to keep application data safe.',
            examples: [
                '/api/misconfig/login - Default credentials',
                '/api/misconfig/error - Detailed error messages',
                '/api/misconfig/parse-xml - XML External Entity (XXE) processing'
            ]
        },
        {
            id: 'A06:2021',
            name: 'Vulnerable and Outdated Components',
            description: 'Using components with known vulnerabilities or failing to update systems.',
            examples: [
                '/api/components/dependencies - Outdated libraries',
                '/api/components/install - No integrity verification',
                '/api/components/render - Vulnerable component usage'
            ]
        },
        {
            id: 'A07:2021',
            name: 'Identification and Authentication Failures',
            description: 'Authentication-related attacks that target user identity, authentication, and session management.',
            examples: [
                '/api/auth/register - Weak password policy',
                '/api/auth/login - No brute force protection',
                '/api/auth/profile - Insecure session management'
            ]
        },
        {
            id: 'A08:2021',
            name: 'Software and Data Integrity Failures',
            description: 'Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations.',
            examples: [
                '/api/integrity/deserialize - Insecure deserialization',
                '/api/integrity/execute-update - Unsigned code execution',
                '/api/integrity/ci-cd-status - Insecure CI/CD pipeline'
            ]
        },
        {
            id: 'A09:2021',
            name: 'Security Logging and Monitoring Failures',
            description: 'This category helps detect, escalate, and respond to active breaches.',
            examples: [
                '/api/logging/login-attempt - Insufficient logging',
                '/api/logging/file-access - No monitoring for suspicious activity',
                '/api/logging/security-event - No alerting mechanism'
            ]
        },
        {
            id: 'A10:2021',
            name: 'Server-Side Request Forgery',
            description: 'SSRF flaws occur when a web application fetches a remote resource without validating the user-supplied URL.',
            examples: [
                '/api/ssrf/fetch-url - No URL validation',
                '/api/ssrf/image-proxy - Insecure image proxy'
            ]
        }
    ];
    
    res.json(vulnerabilities);
});

// Home route
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Helper endpoint to get current logged-in user (for frontend)
app.get('/api/current-user', (req, res) => {
    res.json(brokenAccessControlRoutes.getLoggedInUser());
});

// Start the server
app.listen(PORT, () => {
    console.log(`OWASP Security Demo App running at http://localhost:${PORT}`);
    console.log(`Open http://localhost:${PORT} in your browser to start the demo.`);
});


// Broken Access Control routes are now handled in routes/broken-access-control.js

// All Broken Access Control routes are now handled in routes/broken-access-control.js


// CSRF routes are now handled in routes/broken-access-control.js

// All CSRF routes are now handled in routes/broken-access-control.js

// CSRF balance route is now handled in routes/broken-access-control.js

// --- API Endpoints for File Upload Vulnerability ---

// VULNERABLE File Upload: No validation on file type or content
app.post('/api/upload/vulnerable', upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ success: false, message: 'No file uploaded' });
    }
    
    // No validation on file type or content
    const fileInfo = {
        filename: req.file.filename,
        originalname: req.file.originalname,
        mimetype: req.file.mimetype,
        size: req.file.size,
        path: req.file.path
    };
    
    uploadedFiles.push(fileInfo);
    
    console.log('VULNERABLE UPLOAD:', fileInfo);
    
    res.json({
        success: true,
        message: 'File uploaded successfully (VULNERABLE)',
        file: fileInfo
    });
});

// SECURE File Upload: With validation
app.post('/api/upload/secure', (req, res) => {
    // Use multer middleware inline with validation
    const secureUpload = multer({
        storage: storage,
        fileFilter: (req, file, cb) => {
            // Validate file type
            const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
            if (!allowedTypes.includes(file.mimetype)) {
                return cb(new Error('Only image files are allowed!'), false);
            }
            cb(null, true);
        },
        limits: {
            fileSize: 1024 * 1024 * 5 // 5MB limit
        }
    }).single('file');
    
    secureUpload(req, res, function(err) {
        if (err) {
            return res.status(400).json({
                success: false,
                message: err.message
            });
        }
        
        if (!req.file) {
            return res.status(400).json({
                success: false,
                message: 'No file uploaded'
            });
        }
        
        const fileInfo = {
            filename: req.file.filename,
            originalname: req.file.originalname,
            mimetype: req.file.mimetype,
            size: req.file.size,
            path: req.file.path
        };
        
        uploadedFiles.push(fileInfo);
        
        console.log('SECURE UPLOAD:', fileInfo);
        
        res.json({
            success: true,
            message: 'File uploaded successfully (SECURE)',
            file: fileInfo
        });
    });
});

// File upload routes are now handled in routes/file-upload.js

// Start the server
app.listen(PORT, () => {
    console.log(`Vulnerable Node.js app running at http://localhost:${PORT}`);
    console.log(`Open http://localhost:${PORT} in your browser to start the demo.`);
});