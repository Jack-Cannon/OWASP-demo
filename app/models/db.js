// models/db.js
// In-memory database for demonstration purposes

// User database
const dbUsers = [
    { id: 1, username: 'alice', email: 'alice@example.com', role: 'user' },
    { id: 2, username: 'bob', email: 'bob@example.com', role: 'user' },
    { id: 3, username: 'charlie', email: 'charlie@example.com', role: 'user' },
    { id: 4, username: 'admin', email: 'admin@example.com', role: 'admin' },
    { id: 101, username: 'user', email: 'user@example.com', role: 'user' }
];

// XSS comments storage
const xssComments = [];
const xssSecureComments = [];

// Bank account simulation for CSRF demo
const bankAccounts = {
    'user': { balance: 1000 },
    'admin': { balance: 5000 }
};

// File upload tracking
const uploadedFiles = [];

// Cryptographic failures demo - insecure storage
const userCredentials = [
    { username: 'user', password: 'password' }, // Plaintext password - insecure!
    { username: 'admin', password: 'adminpass' } // Plaintext password - insecure!
];

// Secure version with hashed passwords (simulated)
const secureUserCredentials = [
    { username: 'user', passwordHash: '$2b$10$abcdefghijklmnopqrstuv' }, // Simulated bcrypt hash
    { username: 'admin', passwordHash: '$2b$10$vwxyzabcdefghijklmnopq' } // Simulated bcrypt hash
];

// Insecure Design demo - weak password reset tokens
const passwordResetTokens = new Map();

// Security Misconfiguration - default credentials
const defaultCredentials = {
    username: 'system',
    password: 'admin123'
};

// Software and Data Integrity - update packages
const softwarePackages = [
    { name: 'secure-lib', version: '1.2.3', integrity: 'sha256-abc123', verified: true },
    { name: 'vulnerable-lib', version: '0.9.1', integrity: null, verified: false }
];

// Security Logging data
const securityLogs = [];

module.exports = {
    dbUsers,
    xssComments,
    xssSecureComments,
    bankAccounts,
    uploadedFiles,
    userCredentials,
    secureUserCredentials,
    passwordResetTokens,
    defaultCredentials,
    softwarePackages,
    securityLogs
};
