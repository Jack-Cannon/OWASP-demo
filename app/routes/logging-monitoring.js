// routes/logging-monitoring.js
// Handles A09:2021-Security Logging and Monitoring Failures vulnerabilities

const express = require('express');
const router = express.Router();
const { securityLogs } = require('../models/db');

// --- Security Logging and Monitoring Failures Routes ---

// Helper function to add a log entry
function addLogEntry(type, message, details, isSecure = false) {
    const logEntry = {
        id: securityLogs.length + 1,
        timestamp: new Date().toISOString(),
        type,
        message,
        details,
        isSecure
    };
    
    securityLogs.push(logEntry);
    return logEntry;
}

// VULNERABLE: Insufficient logging
router.post('/logging/login-attempt', (req, res) => {
    const { username, success } = req.body;
    
    if (!username || success === undefined) {
        return res.status(400).json({ message: 'Username and success status are required' });
    }
    
    // --- VULNERABLE LOGIC: Insufficient logging ---
    // Only logs successful logins, not failures
    if (success) {
        // Log successful login
        addLogEntry('login', 'User logged in', { username });
    }
    // Failed login attempts are not logged!
    
    res.json({
        message: success ? 'Login successful' : 'Login failed',
        warning: 'VULNERABLE: Insufficient logging (failed logins not logged)',
        impact: 'Failed login attempts go undetected, making it difficult to identify brute force attacks'
    });
});

// SECURE: Comprehensive logging
router.post('/logging/login-attempt-secure', (req, res) => {
    const { username, success, ipAddress } = req.body;
    
    if (!username || success === undefined) {
        return res.status(400).json({ message: 'Username and success status are required' });
    }
    
    // --- SECURE LOGIC: Comprehensive logging ---
    // Log both successful and failed login attempts with relevant details
    const logType = success ? 'login_success' : 'login_failure';
    const logMessage = success ? 'User logged in successfully' : 'Failed login attempt';
    
    // Include more context in the log
    const logDetails = {
        username,
        ipAddress: ipAddress || '127.0.0.1', // In a real app, this would be the actual IP
        userAgent: req.headers['user-agent'] || 'Unknown',
        timestamp: new Date().toISOString()
    };
    
    addLogEntry(logType, logMessage, logDetails, true);
    
    res.json({
        message: success ? 'Login successful' : 'Login failed',
        note: 'SECURE: Comprehensive logging of all login attempts',
        explanation: 'Both successful and failed login attempts are logged with relevant context'
    });
});

// VULNERABLE: No monitoring for suspicious activity
router.post('/logging/file-access', (req, res) => {
    const { fileId, userId } = req.body;
    
    if (!fileId || !userId) {
        return res.status(400).json({ message: 'File ID and user ID are required' });
    }
    
    // --- VULNERABLE LOGIC: No monitoring for suspicious activity ---
    // This endpoint doesn't monitor for unusual access patterns
    
    // Log the access (minimal information)
    addLogEntry('file_access', 'File accessed', { fileId, userId });
    
    res.json({
        message: 'File access recorded',
        warning: 'VULNERABLE: No monitoring for suspicious activity',
        impact: 'Unusual access patterns go undetected, making it difficult to identify data exfiltration'
    });
});

// SECURE: Monitoring for suspicious activity
router.post('/logging/file-access-secure', (req, res) => {
    const { fileId, userId, fileType } = req.body;
    
    if (!fileId || !userId) {
        return res.status(400).json({ message: 'File ID and user ID are required' });
    }
    
    // --- SECURE LOGIC: Monitoring for suspicious activity ---
    // This endpoint monitors for unusual access patterns
    
    // Simulate checking for suspicious activity
    const isHighValueFile = fileType === 'confidential' || parseInt(fileId, 10) < 100;
    const isFirstTimeAccess = !securityLogs.some(log => 
        log.type === 'file_access' && 
        log.details.fileId === fileId && 
        log.details.userId === userId
    );
    const isRapidAccess = securityLogs.filter(log => 
        log.type === 'file_access' && 
        log.details.userId === userId &&
        new Date(log.timestamp) > new Date(Date.now() - 60000) // Last minute
    ).length > 10;
    
    // Determine if this access is suspicious
    const isSuspicious = isHighValueFile && (isFirstTimeAccess || isRapidAccess);
    
    // Log the access with detailed information
    const logEntry = addLogEntry(
        isSuspicious ? 'suspicious_file_access' : 'file_access',
        isSuspicious ? 'Suspicious file access detected' : 'File accessed',
        {
            fileId,
            userId,
            fileType: fileType || 'unknown',
            ipAddress: '127.0.0.1', // In a real app, this would be the actual IP
            userAgent: req.headers['user-agent'] || 'Unknown',
            isFirstTimeAccess,
            accessCount: securityLogs.filter(log => 
                log.type === 'file_access' && 
                log.details.fileId === fileId && 
                log.details.userId === userId
            ).length + 1
        },
        true
    );
    
    res.json({
        message: 'File access recorded',
        alert: isSuspicious ? 'Suspicious activity detected' : undefined,
        note: 'SECURE: Monitoring for suspicious activity',
        explanation: 'This endpoint monitors for unusual access patterns and flags suspicious activity'
    });
});

// VULNERABLE: No alerting mechanism
router.post('/logging/security-event', (req, res) => {
    const { eventType, severity, details } = req.body;
    
    if (!eventType || !severity) {
        return res.status(400).json({ message: 'Event type and severity are required' });
    }
    
    // --- VULNERABLE LOGIC: No alerting mechanism ---
    // This endpoint logs security events but doesn't alert on high-severity events
    
    // Log the security event
    addLogEntry('security_event', `Security event: ${eventType}`, {
        severity,
        ...details
    });
    
    res.json({
        message: 'Security event logged',
        warning: 'VULNERABLE: No alerting mechanism for high-severity events',
        impact: 'Critical security events may go unnoticed until it\'s too late'
    });
});

// SECURE: Alerting mechanism for high-severity events
router.post('/logging/security-event-secure', (req, res) => {
    const { eventType, severity, details } = req.body;
    
    if (!eventType || !severity) {
        return res.status(400).json({ message: 'Event type and severity are required' });
    }
    
    // --- SECURE LOGIC: Alerting mechanism for high-severity events ---
    // This endpoint logs security events and alerts on high-severity events
    
    // Log the security event
    const logEntry = addLogEntry('security_event', `Security event: ${eventType}`, {
        severity,
        timestamp: new Date().toISOString(),
        ...details
    }, true);
    
    // Determine if an alert should be triggered
    const shouldAlert = severity === 'high' || severity === 'critical';
    
    if (shouldAlert) {
        // Simulate sending an alert (in a real app, this would send an email, SMS, etc.)
        console.log(`[ALERT] Critical security event detected: ${eventType}`);
        
        // In a real app, you might also:
        // - Send an email to security team
        // - Send an SMS to on-call staff
        // - Create a ticket in the incident management system
        // - Trigger an automated response (e.g., block an IP)
    }
    
    res.json({
        message: 'Security event logged',
        alert: shouldAlert ? 'Alert triggered for high-severity event' : undefined,
        note: 'SECURE: Alerting mechanism for high-severity events',
        explanation: 'This endpoint alerts on high-severity security events for immediate attention'
    });
});

// Get all logs (for demo purposes)
router.get('/logging/all-logs', (req, res) => {
    res.json(securityLogs);
});

// Clear all logs (for demo reset)
router.post('/logging/clear-logs', (req, res) => {
    securityLogs.length = 0;
    res.json({ message: 'All logs cleared' });
});

module.exports = router;
