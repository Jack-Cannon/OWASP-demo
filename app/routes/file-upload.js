// routes/file-upload.js
// Handles insecure file upload vulnerabilities (related to multiple OWASP categories)

const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { uploadedFiles } = require('../models/db');

// Ensure uploads directory exists
const uploadsDir = path.join(__dirname, '../uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

// --- Insecure File Upload Routes ---

// VULNERABLE: Insecure file upload
router.post('/upload/file', (req, res) => {
    const { filename, content, contentType } = req.body;
    
    if (!filename || !content) {
        return res.status(400).json({ message: 'Filename and content are required' });
    }
    
    // --- VULNERABLE LOGIC: No file type validation ---
    // This endpoint allows uploading any file type, including potentially dangerous ones
    
    try {
        // Decode base64 content
        const fileBuffer = Buffer.from(content, 'base64');
        
        // Create a unique filename to avoid overwriting
        const uniqueFilename = `${Date.now()}-${filename}`;
        const filePath = path.join(uploadsDir, uniqueFilename);
        
        // Write the file
        fs.writeFileSync(filePath, fileBuffer);
        
        // Track the uploaded file
        uploadedFiles.push({
            originalName: filename,
            savedAs: uniqueFilename,
            contentType: contentType || 'application/octet-stream',
            size: fileBuffer.length,
            uploadedAt: new Date().toISOString()
        });
        
        res.json({
            message: 'File uploaded successfully (VULNERABLE: No file type validation)',
            filename: uniqueFilename,
            warning: 'This endpoint allows uploading any file type, including potentially dangerous ones',
            impact: 'An attacker could upload malicious files (e.g., PHP scripts) that could be executed on the server'
        });
    } catch (error) {
        res.status(500).json({
            message: 'Error uploading file',
            error: error.message
        });
    }
});

// SECURE: Secure file upload
router.post('/upload/file-secure', (req, res) => {
    const { filename, content, contentType } = req.body;
    
    if (!filename || !content) {
        return res.status(400).json({ message: 'Filename and content are required' });
    }
    
    try {
        // --- SECURE LOGIC: File type validation ---
        
        // Check file extension
        const ext = path.extname(filename).toLowerCase();
        const allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.pdf', '.txt', '.csv'];
        
        if (!allowedExtensions.includes(ext)) {
            return res.status(400).json({
                message: 'Invalid file type',
                note: 'SECURE: Only specific file types are allowed',
                allowedExtensions
            });
        }
        
        // Decode base64 content
        const fileBuffer = Buffer.from(content, 'base64');
        
        // Check file signature/magic bytes (simplified)
        const isValidFileType = validateFileSignature(fileBuffer, ext);
        
        if (!isValidFileType) {
            return res.status(400).json({
                message: 'File content does not match the extension',
                note: 'SECURE: File signature validation prevents content spoofing'
            });
        }
        
        // Create a unique filename with a random string to avoid path traversal
        const randomString = crypto.randomBytes(8).toString('hex');
        const sanitizedFilename = path.basename(filename).replace(/[^a-zA-Z0-9_.-]/g, '_');
        const uniqueFilename = `${Date.now()}-${randomString}-${sanitizedFilename}`;
        const filePath = path.join(uploadsDir, uniqueFilename);
        
        // Write the file
        fs.writeFileSync(filePath, fileBuffer);
        
        // Track the uploaded file
        uploadedFiles.push({
            originalName: filename,
            savedAs: uniqueFilename,
            contentType: contentType || 'application/octet-stream',
            size: fileBuffer.length,
            uploadedAt: new Date().toISOString(),
            secureUpload: true
        });
        
        res.json({
            message: 'File uploaded successfully (SECURE: With file type validation)',
            filename: uniqueFilename,
            note: 'This endpoint validates file types and prevents uploading potentially dangerous files'
        });
    } catch (error) {
        res.status(500).json({
            message: 'Error uploading file',
            error: error.message
        });
    }
});

// Helper function to validate file signature (simplified)
function validateFileSignature(buffer, extension) {
    // This is a simplified version - in a real app, you'd use a library like file-type
    if (buffer.length < 4) return false;
    
    const firstBytes = buffer.slice(0, 4).toString('hex');
    
    switch (extension) {
        case '.jpg':
        case '.jpeg':
            return firstBytes.startsWith('ffd8');
        case '.png':
            return firstBytes === '89504e47';
        case '.gif':
            return firstBytes === '47494638';
        case '.pdf':
            return buffer.slice(0, 5).toString() === '%PDF-';
        case '.txt':
        case '.csv':
            // Text files don't have a specific signature, so we check if it's printable ASCII
            return isPrintableAscii(buffer.slice(0, 100));
        default:
            return false;
    }
}

// Helper function to check if a buffer contains printable ASCII
function isPrintableAscii(buffer) {
    for (let i = 0; i < buffer.length; i++) {
        const byte = buffer[i];
        // Check if byte is a printable ASCII character or common control character
        if ((byte < 32 && ![9, 10, 13].includes(byte)) || byte > 126) {
            return false;
        }
    }
    return true;
}

// Get all uploaded files (for demo purposes)
router.get('/upload/files', (req, res) => {
    res.json(uploadedFiles);
});

// Clear all uploaded files (for demo reset)
router.post('/upload/clear-files', (req, res) => {
    // Clear the tracking array
    uploadedFiles.length = 0;
    
    // Attempt to clear the uploads directory
    try {
        const files = fs.readdirSync(uploadsDir);
        for (const file of files) {
            fs.unlinkSync(path.join(uploadsDir, file));
        }
        res.json({ message: 'All uploaded files cleared' });
    } catch (error) {
        res.status(500).json({
            message: 'Error clearing files',
            error: error.message
        });
    }
});

module.exports = router;
