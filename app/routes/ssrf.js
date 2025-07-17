// routes/ssrf.js
// Handles A10:2021-Server-Side Request Forgery vulnerabilities

const express = require('express');
const router = express.Router();
const http = require('http');
const https = require('https');
const url = require('url');

// --- Server-Side Request Forgery (SSRF) Routes ---

// VULNERABLE: SSRF vulnerability
router.get('/ssrf/fetch-url', (req, res) => {
    const { target } = req.query;
    
    if (!target) {
        return res.status(400).json({ message: 'Target URL is required' });
    }
    
    // --- VULNERABLE LOGIC: No URL validation ---
    // This endpoint makes a request to any URL provided by the user
    
    try {
        const parsedUrl = new URL(target);
        const protocol = parsedUrl.protocol === 'https:' ? https : http;
        
        // Make the request to the target URL
        const request = protocol.get(target, (response) => {
            let data = '';
            
            // A chunk of data has been received
            response.on('data', (chunk) => {
                data += chunk;
            });
            
            // The whole response has been received
            response.on('end', () => {
                res.json({
                    url: target,
                    status: response.statusCode,
                    headers: response.headers,
                    data: data.substring(0, 500) + (data.length > 500 ? '...' : ''), // Truncate for demo
                    warning: 'VULNERABLE: This endpoint allows SSRF attacks',
                    impact: 'An attacker could access internal resources or services'
                });
            });
        });
        
        // Handle errors
        request.on('error', (error) => {
            res.status(500).json({
                message: 'Error fetching URL',
                error: error.message
            });
        });
        
        // Set a timeout
        request.setTimeout(5000, () => {
            request.abort();
            res.status(504).json({
                message: 'Request timed out'
            });
        });
    } catch (error) {
        res.status(400).json({
            message: 'Invalid URL',
            error: error.message
        });
    }
});

// SECURE: SSRF protection
router.get('/ssrf/fetch-url-secure', (req, res) => {
    const { target } = req.query;
    
    if (!target) {
        return res.status(400).json({ message: 'Target URL is required' });
    }
    
    // --- SECURE LOGIC: URL validation and restrictions ---
    try {
        const parsedUrl = new URL(target);
        
        // Check for private/internal IP addresses
        const hostname = parsedUrl.hostname;
        
        // Block localhost and private IP ranges
        if (hostname === 'localhost' || 
            hostname === '127.0.0.1' || 
            hostname.startsWith('10.') || 
            hostname.startsWith('172.16.') || 
            hostname.startsWith('192.168.') ||
            hostname.endsWith('.local') ||
            hostname === '[::1]') {
            
            return res.status(403).json({
                message: 'Access to internal/private hosts is forbidden',
                note: 'SECURE: Blocked attempt to access internal resources'
            });
        }
        
        // Only allow http and https protocols
        if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
            return res.status(403).json({
                message: 'Only HTTP and HTTPS protocols are allowed',
                note: 'SECURE: Blocked attempt to use non-HTTP protocol'
            });
        }
        
        // Whitelist approach (in a real app, you might use a whitelist of allowed domains)
        const allowedDomains = ['example.com', 'api.github.com', 'jsonplaceholder.typicode.com'];
        const isAllowed = allowedDomains.some(domain => hostname === domain || hostname.endsWith('.' + domain));
        
        if (!isAllowed) {
            return res.status(403).json({
                message: 'Domain not in whitelist',
                note: 'SECURE: Using a whitelist of allowed domains'
            });
        }
        
        // Make the request to the validated URL
        const protocol = parsedUrl.protocol === 'https:' ? https : http;
        
        const request = protocol.get(target, (response) => {
            let data = '';
            
            // A chunk of data has been received
            response.on('data', (chunk) => {
                data += chunk;
            });
            
            // The whole response has been received
            response.on('end', () => {
                res.json({
                    url: target,
                    status: response.statusCode,
                    headers: response.headers,
                    data: data.substring(0, 500) + (data.length > 500 ? '...' : ''), // Truncate for demo
                    note: 'SECURE: URL validated against whitelist and security checks'
                });
            });
        });
        
        // Handle errors
        request.on('error', (error) => {
            res.status(500).json({
                message: 'Error fetching URL',
                error: error.message
            });
        });
        
        // Set a timeout
        request.setTimeout(5000, () => {
            request.abort();
            res.status(504).json({
                message: 'Request timed out'
            });
        });
    } catch (error) {
        res.status(400).json({
            message: 'Invalid URL',
            error: error.message
        });
    }
});

// VULNERABLE: SSRF via image proxy
router.get('/ssrf/image-proxy', (req, res) => {
    const { url: imageUrl } = req.query;
    
    if (!imageUrl) {
        return res.status(400).json({ message: 'Image URL is required' });
    }
    
    // --- VULNERABLE LOGIC: No URL validation for image proxy ---
    // This endpoint proxies any image URL provided by the user
    
    try {
        const parsedUrl = new URL(imageUrl);
        const protocol = parsedUrl.protocol === 'https:' ? https : http;
        
        // Set the appropriate headers
        res.setHeader('Content-Type', 'image/jpeg'); // Assuming it's a JPEG
        
        // Pipe the image directly to the response
        const request = protocol.get(imageUrl, (response) => {
            // Check if it's an image
            const contentType = response.headers['content-type'] || '';
            
            if (!contentType.startsWith('image/')) {
                // If it's not an image, send a warning
                res.setHeader('Content-Type', 'application/json');
                return res.status(400).json({
                    message: 'Not an image',
                    warning: 'VULNERABLE: This endpoint allows SSRF attacks via image proxy',
                    impact: 'An attacker could access internal resources or services'
                });
            }
            
            // Pipe the image data to the response
            response.pipe(res);
        });
        
        // Handle errors
        request.on('error', (error) => {
            res.setHeader('Content-Type', 'application/json');
            res.status(500).json({
                message: 'Error fetching image',
                error: error.message
            });
        });
        
        // Set a timeout
        request.setTimeout(5000, () => {
            request.abort();
            res.setHeader('Content-Type', 'application/json');
            res.status(504).json({
                message: 'Request timed out'
            });
        });
    } catch (error) {
        res.status(400).json({
            message: 'Invalid URL',
            error: error.message
        });
    }
});

// SECURE: SSRF protection for image proxy
router.get('/ssrf/image-proxy-secure', (req, res) => {
    const { url: imageUrl } = req.query;
    
    if (!imageUrl) {
        return res.status(400).json({ message: 'Image URL is required' });
    }
    
    // --- SECURE LOGIC: URL validation and restrictions for image proxy ---
    try {
        const parsedUrl = new URL(imageUrl);
        
        // Check for private/internal IP addresses
        const hostname = parsedUrl.hostname;
        
        // Block localhost and private IP ranges
        if (hostname === 'localhost' || 
            hostname === '127.0.0.1' || 
            hostname.startsWith('10.') || 
            hostname.startsWith('172.16.') || 
            hostname.startsWith('192.168.') ||
            hostname.endsWith('.local') ||
            hostname === '[::1]') {
            
            return res.status(403).json({
                message: 'Access to internal/private hosts is forbidden',
                note: 'SECURE: Blocked attempt to access internal resources'
            });
        }
        
        // Only allow http and https protocols
        if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
            return res.status(403).json({
                message: 'Only HTTP and HTTPS protocols are allowed',
                note: 'SECURE: Blocked attempt to use non-HTTP protocol'
            });
        }
        
        // Whitelist approach for image domains
        const allowedImageDomains = ['picsum.photos', 'placekitten.com', 'placeimg.com', 'loremflickr.com'];
        const isAllowed = allowedImageDomains.some(domain => hostname === domain || hostname.endsWith('.' + domain));
        
        if (!isAllowed) {
            return res.status(403).json({
                message: 'Image domain not in whitelist',
                note: 'SECURE: Using a whitelist of allowed image domains'
            });
        }
        
        // Make the request to the validated image URL
        const protocol = parsedUrl.protocol === 'https:' ? https : http;
        
        const request = protocol.get(imageUrl, (response) => {
            // Check if it's an image
            const contentType = response.headers['content-type'] || '';
            
            if (!contentType.startsWith('image/')) {
                return res.status(400).json({
                    message: 'Not an image',
                    note: 'Content type validation prevents non-image responses'
                });
            }
            
            // Set the appropriate headers
            res.setHeader('Content-Type', contentType);
            
            // Pipe the image data to the response
            response.pipe(res);
        });
        
        // Handle errors
        request.on('error', (error) => {
            res.status(500).json({
                message: 'Error fetching image',
                error: error.message
            });
        });
        
        // Set a timeout
        request.setTimeout(5000, () => {
            request.abort();
            res.status(504).json({
                message: 'Request timed out'
            });
        });
    } catch (error) {
        res.status(400).json({
            message: 'Invalid URL',
            error: error.message
        });
    }
});

module.exports = router;
