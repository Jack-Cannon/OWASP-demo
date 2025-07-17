// routes/insecure-design.js
// Handles A04:2021-Insecure Design vulnerabilities

const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const { passwordResetTokens } = require('../models/db');

// --- Insecure Design Routes ---

// VULNERABLE: Predictable password reset token
router.post('/design/forgot-password', (req, res) => {
    const { username } = req.body;
    
    if (!username) {
        return res.status(400).json({ message: 'Username is required' });
    }
    
    // --- VULNERABLE LOGIC: Predictable token generation ---
    // Using a timestamp-based token that could be guessed
    const timestamp = Date.now();
    const token = `reset-${username}-${timestamp}`;
    
    // Store the token (in a real app, this would be in a database)
    passwordResetTokens.set(username, token);
    
    res.json({
        success: true,
        message: 'Password reset initiated (INSECURE: Predictable token)',
        token: token, // In a real app, this would be sent via email, not in the response
        expiresIn: '1 hour'
    });
});

// SECURE: Cryptographically secure password reset token
router.post('/design/forgot-password-secure', (req, res) => {
    const { username } = req.body;
    
    if (!username) {
        return res.status(400).json({ message: 'Username is required' });
    }
    
    // --- SECURE LOGIC: Cryptographically secure token generation ---
    const token = crypto.randomBytes(32).toString('hex');
    
    // Store the token with expiration (in a real app, this would be in a database)
    passwordResetTokens.set(username, {
        token: token,
        expires: Date.now() + 3600000 // 1 hour from now
    });
    
    res.json({
        success: true,
        message: 'Password reset initiated (SECURE: Cryptographically secure token)',
        // In a real app, we wouldn't return the token in the response
        note: 'Token would be sent via email, not in the API response'
    });
});

// VULNERABLE: Insecure password reset (no verification)
router.post('/design/reset-password', (req, res) => {
    const { username, token, newPassword } = req.body;
    
    if (!username || !token || !newPassword) {
        return res.status(400).json({ message: 'Username, token, and new password are required' });
    }
    
    // --- VULNERABLE LOGIC: No rate limiting, no account lockout ---
    // This allows unlimited attempts to guess the token
    
    const storedToken = passwordResetTokens.get(username);
    
    if (!storedToken) {
        return res.status(400).json({ message: 'Invalid or expired token' });
    }
    
    if (storedToken !== token) {
        return res.status(400).json({ message: 'Invalid token' });
    }
    
    // Reset the password (in a real app, this would update the database)
    passwordResetTokens.delete(username);
    
    res.json({
        success: true,
        message: 'Password reset successful (INSECURE: No rate limiting or account lockout)'
    });
});

// SECURE: Secure password reset (with verification)
router.post('/design/reset-password-secure', (req, res) => {
    const { username, token, newPassword } = req.body;
    
    if (!username || !token || !newPassword) {
        return res.status(400).json({ message: 'Username, token, and new password are required' });
    }
    
    // --- SECURE LOGIC: Token verification with expiration check ---
    const storedData = passwordResetTokens.get(username);
    
    if (!storedData) {
        return res.status(400).json({ message: 'Invalid or expired token' });
    }
    
    // Check if token is expired
    if (storedData.expires < Date.now()) {
        passwordResetTokens.delete(username);
        return res.status(400).json({ message: 'Token has expired' });
    }
    
    // Verify token using constant-time comparison to prevent timing attacks
    const isTokenValid = crypto.timingSafeEqual(
        Buffer.from(storedData.token),
        Buffer.from(token)
    );
    
    if (!isTokenValid) {
        // In a real app, we would implement rate limiting here
        return res.status(400).json({ message: 'Invalid token' });
    }
    
    // Password complexity check
    if (newPassword.length < 8) {
        return res.status(400).json({ message: 'Password must be at least 8 characters long' });
    }
    
    // Reset the password (in a real app, this would update the database)
    passwordResetTokens.delete(username);
    
    res.json({
        success: true,
        message: 'Password reset successful (SECURE: With expiration and validation)'
    });
});

// VULNERABLE: Insecure business logic (account enumeration)
router.post('/design/check-username', (req, res) => {
    const { username } = req.body;
    
    if (!username) {
        return res.status(400).json({ message: 'Username is required' });
    }
    
    // --- VULNERABLE LOGIC: Account enumeration ---
    // This endpoint reveals whether a username exists in the system
    const validUsernames = ['user', 'admin', 'alice', 'bob'];
    const exists = validUsernames.includes(username);
    
    res.json({
        exists: exists,
        message: exists ? 
            'Username exists in the system' : 
            'Username does not exist',
        warning: 'INSECURE: This endpoint allows account enumeration'
    });
});

// SECURE: Protected business logic (prevents account enumeration)
router.post('/design/check-username-secure', (req, res) => {
    const { username } = req.body;
    
    if (!username) {
        return res.status(400).json({ message: 'Username is required' });
    }
    
    // --- SECURE LOGIC: Prevent account enumeration ---
    // Always return the same response regardless of whether the username exists
    
    res.json({
        message: 'If the username exists, a password reset link will be sent to the associated email address.',
        note: 'SECURE: This response prevents account enumeration'
    });
});

// VULNERABLE: Missing input validation
router.post('/design/create-user', (req, res) => {
    const { username, email, age } = req.body;
    
    // --- VULNERABLE LOGIC: No input validation ---
    // This endpoint doesn't validate any of the inputs
    
    res.json({
        success: true,
        message: 'User created (INSECURE: No input validation)',
        user: {
            username,
            email,
            age: parseInt(age, 10) || 0
        },
        warning: 'This endpoint accepts any input without validation'
    });
});

// SECURE: Proper input validation
router.post('/design/create-user-secure', (req, res) => {
    const { username, email, age } = req.body;
    
    // --- SECURE LOGIC: Input validation ---
    if (!username || username.length < 3) {
        return res.status(400).json({ message: 'Username must be at least 3 characters long' });
    }
    
    if (!email || !email.includes('@') || !email.includes('.')) {
        return res.status(400).json({ message: 'Valid email address is required' });
    }
    
    const parsedAge = parseInt(age, 10);
    if (isNaN(parsedAge) || parsedAge < 18 || parsedAge > 120) {
        return res.status(400).json({ message: 'Age must be between 18 and 120' });
    }
    
    res.json({
        success: true,
        message: 'User created (SECURE: With input validation)',
        user: {
            username,
            email,
            age: parsedAge
        }
    });
});

// VULNERABLE: Insecure discount code implementation
router.post('/apply-discount', (req, res) => {
    const { code } = req.body;
    
    if (!code) {
        return res.status(400).json({ message: 'Discount code is required' });
    }
    
    // --- VULNERABLE LOGIC: Predictable discount codes and no state tracking ---
    // This allows discount stacking and reuse
    let discount = 0;
    let message = '';
    
    // Simple, predictable discount codes
    if (code === 'SAVE10') {
        discount = 10;
        message = '10% discount applied!';
    } else if (code === 'SAVE20') {
        discount = 20;
        message = '20% discount applied!';
    } else if (code === 'SAVE50') {
        discount = 50;
        message = '50% discount applied!';
    } else if (code === 'FREESHIP') {
        discount = 5;
        message = 'Free shipping discount applied!';
    } else {
        return res.status(400).json({ message: 'Invalid discount code' });
    }
    
    res.json({
        success: true,
        discount: discount,
        message: message,
        warning: 'INSECURE: This endpoint allows discount stacking and has predictable codes'
    });
});

// SECURE: Proper discount code implementation
router.post('/apply-discount-secure', (req, res) => {
    const { code, sessionId } = req.body;
    
    if (!code || !sessionId) {
        return res.status(400).json({ message: 'Discount code and session ID are required' });
    }
    
    // --- SECURE LOGIC: One-time use codes with state tracking ---
    // In a real app, we would check if this code has been used before
    // and associate it with the specific user/session
    
    // Simulating a database of valid codes with complex, unpredictable values
    const validCodes = {
        'X7T9P2R5': { discount: 10, used: false },
        'L3K8M5N2': { discount: 20, used: false },
        'A9B7C5D3': { discount: 15, used: false },
    };
    
    if (!validCodes[code]) {
        return res.status(400).json({ message: 'Invalid or expired discount code' });
    }
    
    if (validCodes[code].used) {
        return res.status(400).json({ message: 'This discount code has already been used' });
    }
    
    // Mark the code as used
    validCodes[code].used = true;
    
    res.json({
        success: true,
        discount: validCodes[code].discount,
        message: `${validCodes[code].discount}% discount applied!`,
        note: 'SECURE: This endpoint prevents discount stacking and uses unpredictable codes'
    });
});

// VULNERABLE: Insecure checkout process
router.post('/checkout', (req, res) => {
    const { cart, discounts } = req.body;
    
    if (!cart) {
        return res.status(400).json({ message: 'Cart is required' });
    }
    
    // --- VULNERABLE LOGIC: No validation of discount stacking ---
    // This allows multiple discounts to be applied, potentially reducing price to zero
    
    let totalDiscount = 0;
    if (discounts && Array.isArray(discounts)) {
        // Sum all discounts without any limit
        totalDiscount = discounts.reduce((sum, discount) => sum + discount, 0);
    }
    
    // Calculate final price (with a minimum of $0)
    const originalPrice = 100; // Fixed price for demo
    const discountAmount = originalPrice * (totalDiscount / 100);
    const finalPrice = Math.max(0, originalPrice - discountAmount);
    
    res.json({
        success: true,
        originalPrice: originalPrice,
        discountPercentage: totalDiscount,
        discountAmount: discountAmount.toFixed(2),
        finalPrice: finalPrice.toFixed(2),
        message: 'Checkout completed',
        warning: 'INSECURE: This endpoint allows unlimited discount stacking'
    });
});

// SECURE: Proper checkout process
router.post('/checkout-secure', (req, res) => {
    const { cart, discountCode, sessionId } = req.body;
    
    if (!cart || !sessionId) {
        return res.status(400).json({ message: 'Cart and session ID are required' });
    }
    
    // --- SECURE LOGIC: Proper discount validation and limits ---
    // In a real app, we would validate the discount code against the database
    // and ensure it can only be used once per session/user
    
    const originalPrice = 100; // Fixed price for demo
    let discountPercentage = 0;
    
    // Simulating a check against applied discounts for this session
    if (discountCode) {
        // Maximum discount cap
        discountPercentage = Math.min(20, discountPercentage);
    }
    
    const discountAmount = originalPrice * (discountPercentage / 100);
    const finalPrice = originalPrice - discountAmount;
    
    res.json({
        success: true,
        originalPrice: originalPrice,
        discountPercentage: discountPercentage,
        discountAmount: discountAmount.toFixed(2),
        finalPrice: finalPrice.toFixed(2),
        message: 'Checkout completed securely',
        note: 'SECURE: This endpoint prevents discount abuse and enforces limits'
    });
});

module.exports = router;
