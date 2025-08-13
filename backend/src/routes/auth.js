const express = require('express');
const router = express.Router();
const { getDb } = require('../db/connection');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

router.post('/', async (req, res) => {
    const { username, password } = req.body;
    console.log(`Authenticating user: ${username}`);
    const db = getDb();
    const user = await db.collection('credentials').findOne({ username });

    if (!user) {
        console.log('User not found');
        return res.status(401).json({ error: 'Invalid credentials' });
    }

    console.log(`User found: ${user.username}`);

    const isPasswordValid = await bcrypt.compare(password, user.password);
    console.log(`Password match: ${isPasswordValid}`);

    if (isPasswordValid) {
        const token = jwt.sign({ username }, process.env.JWT_SECRET, { expiresIn: '1h' });
        const isProd = process.env.NODE_ENV === 'production';
        // In production, allow cross-site cookie (requires HTTPS)
        const cookieOptions = {
            httpOnly: true,
            secure: isProd,
            sameSite: isProd ? 'none' : 'lax',
            maxAge: 3600000 // 1 hour
        };
        console.log('Authentication successful, setting cookie with options:', cookieOptions);
        res.cookie('token', token, cookieOptions);
        // Also return token in body for clients that use Authorization header
        res.status(200).json({ message: 'Authentication successful', token });
    } else {
        console.log('Invalid credentials');
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

// Clear auth cookie (logout)
router.post('/logout', (req, res) => {
    try {
        res.clearCookie('token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict'
        });
        console.log('User logged out, cookie cleared');
        res.status(200).json({ message: 'Logged out' });
    } catch (e) {
        console.error('Error during logout', e);
        res.status(500).json({ message: 'Logout failed' });
    }
});

module.exports = router;