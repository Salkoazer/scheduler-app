const express = require('express');
const router = express.Router();
const { getDb } = require('../db/connection');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { z } = require('zod');
const { validateBody } = require('../middleware/validate');

const authSchema = z.object({
    username: z.string().min(1),
    password: z.string().min(1)
});

router.post('/', validateBody(authSchema), async (req, res) => {
    const { username, password } = req.body;
    const logger = require('../logger');
    logger.info({ username }, 'Authenticating user');
    const db = getDb();
    const user = await db.collection('credentials').findOne({ username });

    if (!user) {
    logger.warn('Invalid credentials attempt');
        return res.status(401).json({ error: 'Invalid credentials' });
    }

    logger.debug({ username: user.username }, 'User found');

    const isPasswordValid = await bcrypt.compare(password, user.password);
    logger.debug({ match: isPasswordValid }, 'Password match result');

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
    logger.info({ cookieOptions }, 'Authentication successful, setting cookie');
        res.cookie('token', token, cookieOptions);
    // Cookie set; no need to return token in body
    res.status(200).json({ message: 'Authentication successful' });
    } else {
    logger.warn('Invalid credentials');
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
    logger.info('User logged out, cookie cleared');
        res.status(200).json({ message: 'Logged out' });
    } catch (e) {
    logger.error({ err: e.message }, 'Error during logout');
        res.status(500).json({ message: 'Logout failed' });
    }
});

module.exports = router;

// Authenticated user info (whoami)
router.get('/me', (req, res) => {
    try {
        const token = (req.cookies && req.cookies.token) || null;
        if (!token) return res.status(401).json({ message: 'Not authenticated' });
        const user = jwt.verify(token, process.env.JWT_SECRET);
        res.status(200).json({ username: user.username });
    } catch (e) {
        res.status(401).json({ message: 'Not authenticated' });
    }
});