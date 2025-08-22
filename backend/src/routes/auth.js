const express = require('express');
const router = express.Router();
const { getDb } = require('../db/connection');
const bcrypt = require('bcrypt');
const { signToken, verifyToken } = require('../utils/jwt');
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
    const token = signToken({ username, role: user.role || 'staff' });
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
    // Cookie set; include role for client convenience
    res.status(200).json({ message: 'Authentication successful', role: user.role || 'staff', username: user.username });
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
    const user = verifyToken(token);
        res.status(200).json({ username: user.username, role: user.role || 'staff' });
    } catch (e) {
        res.status(401).json({ message: 'Not authenticated' });
    }
});

    // Middleware to authenticate via cookie token for protected routes below
    function requireAuth(req, res, next) {
        try {
            const token = (req.cookies && req.cookies.token) || null;
            if (!token) return res.status(401).json({ message: 'Not authenticated' });
            const user = verifyToken(token);
            req.user = user;
            next();
        } catch (e) {
            return res.status(401).json({ message: 'Not authenticated' });
        }
    }

    // Admin creates new user (admin or staff)
    const createUserSchema = z.object({
        username: z.string().min(1),
        password: z.string().min(6),
        role: z.enum(['admin', 'staff']).default('staff')
    });

    router.post('/create', requireAuth, validateBody(createUserSchema), async (req, res) => {
        try {
            if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
            const { username, password, role } = req.body;
            const db = getDb();
            const existing = await db.collection('credentials').findOne({ username });
            if (existing) return res.status(409).json({ message: 'Username already exists' });
            const hashed = await bcrypt.hash(password, 10);
            await db.collection('credentials').insertOne({ username, password: hashed, role, createdAt: new Date() });
            return res.status(201).json({ message: 'User created' });
        } catch (e) {
            return res.status(500).json({ message: 'Internal server error' });
        }
    });

    // List users (admin only) - excludes password hashes
    router.get('/users', requireAuth, async (req, res) => {
        try {
            if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
            const db = getDb();
            const users = await db.collection('credentials').find({}, { projection: { username: 1, role: 1, createdAt: 1, _id: 0 } }).sort({ createdAt: 1 }).toArray();
            res.json(users);
        } catch (e) {
            res.status(500).json({ message: 'Internal server error' });
        }
    });

    // Update user (admin only) - can rename username, change password, change role
    const updateUserSchema = z.object({
        newUsername: z.string().min(1).optional(),
        password: z.string().min(6).optional(),
        role: z.enum(['admin', 'staff']).optional()
    }).refine(data => data.newUsername || data.password || data.role, { message: 'At least one field must be provided' });

    router.put('/users/:username', requireAuth, validateBody(updateUserSchema), async (req, res) => {
        try {
            if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
            const { username } = req.params;
            const { newUsername, password, role } = req.body;
            const db = getDb();
            const user = await db.collection('credentials').findOne({ username });
            if (!user) return res.status(404).json({ message: 'User not found' });
            const update = {};
            if (role) update.role = role;
            if (password) update.password = await bcrypt.hash(password, 10);
            if (newUsername) {
                const existing = await db.collection('credentials').findOne({ username: newUsername });
                if (existing) return res.status(409).json({ message: 'Username already exists' });
                update.username = newUsername;
            }
            if (Object.keys(update).length === 0) return res.status(400).json({ message: 'Nothing to update' });
            await db.collection('credentials').updateOne({ username }, { $set: update });
            // Propagate username change to reservations & history if renamed
            if (newUsername) {
                await db.collection('reservations').updateMany({ author: username }, { $set: { author: newUsername } });
                await db.collection('reservationHistory').updateMany({ user: username }, { $set: { user: newUsername } });
            }
            res.json({ message: 'User updated' });
        } catch (e) {
            console.error('Update user error', e);
            res.status(500).json({ message: 'Internal server error' });
        }
    });

    // Delete user (admin only)
    router.delete('/users/:username', requireAuth, async (req, res) => {
        try {
            if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
            const { username } = req.params;
            if (username === req.user.username) return res.status(400).json({ message: 'Cannot delete your own account' });
            const db = getDb();
            const result = await db.collection('credentials').deleteOne({ username });
            if (result.deletedCount === 0) return res.status(404).json({ message: 'User not found' });
            res.json({ message: 'User deleted' });
        } catch (e) {
            res.status(500).json({ message: 'Internal server error' });
        }
    });