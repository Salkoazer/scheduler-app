const express = require('express');
const router = express.Router();
const { getDb } = require('../db/connection');
const bcrypt = require('bcrypt');
const { signAccessToken, signRefreshToken, verifyAccessToken, verifyRefreshToken } = require('../utils/jwt');
const logger = require('../logger');
const { z } = require('zod');
const { validateBody } = require('../middleware/validate');

const authSchema = z.object({
    username: z.string().min(1),
    password: z.string().min(1)
});

// Persistent refresh token storage now handled via Mongo collection 'refreshTokens'
const { randomUUID } = require('crypto');

router.post('/', validateBody(authSchema), async (req, res) => {
    const { username, password } = req.body;
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
    const role = user.role || 'staff';
    const accessToken = signAccessToken({ username, role });
    const jti = randomUUID();
    const refreshToken = signRefreshToken({ username, role }, jti);
    try {
        const decoded = verifyRefreshToken(refreshToken);
        // Persist refresh token allowlist entry
        const expiresAt = new Date(decoded.exp * 1000);
        await db.collection('refreshTokens').insertOne({ jti, username, role, createdAt: new Date(), expiresAt });
    } catch (_) {}
        const isProd = process.env.NODE_ENV === 'production';
        // In production, allow cross-site cookie (requires HTTPS)
        const cookieOptions = {
            httpOnly: true,
            secure: isProd,
            sameSite: isProd ? 'none' : 'lax',
            maxAge: 1000 * 60 * 60 * 8 // 8h max cookie (refresh inside)
        };
    logger.info({ cookieOptions }, 'Authentication successful, setting cookies');
        res.cookie('token', accessToken, cookieOptions);
        res.cookie('refresh', refreshToken, { ...cookieOptions, httpOnly: true, maxAge: 1000 * 60 * 60 * 24 * 7 });
    res.status(200).json({ message: 'Authentication successful', role, username: user.username, expiresIn: process.env.JWT_ACCESS_TTL || '15m' });
    } else {
    logger.warn('Invalid credentials');
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

// Clear auth cookie (logout)
router.post('/logout', async (req, res) => {
    try {
        const refreshToken = req.cookies && req.cookies.refresh;
        if (refreshToken) {
            try {
                const dec = verifyRefreshToken(refreshToken);
                if (dec && dec.jti) {
                    const db = getDb();
                    await db.collection('refreshTokens').deleteOne({ jti: dec.jti });
                }
            } catch(_){}
        }
        res.clearCookie('token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict'
        });
        res.clearCookie('refresh', {
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

// Authenticated user info (whoami)
router.get('/me', (req, res) => {
    try {
        const token = (req.cookies && req.cookies.token) || null;
        if (!token) return res.status(401).json({ message: 'Not authenticated' });
        const user = verifyAccessToken(token);
        const username = user.username || user.sub;
        if (!username) return res.status(401).json({ message: 'Not authenticated' });
        res.status(200).json({ username, role: user.role || 'staff' });
    } catch (e) {
        return res.status(401).json({ message: 'Not authenticated' });
    }
});

    // Middleware to authenticate via cookie token for protected routes below
function requireAuth(req, res, next) {
    try {
        const token = (req.cookies && req.cookies.token) || null;
        if (!token) return res.status(401).json({ message: 'Not authenticated' });
        const user = verifyAccessToken(token);
        const username = user.username || user.sub;
        req.user = { ...user, username };
        next();
    } catch (e) {
        return res.status(401).json({ message: 'Not authenticated' });
    }
}

// Refresh endpoint (rotating refresh tokens)
router.post('/refresh', async (req, res) => {
    try {
        const oldRefresh = (req.cookies && req.cookies.refresh) || null;
        if (!oldRefresh) return res.status(401).json({ message: 'Missing refresh token' });
        const decoded = verifyRefreshToken(oldRefresh);
        if (!decoded || !decoded.jti) return res.status(401).json({ message: 'Invalid refresh token' });
        const db = getDb();
        const entry = await db.collection('refreshTokens').findOne({ jti: decoded.jti });
        if (!entry || entry.username !== decoded.sub) {
            return res.status(401).json({ message: 'Refresh token revoked' });
        }
        await db.collection('refreshTokens').deleteOne({ jti: decoded.jti });
    const role = decoded.role || 'staff';
    const username = decoded.username || decoded.sub;
        const { randomUUID } = require('crypto');
        const newJti = randomUUID();
        const newRefresh = signRefreshToken({ username, role }, newJti);
        const access = signAccessToken({ username, role });
        try {
            const d2 = verifyRefreshToken(newRefresh);
            const expiresAt = new Date(d2.exp * 1000);
            await db.collection('refreshTokens').insertOne({ jti: newJti, username, role, createdAt: new Date(), expiresAt });
        } catch(_){ }
        const isProd = process.env.NODE_ENV === 'production';
        const baseOpts = { httpOnly: true, secure: isProd, sameSite: isProd ? 'none' : 'lax' };
    res.cookie('token', access, { ...baseOpts, maxAge: 1000 * 60 * 60 * 2 });
    res.cookie('refresh', newRefresh, { ...baseOpts, maxAge: 1000 * 60 * 60 * 24 * 7 });
    return res.json({ ok: true, username, role, expiresIn: process.env.JWT_ACCESS_TTL || '15m' });
    } catch (e) {
        return res.status(401).json({ message: 'Not authenticated' });
    }
});

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
            // Prevent a user (even admin) from modifying their own role or password to avoid accidental lockout/demotion
            const isSelf = req.user.username && req.user.username === username;
            if (isSelf && (role && role !== user.role)) {
                return res.status(400).json({ message: 'Cannot change your own role' });
            }
            if (isSelf && password) {
                return res.status(400).json({ message: 'Cannot change your own password via this admin endpoint' });
            }
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
                await db.collection('reservations').updateMany({ author: username }, { $set: { author: newUsername, authorLc: newUsername.toLowerCase() } });
                await db.collection('reservationHistory').updateMany({ user: username }, { $set: { user: newUsername } });
            }
            // If the admin is modifying their OWN username, rotate access & refresh tokens so subsequent self-delete still blocked
            if (newUsername && req.user.username && req.user.username === username) {
                try {
                    // Invalidate prior refresh tokens for old username (best-effort)
                    await db.collection('refreshTokens').deleteMany({ username });
                    const effectiveRole = (role || user.role || 'staff');
                    const { randomUUID } = require('crypto');
                    const newJti = randomUUID();
                    const newRefresh = signRefreshToken({ username: newUsername, role: effectiveRole }, newJti);
                    try {
                        const decoded = verifyRefreshToken(newRefresh);
                        await db.collection('refreshTokens').insertOne({ jti: newJti, username: newUsername, role: effectiveRole, createdAt: new Date(), expiresAt: new Date(decoded.exp * 1000) });
                    } catch(_) {}
                    const access = signAccessToken({ username: newUsername, role: effectiveRole });
                    const isProd = process.env.NODE_ENV === 'production';
                    const baseOpts = { httpOnly: true, secure: isProd, sameSite: isProd ? 'none' : 'lax' };
                    res.cookie('token', access, { ...baseOpts, maxAge: 1000 * 60 * 60 * 2 });
                    res.cookie('refresh', newRefresh, { ...baseOpts, maxAge: 1000 * 60 * 60 * 24 * 7 });
                } catch (e) {
                    // Non-fatal; tokens will be refreshed on next manual login if this fails
                    console.warn('Failed to rotate tokens after username change:', e.message);
                }
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

module.exports = router;

// --- Admin password change (admin can change own password) ---
// Restricted to admins only. Ordinary staff cannot change passwords directly.
const selfPasswordSchema = z.object({
    currentPassword: z.string().min(1),
    newPassword: z.string().min(6)
});

router.post('/change-password', requireAuth, validateBody(selfPasswordSchema), async (req, res) => {
    try {
        if (!req.user || req.user.role !== 'admin') {
            return res.status(403).json({ message: 'Forbidden' });
        }
        const { currentPassword, newPassword } = req.body;
        const db = getDb();
        const userDoc = await db.collection('credentials').findOne({ username: req.user.username });
        if (!userDoc) return res.status(404).json({ message: 'User not found' });
        const match = await bcrypt.compare(currentPassword, userDoc.password);
        if (!match) return res.status(400).json({ message: 'Current password incorrect' });
        if (await bcrypt.compare(newPassword, userDoc.password)) {
            return res.status(400).json({ message: 'New password must be different' });
        }
        const hashed = await bcrypt.hash(newPassword, 10);
        await db.collection('credentials').updateOne({ _id: userDoc._id }, { $set: { password: hashed, passwordChangedAt: new Date() } });
        // Invalidate all refresh tokens for this user (global logout)
        await db.collection('refreshTokens').deleteMany({ username: req.user.username });
        // Issue new tokens (fresh session)
        const { randomUUID } = require('crypto');
        const jti = randomUUID();
        const refresh = signRefreshToken({ username: req.user.username, role: req.user.role }, jti);
        try {
            const dec = verifyRefreshToken(refresh);
            await db.collection('refreshTokens').insertOne({ jti, username: req.user.username, role: req.user.role, createdAt: new Date(), expiresAt: new Date(dec.exp * 1000) });
        } catch(_) {}
        const access = signAccessToken({ username: req.user.username, role: req.user.role });
        const isProd = process.env.NODE_ENV === 'production';
        const baseOpts = { httpOnly: true, secure: isProd, sameSite: isProd ? 'none' : 'lax' };
        res.cookie('token', access, { ...baseOpts, maxAge: 1000 * 60 * 60 * 2 });
        res.cookie('refresh', refresh, { ...baseOpts, maxAge: 1000 * 60 * 60 * 24 * 7 });
        return res.json({ message: 'Password changed' });
    } catch (e) {
        console.error('Self password change error', e);
        return res.status(500).json({ message: 'Internal server error' });
    }
});