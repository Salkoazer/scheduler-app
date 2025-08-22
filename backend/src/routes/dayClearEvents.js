const express = require('express');
const router = express.Router();
const { getDb } = require('../db/connection');
const { verifyAccessToken } = require('../utils/jwt');
const { ObjectId } = require('mongodb');

// Simple auth middleware reused (could import from reservations but keep lightweight)
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const headerToken = authHeader && authHeader.startsWith('Bearer ')
        ? authHeader.split(' ')[1]
        : null;
    const cookieToken = req.cookies && req.cookies.token ? req.cookies.token : null;
    const token = headerToken || cookieToken;
    if (!token) return res.status(401).json({ message: 'Missing auth token' });
    try {
        const user = verifyAccessToken(token);
        const username = user.username || user.sub;
        req.user = { ...user, username };
        next();
    } catch {
        return res.status(403).json({ message: 'Invalid token' });
    }
};

// GET unconsumed events (optionally since timestamp) for logged in user
router.get('/', authenticateToken, async (req, res) => {
    try {
        const db = getDb();
        const since = req.query.since ? new Date(req.query.since) : null;
        const authorLc = (req.user.username || '').toLowerCase();
        const query = { authorLc, consumed: false };
        if (since && !isNaN(since.getTime())) {
            query.createdAt = { $gte: since };
        }
        const events = await db.collection('day_clear_events')
            .find(query)
            .sort({ createdAt: -1 })
            .limit(200)
            .toArray();
        res.json(events.map(e => ({
            id: e._id,
            room: e.room,
            dayKey: e.dayKey,
            createdAt: e.createdAt,
            cause: e.cause
        })));
    } catch (e) {
        console.error('Error listing day clear events', e);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Consume single event
router.post('/:id/consume', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        if (!ObjectId.isValid(id)) return res.status(400).json({ message: 'Invalid id' });
        const db = getDb();
        const authorLc = (req.user.username || '').toLowerCase();
        const result = await db.collection('day_clear_events').updateOne({ _id: new ObjectId(id), authorLc }, { $set: { consumed: true }, $currentDate: { consumedAt: true } });
        if (!result.matchedCount) return res.status(404).json({ message: 'Not found' });
        res.json({ ok: true });
    } catch (e) {
        console.error('Error consuming day clear event', e);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Batch consume
router.post('/consume', authenticateToken, async (req, res) => {
    try {
        const { ids } = req.body || {};
        if (!Array.isArray(ids) || !ids.length) return res.status(400).json({ message: 'ids required' });
        const db = getDb();
        const authorLc = (req.user.username || '').toLowerCase();
        const objIds = ids.filter(id => ObjectId.isValid(id)).map(id => new ObjectId(id));
        if (!objIds.length) return res.status(400).json({ message: 'No valid ids' });
        const result = await db.collection('day_clear_events').updateMany({ _id: { $in: objIds }, authorLc }, { $set: { consumed: true }, $currentDate: { consumedAt: true } });
        res.json({ ok: true, modified: result.modifiedCount });
    } catch (e) {
        console.error('Error batch consuming day clear events', e);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Maintenance: cleanup very old events (admin only). This is an on-demand endpoint; can be hit by a cron.
router.post('/maintenance/cleanup', authenticateToken, async (req, res) => {
    try {
        if (!req.user || req.user.role !== 'admin') {
            return res.status(403).json({ message: 'Forbidden' });
        }
        const db = getDb();
        const now = Date.now();
        const veryOldThreshold = new Date(now - 180*24*60*60*1000); // 180 days
        const autoConsumeThreshold = new Date(now - 120*24*60*60*1000); // 120 days -> convert to consumed so TTL can clear eventually
        // Auto-consume (mark consumed) any lingering unconsumed events older than 120d
        const autoConsumed = await db.collection('day_clear_events').updateMany({ consumed: false, createdAt: { $lte: autoConsumeThreshold } }, { $set: { consumed: true }, $currentDate: { consumedAt: true } });
        // Hard delete any consumed events older than 180d (safety in case TTL misconfigured)
        const hardDeleted = await db.collection('day_clear_events').deleteMany({ consumed: true, createdAt: { $lte: veryOldThreshold } });
        res.json({ ok: true, autoConsumed: autoConsumed.modifiedCount, hardDeleted: hardDeleted.deletedCount });
    } catch (e) {
        console.error('Error cleaning up day clear events', e);
        res.status(500).json({ message: 'Internal server error' });
    }
});

module.exports = router;
