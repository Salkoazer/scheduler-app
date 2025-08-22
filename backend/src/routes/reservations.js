const express = require('express');
const router = express.Router();
const { getDb } = require('../db/connection');
const { ObjectId } = require('mongodb');
const { verifyToken } = require('../utils/jwt');
const { z } = require('zod');
const { validateQuery, validateBody } = require('../middleware/validate');
const writeRateLimiter = require('../middleware/writeRateLimiter');

const rangeSchema = z.object({
    start: z.string().datetime(),
    end: z.string().datetime()
});

const listQuerySchema = rangeSchema.extend({
    limit: z.coerce.number().int().positive().max(200).optional().default(200),
    page: z.coerce.number().int().min(1).optional().default(1)
});

// Validate reservation payloads
const reservationSchema = z.object({
    room: z.string().min(1),
    nif: z.string().regex(/^\d{9}$/, 'NIF must be 9 digits'),
    producerName: z.string().min(1),
    email: z.string().email(),
    contact: z.string().min(1),
    responsablePerson: z.string().min(1),
    event: z.string().min(1),
    eventClassification: z.string().min(1),
    // author is derived from token server-side; accept but ignore if present
    author: z.string().min(1).optional(),
    isActive: z.boolean().optional().default(true),
    date: z.string().datetime(),
    type: z.enum(['event', 'assembly', 'disassembly', 'others']),
        notes: z.string().max(1000).optional(),
        reservationStatus: z.enum(['pre', 'confirmed', 'flagged']).optional().default('pre')
});

const statusUpdateSchema = z.object({
    reservationStatus: z.enum(['pre', 'confirmed', 'flagged'])
});

// Middleware to authenticate JWT token (from Authorization header or cookie)
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const headerToken = authHeader && authHeader.startsWith('Bearer ')
        ? authHeader.split(' ')[1]
        : null;
    const cookieToken = req.cookies && req.cookies.token ? req.cookies.token : null;
    const token = headerToken || cookieToken;
    if (!token) {
        return res.status(401).json({ message: 'Missing auth token' });
    }

    try {
        const user = verifyToken(token);
        req.user = user;
        next();
    } catch (err) {
        return res.status(403).json({ message: 'Invalid token' });
    }
};

// Create new reservation
router.post('/', authenticateToken, writeRateLimiter, validateBody(reservationSchema), async (req, res) => {
    try {
        const db = getDb();
        // Normalize and enrich payload
        const reservation = {
            ...req.body,
            // Ensure date is stored as ISO string for consistent range queries
            date: new Date(req.body.date).toISOString(),
            // Do not trust client for author/isActive
            author: req.user && req.user.username ? req.user.username : 'unknown',
            isActive: true,
            createdAt: new Date(),
            status: 'active',
            // Always start as pre-reservation regardless of client input
            reservationStatus: 'pre'
        };

        console.log('Creating reservation with date:', reservation.date);

        const result = await db.collection('reservations').insertOne(reservation);
        
        if (result.acknowledged) {
            // Log history event
            await db.collection('reservationHistory').insertOne({
                reservationId: result.insertedId,
                room: reservation.room,
                date: reservation.date,
                user: reservation.author,
                action: 'create',
                toStatus: 'pre',
                timestamp: new Date()
            });
            res.status(201).json({ 
                message: 'Reservation created successfully',
                id: result.insertedId 
            });
        } else {
            res.status(400).json({ message: 'Failed to create reservation' });
        }
    } catch (error) {
        console.error('Error creating reservation:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Get all reservations within a date range
router.get('/', authenticateToken, validateQuery(listQuerySchema), async (req, res) => {
    try {
    const { start, end, limit = 200, page = 1 } = req.query;
        if (!start || !end) {
            return res.status(400).json({ message: 'Start and end dates are required' });
        }

        console.log(`Fetching reservations from ${start} to ${end}`);

        const startDate = new Date(start);
        const endDate = new Date(end);

        // Guard: prevent unbounded/huge range scans (max 366 days)
        const MAX_RANGE_MS = 366 * 24 * 60 * 60 * 1000;
        if (endDate - startDate > MAX_RANGE_MS) {
            return res.status(400).json({ message: 'Date range too large. Please reduce the range.' });
        }

        const db = getDb();
        const reservations = await db.collection('reservations')
            .find({
                date: {
                    $gte: new Date(startDate).toISOString(),
                    $lte: new Date(endDate).toISOString()
                }
            }, {
                projection: {
                    _id: 1,
                    date: 1,
                    room: 1,
                    event: 1,
                    type: 1,
                    reservationStatus: 1,
                    author: 1,
                    status: 1,
                    createdAt: 1
                }
            })
            .sort({ createdAt: -1 })
            .limit(Number(limit))
            .skip((Number(page) - 1) * Number(limit))
            .toArray();

        if (process.env.NODE_ENV !== 'production') {
            console.log(`Fetched ${reservations.length} reservations`);
        }
        
        res.json(reservations);
    } catch (error) {
    console.error('Error fetching reservations:', error.message);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Update reservation status (pre | confirmed | flagged)
router.put('/:id/status', authenticateToken, writeRateLimiter, async (req, res) => {
    try {
        const parse = statusUpdateSchema.safeParse(req.body);
        if (!parse.success) {
            return res.status(400).json({ message: 'Invalid status', details: parse.error.errors });
        }
        const db = getDb();
        const id = req.params.id;
        if (!ObjectId.isValid(id)) return res.status(400).json({ message: 'Invalid id' });

        // Fetch existing reservation
        const existing = await db.collection('reservations').findOne({ _id: new ObjectId(id) });
        if (!existing) return res.status(404).json({ message: 'Not found' });

        const newStatus = parse.data.reservationStatus;

        // Enforce at most one confirmed/flagged per (date, room)
        if (['confirmed', 'flagged'].includes(newStatus)) {
            const conflict = await db.collection('reservations').findOne({
                _id: { $ne: new ObjectId(id) },
                room: existing.room,
                date: existing.date,
                reservationStatus: { $in: ['confirmed', 'flagged'] }
            });
            if (conflict) {
                return res.status(409).json({ message: 'Another reservation already confirmed for this room and day' });
            }
        }

        const fromStatus = existing.reservationStatus || 'pre';
        const result = await db.collection('reservations').updateOne(
            { _id: new ObjectId(id) },
            { $set: { reservationStatus: newStatus, updatedAt: new Date() } }
        );
        if (result.matchedCount === 0) return res.status(404).json({ message: 'Not found' });
        // Log history event
        await db.collection('reservationHistory').insertOne({
            reservationId: existing._id,
            room: existing.room,
            date: existing.date,
            user: req.user && req.user.username ? req.user.username : 'unknown',
            action: 'status-change',
            fromStatus,
            toStatus: newStatus,
            timestamp: new Date()
        });
        return res.json({ ok: true });
    } catch (e) {
        console.error('Error updating reservation status:', e);
        return res.status(500).json({ message: 'Internal server error' });
    }
});

// Get reservation history for a given date & room
router.get('/history', authenticateToken, async (req, res) => {
    try {
        const { date, room } = req.query;
        if (!date || !room) return res.status(400).json({ message: 'date and room are required' });
        const day = new Date(date);
        if (isNaN(day.getTime())) return res.status(400).json({ message: 'Invalid date' });
        // Normalize date boundaries (match stored ISO date string exactly by day)
        const dayStartIso = new Date(day.getFullYear(), day.getMonth(), day.getDate()).toISOString();
        const dayEndIso = new Date(day.getFullYear(), day.getMonth(), day.getDate(), 23, 59, 59, 999).toISOString();
        const db = getDb();
        const events = await db.collection('reservationHistory')
            .find({
                room: room,
                date: { $gte: dayStartIso, $lte: dayEndIso }
            })
            .sort({ timestamp: 1 })
            .toArray();
        res.json(events);
    } catch (e) {
        console.error('Error fetching reservation history:', e);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Get single reservation by id (full document)
router.get('/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        if (!ObjectId.isValid(id)) return res.status(400).json({ message: 'Invalid id' });
        const db = getDb();
        const doc = await db.collection('reservations').findOne({ _id: new ObjectId(id) });
        if (!doc) return res.status(404).json({ message: 'Not found' });
        return res.json(doc);
    } catch (e) {
        console.error('Error fetching reservation by id:', e);
        return res.status(500).json({ message: 'Internal server error' });
    }
});

module.exports = router;