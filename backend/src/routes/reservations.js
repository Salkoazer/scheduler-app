const express = require('express');
const router = express.Router();
const { getDb } = require('../db/connection');
const { ObjectId } = require('mongodb');
const jwt = require('jsonwebtoken');
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
    reservationNumber: z.string().min(1),
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
    notes: z.string().max(1000).optional()
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

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid token' });
        req.user = user;
        next();
    });
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
            status: 'active'
        };

        console.log('Creating reservation with date:', reservation.date);

        const result = await db.collection('reservations').insertOne(reservation);
        
        if (result.acknowledged) {
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

module.exports = router;