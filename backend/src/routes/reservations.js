const express = require('express');
const router = express.Router();
const { getDb } = require('../db/connection');
const { ObjectId } = require('mongodb');
const jwt = require('jsonwebtoken');
const { z } = require('zod');
const { validateQuery } = require('../middleware/validate');

const rangeSchema = z.object({
    start: z.string().datetime(),
    end: z.string().datetime()
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
router.post('/', authenticateToken, async (req, res) => {
    try {
        const db = getDb();
        const reservation = {
            ...req.body,
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
router.get('/', authenticateToken, validateQuery(rangeSchema), async (req, res) => {
    try {
        const { start, end } = req.query;
        if (!start || !end) {
            return res.status(400).json({ message: 'Start and end dates are required' });
        }

        console.log(`Fetching reservations from ${start} to ${end}`);

        const startDate = new Date(start);
        const endDate = new Date(end);

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