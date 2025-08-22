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
// New model: client only supplies dates[] (one or more discrete days). We still derive date/endDate internally for range efficiency.
const reservationSchema = z.object({
    room: z.string().min(1),
    nif: z.string().regex(/^[0-9]{9}$/,'NIF must be 9 digits'),
    producerName: z.string().min(1),
    email: z.string().email(),
    contact: z.string().min(1),
    responsablePerson: z.string().min(1),
    event: z.string().min(1),
    eventClassification: z.string().min(1),
    author: z.string().min(1).optional(),
    isActive: z.boolean().optional().default(true),
    dates: z.array(z.string().datetime()).min(1, 'dates must contain at least one day').max(60),
    type: z.enum(['event', 'assembly', 'disassembly', 'others']),
    notes: z.string().max(2000).optional(),
    adminNotes: z.string().max(4000).optional(),
    reservationStatus: z.enum(['pre', 'confirmed', 'flagged']).optional().default('pre')
});

const statusUpdateSchema = z.object({
    reservationStatus: z.enum(['pre','confirmed','flagged'])
});

// Editable fields schema (excludes reservationStatus and date; allows room change)
const editableFieldsSchema = z.object({
    room: z.enum(['room 1','room 2','room 3']).optional(),
    dates: z.array(z.string().datetime()).min(1).max(60).optional(),
    nif: z.string().regex(/^[0-9]{9}$/,'NIF must be 9 digits').optional(),
    producerName: z.string().min(1).optional(),
    email: z.string().email().optional(),
    contact: z.string().min(1).optional(),
    responsablePerson: z.string().min(1).optional(),
    event: z.string().min(1).optional(),
    eventClassification: z.string().min(1).optional(),
    type: z.enum(['event','assembly','disassembly','others']).optional(),
    notes: z.string().max(2000).optional()
}).refine(obj => Object.keys(obj).length > 0, { message: 'No editable fields provided' });

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
        // Normalize multi-day dates (non-contiguous supported)
        let providedDates = Array.isArray(req.body.dates) ? req.body.dates.map(d => new Date(d)) : [];
        providedDates = providedDates.filter(d => !isNaN(d.getTime()));
        // Unique by day string
        const uniqueDayMap = {};
        providedDates.forEach(d => {
            // Normalize to midnight UTC for stable day key (avoids timezone offset shifting previous/next day)
            const dayKey = new Date(Date.UTC(d.getFullYear(), d.getMonth(), d.getDate())).toISOString();
            uniqueDayMap[dayKey] = new Date(dayKey);
        });
        const normalizedDates = Object.values(uniqueDayMap).sort((a,b)=>a.getTime()-b.getTime());
        const firstIso = normalizedDates[0].toISOString();
        const lastIso = normalizedDates[normalizedDates.length-1].toISOString();

        const reservation = {
            ...req.body,
            // derive internal fields
            date: firstIso,
            endDate: lastIso,
            dates: normalizedDates.map(d => d.toISOString()),
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
            const historyBatch = [];
            // Base creation event
            historyBatch.push({
                reservationId: result.insertedId,
                room: reservation.room,
                date: reservation.date,
                endDate: reservation.endDate,
                dates: reservation.dates,
                user: reservation.author,
                action: 'create',
                event: reservation.event,
                toStatus: 'pre',
                timestamp: new Date()
            });
            // If initial notes/adminNotes provided, log a notes-create snapshot
            if (reservation.notes || reservation.adminNotes) {
                const truncate = (s) => s.length > 1000 ? s.slice(0, 1000) + '…' : s;
                const fromNotes = {}; // empty (creation)
                const toNotes = {};
                if (reservation.notes) toNotes.notes = truncate(reservation.notes);
                if (reservation.adminNotes) toNotes.adminNotes = truncate(reservation.adminNotes);
                historyBatch.push({
                    reservationId: result.insertedId,
                    room: reservation.room,
                    date: reservation.date,
                    endDate: reservation.endDate,
                    dates: reservation.dates,
                    user: reservation.author,
                    action: 'notes-create',
                    event: reservation.event,
                    fromStatus: 'pre',
                    toStatus: 'pre',
                    noteFields: Object.keys(toNotes),
                    fromNotes,
                    toNotes,
                    timestamp: new Date()
                });
            }
            if (historyBatch.length === 1) {
                await db.collection('reservationHistory').insertOne(historyBatch[0]);
            } else {
                await db.collection('reservationHistory').insertMany(historyBatch);
            }
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

// Get all reservations within a date range (match any discrete date in range)
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
        const monthStartIso = new Date(startDate).toISOString();
        const monthEndIso = new Date(endDate).toISOString();
    // Overlap if any discrete date falls inside range
    const dateOverlap = { dates: { $elemMatch: { $gte: monthStartIso, $lte: monthEndIso } } };
        let finalQuery = dateOverlap;
        if (req.user && req.user.role !== 'admin') {
            // Visibility subset for staff
            const visibility = {
                $or: [
                    { reservationStatus: { $in: ['confirmed','flagged'] } },
                    { $and: [ { reservationStatus: { $in: [null,'pre'] } }, { author: req.user.username } ] }
                ]
            };
            finalQuery = { $and: [ dateOverlap, visibility ] };
        }
        const reservations = await db.collection('reservations')
            .find(finalQuery, {
                projection: {
                    _id: 1,
                    dates: 1,
                    room: 1,
                    event: 1,
                    type: 1,
                    reservationStatus: 1,
                    author: 1,
                    status: 1,
                    createdAt: 1,
                    notes: 1,
                    adminNotes: 1
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
            // build set of days for existing reservation
            const existingDays = (existing.dates && existing.dates.length > 0 ? existing.dates : [existing.date]);
            const minDay = existingDays[0];
            const maxDay = existing.endDate || existingDays[existingDays.length-1];
            const candidates = await db.collection('reservations').find({
                _id: { $ne: existing._id },
                room: existing.room,
                reservationStatus: { $in: ['confirmed','flagged'] },
                date: { $lte: maxDay },
                $expr: { $gte: [ { $ifNull: [ '$endDate', '$date' ] }, minDay ] }
            }).toArray();
            const existingSet = new Set(existingDays.map(d => d.slice(0,10)));
            const overlap = candidates.find(c => {
                const cDays = (c.dates && c.dates.length>0 ? c.dates : [c.date]);
                return cDays.some(d => existingSet.has(d.slice(0,10)));
            });
            if (overlap) {
                return res.status(409).json({ message: 'Another reservation already confirmed for one of these days & room' });
            }
        }

        const fromStatus = existing.reservationStatus || 'pre';
        const result = await db.collection('reservations').updateOne(
            { _id: new ObjectId(id) },
            { $set: { reservationStatus: newStatus, updatedAt: new Date() } }
        );
        if (result.matchedCount === 0) return res.status(404).json({ message: 'Not found' });
        // Log history event (use distinct action when entering or leaving flagged)
        const action = newStatus === 'flagged' || fromStatus === 'flagged' ? 'flagged-status-change' : 'status-change';
        await db.collection('reservationHistory').insertOne({
            reservationId: existing._id,
            room: existing.room,
            date: existing.date,
            user: req.user && req.user.username ? req.user.username : 'unknown',
            action,
            event: existing.event,
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

// General field update (non-status) for a reservation
router.put('/:id', authenticateToken, writeRateLimiter, async (req, res) => {
    try {
        const { id } = req.params;
        if (!ObjectId.isValid(id)) return res.status(400).json({ message: 'Invalid id' });
        if (process.env.NODE_ENV !== 'production') {
            console.log('[UPDATE incoming raw body]', JSON.stringify(req.body));
        }
        const parse = editableFieldsSchema.safeParse(req.body || {});
        if (!parse.success) return res.status(400).json({ message: 'Invalid payload', details: parse.error.errors });
        const db = getDb();
        const existing = await db.collection('reservations').findOne({ _id: new ObjectId(id) });
        if (!existing) return res.status(404).json({ message: 'Not found' });
        const isAdmin = req.user.role === 'admin';
        const isOwner = existing.author && existing.author.toLowerCase() === (req.user.username || '').toLowerCase();
        if (!isAdmin && !isOwner) return res.status(403).json({ message: 'Forbidden' });
        const update = {};
        const changedFields = [];
        const fromSnapshots = {};
        const toSnapshots = {};
        for (const [k,v] of Object.entries(parse.data)) {
            if (v !== undefined && v !== existing[k]) {
                update[k] = v;
                changedFields.push(k);
                fromSnapshots[k] = existing[k] || '';
                toSnapshots[k] = v;
            }
        }
        // If dates array provided, normalize: unique days sorted; also derive date (earliest) and endDate (latest)
        if (update.dates) {
            const parsed = update.dates.map(d => new Date(d)).filter(d => !isNaN(d.getTime()));
            if (parsed.length === 0) return res.status(400).json({ message: 'Invalid dates' });
            const mapDays = {};
            parsed.forEach(d => { const key = new Date(Date.UTC(d.getFullYear(), d.getMonth(), d.getDate())).toISOString(); mapDays[key] = new Date(key); });
            const norm = Object.values(mapDays).sort((a,b)=>a.getTime()-b.getTime());
            update.dates = norm.map(d => d.toISOString());
            update.date = norm[0].toISOString();
            update.endDate = norm[norm.length-1].toISOString();
            if (process.env.NODE_ENV !== 'production') {
                console.log('Updating reservation dates', {
                    id: existing._id.toString(),
                    newDates: update.dates,
                    newDate: update.date,
                    newEndDate: update.endDate,
                    prevDate: existing.date,
                    prevEndDate: existing.endDate,
                    prevDates: existing.dates
                });
            }
            if (!changedFields.includes('date') && update.date !== existing.date) { changedFields.push('date'); fromSnapshots.date = existing.date; toSnapshots.date = update.date; }
            if (!changedFields.includes('endDate') && update.endDate !== existing.endDate) { changedFields.push('endDate'); fromSnapshots.endDate = existing.endDate || ''; toSnapshots.endDate = update.endDate; }
        } else if (update.date || update.endDate) {
            // Keep consistency if only start or end changed (contiguous assumption)
            if (update.date && !update.endDate) update.endDate = update.date;
            if (update.endDate && !update.date) update.date = existing.date;
        }
        // If room or date is changing and existing is confirmed/flagged, ensure no conflict at target room/date
        if ((update.room || update.dates) && ['confirmed','flagged'].includes(existing.reservationStatus)) {
            const newDates = update.dates ? update.dates : (existing.dates && existing.dates.length>0 ? existing.dates : []);
            const newStart = newDates[0];
            const newEnd = newDates[newDates.length-1];
            const candidates = await db.collection('reservations').find({
                _id: { $ne: existing._id },
                room: update.room || existing.room,
                reservationStatus: { $in: ['confirmed','flagged'] },
                dates: { $elemMatch: { $gte: newStart, $lte: newEnd } }
            }).toArray();
            const newSet = new Set(newDates.map(d => d.slice(0,10)));
            const overlap = candidates.find(c => {
                const cDays = (c.dates && c.dates.length>0 ? c.dates : []);
                return cDays.some(d => newSet.has(d.slice(0,10)));
            });
            if (overlap) return res.status(409).json({ message: 'Another confirmed/flagged reservation exists for at least one selected day & room' });
            }
        if (changedFields.length === 0) return res.status(200).json({ ok: true, changed: [] });
    await db.collection('reservations').updateOne({ _id: existing._id }, { $set: { ...update, updatedAt: new Date() } });
        const truncate = (s) => s && s.length > 1000 ? s.slice(0,1000)+'…' : s;
        Object.keys(fromSnapshots).forEach(k => fromSnapshots[k] = truncate(fromSnapshots[k]));
        Object.keys(toSnapshots).forEach(k => toSnapshots[k] = truncate(toSnapshots[k]));
        await db.collection('reservationHistory').insertOne({
            reservationId: existing._id,
            room: update.room || existing.room,
            date: update.date || existing.date, // kept for backward history compatibility
            endDate: update.endDate || existing.endDate,
            dates: update.dates || existing.dates,
            user: req.user.username,
            action: 'fields-update',
            event: update.event !== undefined ? update.event : existing.event,
            changedFields,
            fromFields: fromSnapshots,
            toFields: toSnapshots,
            fromStatus: existing.reservationStatus || 'pre',
            toStatus: existing.reservationStatus || 'pre',
            timestamp: new Date()
        });
        return res.json({ ok: true, changed: changedFields });
    } catch (e) {
        console.error('Error updating reservation fields', e);
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

// Update notes (owner + admin notes). Owner can edit their own 'notes'; admin can edit both 'notes' and 'adminNotes'.
router.put('/:id/notes', authenticateToken, writeRateLimiter, async (req, res) => {
    try {
        const { id } = req.params;
        if (!ObjectId.isValid(id)) return res.status(400).json({ message: 'Invalid id' });
        const { notes, adminNotes } = req.body || {};
        if (notes === undefined && adminNotes === undefined) return res.status(400).json({ message: 'Nothing to update' });
        const db = getDb();
        const existing = await db.collection('reservations').findOne({ _id: new ObjectId(id) });
        if (!existing) return res.status(404).json({ message: 'Not found' });
    // Treat user as owner if author matches (case-insensitive) OR author missing on a pre-reservation (legacy records)
    const isOwner = (existing.author && (existing.author || '').toLowerCase() === (req.user.username || '').toLowerCase()) || (!existing.author && (existing.reservationStatus === 'pre'));
        const isAdmin = req.user.role === 'admin';
        const update = {};
        const changedFields = [];
        const fromSnapshots = {};
        const toSnapshots = {};
        if (notes !== undefined) {
            if (!isOwner && !isAdmin) return res.status(403).json({ message: 'Forbidden' });
            const newVal = (notes || '').toString();
            if (newVal !== (existing.notes || '')) {
                update.notes = newVal;
                changedFields.push('notes');
                fromSnapshots.notes = existing.notes || '';
                toSnapshots.notes = newVal;
            }
        }
        if (adminNotes !== undefined) {
            if (!isAdmin) return res.status(403).json({ message: 'Forbidden' });
            const newAdminVal = (adminNotes || '').toString();
            if (newAdminVal !== (existing.adminNotes || '')) {
                update.adminNotes = newAdminVal;
                changedFields.push('adminNotes');
                fromSnapshots.adminNotes = existing.adminNotes || '';
                toSnapshots.adminNotes = newAdminVal;
            }
        }
        if (Object.keys(update).length === 0) return res.status(400).json({ message: 'Nothing changed' });
        await db.collection('reservations').updateOne({ _id: existing._id }, { $set: update, $currentDate: { updatedAt: true } });
        // Limit snapshot sizes to avoid bloating history (truncate long strings)
        const truncate = (s) => s.length > 1000 ? s.slice(0, 1000) + '…' : s;
        Object.keys(fromSnapshots).forEach(k => { fromSnapshots[k] = truncate(fromSnapshots[k]); });
        Object.keys(toSnapshots).forEach(k => { toSnapshots[k] = truncate(toSnapshots[k]); });
        await db.collection('reservationHistory').insertOne({
            reservationId: existing._id,
            room: existing.room,
            date: existing.date,
            user: req.user.username,
            action: 'notes-change',
            event: existing.event,
            fromStatus: existing.reservationStatus || 'pre',
            toStatus: existing.reservationStatus || 'pre',
            noteFields: changedFields,
            fromNotes: fromSnapshots,
            toNotes: toSnapshots,
            timestamp: new Date()
        });
        return res.json({ ok: true, changed: changedFields });
    } catch (e) {
        console.error('Error updating notes', e);
        return res.status(500).json({ message: 'Internal server error' });
    }
});

// Delete a pre-reservation (only allowed if current status is 'pre'). Admin can delete any; staff only their own.
router.delete('/:id', authenticateToken, writeRateLimiter, async (req, res) => {
    try {
        const { id } = req.params;
        if (!ObjectId.isValid(id)) return res.status(400).json({ message: 'Invalid id' });
        const db = getDb();
        const existing = await db.collection('reservations').findOne({ _id: new ObjectId(id) });
        if (!existing) return res.status(404).json({ message: 'Not found' });
        const status = existing.reservationStatus || 'pre';
        if (status !== 'pre') return res.status(400).json({ message: 'Only pre-reservations can be deleted' });
        const isAdmin = req.user.role === 'admin';
        const isOwner = existing.author && existing.author.toLowerCase() === (req.user.username || '').toLowerCase();
        if (!isAdmin && !isOwner) return res.status(403).json({ message: 'Forbidden' });
        await db.collection('reservations').deleteOne({ _id: existing._id });
        await db.collection('reservationHistory').insertOne({
            reservationId: existing._id,
            room: existing.room,
            date: existing.date,
            user: req.user.username,
            action: 'delete',
            event: existing.event,
            fromStatus: status,
            toStatus: 'deleted',
            timestamp: new Date()
        });
        return res.json({ ok: true });
    } catch (e) {
        console.error('Error deleting reservation', e);
        return res.status(500).json({ message: 'Internal server error' });
    }
});

module.exports = router;