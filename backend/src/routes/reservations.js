const express = require('express');
const router = express.Router();
const { getDb } = require('../db/connection');
const { ObjectId } = require('mongodb');
const { verifyAccessToken } = require('../utils/jwt');
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

// Validate reservation payloads (relaxed). Only room, event and dates are required.
// Formatting constraints intentionally removed to allow flexible input pre-data cleanup phase.
const reservationSchema = z.object({
    room: z.string().min(1),
    event: z.string().min(1),
    dates: z.array(z.string().datetime()).min(1, 'dates must contain at least one day').max(60),
    nif: z.string().optional(),
    producerName: z.string().optional(),
    email: z.string().optional(),
    contact: z.string().optional(),
    responsablePerson: z.string().optional(),
    eventClassification: z.string().optional(),
    author: z.string().optional(),
    isActive: z.boolean().optional().default(true),
    type: z.enum(['event', 'assembly', 'disassembly', 'others']).optional(),
    notes: z.string().max(2000).optional(),
    adminNotes: z.string().max(4000).optional(),
    reservationStatus: z.enum(['pre', 'confirmed', 'flagged']).optional().default('pre')
});

const statusUpdateSchema = z.object({
    reservationStatus: z.enum(['pre','confirmed','flagged'])
});

// Editable fields schema (relaxed). Empty strings will be ignored server-side (treated as no-op) rather than stored.
const editableFieldsSchema = z.object({
    room: z.enum(['room 1','room 2','room 3']).optional(),
    dates: z.array(z.string().datetime()).min(1).max(60).optional(),
    nif: z.string().optional(),
    producerName: z.string().optional(),
    email: z.string().optional(),
    contact: z.string().optional(),
    responsablePerson: z.string().optional(),
    event: z.string().optional(),
    eventClassification: z.string().optional(),
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
    const user = verifyAccessToken(token);
    const username = user.username || user.sub; // normalize sub -> username
    req.user = { ...user, username };
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

        // Clean up optional fields: treat empty strings as absent
        const rawBody = { ...req.body };
        ['nif','producerName','email','contact','responsablePerson','eventClassification','type','notes','adminNotes'].forEach(k => {
            if (rawBody[k] === '') delete rawBody[k];
        });
        const reservation = {
            ...rawBody,
            // derive internal fields
            date: firstIso,
            endDate: lastIso,
            dates: normalizedDates.map(d => d.toISOString()),
            // Do not trust client for author/isActive
            author: req.user && req.user.username ? req.user.username : 'unknown',
            authorLc: (req.user && req.user.username ? req.user.username : 'unknown').toLowerCase(),
            isActive: true,
            createdAt: new Date(),
            status: 'active',
            // Always start as pre-reservation regardless of client input
            reservationStatus: 'pre'
        };

        // Prevent creating reservations entirely in the past (earliest day before today UTC)
        try {
            const now = new Date();
            const todayUtcStart = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
            if (normalizedDates.length && normalizedDates[0] < todayUtcStart) {
                return res.status(400).json({ message: 'Cannot create reservation in the past' });
            }
        } catch (_) { /* fail-open not desired; silently ignore errors computing date */ }

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
            // Visibility subset for staff (include their own pre-reservations)
            const userLower = (req.user.username || '').toLowerCase();
            const visibility = {
                $or: [
                    { reservationStatus: { $in: ['confirmed','flagged'] } },
                    { $and: [ { reservationStatus: { $in: [null,'pre'] } }, { authorLc: userLower } ] }
                ]
            };
            finalQuery = { $and: [ dateOverlap, visibility ] };
        }
        const reservations = await db.collection('reservations')
            .find({ $and: [ finalQuery, { $or: [ { deleted: { $exists: false } }, { deleted: false } ] } ] }, {
                projection: {
                    _id: 1,
                    dates: 1,
                    room: 1,
                    event: 1,
                    eventClassification: 1,
                    type: 1,
                    reservationStatus: 1,
                    author: 1,
                    status: 1,
                    createdAt: 1,
                    updatedAt: 1,
                    nif: 1,
                    producerName: 1,
                    email: 1,
                    contact: 1,
                    responsablePerson: 1,
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

        // Fetch latest reservation
    const existing = await db.collection('reservations').findOne({ _id: new ObjectId(id), $or: [ { deleted: { $exists: false } }, { deleted: false } ] });
        if (!existing) return res.status(404).json({ message: 'Not found' });

        const newStatus = parse.data.reservationStatus;
        const fromStatus = existing.reservationStatus || 'pre';

        // Concurrency guard for promoting to confirmed/flagged with self-healing of stale confirmed_flags
        // If simply switching between confirmed <-> flagged for the SAME reservation, we already own the flags; skip re-claim.
        const switchingWithinOwned = ['confirmed','flagged'].includes(fromStatus) && ['confirmed','flagged'].includes(newStatus);
        let claimedDays = [];
        if (['confirmed','flagged'].includes(newStatus) && !switchingWithinOwned) {
            const days = (existing.dates && existing.dates.length>0 ? existing.dates : [existing.date]).map(d => d.slice(0,10));
            let attemptedHeal = false;
            while (true) {
                try {
                    for (const day of days) {
                        await db.collection('confirmed_flags').insertOne({ room: existing.room, day, reservationId: existing._id, createdAt: new Date() });
                        claimedDays.push(day);
                    }
                    break; // success
                } catch (e) {
                    if (e.code === 11000) {
                        // Possible stale flag. Attempt heal once.
                        if (!attemptedHeal) {
                            attemptedHeal = true;
                            // Find stale flags for these days in this room whose reservationId is missing or not confirmed/flagged
                            const staleFlags = await db.collection('confirmed_flags').aggregate([
                                { $match: { room: existing.room, day: { $in: days } } },
                                { $lookup: { from: 'reservations', localField: 'reservationId', foreignField: '_id', as: 'resv' } },
                                { $unwind: { path: '$resv', preserveNullAndEmptyArrays: true } },
                                { $match: { $or: [ { resv: { $exists: false } }, { 'resv.reservationStatus': { $nin: ['confirmed','flagged'] } }, { 'resv.deleted': true } ] } },
                                { $project: { _id: 1 } }
                            ]).toArray();
                            if (staleFlags.length) {
                                const ids = staleFlags.map(f => f._id);
                                await db.collection('confirmed_flags').deleteMany({ _id: { $in: ids } });
                                // rollback any partially claimed for our reservation before retrying
                                if (claimedDays.length) {
                                    await db.collection('confirmed_flags').deleteMany({ room: existing.room, day: { $in: claimedDays }, reservationId: existing._id });
                                    claimedDays = [];
                                }
                                continue; // retry claim
                            }
                            // If not stale, check if the conflicting flags actually belong to this reservation already (switch case)
                            const ownership = await db.collection('confirmed_flags').findOne({ room: existing.room, day: days[0] });
                            if (ownership && ownership.reservationId && ownership.reservationId.equals(existing._id)) {
                                // Already ours; treat as success
                                claimedDays = [];
                                break;
                            }
                        }
                        // Conflict remains or already healed once -> abort
                        if (claimedDays.length) {
                            await db.collection('confirmed_flags').deleteMany({ room: existing.room, day: { $in: claimedDays }, reservationId: existing._id });
                        }
                        return res.status(409).json({ message: 'Conflict: another confirmed/flagged reservation already occupies at least one day for this room' });
                    }
                    // Unexpected error
                    if (claimedDays.length) {
                        await db.collection('confirmed_flags').deleteMany({ room: existing.room, day: { $in: claimedDays }, reservationId: existing._id });
                    }
                    throw e;
                }
            }
        }

        const result = await db.collection('reservations').updateOne(
            { _id: new ObjectId(id) },
            { $set: { reservationStatus: newStatus, updatedAt: new Date() } }
        );
        if (result.matchedCount === 0) {
            // release claims if update lost race
            if (claimedDays.length) {
                await db.collection('confirmed_flags').deleteMany({ room: existing.room, day: { $in: claimedDays }, reservationId: existing._id });
            }
            return res.status(404).json({ message: 'Not found' });
        }

        // Helper: generate day clear events for days now unblocked
        const maybeGenerateDayClearEvents = async (room, days, actingUserLc, cause) => {
            for (const dayKey of days) {
                // If any other confirmed/flagged remains for (room, dayKey) skip
                const stillOccupied = await db.collection('reservations').countDocuments({
                    room,
                    dates: { $elemMatch: { $gte: dayKey + 'T00:00:00.000Z', $lte: dayKey + 'T23:59:59.999Z' } },
                    reservationStatus: { $in: ['confirmed','flagged'] },
                    deleted: { $ne: true }
                });
                if (stillOccupied > 0) continue;
                // Find distinct authors with pre reservations that include this day
                const preAuthors = await db.collection('reservations').distinct('authorLc', {
                    room,
                    dates: { $elemMatch: { $gte: dayKey + 'T00:00:00.000Z', $lte: dayKey + 'T23:59:59.999Z' } },
                    deleted: { $ne: true },
                    $or: [ { reservationStatus: 'pre' }, { reservationStatus: { $exists: false } } ]
                });
                for (const authorLc of preAuthors) {
                    if (!authorLc || authorLc === actingUserLc) continue; // skip acting user
                    // Prevent duplicate unconsumed event for same (room, dayKey, author)
                    const existingEvent = await db.collection('day_clear_events').findOne({ room, dayKey, authorLc, consumed: false });
                    if (existingEvent) continue;
                    await db.collection('day_clear_events').insertOne({
                        room,
                        dayKey,
                        authorLc,
                        createdAt: new Date(),
                        consumed: false,
                        cause,
                        // Set an expiry marker 120 days out for TTL cleanup after consumption
                        expiresAt: new Date(Date.now() + 120*24*60*60*1000)
                    });
                }
            }
        };

        // If demoting out of confirmed/flagged, release flags and generate events
        if (!['confirmed','flagged'].includes(newStatus) && ['confirmed','flagged'].includes(fromStatus)) {
            const days = (existing.dates && existing.dates.length>0 ? existing.dates : [existing.date]).map(d => d.slice(0,10));
            await db.collection('confirmed_flags').deleteMany({ room: existing.room, day: { $in: days }, reservationId: existing._id });
            try {
                await maybeGenerateDayClearEvents(existing.room, days, (req.user.username||'').toLowerCase(), { type: 'demotion', reservationId: existing._id, fromStatus, toStatus: newStatus });
            } catch (genErr) {
                console.warn('Failed generating day_clear_events (demotion):', genErr.message);
            }
        }

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
    const existing = await db.collection('reservations').findOne({ _id: new ObjectId(id), $or: [ { deleted: { $exists: false } }, { deleted: false } ] });
        if (!existing) return res.status(404).json({ message: 'Not found' });
        const isAdmin = req.user.role === 'admin';
        const isOwner = existing.author && existing.author.toLowerCase() === (req.user.username || '').toLowerCase();
        if (!isAdmin && !isOwner) return res.status(403).json({ message: 'Forbidden' });
        const update = {};
        const changedFields = [];
        const fromSnapshots = {};
        const toSnapshots = {};
        for (const [k,v] of Object.entries(parse.data)) {
            if (v === '') continue; // ignore empty string updates (treated as no-op)
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
            // Block moving reservation into the past (earliest day before today UTC)
            const now = new Date();
            const todayUtcStart = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
            if (norm[0] < todayUtcStart) return res.status(400).json({ message: 'Cannot set reservation dates in the past' });
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
            // Maintain confirmed_flags docs: claim new, release old (atomic-ish with rollback on conflict)
            const oldDays = (existing.dates && existing.dates.length>0 ? existing.dates : []).map(d => d.slice(0,10));
            const newDays = newDates.map(d => d.slice(0,10));
            const oldRoom = existing.room;
            const newRoom = update.room || existing.room;
            const roomChanged = oldRoom !== newRoom;
            const oldSet = new Set(oldDays);
            const newSetDays = new Set(newDays);
            const daysToAdd = roomChanged ? newDays : newDays.filter(d => !oldSet.has(d));
            const daysToRemove = roomChanged ? oldDays : oldDays.filter(d => !newSetDays.has(d));
            let claimed = [];
            try {
                for (const day of daysToAdd) {
                    await db.collection('confirmed_flags').insertOne({ room: newRoom, day, reservationId: existing._id, createdAt: new Date() });
                    claimed.push(day);
                }
            } catch (e) {
                if (e.code === 11000) {
                    if (claimed.length) {
                        await db.collection('confirmed_flags').deleteMany({ room: newRoom, day: { $in: claimed }, reservationId: existing._id });
                    }
                    return res.status(409).json({ message: 'Conflict: another confirmed/flagged reservation already occupies at least one target day for this room' });
                }
                if (claimed.length) {
                    await db.collection('confirmed_flags').deleteMany({ room: newRoom, day: { $in: claimed }, reservationId: existing._id });
                }
                throw e;
            }
            if (daysToRemove.length) {
                await db.collection('confirmed_flags').deleteMany({ room: oldRoom, day: { $in: daysToRemove }, reservationId: existing._id });
            }
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
    const existing = await db.collection('reservations').findOne({ _id: new ObjectId(id), $or: [ { deleted: { $exists: false } }, { deleted: false } ] });
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
        const existing = await db.collection('reservations').findOne({ _id: new ObjectId(id), $or: [ { deleted: { $exists: false } }, { deleted: false } ] });
        if (!existing) return res.status(404).json({ message: 'Not found' });
        const status = existing.reservationStatus || 'pre';
        if (status !== 'pre') return res.status(400).json({ message: 'Only pre-reservations can be deleted' });
        const isAdmin = req.user.role === 'admin';
        const isOwner = existing.author && existing.author.toLowerCase() === (req.user.username || '').toLowerCase();
        if (!isAdmin && !isOwner) return res.status(403).json({ message: 'Forbidden' });
        await db.collection('reservations').updateOne({ _id: existing._id }, { $set: { deleted: true, deletedAt: new Date(), updatedAt: new Date() } });
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
    // If deleting a confirmed/flagged (shouldn't happen via this endpoint since guard earlier) left for completeness
    // If this deletion could free a day (not current path), analogous generation would occur.
        return res.json({ ok: true });
    } catch (e) {
        console.error('Error deleting reservation', e);
        return res.status(500).json({ message: 'Internal server error' });
    }
});

// Restore a soft-deleted reservation within retention window (admin only)
router.post('/:id/restore', authenticateToken, writeRateLimiter, async (req, res) => {
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });
        const { id } = req.params;
        if (!ObjectId.isValid(id)) return res.status(400).json({ message: 'Invalid id' });
        const db = getDb();
        const existing = await db.collection('reservations').findOne({ _id: new ObjectId(id), deleted: true });
        if (!existing) return res.status(404).json({ message: 'Not found or not deleted' });
        // Ensure within 30-day retention
        if (!existing.deletedAt || (Date.now() - new Date(existing.deletedAt).getTime()) > 30*24*60*60*1000) {
            return res.status(400).json({ message: 'Retention window expired' });
        }
        await db.collection('reservations').updateOne({ _id: existing._id }, { $set: { deleted: false }, $unset: { deletedAt: '' }, $currentDate: { updatedAt: true } });
        await db.collection('reservationHistory').insertOne({
            reservationId: existing._id,
            room: existing.room,
            date: existing.date,
            user: req.user.username,
            action: 'restore',
            event: existing.event,
            fromStatus: 'deleted',
            toStatus: existing.reservationStatus || 'pre',
            timestamp: new Date()
        });
        return res.json({ ok: true });
    } catch (e) {
        console.error('Error restoring reservation', e);
        return res.status(500).json({ message: 'Internal server error' });
    }
});

module.exports = router;