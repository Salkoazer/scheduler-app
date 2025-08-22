const { getDb } = require('./connection');
const bcrypt = require('bcrypt');

let isInitialized = false;

async function initializeDatabase() {
    if (isInitialized) {
        console.log('Database already initialized');
        return;
    }

    try {
        const db = getDb();
        
        // Check if credentials collection exists
        const collections = await db.listCollections().toArray();
        const hasCredentials = collections.some(c => c.name === 'credentials');
        
        if (!hasCredentials) {
            console.log('Creating credentials collection...');
            await db.createCollection('credentials');
        }

        // Ensure updated indexes for reservations collection (dates[] model)
        try {
            await db.collection('reservations').createIndexes([
                { key: { dates: 1, room: 1 }, name: 'idx_reservations_dates_room' },
                { key: { room: 1, reservationStatus: 1, dates: 1 }, name: 'idx_reservations_room_status_dates' },
                { key: { createdAt: -1 }, name: 'idx_reservations_createdAt' },
                // TTL for soft-deleted documents (expire after 30 days)
                { key: { deletedAt: 1 }, name: 'ttl_reservations_deletedAt', expireAfterSeconds: 60 * 60 * 24 * 30, partialFilterExpression: { deleted: true } }
            ]);
            console.log('Ensured reservation indexes (dates model)');
        } catch (e) {
            console.warn('Failed creating reservations indexes:', e.message);
        }

        // Ensure indexes for reservationHistory
        try {
            await db.collection('reservationHistory').createIndexes([
                { key: { reservationId: 1, timestamp: 1 }, name: 'idx_history_reservation_timestamp' },
                { key: { date: 1, room: 1, timestamp: 1 }, name: 'idx_history_day_room_ts' }
            ]);
            console.log('Ensured history indexes');
        } catch (e) {
            console.warn('Failed creating history indexes:', e.message);
        }

        // Ensure confirmed_flags collection + unique index (one doc per (room, day))
        try {
            const hasConfirmedFlags = collections.some(c => c.name === 'confirmed_flags');
            if (!hasConfirmedFlags) {
                console.log('Creating confirmed_flags collection...');
                await db.createCollection('confirmed_flags');
            }
            await db.collection('confirmed_flags').createIndex({ room: 1, day: 1 }, { unique: true, name: 'uniq_confirmed_flag_room_day' });
            console.log('Ensured confirmed_flags unique index');
        } catch (e) {
            console.warn('Failed ensuring confirmed_flags index:', e.message);
        }

        // Ensure refreshTokens collection (persistent refresh token allowlist)
        try {
            const hasRefresh = collections.some(c => c.name === 'refreshTokens');
            if (!hasRefresh) {
                console.log('Creating refreshTokens collection...');
                await db.createCollection('refreshTokens');
            }
            await db.collection('refreshTokens').createIndexes([
                { key: { jti: 1 }, name: 'uniq_refresh_jti', unique: true },
                { key: { expiresAt: 1 }, name: 'ttl_refresh_expiresAt', expireAfterSeconds: 0 },
                { key: { username: 1 }, name: 'idx_refresh_username' }
            ]);
            console.log('Ensured refreshTokens indexes');
        } catch (e) {
            console.warn('Failed ensuring refreshTokens indexes:', e.message);
        }

        // Ensure unique index on credentials.username
        try {
            await db.collection('credentials').createIndex({ username: 1 }, { unique: true, name: 'uniq_credentials_username' });
        } catch (e) {
            console.warn('Failed to ensure unique index on credentials.username:', e.message);
        }

        // Seed admin only in non-production environments
        if (process.env.NODE_ENV !== 'production') {
            const adminUser = await db.collection('credentials').findOne({ username: 'admin' });
            if (!adminUser) {
                console.log('Creating admin user...');
                const hashedPassword = await bcrypt.hash('admin', 10);
                await db.collection('credentials').insertOne({
                    username: 'admin',
                    password: hashedPassword,
                    role: 'admin',
                    createdAt: new Date()
                });
                console.log('Admin user created successfully');
            } else {
                console.log('Admin user already exists');
                // Backfill role if missing
                if (!adminUser.role) {
                    await db.collection('credentials').updateOne({ _id: adminUser._id }, { $set: { role: 'admin' } });
                }
            }
        }
        
        isInitialized = true;
    } catch (error) {
        console.error('Database initialization failed:', error);
        throw error;
    }
}

module.exports = { initializeDatabase };
