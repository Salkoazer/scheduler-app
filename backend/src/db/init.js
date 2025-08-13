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

        // Ensure indexes for reservations collection
        try {
            await db.collection('reservations').createIndexes([
                { key: { date: 1 }, name: 'idx_reservations_date' },
                { key: { room: 1, date: 1 }, name: 'idx_reservations_room_date' },
                { key: { createdAt: -1 }, name: 'idx_reservations_createdAt' }
            ]);
            console.log('Ensured reservation indexes');
        } catch (e) {
            console.warn('Failed creating indexes for reservations:', e.message);
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
                    createdAt: new Date()
                });
                console.log('Admin user created successfully');
            } else {
                console.log('Admin user already exists');
            }
        }
        
        isInitialized = true;
    } catch (error) {
        console.error('Database initialization failed:', error);
        throw error;
    }
}

module.exports = { initializeDatabase };
