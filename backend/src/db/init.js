const { getDb } = require('./connection');
const bcrypt = require('bcrypt');

async function initializeDatabase() {
    try {
        const db = getDb();
        
        // Check if credentials collection exists
        const collections = await db.listCollections().toArray();
        const hasCredentials = collections.some(c => c.name === 'credentials');
        
        if (!hasCredentials) {
            console.log('Creating credentials collection...');
            await db.createCollection('credentials');
        }

        // Check if admin user exists
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
        
    } catch (error) {
        console.error('Database initialization failed:', error);
        throw error;
    }
}

module.exports = { initializeDatabase };
