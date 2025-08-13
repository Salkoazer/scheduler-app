const { MongoClient } = require('mongodb');
const logger = require('../logger');

let db;
let isConnecting = false;

const connectToDb = async (uri) => {
    if (isConnecting || db) {
        return;
    }

    try {
        isConnecting = true;
        
        if (!uri || uri.includes('localhost')) {
            logger.error('Invalid or local MongoDB URI detected. Please check your MONGO_URI environment variable.');
            throw new Error('Invalid MongoDB URI');
        }

        const client = new MongoClient(uri, { 
            useNewUrlParser: true, 
            useUnifiedTopology: true,
            maxPoolSize: 10, // Correct option for connection pooling
            serverSelectionTimeoutMS: 5000 // Add timeout
        });

        await client.connect();
        
        // Explicitly use the database name from the URI or fallback
        const dbName = uri.split('/').pop().split('?')[0] || 'schedule-app-database';
        db = client.db(dbName);
        
    logger.info({
            uri: uri.replace(/:\/\/.*?:.*?@/, '://****:****@'), // Mask credentials
            database: dbName
    }, 'Successfully connected to:');

        // Extract and log cluster information from URI
        const clusterInfo = uri.match(/@(.*?)\//);
    logger.debug({ cluster: clusterInfo ? clusterInfo[1] : 'unknown' }, 'Attempting to connect to cluster');
        
        // Get deployment information
    const serverInfo = await client.db().admin().serverInfo();
    logger.info({ version: serverInfo.version }, 'Connected to MongoDB');
        
        // List all databases
    const dbs = await client.db().admin().listDatabases();
    logger.debug({ dbs: dbs.databases.map(db => db.name) }, 'Available databases');
        
        // List all collections in current database
    const collections = await db.listCollections().toArray();
    logger.debug({ collections: collections.map(c => c.name) }, 'Collections in current database');
        
    logger.info('Successfully connected to MongoDB!');
    } catch (err) {
    logger.error({ err: err.message }, 'MongoDB connection error');
        isConnecting = false;
        throw err;
    }
};

const getDb = () => {
  if (!db) {
    throw new Error('Database not connected');
  }
  return db;
};

module.exports = { connectToDb, getDb };