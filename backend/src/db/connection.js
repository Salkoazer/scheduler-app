const { MongoClient } = require('mongodb');

let db;
let isConnecting = false;

const connectToDb = async (uri) => {
    if (isConnecting || db) {
        return;
    }

    try {
        isConnecting = true;
        
        if (!uri || uri.includes('localhost')) {
            console.error('Invalid or local MongoDB URI detected. Please check your .env file.');
            throw new Error('Invalid MongoDB URI');
        }

        const client = new MongoClient(uri, { 
            useNewUrlParser: true, 
            useUnifiedTopology: true,
            serverSelectionTimeoutMS: 5000 // Add timeout
        });

        await client.connect();
        
        // Explicitly use the database name from the URI or fallback
        const dbName = uri.split('/').pop().split('?')[0] || 'schedule-app-database';
        db = client.db(dbName);
        
        console.log('Successfully connected to:', {
            uri: uri.replace(/:[^:]*@/, ':****@'),
            database: dbName,
            isConnected: client.isConnected()
        });

        // Extract and log cluster information from URI
        const clusterInfo = uri.match(/@(.*?)\//);
        console.log('Attempting to connect to cluster:', clusterInfo ? clusterInfo[1] : 'unknown');
        
        console.log('Connecting to MongoDB with URI:', uri.replace(/:[^:]*@/, ':****@')); // Hide password in logs
        
        // Get deployment information
        const serverInfo = await client.db().admin().serverInfo();
        console.log('Connected to MongoDB version:', serverInfo.version);
        console.log('Cluster connection string:', uri.replace(/:([^:@]+)@/, ':****@'));
        
        console.log('Connected to MongoDB');
        console.log('Database name:', db.databaseName);
        console.log('Current database:', client.db().databaseName);
        
        // List all databases
        const dbs = await client.db().admin().listDatabases();
        console.log('Available databases:', dbs.databases.map(db => db.name));
        
        // List all collections in current database
        const collections = await db.listCollections().toArray();
        console.log('Collections in current database:', collections.map(c => c.name));
        
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } catch (err) {
        console.error('MongoDB connection error:', err);
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