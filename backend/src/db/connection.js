const { MongoClient } = require('mongodb');

let db;
let isConnecting = false;

const connectToDb = async (uri) => {
    if (isConnecting) {
        console.log('Connection already in progress...');
        return;
    }

    if (db) {
        console.log('Already connected to MongoDB');
        return;
    }

    try {
        isConnecting = true;
        // Extract and log cluster information from URI
        const clusterInfo = uri.match(/@(.*?)\//);
        console.log('Attempting to connect to cluster:', clusterInfo ? clusterInfo[1] : 'unknown');
        
        console.log('Connecting to MongoDB with URI:', uri.replace(/:[^:]*@/, ':****@')); // Hide password in logs
        
        const client = new MongoClient(uri, { useNewUrlParser: true, useUnifiedTopology: true });
        await client.connect();
        
        // Get deployment information
        const serverInfo = await client.db().admin().serverInfo();
        console.log('Connected to MongoDB version:', serverInfo.version);
        console.log('Cluster connection string:', uri.replace(/:([^:@]+)@/, ':****@'));
        
        db = client.db('schedule-app-database');
        
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
        console.error('Failed to connect to MongoDB:', err);
        throw err;
    } finally {
        isConnecting = false;
    }
};

const getDb = () => {
  if (!db) {
    throw new Error('Database not connected');
  }
  return db;
};

module.exports = { connectToDb, getDb };