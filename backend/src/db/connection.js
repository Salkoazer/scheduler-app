const { MongoClient } = require('mongodb');

let db;

const connectToDb = async (uri) => {
  const client = new MongoClient(uri, { useNewUrlParser: true, useUnifiedTopology: true });
  await client.connect();
  
  // Explicitly specify the database name
  db = client.db('schedule-app-database');
  
  console.log('Connected to MongoDB');
  console.log('Database name:', db.databaseName);
  
  try {
    await db.admin().command({ ping: 1 });
    
    // Add this to verify collections
    const collections = await db.listCollections().toArray();
    console.log('Available collections:', collections.map(c => c.name));
    
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } catch (err) {
    console.error('Failed to ping MongoDB:', err);
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