const { MongoClient } = require('mongodb');

let db;

const connectToDb = async (uri) => {
  const client = new MongoClient(uri, { useNewUrlParser: true, useUnifiedTopology: true });
  await client.connect();
  db = client.db();
  console.log('Connected to MongoDB');

  try {
    await db.admin().command({ ping: 1 });
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