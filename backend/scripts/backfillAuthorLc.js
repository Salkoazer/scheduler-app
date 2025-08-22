#!/usr/bin/env node
require('dotenv').config();
const { MongoClient } = require('mongodb');

async function run() {
  const uri = process.env.MONGO_URI;
  if (!uri) {
    console.error('MONGO_URI not set');
    process.exit(1);
  }
  const client = new MongoClient(uri);
  try {
    await client.connect();
    const dbNameMatch = uri.match(/\/([^/?]+)(?:\?|$)/);
    const dbName = (dbNameMatch && dbNameMatch[1]) || process.env.MONGO_DB || 'schedule-app-database';
    const db = client.db(dbName);
    const col = db.collection('reservations');
    const cursor = col.find({ $or: [ { authorLc: { $exists: false } }, { authorLc: null } ] });
    let updated = 0;
    while (await cursor.hasNext()) {
      const doc = await cursor.next();
      const author = typeof doc.author === 'string' ? doc.author : 'unknown';
      await col.updateOne({ _id: doc._id }, { $set: { authorLc: author.toLowerCase() } });
      updated++;
    }
    console.log(`Backfill complete. Updated ${updated} documents.`);
  } catch (e) {
    console.error('Backfill failed', e);
    process.exit(1);
  } finally {
    await client.close();
  }
}

run();