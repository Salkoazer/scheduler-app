#!/usr/bin/env node
/**
 * clearDemoData.js
 *
 * Purpose: Purge reservation-related collections (reservations, reservationHistory,
 * confirmed_flags, day_clear_events) so you can hand over a clean system to end users.
 *
 * Safety:
 *  - Requires explicit confirmation via CLI flag or interactive prompt.
 *  - Refuses to run if NODE_ENV==='production' unless --force is provided.
 *  - Does NOT touch user credentials or refreshTokens.
 *  - Creates an optional JSON backup (use --backup) before deletion.
 *
 * Usage:
 *   NODE_ENV=staging MONGO_URI="mongodb+srv://..." npm run clean:demo
 *   npm run clean:demo -- --backup ./pre-clean-backup.json
 *   npm run clean:demo -- --force   (allow in production)
 */

const fs = require('fs');
const path = require('path');
const { MongoClient } = require('mongodb');

function parseArgs() {
  const args = process.argv.slice(2);
  const opts = { force:false, backupPath:null, yes:false };
  for (let i=0;i<args.length;i++) {
    const a = args[i];
    if (a === '--force') opts.force = true;
    else if (a === '--yes' || a === '-y') opts.yes = true;
    else if (a === '--backup') { opts.backupPath = args[i+1]; i++; }
  }
  return opts;
}

(async () => {
  const { force, backupPath, yes } = parseArgs();
  const uri = process.env.MONGO_URI;
  if (!uri) {
    console.error('MONGO_URI not set');
    process.exit(1);
  }
  // Basic validation & placeholder guard
  if (!/^mongodb(\+srv)?:\/\//.test(uri)) {
    console.error('MONGO_URI invalid: must start with mongodb:// or mongodb+srv://');
    process.exit(1);
  }
  if (/YOUR_ATLAS_URI|changeme|placeholder/i.test(uri)) {
    console.error('MONGO_URI appears to be a placeholder. Replace with your real connection string from Atlas.');
    process.exit(1);
  }
  if (process.env.NODE_ENV === 'production' && !force) {
    console.error('Refusing to run in production without --force');
    process.exit(1);
  }

  if (!yes) {
    // Minimal interactive confirmation
    process.stdout.write('This will DELETE all reservation data. Type "yes" to continue: ');
    const input = await new Promise(res => {
      process.stdin.resume();
      process.stdin.setEncoding('utf8');
      process.stdin.once('data', d => res(d.trim()));
    });
    if (input !== 'yes') {
      console.log('Aborted.');
      process.exit(0);
    }
  }

  const client = new MongoClient(uri, { useUnifiedTopology:true });
  try {
    await client.connect();
    const dbName = uri.split('/').pop().split('?')[0];
    const db = client.db(dbName);
    console.log('Connected to', dbName);

    const reservationsCol = db.collection('reservations');
    const historyCol = db.collection('reservationHistory');
    const flagsCol = db.collection('confirmed_flags');
    const dceCol = db.collection('day_clear_events');

    if (backupPath) {
      console.log('Creating backup to', backupPath);
      const snapshot = {
        ts: new Date().toISOString(),
        reservations: await reservationsCol.find({}).toArray(),
        reservationHistory: await historyCol.find({}).toArray(),
        confirmed_flags: await flagsCol.find({}).toArray(),
        day_clear_events: await dceCol.find({}).toArray()
      };
      fs.writeFileSync(path.resolve(backupPath), JSON.stringify(snapshot, null, 2));
      console.log('Backup written. Size:', (fs.statSync(path.resolve(backupPath)).size/1024).toFixed(1)+'KB');
    }

    const resDel = await reservationsCol.deleteMany({});
    const histDel = await historyCol.deleteMany({});
    const flagsDel = await flagsCol.deleteMany({});
    const dceDel = await dceCol.deleteMany({});

    console.log('Deleted counts:', {
      reservations: resDel.deletedCount,
      reservationHistory: histDel.deletedCount,
      confirmed_flags: flagsDel.deletedCount,
      day_clear_events: dceDel.deletedCount
    });
    console.log('Done.');
  } catch (e) {
    console.error('Error clearing demo data:', e);
    process.exit(1);
  } finally {
    await client.close();
  }
})();
