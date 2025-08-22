#!/usr/bin/env node
// Simple backup script: dumps reservations (including soft-deleted) and reservationHistory to local JSON files
// Optional S3 upload if AWS creds + BUCKET provided (uses aws-sdk v3 if installed)

const fs = require('fs');
const path = require('path');
const { connectToDb } = require('../src/db/connection');
const { getDb } = require('../src/db/connection');

(async () => {
  try {
    const mongoUri = process.env.MONGO_URI;
    if (!mongoUri) {
      console.error('MONGO_URI not set');
      process.exit(1);
    }
    await connectToDb(mongoUri);
    const db = getDb();

    const ts = new Date().toISOString().replace(/[:.]/g, '-');
    const outDir = path.resolve(process.env.BACKUP_DIR || 'backups');
    if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });

    const reservations = await db.collection('reservations').find({}).toArray();
    const history = await db.collection('reservationHistory').find({}).toArray();

    const resFile = path.join(outDir, `reservations-${ts}.json`);
    const histFile = path.join(outDir, `reservationHistory-${ts}.json`);

    fs.writeFileSync(resFile, JSON.stringify(reservations, null, 2));
    fs.writeFileSync(histFile, JSON.stringify(history, null, 2));
    console.log('Backup written:', resFile, histFile);

    if (process.env.AWS_S3_BUCKET && process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY) {
      try {
        const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
        const s3 = new S3Client({ region: process.env.AWS_REGION || 'us-east-1' });
        const bucket = process.env.AWS_S3_BUCKET;
        for (const f of [resFile, histFile]) {
          const body = fs.readFileSync(f);
            const key = path.basename(f);
            await s3.send(new PutObjectCommand({ Bucket: bucket, Key: `calendar-backups/${key}`, Body: body, ContentType: 'application/json' }));
            console.log('Uploaded to S3:', key);
        }
      } catch (e) {
        console.warn('S3 upload failed (ensure @aws-sdk/client-s3 installed):', e.message);
      }
    }
    process.exit(0);
  } catch (e) {
    console.error('Backup failed:', e);
    process.exit(1);
  }
})();
