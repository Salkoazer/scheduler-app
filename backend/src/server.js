const path = require('path');
const dotenv = require('dotenv');

// Load environment variables from .env file
const result = dotenv.config({ path: path.resolve(__dirname, '../.env') });
if (result.error) {
    console.error('Error loading .env file:', result.error);
    process.exit(1);
}

const express = require('express');
const cors = require('cors');
const { connectToDb } = require('./db/connection.js');
const { initializeDatabase } = require('./db/init');
const authRoutes = require('./routes/auth');
const reservationRoutes = require('./routes/reservations');

// Debug MongoDB URI selection with more detailed logging
const configuredUri = process.env.MONGODB_URI;
const productionConfig = require('../config/production');
const mongoUri = configuredUri || productionConfig.mongoUri;

console.log('Environment variables loaded:', {
    MONGODB_URI: configuredUri ? 'Set' : 'Not set',
    PORT: process.env.PORT || 'Not set',
    NODE_ENV: process.env.NODE_ENV || 'Not set'
});

console.log('Selected MongoDB URI:', mongoUri.replace(/:[^:]*@/, ':****@'));

if (mongoUri.includes('localhost')) {
    console.warn('WARNING: Using local MongoDB instance instead of Atlas cluster');
}

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// Mount routes with correct prefixes
app.use('/api/auth', authRoutes);
app.use('/api/reservations', reservationRoutes);

// Debug route logging
app._router.stack.forEach(function(r){
    if (r.route && r.route.path){
        console.log(`Route: ${Object.keys(r.route.methods)} ${r.route.path}`)
    }
});

// Health check endpoint
app.get('/api/healthcheck', (req, res) => {
    res.status(200).json({ status: 'ok' });
});

connectToDb(mongoUri)
  .then(async () => {
    console.log('Connected to database, initializing...');
    await initializeDatabase();
    console.log('Database initialized');
    
  app.listen(port, () => {
    console.log(`Server is running on port: ${port}`);
  });
})
.catch(err => {
  console.error('Failed to connect to the database', err);
  process.exit(1);
});