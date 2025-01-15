require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { connectToDb } = require('./db/connection.js');
const { initializeDatabase } = require('./db/init');
const authRoutes = require('./routes/auth');
const reservationRoutes = require('./routes/reservations');

// Add this debug log
console.log('Using MongoDB URI from:', process.env.MONGODB_URI ? '.env file' : 'default config');

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

connectToDb(process.env.MONGODB_URI)
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