require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { connectToDb } = require('./db/connection.js'); // Ensure the correct path and file extension
const authRoutes = require('./routes/auth');
const reservationRoutes = require('./routes/reservations');

const app = express();
const port = process.env.PORT || 5000;

// Configure CORS
const corsOptions = {
    origin: (origin, callback) => {
        if (!origin || origin === 'http://localhost:9000') {
            // Allow requests with no origin (like mobile apps or curl requests)
            // and requests from localhost
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
};

app.use((req, res, next) => {
    if (req.headers.origin === 'http://localhost:9000') {
        // Skip CORS for localhost
        next();
    } else {
        cors(corsOptions)(req, res, next);
    }
});

app.options('*', cors(corsOptions)); // Preflight request handling

app.use(express.json());

app.use('/api', authRoutes);
app.use('/api', reservationRoutes);

// Health check endpoint
app.get('/api/healthcheck', (req, res) => {
    res.status(200).json({ status: 'ok' });
});

connectToDb(process.env.MONGODB_URI).then(() => {
  app.listen(port, () => {
    console.log(`Server is running on port: ${port}`);
  });
}).catch(err => {
  console.error('Failed to connect to the database', err);
  process.exit(1);
});