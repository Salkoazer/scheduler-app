const express = require('express');
const cors = require('cors');
const { connectToDb } = require('./db/connection');
const authRoutes = require('./routes/auth');
const reservationRoutes = require('./routes/reservations');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

// Configure CORS
const corsOptions = {
  origin: ['http://localhost:9000', 'https://main.d2mypo62hcjz5y.amplifyapp.com'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions)); // Preflight request handling

app.use(express.json());

app.use('/api/auth', authRoutes); // Ensure auth routes are prefixed correctly
app.use('/api/reservations', reservationRoutes); // Ensure reservation routes are prefixed correctly

connectToDb(process.env.MONGODB_URI).then(() => {
  app.listen(port, () => {
    console.log(`Server is running on port: ${port}`);
  });
}).catch(err => {
  console.error('Failed to connect to the database', err);
  process.exit(1);
});