const path = require('path');
const dotenv = require('dotenv');
const pinoHttp = require('pino-http');
const logger = require('./logger');
const requestId = require('./middleware/requestId');

// Debug: Show initial process.env values
logger.info({
  MONGO_URI: process.env.MONGO_URI ? 'Set from system' : 'Not set',
  PORT: process.env.PORT ? 'Set from system' : 'Not set',
  NODE_ENV: process.env.NODE_ENV ? 'Set from system' : 'Not set'
}, 'Initial process.env');

// Load environment variables from .env file
const envPath = path.resolve(__dirname, '../.env');
logger.debug({ envPath }, 'Loading .env');
const result = dotenv.config({ path: envPath });

// Debug: Show which variables were loaded from .env
logger.debug({
    error: result.error ? 'Failed to load' : 'Loaded successfully',
    parsed: result.parsed ? Object.keys(result.parsed) : []
}, '.env file load result');

// Debug: Show process.env after .env load
logger.info({
  MONGO_URI: process.env.MONGO_URI ? 'Set from .env' : 'Not set',
  PORT: process.env.PORT ? 'Set from .env' : 'Not set',
  NODE_ENV: process.env.NODE_ENV ? 'Set from .env' : 'Not set'
}, 'After .env load');

const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const { connectToDb } = require('./db/connection.js');
const { initializeDatabase } = require('./db/init');
const authRoutes = require('./routes/auth');
const reservationRoutes = require('./routes/reservations');
const rateLimiter = require('./middleware/rateLimiter');
const secureHeaders = require('./middleware/secureHeaders');
const authRateLimiter = require('./middleware/authRateLimiter');

// Debug: Show production config values
const productionConfig = require('../config/production');
logger.debug({
    mongoUri: productionConfig.mongoUri ? 'Set' : 'Not set',
    port: productionConfig.port ? 'Set' : 'Not set'
}, 'Production config values');

// Debug MongoDB URI selection with more detailed logging
const configuredUri = process.env.MONGO_URI;
const mongoUri = configuredUri || productionConfig.mongoUri;

logger.info({
  MONGO_URI: configuredUri ? 'Set' : 'Not set',
  PORT: process.env.PORT || 'Not set',
  NODE_ENV: process.env.NODE_ENV || 'Not set'
}, 'Environment variables loaded');

logger.info({ mongoUri: mongoUri.replace(/:[^:]*@/, ':****@') }, 'Selected MongoDB URI');

if (mongoUri.includes('localhost')) {
  logger.warn('WARNING: Using local MongoDB instance instead of Atlas cluster');
}

const app = express();
app.use(requestId);
app.use(pinoHttp({ logger }));
const port = process.env.PORT || 3000;
// Minor hardening: hide Express signature
app.disable('x-powered-by');

// CORS: allow selected origins and log decisions
const envAllowed = process.env.CORS_ALLOWED_ORIGINS;
const allowedOrigins = envAllowed
  ? envAllowed.split(',').map(s => s.trim()).filter(Boolean)
  : [
      'http://localhost:9000',
      'http://calendariocoliseu.site',
      'https://calendariocoliseu.site'
    ];

const corsOptions = {
  origin: (origin, callback) => {
    const reqOrigin = origin || 'null';
    const isAllowed = !origin || allowedOrigins.includes(reqOrigin);
    console.log(`[CORS] Origin: ${reqOrigin} -> ${isAllowed ? 'allowed' : 'denied'}`);
    callback(isAllowed ? null : new Error(`Not allowed by CORS: ${reqOrigin}`), isAllowed);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
};

// Request/response logging (before CORS so preflights are captured)
app.use((req, res, next) => {
  const { method, originalUrl } = req;
  const o = req.headers.origin;
  const acrm = req.headers['access-control-request-method'];
  const acrh = req.headers['access-control-request-headers'];

  if (process.env.NODE_ENV !== 'production') {
    console.log(`→ ${method} ${originalUrl}`, {
      origin: o || null,
      'access-control-request-method': acrm || null,
      'access-control-request-headers': acrh || null
    });
  }

  res.on('finish', () => {
    if (process.env.NODE_ENV !== 'production') {
      const hdrs = res.getHeaders();
      const pick = (k) => (hdrs[k.toLowerCase()] ?? undefined);
      console.log(`← ${res.statusCode} ${method} ${originalUrl}`, {
        'access-control-allow-origin': pick('access-control-allow-origin'),
        'access-control-allow-credentials': pick('access-control-allow-credentials'),
        'access-control-allow-methods': pick('access-control-allow-methods'),
        'access-control-allow-headers': pick('access-control-allow-headers'),
        'vary': pick('vary'),
        'set-cookie': pick('set-cookie')
      });
    } else {
      console.log(`${res.statusCode} ${method} ${originalUrl}`);
    }
  });
  next();
});

// Apply CORS (handles preflights too)
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

app.use(express.json({ limit: '200kb' }));
app.use(cookieParser());

// Apply secure headers middleware
app.use(secureHeaders);

// Enforce HTTPS in production (behind proxy/load balancer)
app.set('trust proxy', 1);
if (process.env.NODE_ENV === 'production') {
  app.use((req, res, next) => {
    const isSecure = req.secure || req.headers['x-forwarded-proto'] === 'https';
    if (isSecure) return next();
    const host = req.headers.host;
    return res.redirect(301, `https://${host}${req.originalUrl}`);
  });
}

// Apply rate limiting middleware
app.use(rateLimiter);

// Mount routes with correct prefixes
// Apply stricter rate limits for auth routes
app.use('/api/auth', authRateLimiter, authRoutes);
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