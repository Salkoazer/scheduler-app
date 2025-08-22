const rateLimit = require('express-rate-limit');

// Configurable basic rate limiter for read (GET) endpoints and general traffic.
// Environment overrides:
//   RATE_LIMIT_WINDOW_MS (default 15 * 60 * 1000)
//   RATE_LIMIT_MAX (default 600)  (was 100)
// These can be tuned without code changes if traffic patterns evolve.
const windowMs = parseInt(process.env.RATE_LIMIT_WINDOW_MS || '', 10) || 15 * 60 * 1000;
const max = parseInt(process.env.RATE_LIMIT_MAX || '', 10) || 600; // increase default ceiling

const limiter = rateLimit({
    windowMs,
    max,
    standardHeaders: true,
    legacyHeaders: false,
    message: 'Too many requests from this IP, please try again later.'
});

module.exports = limiter;
