const rateLimit = require('express-rate-limit');

// Stricter limiter for authentication endpoints
// Authentication endpoints: modest increase but still protective against brute force.
// Environment overrides:
//   AUTH_RATE_LIMIT_WINDOW_MS (default 15m)
//   AUTH_RATE_LIMIT_MAX (default 40) (was 20)
const authWindowMs = parseInt(process.env.AUTH_RATE_LIMIT_WINDOW_MS || '', 10) || 15 * 60 * 1000;
const authMax = parseInt(process.env.AUTH_RATE_LIMIT_MAX || '', 10) || 40;

module.exports = rateLimit({
  windowMs: authWindowMs,
  max: authMax,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many login attempts, please try again later.'
});
