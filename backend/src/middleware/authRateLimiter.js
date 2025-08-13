const rateLimit = require('express-rate-limit');

// Stricter limiter for authentication endpoints
module.exports = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many login attempts, please try again later.'
});
