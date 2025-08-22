const rateLimit = require('express-rate-limit');

// Write-intensive endpoints (creation / updates / deletes) get a higher but still bounded limit.
// Environment overrides:
//   WRITE_RATE_LIMIT_WINDOW_MS (default same 15m)
//   WRITE_RATE_LIMIT_MAX (default 200) (was 60)
const writeWindowMs = parseInt(process.env.WRITE_RATE_LIMIT_WINDOW_MS || '', 10) || 15 * 60 * 1000;
const writeMax = parseInt(process.env.WRITE_RATE_LIMIT_MAX || '', 10) || 200;

module.exports = rateLimit({
  windowMs: writeWindowMs,
  max: writeMax,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many write requests, please try again later.'
});
