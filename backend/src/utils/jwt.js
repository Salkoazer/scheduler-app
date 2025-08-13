const jwt = require('jsonwebtoken');

const primary = process.env.JWT_SECRET;
const previous = process.env.JWT_SECRET_PREV;

// server.js enforces presence/strength; utils stays tolerant for tests
function signToken(payload, options = {}) {
  return jwt.sign(payload, primary, { expiresIn: '1h', ...options });
}

function verifyToken(token) {
  try {
    return jwt.verify(token, primary);
  } catch (err) {
    if (previous) {
      try {
        return jwt.verify(token, previous);
      } catch (_) {
        // ignore
      }
    }
    throw err;
  }
}

module.exports = { signToken, verifyToken };
