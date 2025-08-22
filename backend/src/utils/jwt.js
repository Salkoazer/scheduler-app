const jwt = require('jsonwebtoken');

// Primary & previous secrets allow secret rotation
const primary = process.env.JWT_SECRET;
const previous = process.env.JWT_SECRET_PREV;

// Standard claims configuration
const ISSUER = process.env.JWT_ISSUER || 'scheduler-app';
const AUDIENCE = process.env.JWT_AUDIENCE || 'scheduler-app-clients';

// Durations (can be overridden by env, e.g., '15m', '7d')
const ACCESS_TTL = process.env.JWT_ACCESS_TTL || '15m';
const REFRESH_TTL = process.env.JWT_REFRESH_TTL || '7d';

// Helper to sign with common claims
function sign(payload, opts) {
  return jwt.sign(
    payload,
    primary,
    {
      issuer: ISSUER,
      audience: AUDIENCE,
      ...opts
    }
  );
}

// Access token: short-lived; minimal payload (username, role)
function signAccessToken(user) {
  const { username, role } = user;
  return sign({ sub: username, role }, { expiresIn: ACCESS_TTL });
}

// Refresh token: longer-lived; rotate on each use
function signRefreshToken(user, rotationId) {
  const { username, role } = user;
  // rotationId (jti) used to detect reuse after rotation
  return sign({ sub: username, role, jti: rotationId }, { expiresIn: REFRESH_TTL });
}

// Generic verifier with fallback to previous secret (rotation)
function verify(token, opts = {}) {
  try {
    return jwt.verify(token, primary, { issuer: ISSUER, audience: AUDIENCE, ...opts });
  } catch (err) {
    if (previous) {
      try {
        return jwt.verify(token, previous, { issuer: ISSUER, audience: AUDIENCE, ...opts });
      } catch (_) {
        // fall through
      }
    }
    throw err;
  }
}

function verifyAccessToken(token) {
  return verify(token);
}

function verifyRefreshToken(token) {
  return verify(token);
}

module.exports = {
  signAccessToken,
  signRefreshToken,
  verifyAccessToken,
  verifyRefreshToken,
  // Expose constants for testing
  ISSUER,
  AUDIENCE,
  ACCESS_TTL,
  REFRESH_TTL
};
