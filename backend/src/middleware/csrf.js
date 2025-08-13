const crypto = require('crypto');

function generateToken() {
  return crypto.randomBytes(32).toString('base64url');
}

function cookieOptions() {
  const isProd = process.env.NODE_ENV === 'production';
  return {
    httpOnly: false, // readable by frontend JS for header
    secure: isProd,
    sameSite: isProd ? 'none' : 'lax',
    path: '/',
    maxAge: 60 * 60 * 1000 // 1 hour
  };
}

// Ensure a CSRF token cookie exists for safe methods so clients can read it
function ensureCsrfCookie(req, res, next) {
  const method = req.method.toUpperCase();
  if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') {
    if (!req.cookies || !req.cookies.csrfToken) {
      const token = generateToken();
      res.cookie('csrfToken', token, cookieOptions());
    }
  }
  next();
}

// Verify CSRF on state-changing requests
function verifyCsrf(req, res, next) {
  const method = req.method.toUpperCase();
  if (method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE') {
    const headerToken = req.get('X-CSRF-Token');
    const cookieToken = req.cookies ? req.cookies.csrfToken : undefined;
    if (!headerToken || !cookieToken || headerToken !== cookieToken) {
      return res.status(403).json({ message: 'CSRF validation failed' });
    }
  }
  next();
}

// Route handler to rotate and return a CSRF token
function csrfTokenRoute(req, res) {
  const token = generateToken();
  res.cookie('csrfToken', token, cookieOptions());
  res.status(200).json({ csrfToken: token });
}

module.exports = { ensureCsrfCookie, verifyCsrf, csrfTokenRoute };
