'use strict';
/**
 * middleware/auth.js
 * Lightweight JWT authentication middleware.
 *
 * Usage:
 *   POST /api/auth/login  { username, password }  → { token }
 *   Protected routes send:  Authorization: Bearer <token>
 *
 * Environment variables:
 *   ADMIN_USERNAME  – default "admin"
 *   ADMIN_PASSWORD  – required in production (no default)
 *   JWT_SECRET      – required in production (no default)
 *   JWT_EXPIRES_IN  – token lifetime, e.g. "8h" (default "8h")
 */
const jwt = require('jsonwebtoken');

// ---------------------------------------------------------------------------
// Token verification middleware
// ---------------------------------------------------------------------------
function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  if (!authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or malformed Authorization header (Bearer token required).' });
  }

  const token  = authHeader.slice(7);
  const secret = process.env.JWT_SECRET;

  if (!secret) {
    // Guard: if JWT_SECRET is not set the server is misconfigured.
    return res.status(500).json({ error: 'Server misconfiguration: JWT_SECRET is not set.' });
  }

  try {
    const payload = jwt.verify(token, secret);
    req.admin     = payload;   // attach decoded payload to request
    next();
  } catch (err) {
    const msg = err.name === 'TokenExpiredError' ? 'Token expired.' : 'Invalid token.';
    return res.status(401).json({ error: msg });
  }
}

// ---------------------------------------------------------------------------
// Login handler — returns a signed JWT on success
// ---------------------------------------------------------------------------
function loginHandler(req, res) {
  const { username, password } = req.body || {};
  const secret = process.env.JWT_SECRET;

  if (!secret) {
    return res.status(500).json({ error: 'Server misconfiguration: JWT_SECRET is not set.' });
  }

  const validUser = process.env.ADMIN_USERNAME || 'admin';
  const validPass = process.env.ADMIN_PASSWORD;

  if (!validPass) {
    return res.status(500).json({ error: 'Server misconfiguration: ADMIN_PASSWORD is not set.' });
  }

  if (username !== validUser || password !== validPass) {
    return res.status(401).json({ error: 'Invalid credentials.' });
  }

  const expiresIn = process.env.JWT_EXPIRES_IN || '8h';
  const token     = jwt.sign({ username: validUser, role: 'admin' }, secret, { expiresIn });

  res.json({ token, expiresIn });
}

module.exports = { requireAuth, loginHandler };
