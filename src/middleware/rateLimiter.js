const rateLimit = require('express-rate-limit');

// Tight limit on auth endpoints — the main defense against password
// brute-forcing and account-enumeration-by-timing attacks. Configurable via
// env var so automated test suites (which legitimately hit many auth
// endpoints in quick succession from one "IP") can raise it without
// touching the production default.
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: parseInt(process.env.AUTH_RATE_LIMIT_MAX, 10) || 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts. Please wait a few minutes and try again.' },
});

// Looser general-purpose limiter for the rest of the REST API.
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Please slow down.' },
});

// The encrypted key backup is large (it grows with account age) and is parsed
// with a bigger body limit than other routes, so uploads are capped per hour
// to keep that from being abused.
const backupLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many backup uploads. Please try again later.' },
});

module.exports = { authLimiter, apiLimiter, backupLimiter };
