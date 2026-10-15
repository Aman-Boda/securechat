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

module.exports = { authLimiter, apiLimiter };
