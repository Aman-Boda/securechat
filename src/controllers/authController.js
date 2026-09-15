const bcrypt = require('bcrypt');
const userRepo = require('../db/repositories/userRepo');
const { signToken, COOKIE_NAME } = require('../utils/jwt');
const { isProduction } = require('../config/env');

const SALT_ROUNDS = 12;
const COOKIE_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000; // 7 days, matches JWT TTL

// A precomputed hash with no matching password, used to keep login timing
// consistent when the identifier doesn't match any account. Without this,
// an attacker could tell "wrong password" apart from "no such user" by
// measuring response time (bcrypt only runs when a user is found).
const DUMMY_HASH = bcrypt.hashSync('not-a-real-password-used-for-timing-safety', SALT_ROUNDS);

function baseCookieOptions() {
  return {
    httpOnly: true, // not readable by JavaScript — the main defense against session theft via XSS
    secure: isProduction, // HTTPS-only outside local dev
    sameSite: 'lax', // blocks the cookie being sent on cross-site POSTs (CSRF)
    path: '/',
  };
}

async function register(req, res) {
  const { username, email, password } = req.body;

  if (await userRepo.findByUsername(username)) {
    return res.status(409).json({ error: 'That username is already taken.' });
  }
  if (await userRepo.findByEmail(email)) {
    return res.status(409).json({ error: 'An account with that email already exists.' });
  }

  const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
  const user = await userRepo.createUser({ username, email, passwordHash });

  const token = signToken({ sub: user.id });
  res.cookie(COOKIE_NAME, token, { ...baseCookieOptions(), maxAge: COOKIE_MAX_AGE_MS });
  return res.status(201).json({ user: userRepo.toPublic(user) });
}

async function login(req, res) {
  const { identifier, password } = req.body;
  const user = (await userRepo.findByUsername(identifier)) || (await userRepo.findByEmail(identifier));

  const hashToCompare = user ? user.password_hash : DUMMY_HASH;
  const passwordMatches = await bcrypt.compare(password, hashToCompare);

  if (!user || !passwordMatches) {
    return res.status(401).json({ error: 'Invalid username/email or password.' });
  }

  await userRepo.touchLastSeen(user.id);
  const token = signToken({ sub: user.id });
  res.cookie(COOKIE_NAME, token, { ...baseCookieOptions(), maxAge: COOKIE_MAX_AGE_MS });
  return res.json({ user: userRepo.toPublic(user) });
}

function logout(_req, res) {
  res.clearCookie(COOKIE_NAME, baseCookieOptions());
  return res.status(204).send();
}

function me(req, res) {
  return res.json({ user: userRepo.toPublic(req.user) });
}

module.exports = { register, login, logout, me };
