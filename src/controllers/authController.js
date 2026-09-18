const crypto = require('node:crypto');
const bcrypt = require('bcrypt');
const userRepo = require('../db/repositories/userRepo');
const { signToken, COOKIE_NAME } = require('../utils/jwt');
const { isProduction, clientOrigin } = require('../config/env');
const { sendVerificationEmail, sendPasswordResetEmail } = require('../utils/email');

const SALT_ROUNDS = 12;
const COOKIE_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000; // 7 days, matches JWT TTL
const VERIFICATION_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const RESET_TTL_MS = 60 * 60 * 1000; // 1 hour — shorter, since this is more sensitive

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

function issueSession(res, user) {
  const token = signToken({ sub: user.id, tokenVersion: user.token_version });
  res.cookie(COOKIE_NAME, token, { ...baseCookieOptions(), maxAge: COOKIE_MAX_AGE_MS });
}

// Raw tokens go out in emailed links; only their SHA-256 hash is stored, so
// a database read alone can never yield a usable token.
function generateToken() {
  const raw = crypto.randomBytes(32).toString('hex');
  const hash = crypto.createHash('sha256').update(raw).digest('hex');
  return { raw, hash };
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

  // Best-effort: registration succeeds even if the verification email
  // fails to send (e.g. email isn't configured yet) — verification is a
  // trust signal, not a gate on using the app.
  try {
    const { raw, hash } = generateToken();
    await userRepo.setVerificationToken(user.id, hash, new Date(Date.now() + VERIFICATION_TTL_MS));
    const verifyUrl = `${clientOrigin}/?verify=${raw}`;
    await sendVerificationEmail(user.email, verifyUrl);
  } catch (err) {
    console.error('Failed to send verification email:', err);
  }

  issueSession(res, user);
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
  issueSession(res, user);
  return res.json({ user: userRepo.toPublic(user) });
}

function logout(_req, res) {
  res.clearCookie(COOKIE_NAME, baseCookieOptions());
  return res.status(204).send();
}

function me(req, res) {
  return res.json({ user: userRepo.toPublic(req.user) });
}

async function verifyEmail(req, res) {
  const { token } = req.body;
  if (!token || typeof token !== 'string') {
    return res.status(400).json({ error: 'Verification token is required.' });
  }
  const hash = crypto.createHash('sha256').update(token).digest('hex');
  const user = await userRepo.verifyEmailByTokenHash(hash);
  if (!user) {
    return res.status(400).json({ error: 'This link is invalid or has expired.' });
  }
  return res.json({ user: userRepo.toPublic(user) });
}

// Authenticated — resends to whoever is currently logged in, not an
// arbitrary address, so this can't be used to spam other people's inboxes.
async function resendVerification(req, res) {
  if (req.user.email_verified) {
    return res.status(400).json({ error: 'Your email is already verified.' });
  }
  const { raw, hash } = generateToken();
  await userRepo.setVerificationToken(req.user.id, hash, new Date(Date.now() + VERIFICATION_TTL_MS));
  const verifyUrl = `${clientOrigin}/?verify=${raw}`;
  await sendVerificationEmail(req.user.email, verifyUrl);
  return res.status(204).send();
}

// Always responds the same way whether or not the email exists — this is
// what stops the endpoint from being usable to check who has an account.
async function forgotPassword(req, res) {
  const { email } = req.body;
  const genericResponse = () =>
    res.json({ message: 'If an account with that email exists, a reset link has been sent.' });

  if (!email || typeof email !== 'string') return genericResponse();

  const user = await userRepo.findByEmail(email);
  if (!user) return genericResponse();

  const { raw, hash } = generateToken();
  await userRepo.setResetToken(user.id, hash, new Date(Date.now() + RESET_TTL_MS));
  const resetUrl = `${clientOrigin}/?reset=${raw}`;
  await sendPasswordResetEmail(user.email, resetUrl);
  return genericResponse();
}

async function resetPassword(req, res) {
  const { token, newPassword } = req.body;
  if (!token || typeof token !== 'string') {
    return res.status(400).json({ error: 'Reset token is required.' });
  }
  if (!newPassword || newPassword.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  }

  const hash = crypto.createHash('sha256').update(token).digest('hex');
  const passwordHash = await bcrypt.hash(newPassword, SALT_ROUNDS);
  const user = await userRepo.resetPasswordByTokenHash(hash, passwordHash);
  if (!user) {
    return res.status(400).json({ error: 'This link is invalid or has expired.' });
  }

  // token_version was bumped by resetPasswordByTokenHash, so this issues a
  // session that is valid while every OLDER session (a possibly-compromised
  // one) stops working the next time it's used.
  issueSession(res, user);
  return res.json({ user: userRepo.toPublic(user) });
}

module.exports = { register, login, logout, me, verifyEmail, resendVerification, forgotPassword, resetPassword };
