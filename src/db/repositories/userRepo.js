const crypto = require('node:crypto');
const { pool } = require('../index');

// A small curated palette (kept within the app's own color language) so
// avatars have variety without pulling in external images.
const AVATAR_PALETTE = ['#6FA88A', '#7C93C7', '#C99A5B', '#B07CC6', '#5FA8A0', '#C4738A'];

function colorForUsername(username) {
  let hash = 0;
  for (let i = 0; i < username.length; i += 1) {
    hash = (hash * 31 + username.charCodeAt(i)) >>> 0;
  }
  return AVATAR_PALETTE[hash % AVATAR_PALETTE.length];
}

async function createUser({ username, email, passwordHash }) {
  const id = crypto.randomUUID();
  const avatarColor = colorForUsername(username);
  const result = await pool.query(
    `INSERT INTO users (id, username, email, password_hash, avatar_color)
     VALUES ($1, $2, $3, $4, $5)
     RETURNING *`,
    [id, username, email, passwordHash, avatarColor]
  );
  return result.rows[0];
}

async function findByUsername(username) {
  const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
  return result.rows[0] || null;
}

async function findByEmail(email) {
  const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  return result.rows[0] || null;
}

async function findById(id) {
  const result = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
  return result.rows[0] || null;
}

async function touchLastSeen(id) {
  await pool.query('UPDATE users SET last_seen_at = now() WHERE id = $1', [id]);
}

async function setPublicKey(id, publicKeyJwk) {
  await pool.query('UPDATE users SET public_key = $1 WHERE id = $2', [JSON.stringify(publicKeyJwk), id]);
}

async function setVerificationToken(userId, tokenHash, expiresAt) {
  await pool.query(
    'UPDATE users SET verification_token_hash = $1, verification_token_expires = $2 WHERE id = $3',
    [tokenHash, expiresAt, userId]
  );
}

// Finds a user by a non-expired verification token hash, marks them
// verified, and clears the token so it can't be reused. Returns the user,
// or null if the token doesn't match any pending, unexpired verification.
async function verifyEmailByTokenHash(tokenHash) {
  const result = await pool.query(
    `UPDATE users
     SET email_verified = true, verification_token_hash = NULL, verification_token_expires = NULL
     WHERE verification_token_hash = $1 AND verification_token_expires > now()
     RETURNING *`,
    [tokenHash]
  );
  return result.rows[0] || null;
}

async function setResetToken(userId, tokenHash, expiresAt) {
  await pool.query('UPDATE users SET reset_token_hash = $1, reset_token_expires = $2 WHERE id = $3', [
    tokenHash,
    expiresAt,
    userId,
  ]);
}

// Finds a user by a non-expired reset token hash, sets their new password,
// clears the reset token, and bumps token_version — which is what
// invalidates any session issued before this reset. Returns the user, or
// null if the token doesn't match any pending, unexpired reset.
async function resetPasswordByTokenHash(tokenHash, newPasswordHash) {
  const result = await pool.query(
    `UPDATE users
     SET password_hash = $1,
         reset_token_hash = NULL,
         reset_token_expires = NULL,
         token_version = token_version + 1
     WHERE reset_token_hash = $2 AND reset_token_expires > now()
     RETURNING *`,
    [newPasswordHash, tokenHash]
  );
  return result.rows[0] || null;
}

function parsePublicKey(user) {
  if (!user || !user.public_key) return null;
  try {
    return JSON.parse(user.public_key);
  } catch {
    return null;
  }
}

// Escapes SQL LIKE wildcards (% and _) so a search for "50%" doesn't match everything.
function escapeLikePattern(raw) {
  return raw.replace(/[\\%_]/g, (match) => `\\${match}`);
}

async function searchUsers(query, excludeId, limit = 10) {
  const pattern = `%${escapeLikePattern(query)}%`;
  const result = await pool.query(
    `SELECT id, username, avatar_color, last_seen_at, public_key
     FROM users
     WHERE id != $1 AND username ILIKE $2 ESCAPE '\\'
     ORDER BY username ASC
     LIMIT $3`,
    [excludeId, pattern, limit]
  );
  return result.rows;
}

// Never send password_hash to the client.
function toPublic(user) {
  if (!user) return null;
  return {
    id: user.id,
    username: user.username,
    avatarColor: user.avatar_color,
    publicKey: parsePublicKey(user),
    emailVerified: user.email_verified,
    createdAt: user.created_at,
    lastSeenAt: user.last_seen_at,
  };
}

module.exports = {
  createUser,
  findByUsername,
  findByEmail,
  findById,
  touchLastSeen,
  setPublicKey,
  setVerificationToken,
  verifyEmailByTokenHash,
  setResetToken,
  resetPasswordByTokenHash,
  searchUsers,
  toPublic,
};
