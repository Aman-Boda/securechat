const { pool } = require('../index');

// Upsert: creating a new backup replaces any previous one for this user.
async function setBackup(userId, { ciphertext, salt, iv }) {
  await pool.query(
    `INSERT INTO key_backups (user_id, ciphertext, salt, iv, updated_at)
     VALUES ($1, $2, $3, $4, now())
     ON CONFLICT (user_id) DO UPDATE
       SET ciphertext = EXCLUDED.ciphertext, salt = EXCLUDED.salt, iv = EXCLUDED.iv, updated_at = now()`,
    [userId, ciphertext, salt, iv]
  );
}

// Returns null if the user has never created a backup: not an error.
async function getBackup(userId) {
  const result = await pool.query('SELECT ciphertext, salt, iv, updated_at FROM key_backups WHERE user_id = $1', [
    userId,
  ]);
  return result.rows[0] || null;
}

module.exports = { setBackup, getBackup };
