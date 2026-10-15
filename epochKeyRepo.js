const { pool } = require('../index');

// Upsert: publishing the same epoch's key again (e.g. a page reload within
// the same hour) just overwrites the row rather than erroring.
async function setEpochKey(userId, epochIndex, publicKeyJwk) {
  await pool.query(
    `INSERT INTO epoch_keys (user_id, epoch_index, public_key)
     VALUES ($1, $2, $3)
     ON CONFLICT (user_id, epoch_index) DO UPDATE SET public_key = EXCLUDED.public_key`,
    [userId, epochIndex, JSON.stringify(publicKeyJwk)]
  );
}

// Returns the JWK object, or null if that user hasn't published a key for
// that epoch (e.g. they weren't active then) — callers fall back to the
// recipient's static identity key in that case.
async function getEpochKey(userId, epochIndex) {
  const result = await pool.query('SELECT public_key FROM epoch_keys WHERE user_id = $1 AND epoch_index = $2', [
    userId,
    epochIndex,
  ]);
  if (!result.rows[0]) return null;
  try {
    return JSON.parse(result.rows[0].public_key);
  } catch {
    return null;
  }
}

module.exports = { setEpochKey, getEpochKey };
