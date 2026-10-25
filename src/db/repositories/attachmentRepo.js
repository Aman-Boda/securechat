const { pool } = require('../index');

// Attachments are opaque: the bytes are AES-GCM ciphertext made in the sender's
// browser with a one-time key that only travels inside the encrypted message.
async function create({ id, roomId, uploaderId, data }) {
  await pool.query('INSERT INTO attachments (id, room_id, uploader_id, size, data) VALUES ($1, $2, $3, $4, $5)', [
    id,
    roomId,
    uploaderId,
    data.length,
    data,
  ]);
}

async function get(id) {
  const result = await pool.query('SELECT id, room_id, message_id, size, data FROM attachments WHERE id = $1', [id]);
  return result.rows[0] || null;
}

// Uploads that were never attached to a message.
async function countPending(userId) {
  const result = await pool.query(
    'SELECT COUNT(*)::int AS count FROM attachments WHERE uploader_id = $1 AND message_id IS NULL',
    [userId]
  );
  return result.rows[0].count;
}

async function deleteOrphans() {
  await pool.query(`DELETE FROM attachments WHERE message_id IS NULL AND created_at < now() - interval '1 day'`);
}

module.exports = { create, get, countPending, deleteOrphans };
