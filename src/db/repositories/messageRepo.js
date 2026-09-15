const crypto = require('node:crypto');
const { pool } = require('../index');

function toDto(row) {
  return {
    id: row.id,
    content: row.content,
    iv: row.iv,
    createdAt: row.created_at,
    editedAt: row.edited_at,
    roomId: row.room_id,
    senderId: row.sender_id,
    senderUsername: row.sender_username,
    senderAvatarColor: row.sender_avatar_color,
  };
}

async function createMessage({ content, senderId, roomId, iv = null }) {
  const id = crypto.randomUUID();
  await pool.query('INSERT INTO messages (id, content, iv, sender_id, room_id) VALUES ($1, $2, $3, $4, $5)', [
    id,
    content,
    iv,
    senderId,
    roomId,
  ]);
  const result = await pool.query(
    `SELECT m.id, m.content, m.iv, m.created_at, m.edited_at, m.room_id, m.sender_id,
            u.username AS sender_username, u.avatar_color AS sender_avatar_color
     FROM messages m
     JOIN users u ON u.id = m.sender_id
     WHERE m.id = $1`,
    [id]
  );
  return toDto(result.rows[0]);
}

// Cursor-based pagination: fetch messages older than `before` (a timestamp),
// newest first, then reverse for display order.
async function listMessagesForRoom(roomId, { before = null, limit = 50 } = {}) {
  const result = await pool.query(
    `SELECT m.id, m.content, m.iv, m.created_at, m.edited_at, m.room_id, m.sender_id,
            u.username AS sender_username, u.avatar_color AS sender_avatar_color
     FROM messages m
     JOIN users u ON u.id = m.sender_id
     WHERE m.room_id = $1
       AND m.deleted_at IS NULL
       AND ($2::timestamptz IS NULL OR m.created_at < $2::timestamptz)
     ORDER BY m.created_at DESC
     LIMIT $3`,
    [roomId, before, limit]
  );
  return result.rows.map(toDto).reverse();
}

module.exports = {
  createMessage,
  listMessagesForRoom,
};
