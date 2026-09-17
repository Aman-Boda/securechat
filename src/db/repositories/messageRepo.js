const crypto = require('node:crypto');
const { pool } = require('../index');

function toDto(row) {
  return {
    id: row.id,
    content: row.content,
    iv: row.iv,
    createdAt: row.created_at,
    editedAt: row.edited_at,
    deletedAt: row.deleted_at,
    roomId: row.room_id,
    senderId: row.sender_id,
    senderUsername: row.sender_username,
    senderAvatarColor: row.sender_avatar_color,
  };
}

const SELECT_WITH_SENDER = `
  SELECT m.id, m.content, m.iv, m.created_at, m.edited_at, m.deleted_at, m.room_id, m.sender_id,
         u.username AS sender_username, u.avatar_color AS sender_avatar_color
  FROM messages m
  JOIN users u ON u.id = m.sender_id
`;

async function createMessage({ content, senderId, roomId, iv = null }) {
  const id = crypto.randomUUID();
  await pool.query('INSERT INTO messages (id, content, iv, sender_id, room_id) VALUES ($1, $2, $3, $4, $5)', [
    id,
    content,
    iv,
    senderId,
    roomId,
  ]);
  const result = await pool.query(`${SELECT_WITH_SENDER} WHERE m.id = $1`, [id]);
  return toDto(result.rows[0]);
}

async function getMessageById(id) {
  const result = await pool.query(`${SELECT_WITH_SENDER} WHERE m.id = $1`, [id]);
  return result.rows[0] ? toDto(result.rows[0]) : null;
}

// Content/iv are replaced (re-encrypted client-side for DMs before this is
// called) and edited_at is stamped. Caller is responsible for confirming
// the requester actually owns this message first.
async function updateMessage(id, { content, iv = null }) {
  await pool.query('UPDATE messages SET content = $1, iv = $2, edited_at = now() WHERE id = $3', [content, iv, id]);
  return getMessageById(id);
}

// A real (not just hidden) delete of the content — the row stays as a
// tombstone so the conversation shows "message deleted", but the actual
// text/ciphertext is gone from the database, not just flagged.
async function softDeleteMessage(id) {
  await pool.query("UPDATE messages SET content = '', iv = NULL, deleted_at = now() WHERE id = $1", [id]);
  return getMessageById(id);
}

// Cursor-based pagination: fetch messages older than `before` (a timestamp),
// newest first, then reverse for display order. Deleted messages are still
// included (as tombstones — content is already cleared) so the timeline
// doesn't have unexplained gaps.
async function listMessagesForRoom(roomId, { before = null, limit = 50 } = {}) {
  const result = await pool.query(
    `${SELECT_WITH_SENDER}
     WHERE m.room_id = $1
       AND ($2::timestamptz IS NULL OR m.created_at < $2::timestamptz)
     ORDER BY m.created_at DESC
     LIMIT $3`,
    [roomId, before, limit]
  );
  return result.rows.map(toDto).reverse();
}

// Messages in this room, after `since`, sent by anyone other than
// `excludeSenderId` (you don't count your own messages as unread) and not
// deleted. Used to compute unread badge counts.
async function countUnread(roomId, since, excludeSenderId) {
  const result = await pool.query(
    `SELECT COUNT(*)::int AS count
     FROM messages
     WHERE room_id = $1 AND created_at > $2 AND sender_id != $3 AND deleted_at IS NULL`,
    [roomId, since, excludeSenderId]
  );
  return result.rows[0].count;
}

module.exports = {
  createMessage,
  getMessageById,
  updateMessage,
  softDeleteMessage,
  listMessagesForRoom,
  countUnread,
};
