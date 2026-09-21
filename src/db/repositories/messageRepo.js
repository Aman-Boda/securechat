const crypto = require('node:crypto');
const { pool } = require('../index');

function toDto(row) {
  return {
    id: row.id,
    content: row.content,
    iv: row.iv,
    // Forward-secrecy fields — only meaningful for encrypted DM messages.
    epochIndex: row.epoch_index === null ? null : Number(row.epoch_index),
    senderEpochPublicKey: row.sender_epoch_public_key ? JSON.parse(row.sender_epoch_public_key) : null,
    keyMode: row.key_mode,
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
  SELECT m.id, m.content, m.iv, m.epoch_index, m.sender_epoch_public_key, m.key_mode,
         m.created_at, m.edited_at, m.deleted_at, m.room_id, m.sender_id,
         u.username AS sender_username, u.avatar_color AS sender_avatar_color
  FROM messages m
  JOIN users u ON u.id = m.sender_id
`;

async function createMessage({
  content,
  senderId,
  roomId,
  iv = null,
  epochIndex = null,
  senderEpochPublicKey = null,
  keyMode = null,
}) {
  const id = crypto.randomUUID();
  await pool.query(
    `INSERT INTO messages (id, content, iv, epoch_index, sender_epoch_public_key, key_mode, sender_id, room_id)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
    [
      id,
      content,
      iv,
      epochIndex,
      senderEpochPublicKey ? JSON.stringify(senderEpochPublicKey) : null,
      keyMode,
      senderId,
      roomId,
    ]
  );
  const result = await pool.query(`${SELECT_WITH_SENDER} WHERE m.id = $1`, [id]);
  return toDto(result.rows[0]);
}

async function getMessageById(id) {
  const result = await pool.query(`${SELECT_WITH_SENDER} WHERE m.id = $1`, [id]);
  return result.rows[0] ? toDto(result.rows[0]) : null;
}

// Content/iv are replaced (re-encrypted client-side for DMs before this is
// called) and edited_at is stamped. Caller is responsible for confirming
// the requester actually owns this message first. Editing keeps the
// original message's epoch/key-mode/sender-epoch-key — an edit is
// encrypted fresh, but under the same forward-secrecy terms as the
// original send (new iv, new ciphertext, same epoch bookkeeping the caller
// already worked out when it re-encrypted).
async function updateMessage(id, { content, iv = null, epochIndex = null, senderEpochPublicKey = null, keyMode = null }) {
  await pool.query(
    `UPDATE messages
     SET content = $1, iv = $2, epoch_index = $3, sender_epoch_public_key = $4, key_mode = $5, edited_at = now()
     WHERE id = $6`,
    [content, iv, epochIndex, senderEpochPublicKey ? JSON.stringify(senderEpochPublicKey) : null, keyMode, id]
  );
  return getMessageById(id);
}

// A real (not just hidden) delete of the content — the row stays as a
// tombstone so the conversation shows "message deleted", but the actual
// text/ciphertext is gone from the database, not just flagged.
async function softDeleteMessage(id) {
  await pool.query(
    `UPDATE messages
     SET content = '', iv = NULL, sender_epoch_public_key = NULL, key_mode = NULL, deleted_at = now()
     WHERE id = $1`,
    [id]
  );
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
