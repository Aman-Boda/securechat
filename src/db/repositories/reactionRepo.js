const { pool } = require('../index');

// A reaction is stored exactly like a message body: the emoji is ENCRYPTED
// client-side (DM epoch keys or the group key), so the server only knows that
// someone reacted to a message, never with what.
function toReactionDto(row) {
  return {
    messageId: row.message_id,
    userId: row.user_id,
    username: row.username,
    content: row.content,
    iv: row.iv,
    epochIndex: row.epoch_index === null ? null : Number(row.epoch_index),
    senderEpochPublicKey: row.sender_epoch_public_key ? JSON.parse(row.sender_epoch_public_key) : null,
    keyMode: row.key_mode,
    createdAt: row.created_at,
  };
}

const SELECT_REACTION = `
  SELECT r.message_id, r.user_id, r.content, r.iv, r.epoch_index, r.sender_epoch_public_key,
         r.key_mode, r.created_at, u.username
  FROM reactions r JOIN users u ON u.id = r.user_id
`;

// One reaction per person per message: reacting again replaces the old one.
async function upsertReaction({ messageId, userId, roomId, content, iv, epochIndex = null, senderEpochPublicKey = null, keyMode }) {
  await pool.query(
    `INSERT INTO reactions (message_id, user_id, room_id, content, iv, epoch_index, sender_epoch_public_key, key_mode)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
     ON CONFLICT (message_id, user_id) DO UPDATE
       SET content = EXCLUDED.content, iv = EXCLUDED.iv, epoch_index = EXCLUDED.epoch_index,
           sender_epoch_public_key = EXCLUDED.sender_epoch_public_key, key_mode = EXCLUDED.key_mode, created_at = now()`,
    [messageId, userId, roomId, content, iv, epochIndex, senderEpochPublicKey ? JSON.stringify(senderEpochPublicKey) : null, keyMode]
  );
  const result = await pool.query(`${SELECT_REACTION} WHERE r.message_id = $1 AND r.user_id = $2`, [messageId, userId]);
  return toReactionDto(result.rows[0]);
}

async function deleteReaction(messageId, userId) {
  const result = await pool.query('DELETE FROM reactions WHERE message_id = $1 AND user_id = $2', [messageId, userId]);
  return result.rowCount > 0;
}

// message id -> [reaction, ...] for a batch of messages.
async function listForMessages(messageIds) {
  const byMessage = new Map();
  if (messageIds.length === 0) return byMessage;
  const result = await pool.query(`${SELECT_REACTION} WHERE r.message_id = ANY($1) ORDER BY r.created_at ASC`, [messageIds]);
  for (const row of result.rows) {
    if (!byMessage.has(row.message_id)) byMessage.set(row.message_id, []);
    byMessage.get(row.message_id).push(toReactionDto(row));
  }
  return byMessage;
}

module.exports = { upsertReaction, deleteReaction, listForMessages };
