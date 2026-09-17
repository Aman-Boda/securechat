const crypto = require('node:crypto');
const { pool } = require('../index');
const messageRepo = require('./messageRepo');

async function getRoomById(id) {
  const result = await pool.query('SELECT * FROM rooms WHERE id = $1', [id]);
  return result.rows[0] || null;
}

async function isMember(userId, roomId) {
  const result = await pool.query(
    'SELECT 1 FROM room_memberships WHERE user_id = $1 AND room_id = $2 LIMIT 1',
    [userId, roomId]
  );
  return result.rowCount > 0;
}

async function getMembers(roomId) {
  const result = await pool.query(
    `SELECT u.id, u.username, u.avatar_color, u.last_seen_at, m.role, m.joined_at
     FROM room_memberships m
     JOIN users u ON u.id = m.user_id
     WHERE m.room_id = $1
     ORDER BY m.joined_at ASC`,
    [roomId]
  );
  return result.rows.map((m) => ({
    id: m.id,
    username: m.username,
    avatarColor: m.avatar_color,
    lastSeenAt: m.last_seen_at,
    role: m.role,
    joinedAt: m.joined_at,
  }));
}

async function addMember(roomId, userId, role = 'member') {
  await pool.query(
    'INSERT INTO room_memberships (id, user_id, room_id, role) VALUES ($1, $2, $3, $4)',
    [crypto.randomUUID(), userId, roomId, role]
  );
}

async function removeMember(roomId, userId) {
  await pool.query('DELETE FROM room_memberships WHERE room_id = $1 AND user_id = $2', [roomId, userId]);
}

async function markRoomRead(userId, roomId) {
  await pool.query('UPDATE room_memberships SET last_read_at = now() WHERE user_id = $1 AND room_id = $2', [
    userId,
    roomId,
  ]);
}

async function createGroupRoom({ name, createdById }) {
  const roomId = crypto.randomUUID();
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('INSERT INTO rooms (id, name, is_group, created_by) VALUES ($1, $2, true, $3)', [
      roomId,
      name,
      createdById,
    ]);
    await client.query('INSERT INTO room_memberships (id, user_id, room_id, role) VALUES ($1, $2, $3, $4)', [
      crypto.randomUUID(),
      createdById,
      roomId,
      'admin',
    ]);
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
  return getRoomById(roomId);
}

async function findOrCreateDirectRoom(userIdA, userIdB) {
  const existing = await pool.query(
    `SELECT r.id FROM rooms r
     JOIN room_memberships m1 ON m1.room_id = r.id AND m1.user_id = $1
     JOIN room_memberships m2 ON m2.room_id = r.id AND m2.user_id = $2
     WHERE r.is_group = false
     LIMIT 1`,
    [userIdA, userIdB]
  );
  if (existing.rows[0]) return getRoomById(existing.rows[0].id);

  const roomId = crypto.randomUUID();
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('INSERT INTO rooms (id, name, is_group, created_by) VALUES ($1, NULL, false, $2)', [
      roomId,
      userIdA,
    ]);
    await client.query('INSERT INTO room_memberships (id, user_id, room_id, role) VALUES ($1, $2, $3, $4)', [
      crypto.randomUUID(),
      userIdA,
      roomId,
      'member',
    ]);
    await client.query('INSERT INTO room_memberships (id, user_id, room_id, role) VALUES ($1, $2, $3, $4)', [
      crypto.randomUUID(),
      userIdB,
      roomId,
      'member',
    ]);
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
  return getRoomById(roomId);
}

async function getRoomSummaryForUser(roomId, userId) {
  const room = await getRoomById(roomId);
  if (!room) return null;

  const [lastMessageResult, memberCountResult, membershipResult] = await Promise.all([
    pool.query(
      `SELECT m.content, m.iv, m.created_at, m.sender_id, m.deleted_at, u.username AS sender_username
       FROM messages m
       JOIN users u ON u.id = m.sender_id
       WHERE m.room_id = $1
       ORDER BY m.created_at DESC
       LIMIT 1`,
      [roomId]
    ),
    pool.query('SELECT COUNT(*)::int AS count FROM room_memberships WHERE room_id = $1', [roomId]),
    pool.query('SELECT last_read_at FROM room_memberships WHERE user_id = $1 AND room_id = $2', [userId, roomId]),
  ]);

  const lastMessage = lastMessageResult.rows[0] || null;
  const memberCount = memberCountResult.rows[0].count;
  const lastReadAt = membershipResult.rows[0]?.last_read_at || null;
  const unreadCount = lastReadAt ? await messageRepo.countUnread(roomId, lastReadAt, userId) : 0;

  let displayName = room.name;
  let otherMember = null;

  if (!room.is_group) {
    const otherResult = await pool.query(
      `SELECT u.id, u.username, u.avatar_color, u.last_seen_at, u.public_key
       FROM room_memberships m
       JOIN users u ON u.id = m.user_id
       WHERE m.room_id = $1 AND m.user_id != $2
       LIMIT 1`,
      [roomId, userId]
    );
    const other = otherResult.rows[0];
    if (other) {
      otherMember = {
        id: other.id,
        username: other.username,
        avatarColor: other.avatar_color,
        lastSeenAt: other.last_seen_at,
        publicKey: other.public_key ? JSON.parse(other.public_key) : null,
      };
      displayName = other.username;
    } else {
      displayName = 'Direct message';
    }
  }

  return {
    id: room.id,
    name: displayName,
    isGroup: !!room.is_group,
    createdAt: room.created_at,
    memberCount,
    unreadCount,
    otherMember,
    lastMessage: lastMessage
      ? {
          content: lastMessage.content,
          iv: lastMessage.iv,
          createdAt: lastMessage.created_at,
          senderId: lastMessage.sender_id,
          senderUsername: lastMessage.sender_username,
          deletedAt: lastMessage.deleted_at,
        }
      : null,
  };
}

async function listRoomsForUser(userId) {
  const result = await pool.query(
    `SELECT r.id
     FROM rooms r
     JOIN room_memberships m ON m.room_id = r.id
     WHERE m.user_id = $1
     ORDER BY r.created_at DESC`,
    [userId]
  );
  return Promise.all(result.rows.map((row) => getRoomSummaryForUser(row.id, userId)));
}

async function listJoinableGroupRooms(userId) {
  const result = await pool.query(
    `SELECT r.id, r.name, r.created_at,
       (SELECT COUNT(*)::int FROM room_memberships WHERE room_id = r.id) AS member_count
     FROM rooms r
     WHERE r.is_group = true
       AND r.id NOT IN (SELECT room_id FROM room_memberships WHERE user_id = $1)
     ORDER BY r.created_at DESC`,
    [userId]
  );
  return result.rows.map((r) => ({
    id: r.id,
    name: r.name,
    createdAt: r.created_at,
    memberCount: r.member_count,
  }));
}

module.exports = {
  getRoomById,
  isMember,
  getMembers,
  addMember,
  removeMember,
  markRoomRead,
  createGroupRoom,
  findOrCreateDirectRoom,
  listRoomsForUser,
  getRoomSummaryForUser,
  listJoinableGroupRooms,
};
