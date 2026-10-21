const crypto = require('node:crypto');
const { pool } = require('../index');

// Thrown for rule violations that should reach the client as a clean 4xx.
class KeyUploadError extends Error {
  constructor(status, message, extra = {}) {
    super(message);
    this.status = status;
    this.extra = extra;
  }
}

function fingerprintOf(jwk) {
  return `${jwk.x}.${jwk.y}`;
}

function parseJwk(text) {
  try {
    return text ? JSON.parse(text) : null;
  } catch {
    return null;
  }
}

async function getMemberRole(roomId, userId) {
  const r = await pool.query('SELECT role FROM room_memberships WHERE room_id = $1 AND user_id = $2', [roomId, userId]);
  return r.rows[0] ? r.rows[0].role : null;
}

async function listEncryptedRoomIds(userId) {
  const r = await pool.query(
    `SELECT r.id FROM rooms r JOIN room_memberships m ON m.room_id = r.id
     WHERE m.user_id = $1 AND r.encrypted = true`,
    [userId]
  );
  return r.rows.map((row) => row.id);
}

async function countMembers(roomId) {
  const r = await pool.query('SELECT COUNT(*)::int AS count FROM room_memberships WHERE room_id = $1', [roomId]);
  return r.rows[0].count;
}

async function hasKey(roomId, userId, generation) {
  const r = await pool.query('SELECT 1 FROM group_keys WHERE room_id = $1 AND user_id = $2 AND generation = $3', [
    roomId,
    userId,
    generation,
  ]);
  return r.rowCount > 0;
}

// A member's own wrapped copies of the group key, one per generation they hold.
async function getKeysForUser(roomId, userId) {
  const r = await pool.query(
    `SELECT generation, wrapped_key, iv, wrapper_public_key
     FROM group_keys WHERE room_id = $1 AND user_id = $2 ORDER BY generation ASC`,
    [roomId, userId]
  );
  return r.rows.map((row) => ({
    generation: row.generation,
    wrappedKey: row.wrapped_key,
    iv: row.iv,
    wrapperPublicKey: parseJwk(row.wrapper_public_key),
  }));
}

// Everything a keyholder needs to decide what to wrap for whom: who is in the
// group, each member's current identity PUBLIC key, and which generations they
// already hold a wrap for (and for which identity key). Public data only.
async function getKeyStatus(roomId) {
  const room = (
    await pool.query('SELECT key_generation, needs_rotation, history_policy, join_policy FROM rooms WHERE id = $1', [roomId])
  ).rows[0];
  const members = await pool.query(
    `SELECT u.id AS user_id, u.public_key
     FROM room_memberships m JOIN users u ON u.id = m.user_id
     WHERE m.room_id = $1 ORDER BY m.joined_at ASC`,
    [roomId]
  );
  const keys = await pool.query('SELECT user_id, generation, wrapped_for_fp FROM group_keys WHERE room_id = $1', [roomId]);
  const byUser = new Map();
  keys.rows.forEach((k) => {
    if (!byUser.has(k.user_id)) byUser.set(k.user_id, []);
    byUser.get(k.user_id).push({ generation: k.generation, wrappedForFp: k.wrapped_for_fp });
  });
  return {
    keyGeneration: room.key_generation,
    needsRotation: room.needs_rotation,
    historyPolicy: room.history_policy,
    joinPolicy: room.join_policy,
    members: members.rows.map((m) => ({
      userId: m.user_id,
      publicKey: parseJwk(m.public_key),
      generations: byUser.get(m.user_id) || [],
    })),
  };
}

async function loadMemberFingerprints(client, roomId) {
  const rows = await client.query(
    `SELECT m.user_id, u.public_key FROM room_memberships m JOIN users u ON u.id = m.user_id WHERE m.room_id = $1`,
    [roomId]
  );
  return new Map(
    rows.rows.map((m) => {
      const jwk = parseJwk(m.public_key);
      return [m.user_id, jwk ? fingerprintOf(jwk) : null];
    })
  );
}

const INSERT_WRAP = `INSERT INTO group_keys (room_id, generation, user_id, wrapped_key, iv, wrapper_public_key, wrapped_for_fp, wrapped_by)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`;

function wrapParams(roomId, generation, w, byId) {
  return [roomId, generation, w.userId, w.wrappedKey, w.iv, JSON.stringify(w.wrapperPublicKey), w.wrappedForFp, byId];
}

async function createEncryptedGroup({ roomId, name, createdById, joinPolicy, historyPolicy, wrap }) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(
      `INSERT INTO rooms (id, name, is_group, created_by, encrypted, join_policy, history_policy, key_generation)
       VALUES ($1, $2, true, $3, true, $4, $5, 1)`,
      [roomId, name, createdById, joinPolicy, historyPolicy]
    );
    await client.query('INSERT INTO room_memberships (id, user_id, room_id, role) VALUES ($1, $2, $3, $4)', [
      crypto.randomUUID(),
      createdById,
      roomId,
      'admin',
    ]);
    await client.query(INSERT_WRAP, wrapParams(roomId, 1, { ...wrap, userId: createdById }, createdById));
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    if (err.code === '23505') throw new KeyUploadError(409, 'A room with that id already exists.');
    throw err;
  } finally {
    client.release();
  }
}

// Creates generation (expected + 1). Atomic: the room row is locked, and the
// caller must name the generation they saw, so two members rotating at once
// can never both win. The new key must reach every member who holds the
// current key (a rotation can add people, never silently drop one).
async function rotate(roomId, { callerId, expectedGeneration, wraps }) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const room = (await client.query('SELECT * FROM rooms WHERE id = $1 FOR UPDATE', [roomId])).rows[0];
    if (!room || !room.encrypted) throw new KeyUploadError(400, 'This room is not an encrypted group.');
    if (room.key_generation !== expectedGeneration) {
      throw new KeyUploadError(409, 'The group key changed while you were working. Try again.', {
        keyGeneration: room.key_generation,
      });
    }
    const callerHolds = await client.query(
      'SELECT 1 FROM group_keys WHERE room_id = $1 AND user_id = $2 AND generation = $3',
      [roomId, callerId, room.key_generation]
    );
    if (!callerHolds.rowCount) {
      throw new KeyUploadError(403, 'Only a member who holds the current group key can rotate it.');
    }
    const fps = await loadMemberFingerprints(client, roomId);
    const holders = await client.query('SELECT user_id FROM group_keys WHERE room_id = $1 AND generation = $2', [
      roomId,
      room.key_generation,
    ]);
    const recipients = new Set();
    for (const w of wraps) {
      if (!fps.has(w.userId)) throw new KeyUploadError(400, 'Keys can only be wrapped for current members.');
      if (recipients.has(w.userId)) throw new KeyUploadError(400, 'Duplicate recipient in key upload.');
      if (fps.get(w.userId) !== w.wrappedForFp) {
        throw new KeyUploadError(400, 'A key was wrapped for an out-of-date identity key.');
      }
      recipients.add(w.userId);
    }
    if (!recipients.has(callerId)) throw new KeyUploadError(400, 'The rotation must include you.');
    for (const h of holders.rows) {
      if (fps.has(h.user_id) && !recipients.has(h.user_id)) {
        throw new KeyUploadError(400, 'The new key must be shared with every member who holds the current key.');
      }
    }
    const next = room.key_generation + 1;
    for (const w of wraps) await client.query(INSERT_WRAP, wrapParams(roomId, next, w, callerId));
    await client.query('UPDATE rooms SET key_generation = $1, needs_rotation = false WHERE id = $2', [next, roomId]);
    await client.query('COMMIT');
    return { keyGeneration: next };
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

// Adds or refreshes wraps of EXISTING generations. A good wrap is never
// overwritten; a wrap made for an identity key the member no longer uses
// (stale) can be replaced. Brand-new recipients are only allowed in groups
// whose history policy is 'full' (otherwise the only way in is a rotation).
async function share(roomId, { callerId, wraps }) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const room = (await client.query('SELECT * FROM rooms WHERE id = $1 FOR UPDATE', [roomId])).rows[0];
    if (!room || !room.encrypted) throw new KeyUploadError(400, 'This room is not an encrypted group.');
    const holds = await client.query(
      'SELECT 1 FROM group_keys WHERE room_id = $1 AND user_id = $2 AND generation = $3',
      [roomId, callerId, room.key_generation]
    );
    if (!holds.rowCount) throw new KeyUploadError(403, 'Only a member who holds the current group key can share keys.');
    const fps = await loadMemberFingerprints(client, roomId);
    const existing = await client.query('SELECT user_id, generation, wrapped_for_fp FROM group_keys WHERE room_id = $1', [roomId]);
    const have = new Map(existing.rows.map((r) => [`${r.user_id}:${r.generation}`, r.wrapped_for_fp]));
    const seen = new Set();
    let stored = 0;
    for (const w of wraps) {
      const id = `${w.userId}:${w.generation}`;
      if (seen.has(id)) throw new KeyUploadError(400, 'Duplicate wrap in key upload.');
      seen.add(id);
      if (!fps.has(w.userId)) throw new KeyUploadError(400, 'Keys can only be wrapped for current members.');
      if (fps.get(w.userId) !== w.wrappedForFp) {
        throw new KeyUploadError(400, 'A key was wrapped for an out-of-date identity key.');
      }
      if (w.generation < 1 || w.generation > room.key_generation) {
        throw new KeyUploadError(400, 'Unknown group key generation.');
      }
      if (have.has(id)) {
        if (have.get(id) === w.wrappedForFp) continue; // already good: never overwrite
        await client.query(
          `UPDATE group_keys
           SET wrapped_key = $1, iv = $2, wrapper_public_key = $3, wrapped_for_fp = $4, wrapped_by = $5, created_at = now()
           WHERE room_id = $6 AND generation = $7 AND user_id = $8`,
          [w.wrappedKey, w.iv, JSON.stringify(w.wrapperPublicKey), w.wrappedForFp, callerId, roomId, w.generation, w.userId]
        );
      } else {
        if (room.history_policy !== 'full') {
          throw new KeyUploadError(403, 'This group only gives new members keys from the moment they join.');
        }
        await client.query(INSERT_WRAP, wrapParams(roomId, w.generation, w, callerId));
      }
      stored += 1;
    }
    await client.query('COMMIT');
    return { keyGeneration: room.key_generation, stored };
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

async function deleteKeysForUser(roomId, userId) {
  await pool.query('DELETE FROM group_keys WHERE room_id = $1 AND user_id = $2', [roomId, userId]);
}

async function markNeedsRotation(roomId) {
  await pool.query('UPDATE rooms SET needs_rotation = true WHERE id = $1 AND encrypted = true', [roomId]);
}

async function promoteOldestMember(roomId) {
  await pool.query(
    `UPDATE room_memberships SET role = 'admin'
     WHERE id = (SELECT id FROM room_memberships WHERE room_id = $1 ORDER BY joined_at ASC LIMIT 1)`,
    [roomId]
  );
}

async function updateSettings(roomId, { joinPolicy, historyPolicy }) {
  if (joinPolicy !== undefined) await pool.query('UPDATE rooms SET join_policy = $1 WHERE id = $2', [joinPolicy, roomId]);
  if (historyPolicy !== undefined) {
    await pool.query('UPDATE rooms SET history_policy = $1 WHERE id = $2', [historyPolicy, roomId]);
  }
}

module.exports = {
  KeyUploadError,
  fingerprintOf,
  getMemberRole,
  listEncryptedRoomIds,
  countMembers,
  hasKey,
  getKeysForUser,
  getKeyStatus,
  createEncryptedGroup,
  rotate,
  share,
  deleteKeysForUser,
  markNeedsRotation,
  promoteOldestMember,
  updateSettings,
};
