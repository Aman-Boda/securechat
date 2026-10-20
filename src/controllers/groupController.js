const roomRepo = require('../db/repositories/roomRepo');
const userRepo = require('../db/repositories/userRepo');
const groupKeyRepo = require('../db/repositories/groupKeyRepo');
const { subscribeUserToRoom } = require('../sockets');

const MAX_GROUP_MEMBERS = 100;
const MAX_WRAPS_PER_REQUEST = 200;
const JOIN_POLICIES = ['open', 'invite'];
const HISTORY_POLICIES = ['after_join', 'full'];

// A wrapped copy of a group key for one member. The server cannot open it: it
// is encrypted to that member's identity public key. We only check its shape.
function parseWrap(input, { withGeneration }) {
  if (!input || typeof input !== 'object') return null;
  const { userId, generation, wrappedKey, iv, wrapperPublicKey, wrappedForFp } = input;
  if (typeof userId !== 'string' || !userId) return null;
  if (withGeneration && !(Number.isInteger(generation) && generation >= 1)) return null;
  if (typeof wrappedKey !== 'string' || !wrappedKey || wrappedKey.length > 1024) return null;
  if (typeof iv !== 'string' || !iv || iv.length > 64) return null;
  if (!wrapperPublicKey || typeof wrapperPublicKey !== 'object' || Array.isArray(wrapperPublicKey)) return null;
  if (typeof wrappedForFp !== 'string' || !wrappedForFp || wrappedForFp.length > 300) return null;
  return { userId, generation, wrappedKey, iv, wrapperPublicKey, wrappedForFp };
}

function requireEncrypted(req, res) {
  if (!req.room.is_group || !req.room.encrypted) {
    res.status(400).json({ error: 'This room is not an encrypted group.' });
    return false;
  }
  return true;
}

async function requireAdmin(req, res) {
  if (!req.room.is_group) {
    res.status(400).json({ error: 'Only groups have admins.' });
    return false;
  }
  if ((await groupKeyRepo.getMemberRole(req.room.id, req.user.id)) !== 'admin') {
    res.status(403).json({ error: 'Only a group admin can do that.' });
    return false;
  }
  return true;
}

function sendKeyError(res, err) {
  if (err instanceof groupKeyRepo.KeyUploadError) {
    return res.status(err.status).json({ error: err.message, ...err.extra });
  }
  throw err;
}

// ---- keys ------------------------------------------------------------------

async function getMyKeys(req, res) {
  if (!requireEncrypted(req, res)) return;
  const room = await roomRepo.getRoomById(req.room.id);
  const keys = await groupKeyRepo.getKeysForUser(room.id, req.user.id);
  return res.json({ keyGeneration: room.key_generation, keys });
}

async function getKeyStatus(req, res) {
  if (!requireEncrypted(req, res)) return;
  return res.json(await groupKeyRepo.getKeyStatus(req.room.id));
}

async function putKeys(req, res) {
  if (!requireEncrypted(req, res)) return;
  const { mode } = req.body;
  const raw = Array.isArray(req.body.wraps) ? req.body.wraps : null;
  if (!raw || raw.length === 0 || raw.length > MAX_WRAPS_PER_REQUEST) {
    return res.status(400).json({ error: `wraps must be a list of 1 to ${MAX_WRAPS_PER_REQUEST} items.` });
  }
  const wraps = raw.map((w) => parseWrap(w, { withGeneration: mode === 'share' }));
  if (wraps.some((w) => !w)) return res.status(400).json({ error: 'Malformed key wrap.' });

  try {
    let result;
    if (mode === 'rotate') {
      if (!Number.isInteger(req.body.expectedGeneration)) {
        return res.status(400).json({ error: 'expectedGeneration is required.' });
      }
      result = await groupKeyRepo.rotate(req.room.id, {
        callerId: req.user.id,
        expectedGeneration: req.body.expectedGeneration,
        wraps,
      });
    } else if (mode === 'share') {
      result = await groupKeyRepo.share(req.room.id, { callerId: req.user.id, wraps });
    } else {
      return res.status(400).json({ error: "mode must be 'rotate' or 'share'." });
    }
    req.app.get('io').to(`room:${req.room.id}`).emit('group:keys-updated', {
      roomId: req.room.id,
      keyGeneration: result.keyGeneration,
    });
    return res.json(result);
  } catch (err) {
    return sendKeyError(res, err);
  }
}

// ---- membership ------------------------------------------------------------

// Shared by "leave" and "remove": cut the person's live connections out of the
// room channel, delete their key copies, and (for encrypted groups) flag that
// the key must be replaced so they cannot read anything sent from now on.
async function afterDeparture(req, room, userId, { removed }) {
  const io = req.app.get('io');
  io.in(`user:${userId}`).socketsLeave(`room:${room.id}`);
  await groupKeyRepo.deleteKeysForUser(room.id, userId);
  if (room.encrypted) {
    await groupKeyRepo.markNeedsRotation(room.id);
    io.to(`room:${room.id}`).emit('group:keys-needed', { roomId: room.id });
  }
  if (removed) io.to(`user:${userId}`).emit('room:removed', { roomId: room.id });
}

async function addMember(req, res) {
  if (!(await requireAdmin(req, res))) return;
  const userId = typeof req.body.userId === 'string' ? req.body.userId : '';
  const target = userId ? await userRepo.findById(userId) : null;
  if (!target) return res.status(404).json({ error: 'User not found.' });
  if (await roomRepo.isMember(userId, req.room.id)) {
    return res.status(409).json({ error: 'That person is already in this group.' });
  }
  if ((await groupKeyRepo.countMembers(req.room.id)) >= MAX_GROUP_MEMBERS) {
    return res.status(400).json({ error: `Groups are limited to ${MAX_GROUP_MEMBERS} members.` });
  }
  await roomRepo.addMember(req.room.id, userId);
  const io = req.app.get('io');
  subscribeUserToRoom(io, userId, req.room.id);
  const summary = await roomRepo.getRoomSummaryForUser(req.room.id, userId);
  io.to(`user:${userId}`).emit('room:new', { room: summary });
  if (req.room.encrypted) io.to(`room:${req.room.id}`).emit('group:keys-needed', { roomId: req.room.id });
  return res.status(201).json({ members: await roomRepo.getMembers(req.room.id) });
}

async function removeMember(req, res) {
  if (!(await requireAdmin(req, res))) return;
  const { userId } = req.params;
  if (userId === req.user.id) {
    return res.status(400).json({ error: 'Use "Leave group" to leave a group yourself.' });
  }
  if (!(await roomRepo.isMember(userId, req.room.id))) {
    return res.status(404).json({ error: 'That person is not in this group.' });
  }
  await roomRepo.removeMember(req.room.id, userId);
  await afterDeparture(req, req.room, userId, { removed: true });
  return res.status(204).send();
}

async function updateSettings(req, res) {
  if (!(await requireAdmin(req, res))) return;
  const { joinPolicy, historyPolicy } = req.body;
  if (joinPolicy === undefined && historyPolicy === undefined) {
    return res.status(400).json({ error: 'Nothing to change.' });
  }
  if (joinPolicy !== undefined && !JOIN_POLICIES.includes(joinPolicy)) {
    return res.status(400).json({ error: "joinPolicy must be 'open' or 'invite'." });
  }
  if (historyPolicy !== undefined && !HISTORY_POLICIES.includes(historyPolicy)) {
    return res.status(400).json({ error: "historyPolicy must be 'after_join' or 'full'." });
  }
  await groupKeyRepo.updateSettings(req.room.id, { joinPolicy, historyPolicy });
  const room = await roomRepo.getRoomById(req.room.id);
  const settings = { roomId: room.id, joinPolicy: room.join_policy, historyPolicy: room.history_policy };
  req.app.get('io').to(`room:${room.id}`).emit('group:settings-updated', settings);
  return res.json(settings);
}

module.exports = {
  MAX_GROUP_MEMBERS,
  JOIN_POLICIES,
  HISTORY_POLICIES,
  parseWrap,
  afterDeparture,
  getMyKeys,
  getKeyStatus,
  putKeys,
  addMember,
  removeMember,
  updateSettings,
};
