const roomRepo = require('../db/repositories/roomRepo');
const userRepo = require('../db/repositories/userRepo');
const { subscribeUserToRoom } = require('../sockets');
const groupController = require('./groupController');
const groupKeyRepo = require('../db/repositories/groupKeyRepo');

const UUID_RE = /^[0-9a-fA-F-]{36}$/;

async function listMine(req, res) {
  return res.json({ rooms: await roomRepo.listRoomsForUser(req.user.id) });
}

async function listJoinable(req, res) {
  return res.json({ rooms: await roomRepo.listJoinableGroupRooms(req.user.id) });
}

// Every new group is end-to-end encrypted. The creator's browser makes the
// first group key and sends it wrapped to their own identity key; the server
// stores only that wrapped copy. The room id is chosen by the client because
// the wrap is cryptographically bound to it.
async function createGroup(req, res) {
  const { name } = req.body;
  const joinPolicy = req.body.joinPolicy === undefined ? 'open' : req.body.joinPolicy;
  const historyPolicy = req.body.historyPolicy === undefined ? 'after_join' : req.body.historyPolicy;
  if (!groupController.JOIN_POLICIES.includes(joinPolicy)) {
    return res.status(400).json({ error: "joinPolicy must be 'open' or 'invite'." });
  }
  if (!groupController.HISTORY_POLICIES.includes(historyPolicy)) {
    return res.status(400).json({ error: "historyPolicy must be 'after_join' or 'full'." });
  }
  const roomId = req.body.id;
  const wrap = groupController.parseWrap({ ...(req.body.key || {}), userId: req.user.id }, { withGeneration: false });
  if (typeof roomId !== 'string' || !UUID_RE.test(roomId) || !wrap) {
    return res
      .status(400)
      .json({ error: 'New groups are end-to-end encrypted. Reload the page to update the app, then try again.' });
  }
  const me = await userRepo.findById(req.user.id);
  const myKey = me.public_key ? JSON.parse(me.public_key) : null;
  if (!myKey || groupKeyRepo.fingerprintOf(myKey) !== wrap.wrappedForFp) {
    return res.status(400).json({ error: 'Your encryption key is not ready yet. Try again in a moment.' });
  }
  try {
    await groupKeyRepo.createEncryptedGroup({ roomId, name, createdById: req.user.id, joinPolicy, historyPolicy, wrap });
  } catch (err) {
    if (err instanceof groupKeyRepo.KeyUploadError) return res.status(err.status).json({ error: err.message });
    throw err;
  }
  subscribeUserToRoom(req.app.get('io'), req.user.id, roomId);
  return res.status(201).json({ room: await roomRepo.getRoomSummaryForUser(roomId, req.user.id) });
}

async function startDirect(req, res) {
  const { userId } = req.body;

  if (userId === req.user.id) {
    return res.status(400).json({ error: "You can't start a conversation with yourself." });
  }

  const otherUser = await userRepo.findById(userId);
  if (!otherUser) {
    return res.status(404).json({ error: 'User not found.' });
  }

  const room = await roomRepo.findOrCreateDirectRoom(req.user.id, userId);
  const io = req.app.get('io');

  // Both people need their live connections in this room's channel. The
  // requester's own browser also does this via a "room:subscribe" socket
  // event right after this response — but the OTHER user never took any
  // action, so without this line their already-open connection would sit
  // outside the channel and simply never receive messages here until they
  // refreshed the page.
  subscribeUserToRoom(io, req.user.id, room.id);
  subscribeUserToRoom(io, userId, room.id);

  // Push the new conversation to the other user's open tab(s) too, so it
  // shows up in their sidebar immediately instead of only after a reload.
  const roomForOtherUser = await roomRepo.getRoomSummaryForUser(room.id, userId);
  io.to(`user:${userId}`).emit('room:new', { room: roomForOtherUser });

  return res.status(201).json({
    room: { id: room.id, isGroup: false, createdAt: room.created_at, otherMember: userRepo.toPublic(otherUser) },
  });
}

async function join(req, res) {
  const { room } = req;
  if (!room.is_group) {
    return res.status(400).json({ error: 'Direct messages cannot be joined this way.' });
  }
  if (await roomRepo.isMember(req.user.id, room.id)) {
    return res.status(409).json({ error: 'You are already a member of this room.' });
  }
  if (room.join_policy === 'invite') {
    return res.status(403).json({ error: 'This group is invite-only. Ask its admin to add you.' });
  }
  if ((await groupKeyRepo.countMembers(room.id)) >= groupController.MAX_GROUP_MEMBERS) {
    return res.status(400).json({ error: 'This group is full.' });
  }
  await roomRepo.addMember(room.id, req.user.id);
  const io = req.app.get('io');
  subscribeUserToRoom(io, req.user.id, room.id);
  // In an encrypted group the newcomer cannot read anything until a member who
  // holds the key hands it over: tell the room's members to do that.
  if (room.encrypted) io.to(`room:${room.id}`).emit('group:keys-needed', { roomId: room.id });
  return res.json({ room: await roomRepo.getRoomSummaryForUser(room.id, req.user.id) });
}

// Note: this route is guarded by requireRoomMembership, so req.room is
// already confirmed to exist and req.user is already confirmed to be a member.
async function leave(req, res) {
  const { room } = req;
  const role = room.is_group ? await groupKeyRepo.getMemberRole(room.id, req.user.id) : null;
  await roomRepo.removeMember(room.id, req.user.id);
  if (room.is_group) {
    if (role === 'admin') await groupKeyRepo.promoteOldestMember(room.id);
    // Stops their live connections receiving the room's events, deletes their
    // key copies and (encrypted groups) schedules a key rotation.
    await groupController.afterDeparture(req, room, req.user.id, { removed: false });
  }
  return res.status(204).send();
}

async function getMembers(req, res) {
  return res.json({ members: await roomRepo.getMembers(req.room.id) });
}

// Guarded by requireRoomMembership.
async function markRead(req, res) {
  await roomRepo.markRoomRead(req.user.id, req.room.id);
  return res.status(204).send();
}

module.exports = { listMine, listJoinable, createGroup, startDirect, join, leave, getMembers, markRead };
