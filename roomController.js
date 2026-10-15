const roomRepo = require('../db/repositories/roomRepo');
const userRepo = require('../db/repositories/userRepo');
const { subscribeUserToRoom } = require('../sockets');

async function listMine(req, res) {
  return res.json({ rooms: await roomRepo.listRoomsForUser(req.user.id) });
}

async function listJoinable(req, res) {
  return res.json({ rooms: await roomRepo.listJoinableGroupRooms(req.user.id) });
}

async function createGroup(req, res) {
  const { name } = req.body;
  const room = await roomRepo.createGroupRoom({ name, createdById: req.user.id });
  subscribeUserToRoom(req.app.get('io'), req.user.id, room.id);
  return res.status(201).json({
    room: { id: room.id, name: room.name, isGroup: true, createdAt: room.created_at },
  });
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
  await roomRepo.addMember(room.id, req.user.id);
  subscribeUserToRoom(req.app.get('io'), req.user.id, room.id);
  return res.status(204).send();
}

// Note: this route is guarded by requireRoomMembership, so req.room is
// already confirmed to exist and req.user is already confirmed to be a member.
async function leave(req, res) {
  await roomRepo.removeMember(req.room.id, req.user.id);
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
