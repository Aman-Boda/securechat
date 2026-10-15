const roomRepo = require('../db/repositories/roomRepo');
const { asyncHandler } = require('../utils/asyncHandler');

// Loads the room from :roomId, 404s if it doesn't exist. Does NOT check
// membership — used for endpoints like "join" where the user is, by
// definition, not a member yet.
const loadRoom = asyncHandler(async (req, res, next) => {
  const room = await roomRepo.getRoomById(req.params.roomId);
  if (!room) {
    return res.status(404).json({ error: 'Room not found.' });
  }
  req.room = room;
  next();
});

// Loads the room AND confirms the authenticated user is a member. This is
// what stops one user from reading another user's DMs or group history just
// by guessing/incrementing a room ID.
const requireRoomMembership = asyncHandler(async (req, res, next) => {
  const room = await roomRepo.getRoomById(req.params.roomId);
  if (!room) {
    return res.status(404).json({ error: 'Room not found.' });
  }
  const member = await roomRepo.isMember(req.user.id, room.id);
  if (!member) {
    return res.status(403).json({ error: 'You are not a member of this room.' });
  }
  req.room = room;
  next();
});

module.exports = { loadRoom, requireRoomMembership };
