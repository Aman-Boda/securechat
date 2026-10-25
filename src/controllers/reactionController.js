const messageRepo = require('../db/repositories/messageRepo');
const reactionRepo = require('../db/repositories/reactionRepo');
const { validateEncryptedPayload } = require('./messageController');
const { validateGroupPayload } = require('../utils/groupPayload');

async function loadTarget(req, res) {
  const room = req.room;
  if (room.is_group && !room.encrypted) {
    res.status(400).json({ error: 'Reactions are only available in encrypted conversations.' });
    return null;
  }
  const message = await messageRepo.getMessageById(req.params.messageId);
  if (!message || message.roomId !== room.id) {
    res.status(404).json({ error: 'Message not found.' });
    return null;
  }
  if (message.deletedAt) {
    res.status(400).json({ error: 'Cannot react to a deleted message.' });
    return null;
  }
  return message;
}

// Set (or replace) my reaction. The body is an encrypted payload in exactly the
// same shape as a message body: the emoji itself is never visible to the server.
async function put(req, res) {
  const message = await loadTarget(req, res);
  if (!message) return;
  const parsed = req.room.is_group
    ? await validateGroupPayload(req.room, req.body, req.user.id)
    : validateEncryptedPayload(req.body);
  if (parsed.error) return res.status(400).json({ error: parsed.error });

  const reaction = await reactionRepo.upsertReaction({
    messageId: message.id,
    userId: req.user.id,
    roomId: req.room.id,
    ...parsed,
  });
  req.app.get('io').to(`room:${req.room.id}`).emit('reaction:updated', {
    roomId: req.room.id,
    messageId: message.id,
    userId: req.user.id,
    reaction,
  });
  return res.json({ reaction });
}

async function del(req, res) {
  const message = await loadTarget(req, res);
  if (!message) return;
  await reactionRepo.deleteReaction(message.id, req.user.id);
  req.app.get('io').to(`room:${req.room.id}`).emit('reaction:updated', {
    roomId: req.room.id,
    messageId: message.id,
    userId: req.user.id,
    reaction: null,
  });
  return res.status(204).send();
}

module.exports = { put, del };
