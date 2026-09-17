const messageRepo = require('../db/repositories/messageRepo');
const { sanitizeMessageContent } = require('../utils/sanitize');

const MAX_CIPHERTEXT_LENGTH = 8000; // generous — encrypted content is ~33% larger than plaintext, plus overhead

// Guarded by requireRoomMembership — req.room is confirmed to exist and
// req.user is confirmed to be a member before this runs.
async function history(req, res) {
  const before = req.query.before || null;
  const limit = Math.min(parseInt(req.query.limit, 10) || 50, 100);
  const messages = await messageRepo.listMessagesForRoom(req.room.id, { before, limit });
  return res.json({ messages });
}

// REST fallback for sending a message (the primary path is the Socket.io
// "message:send" event — see src/sockets/index.js). Kept so the API works
// for simple HTTP clients too, and both paths share the same rules.
//
// Direct messages are ALWAYS end-to-end encrypted: the server requires an
// `iv` for any non-group room. Group rooms are not encrypted in this
// version, so their content is sanitized server-side the same way it
// always was.
async function send(req, res) {
  const { content, iv } = req.body;

  if (!req.room.is_group) {
    if (!iv || typeof content !== 'string' || !content) {
      return res.status(400).json({ error: 'Direct messages must be sent encrypted (missing iv/content).' });
    }
    if (content.length > MAX_CIPHERTEXT_LENGTH) {
      return res.status(400).json({ error: 'Message too large.' });
    }
    const message = await messageRepo.createMessage({ content, iv, senderId: req.user.id, roomId: req.room.id });
    req.app.get('io').to(`room:${req.room.id}`).emit('message:new', message);
    return res.status(201).json({ message });
  }

  const clean = sanitizeMessageContent(content);
  if (!clean) {
    return res.status(400).json({ error: 'Message cannot be empty.' });
  }
  const message = await messageRepo.createMessage({ content: clean, senderId: req.user.id, roomId: req.room.id });
  req.app.get('io').to(`room:${req.room.id}`).emit('message:new', message);
  return res.status(201).json({ message });
}

// Shared ownership/state checks for edit and delete.
async function loadOwnedMessage(req, res) {
  const message = await messageRepo.getMessageById(req.params.messageId);
  if (!message || message.roomId !== req.room.id) {
    res.status(404).json({ error: 'Message not found.' });
    return null;
  }
  if (message.senderId !== req.user.id) {
    res.status(403).json({ error: 'You can only change your own messages.' });
    return null;
  }
  return message;
}

async function edit(req, res) {
  const message = await loadOwnedMessage(req, res);
  if (!message) return; // response already sent

  if (message.deletedAt) {
    return res.status(400).json({ error: 'Cannot edit a deleted message.' });
  }

  const { content, iv } = req.body;
  let updated;

  if (!req.room.is_group) {
    if (!iv || typeof content !== 'string' || !content) {
      return res.status(400).json({ error: 'Direct messages must be sent encrypted (missing iv/content).' });
    }
    if (content.length > MAX_CIPHERTEXT_LENGTH) {
      return res.status(400).json({ error: 'Message too large.' });
    }
    updated = await messageRepo.updateMessage(message.id, { content, iv });
  } else {
    const clean = sanitizeMessageContent(content);
    if (!clean) return res.status(400).json({ error: 'Message cannot be empty.' });
    updated = await messageRepo.updateMessage(message.id, { content: clean });
  }

  req.app.get('io').to(`room:${req.room.id}`).emit('message:updated', updated);
  return res.json({ message: updated });
}

async function del(req, res) {
  const message = await loadOwnedMessage(req, res);
  if (!message) return; // response already sent

  if (message.deletedAt) {
    return res.status(204).send(); // already deleted — idempotent
  }

  const deleted = await messageRepo.softDeleteMessage(message.id);
  req.app.get('io').to(`room:${req.room.id}`).emit('message:deleted', {
    messageId: deleted.id,
    roomId: req.room.id,
    deletedAt: deleted.deletedAt,
  });
  return res.status(204).send();
}

module.exports = { history, send, edit, del };
