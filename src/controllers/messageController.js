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
// `iv` for any non-group room and never touches (or could touch) the
// plaintext — the app never sends it plaintext content for a DM in the
// first place. Group rooms are not encrypted in this version, so their
// content is sanitized server-side the same way it always was.
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

module.exports = { history, send };
