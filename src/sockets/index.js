const { verifyToken, COOKIE_NAME } = require('../utils/jwt');
const userRepo = require('../db/repositories/userRepo');
const roomRepo = require('../db/repositories/roomRepo');
const messageRepo = require('../db/repositories/messageRepo');
const { sanitizeMessageContent } = require('../utils/sanitize');

// userId -> Set<socketId>. Lets a user have multiple tabs/devices open
// without their presence flickering online/offline as individual tabs close.
const onlineSockets = new Map();

// Simple in-memory per-socket rate limit for messages (REST already has its
// own limiter; sockets bypass REST entirely, so they need their own guard).
const MESSAGE_WINDOW_MS = 10_000;
const MESSAGE_MAX_PER_WINDOW = 20;
const MAX_CIPHERTEXT_LENGTH = 8000; // generous — ciphertext is ~33% larger than plaintext, plus overhead
const messageTimestamps = new Map();

function isRateLimited(socketId) {
  const now = Date.now();
  const recent = (messageTimestamps.get(socketId) || []).filter((t) => now - t < MESSAGE_WINDOW_MS);
  recent.push(now);
  messageTimestamps.set(socketId, recent);
  return recent.length > MESSAGE_MAX_PER_WINDOW;
}

function markOnline(userId, socketId) {
  if (!onlineSockets.has(userId)) onlineSockets.set(userId, new Set());
  const set = onlineSockets.get(userId);
  set.add(socketId);
  return set.size === 1; // true the moment the user's *first* connection opens
}

function markOffline(userId, socketId) {
  const set = onlineSockets.get(userId);
  if (!set) return true;
  set.delete(socketId);
  if (set.size === 0) {
    onlineSockets.delete(userId);
    return true; // true only once their *last* connection closes
  }
  return false;
}

function parseCookie(cookieHeader, name) {
  if (!cookieHeader) return null;
  for (const part of cookieHeader.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const key = part.slice(0, idx).trim();
    if (key === name) return decodeURIComponent(part.slice(idx + 1).trim());
  }
  return null;
}

// Called from REST controllers (not just the socket layer itself) whenever
// someone is added to a room — e.g. when a DM is created, the OTHER person
// never emitted anything themselves, so without this their already-open
// connection would sit outside the room channel and simply never receive
// that room's real-time events until they refreshed the page.
function subscribeUserToRoom(io, userId, roomId) {
  io.in(`user:${userId}`).socketsJoin(`room:${roomId}`);
}

function initSockets(io) {
  // Every socket connection must present the same httpOnly JWT cookie used
  // by the REST API — there is no separate, weaker auth path for sockets.
  io.use(async (socket, next) => {
    const token = parseCookie(socket.handshake.headers.cookie, COOKIE_NAME);
    if (!token) return next(new Error('unauthorized'));

    try {
      const payload = verifyToken(token);
      const user = await userRepo.findById(payload.sub);
      if (!user) return next(new Error('unauthorized'));
      if (payload.tokenVersion !== user.token_version) return next(new Error('unauthorized'));
      socket.user = user;
      next();
    } catch {
      next(new Error('unauthorized'));
    }
  });

  io.on('connection', (socket) => {
    const { user } = socket;

    // Every listener below is registered synchronously, with no `await`
    // before it — if we awaited a DB call first, a message sent in the
    // instant right after connecting could arrive before this handler
    // exists and be silently dropped. The room-joining/presence work below
    // still happens asynchronously, but only *after* we're already
    // listening for everything.

    socket.on('room:subscribe', async ({ roomId } = {}) => {
      try {
        if (roomId && (await roomRepo.isMember(user.id, roomId))) socket.join(`room:${roomId}`);
      } catch (err) {
        console.error('room:subscribe failed:', err);
      }
    });

    socket.on('room:unsubscribe', ({ roomId } = {}) => {
      if (roomId) socket.leave(`room:${roomId}`);
    });

    socket.on('message:send', async ({ roomId, content, iv, epochIndex, senderEpochPublicKey, keyMode } = {}, ack) => {
      const reply = typeof ack === 'function' ? ack : () => {};
      try {
        if (!roomId) return reply({ error: 'roomId is required.' });
        const room = await roomRepo.getRoomById(roomId);
        if (!room || !(await roomRepo.isMember(user.id, roomId))) {
          return reply({ error: 'You are not a member of this room.' });
        }
        if (isRateLimited(socket.id)) {
          return reply({ error: 'Sending messages too fast. Please slow down.' });
        }

        let message;
        if (!room.is_group) {
          // Direct messages are always end-to-end encrypted, with forward
          // secrecy: the server never sees plaintext, and never derives or
          // checks the key itself — only that the shape is sane.
          if (!iv || typeof content !== 'string' || !content) {
            return reply({ error: 'Direct messages must be sent encrypted.' });
          }
          if (content.length > MAX_CIPHERTEXT_LENGTH) {
            return reply({ error: 'Message too large.' });
          }
          if (!Number.isInteger(epochIndex) || epochIndex < 0) {
            return reply({ error: 'epochIndex is required for encrypted messages.' });
          }
          if (!senderEpochPublicKey || typeof senderEpochPublicKey !== 'object') {
            return reply({ error: 'senderEpochPublicKey is required for encrypted messages.' });
          }
          if (keyMode !== 'mutual' && keyMode !== 'identity') {
            return reply({ error: "keyMode must be 'mutual' or 'identity'." });
          }
          message = await messageRepo.createMessage({
            content,
            iv,
            epochIndex,
            senderEpochPublicKey,
            keyMode,
            senderId: user.id,
            roomId,
          });
        } else {
          const clean = sanitizeMessageContent(content);
          if (!clean) return reply({ error: 'Message cannot be empty.' });
          message = await messageRepo.createMessage({ content: clean, senderId: user.id, roomId });
        }

        io.to(`room:${roomId}`).emit('message:new', message);
        reply({ message });
      } catch (err) {
        console.error('message:send failed:', err);
        reply({ error: 'Something went wrong sending your message.' });
      }
    });

    socket.on('message:edit', async ({ roomId, messageId, content, iv, epochIndex, senderEpochPublicKey, keyMode } = {}, ack) => {
      const reply = typeof ack === 'function' ? ack : () => {};
      try {
        if (!roomId || !messageId) return reply({ error: 'roomId and messageId are required.' });
        const room = await roomRepo.getRoomById(roomId);
        if (!room || !(await roomRepo.isMember(user.id, roomId))) {
          return reply({ error: 'You are not a member of this room.' });
        }
        const existing = await messageRepo.getMessageById(messageId);
        if (!existing || existing.roomId !== roomId) return reply({ error: 'Message not found.' });
        if (existing.senderId !== user.id) return reply({ error: 'You can only edit your own messages.' });
        if (existing.deletedAt) return reply({ error: 'Cannot edit a deleted message.' });

        let updated;
        if (!room.is_group) {
          if (!iv || typeof content !== 'string' || !content) {
            return reply({ error: 'Direct messages must be sent encrypted.' });
          }
          if (content.length > MAX_CIPHERTEXT_LENGTH) return reply({ error: 'Message too large.' });
          if (!Number.isInteger(epochIndex) || epochIndex < 0) {
            return reply({ error: 'epochIndex is required for encrypted messages.' });
          }
          if (!senderEpochPublicKey || typeof senderEpochPublicKey !== 'object') {
            return reply({ error: 'senderEpochPublicKey is required for encrypted messages.' });
          }
          if (keyMode !== 'mutual' && keyMode !== 'identity') {
            return reply({ error: "keyMode must be 'mutual' or 'identity'." });
          }
          updated = await messageRepo.updateMessage(messageId, { content, iv, epochIndex, senderEpochPublicKey, keyMode });
        } else {
          const clean = sanitizeMessageContent(content);
          if (!clean) return reply({ error: 'Message cannot be empty.' });
          updated = await messageRepo.updateMessage(messageId, { content: clean });
        }

        io.to(`room:${roomId}`).emit('message:updated', updated);
        reply({ message: updated });
      } catch (err) {
        console.error('message:edit failed:', err);
        reply({ error: 'Something went wrong editing that message.' });
      }
    });

    socket.on('message:delete', async ({ roomId, messageId } = {}, ack) => {
      const reply = typeof ack === 'function' ? ack : () => {};
      try {
        if (!roomId || !messageId) return reply({ error: 'roomId and messageId are required.' });
        if (!(await roomRepo.isMember(user.id, roomId))) {
          return reply({ error: 'You are not a member of this room.' });
        }
        const existing = await messageRepo.getMessageById(messageId);
        if (!existing || existing.roomId !== roomId) return reply({ error: 'Message not found.' });
        if (existing.senderId !== user.id) return reply({ error: 'You can only delete your own messages.' });

        if (!existing.deletedAt) {
          const deleted = await messageRepo.softDeleteMessage(messageId);
          io.to(`room:${roomId}`).emit('message:deleted', { messageId, roomId, deletedAt: deleted.deletedAt });
        }
        reply({ ok: true });
      } catch (err) {
        console.error('message:delete failed:', err);
        reply({ error: 'Something went wrong deleting that message.' });
      }
    });

    // Marks the room read for THIS user right now — used when they open a
    // room and whenever a new message arrives while it's the active room,
    // so the unread count never accumulates for something they're already
    // looking at.
    socket.on('room:read', async ({ roomId } = {}) => {
      try {
        if (roomId && (await roomRepo.isMember(user.id, roomId))) {
          await roomRepo.markRoomRead(user.id, roomId);
        }
      } catch (err) {
        console.error('room:read failed:', err);
      }
    });

    socket.on('typing:start', async ({ roomId } = {}) => {
      try {
        if (roomId && (await roomRepo.isMember(user.id, roomId))) {
          socket.to(`room:${roomId}`).emit('typing:update', { roomId, userId: user.id, username: user.username, isTyping: true });
        }
      } catch (err) {
        console.error('typing:start failed:', err);
      }
    });

    socket.on('typing:stop', async ({ roomId } = {}) => {
      try {
        if (roomId && (await roomRepo.isMember(user.id, roomId))) {
          socket.to(`room:${roomId}`).emit('typing:update', { roomId, userId: user.id, username: user.username, isTyping: false });
        }
      } catch (err) {
        console.error('typing:stop failed:', err);
      }
    });

    socket.on('disconnect', async () => {
      messageTimestamps.delete(socket.id);
      try {
        await userRepo.touchLastSeen(user.id);
        if (markOffline(user.id, socket.id)) {
          const lastSeenAt = new Date().toISOString();
          const rooms = await roomRepo.listRoomsForUser(user.id);
          rooms.forEach((r) => {
            io.to(`room:${r.id}`).emit('presence:update', { userId: user.id, online: false, lastSeenAt });
          });
        }
      } catch (err) {
        console.error('disconnect handling failed:', err);
      }
    });

    // Fire-and-forget: join this socket to the channels for every room the
    // user already belongs to, and announce them as online. This runs
    // *after* every listener above already exists.
    (async () => {
      try {
        const myRooms = await roomRepo.listRoomsForUser(user.id);
        myRooms.forEach((r) => socket.join(`room:${r.id}`));
        socket.join(`user:${user.id}`);
        if (markOnline(user.id, socket.id)) {
          myRooms.forEach((r) => socket.to(`room:${r.id}`).emit('presence:update', { userId: user.id, online: true }));
        }
      } catch (err) {
        console.error('Failed to initialize socket connection:', err);
      }
    })();
  });
}

module.exports = { initSockets, subscribeUserToRoom };
