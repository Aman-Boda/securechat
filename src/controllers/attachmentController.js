const crypto = require('node:crypto');
const attachmentRepo = require('../db/repositories/attachmentRepo');
const { ID_RE } = require('../utils/attachmentIds');

const MAX_BYTES = 1000000; // the browser shrinks images far below this
const MIN_BYTES = 29; // 12-byte iv + 16-byte tag + at least one byte
const MAX_PENDING = 12; // uploads not yet attached to a sent message, per user

// The body is AES-GCM ciphertext (iv + ciphertext) made in the sender's browser.
// The server stores it as an opaque blob: it cannot see what the image is.
async function upload(req, res) {
  const room = req.room;
  if (room.is_group && !room.encrypted) {
    return res.status(400).json({ error: 'Images can only be sent in encrypted conversations.' });
  }
  const body = req.body;
  if (!Buffer.isBuffer(body) || body.length < MIN_BYTES) {
    return res.status(400).json({ error: 'Send the encrypted image as application/octet-stream.' });
  }
  if (body.length > MAX_BYTES) return res.status(413).json({ error: 'That image is too large.' });

  await attachmentRepo.deleteOrphans(); // unsent uploads older than a day
  if ((await attachmentRepo.countPending(req.user.id)) >= MAX_PENDING) {
    return res.status(429).json({ error: 'Too many unsent images. Send or discard some first.' });
  }
  const id = crypto.randomUUID();
  await attachmentRepo.create({ id, roomId: room.id, uploaderId: req.user.id, data: body });
  return res.status(201).json({ id });
}

async function download(req, res) {
  const { attachmentId } = req.params;
  const row = ID_RE.test(attachmentId) ? await attachmentRepo.get(attachmentId) : null;
  if (!row || row.room_id !== req.room.id) return res.status(404).json({ error: 'Image not found.' });
  res.set({
    'Content-Type': 'application/octet-stream',
    'Content-Length': String(row.size),
    // The ciphertext of a given id never changes, so the browser may keep it.
    'Cache-Control': 'private, max-age=31536000, immutable',
  });
  return res.send(row.data);
}

module.exports = { upload, download };
