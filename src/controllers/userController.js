const userRepo = require('../db/repositories/userRepo');
const epochKeyRepo = require('../db/repositories/epochKeyRepo');

async function search(req, res) {
  const query = (req.query.q || '').toString().trim();
  if (query.length < 1) {
    return res.json({ users: [] });
  }

  const results = await userRepo.searchUsers(query, req.user.id, 10);
  return res.json({
    users: results.map((u) => ({
      id: u.id,
      username: u.username,
      avatarColor: u.avatar_color,
      lastSeenAt: u.last_seen_at,
      publicKey: u.public_key ? JSON.parse(u.public_key) : null,
    })),
  });
}

// Called once per browser, automatically, right after login — the client
// generates an ECDH key pair locally and uploads only the PUBLIC half here.
// The private key never leaves the browser (see public/js/crypto.js).
async function setPublicKey(req, res) {
  const { publicKey } = req.body;
  if (!publicKey || typeof publicKey !== 'object' || Array.isArray(publicKey)) {
    return res.status(400).json({ error: 'publicKey must be a JWK object.' });
  }
  await userRepo.setPublicKey(req.user.id, publicKey);
  return res.status(204).send();
}

// Publishes the caller's ONE-TIME ephemeral public key for a given hour-long
// epoch — part of forward secrecy. The matching private key never leaves
// their browser and is discarded client-side once it ages out; this
// endpoint only ever sees public material.
async function setEpochKey(req, res) {
  const { epochIndex, publicKey } = req.body;
  if (!Number.isInteger(epochIndex) || epochIndex < 0) {
    return res.status(400).json({ error: 'epochIndex must be a non-negative integer.' });
  }
  if (!publicKey || typeof publicKey !== 'object' || Array.isArray(publicKey)) {
    return res.status(400).json({ error: 'publicKey must be a JWK object.' });
  }
  await epochKeyRepo.setEpochKey(req.user.id, epochIndex, publicKey);
  return res.status(204).send();
}

// Lets someone fetch a DM partner's ephemeral key for a specific epoch, so
// they can use the stronger mutual-ephemeral derivation. Returns
// { publicKey: null } (not a 404) when the user simply wasn't active that
// epoch — that's an expected, routine case, not an error.
async function getEpochKey(req, res) {
  const { userId, epochIndex } = req.params;
  const parsedEpoch = parseInt(epochIndex, 10);
  if (!Number.isInteger(parsedEpoch) || parsedEpoch < 0) {
    return res.status(400).json({ error: 'epochIndex must be a non-negative integer.' });
  }
  const publicKey = await epochKeyRepo.getEpochKey(userId, parsedEpoch);
  return res.json({ publicKey });
}

module.exports = { search, setPublicKey, setEpochKey, getEpochKey };
