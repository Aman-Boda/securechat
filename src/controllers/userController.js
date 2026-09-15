const userRepo = require('../db/repositories/userRepo');

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

module.exports = { search, setPublicKey };
