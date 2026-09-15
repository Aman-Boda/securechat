const { verifyToken, COOKIE_NAME } = require('../utils/jwt');
const userRepo = require('../db/repositories/userRepo');
const { asyncHandler } = require('../utils/asyncHandler');

// Verifies the JWT stored in an httpOnly cookie and attaches the current
// user to req.user. Rejects with 401 if missing/invalid/expired, or if the
// user referenced by the token no longer exists (e.g. deleted account).
const requireAuth = asyncHandler(async (req, res, next) => {
  const token = req.cookies?.[COOKIE_NAME];
  if (!token) {
    return res.status(401).json({ error: 'Not authenticated.' });
  }

  let payload;
  try {
    payload = verifyToken(token);
  } catch {
    return res.status(401).json({ error: 'Session expired or invalid. Please log in again.' });
  }

  const user = await userRepo.findById(payload.sub);
  if (!user) {
    return res.status(401).json({ error: 'Account no longer exists.' });
  }

  req.user = user;
  next();
});

module.exports = { requireAuth };
