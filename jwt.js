const jwt = require('jsonwebtoken');
const { jwtSecret } = require('../config/env');

const TOKEN_TTL = '7d';
const COOKIE_NAME = 'securechat_token';

function signToken(payload) {
  return jwt.sign(payload, jwtSecret, { expiresIn: TOKEN_TTL, algorithm: 'HS256' });
}

function verifyToken(token) {
  // Throws if invalid/expired — callers should catch this.
  return jwt.verify(token, jwtSecret, { algorithms: ['HS256'] });
}

module.exports = { signToken, verifyToken, COOKIE_NAME };
