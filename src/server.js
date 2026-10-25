const path = require('node:path');
const http = require('node:http');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const { Server } = require('socket.io');

// Requiring this validates required env vars and throws immediately if
// something critical (like JWT_SECRET) is missing, rather than starting
// insecurely.
const { port, clientOrigin, isProduction } = require('./config/env');

const { requireAuth } = require('./middleware/auth');
const { backupLimiter, attachmentLimiter } = require('./middleware/rateLimiter');
const { requireRoomMembership } = require('./middleware/roomAccess');
const { asyncHandler } = require('./utils/asyncHandler');
const attachmentController = require('./controllers/attachmentController');
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/users');
const roomRoutes = require('./routes/rooms');
const { initSockets } = require('./sockets');
const { initDb } = require('./db');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: clientOrigin, credentials: true },
});

app.set('io', io);
app.set('trust proxy', 1); // correct client IPs / secure cookies when run behind a reverse proxy

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", 'data:', 'blob:'], // blob: = decrypted images shown in the page
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        frameAncestors: ["'self'"],
      },
    },
  })
);
app.use(cors({ origin: clientOrigin, credentials: true }));
app.use(cookieParser());
// The encrypted key backup grows by one key pair per active hour, so it needs
// a far larger body limit than ordinary requests. That limit applies to this
// one route only, and only after authentication and rate limiting, so an
// anonymous client can never make the server buffer a large body.
app.put('/api/users/me/key-backup', requireAuth, backupLimiter, express.json({ limit: '20mb' }));
// Encrypted image upload: a raw binary body, accepted only from a logged-in member
// of the room, rate limited, and only then read (never buffered for anyone else).
app.post(
  '/api/rooms/:roomId/attachments',
  requireAuth,
  attachmentLimiter,
  requireRoomMembership,
  express.raw({ type: 'application/octet-stream', limit: '1100kb' }),
  asyncHandler(attachmentController.upload)
);
app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, '..', 'public')));

app.get('/api/health', (_req, res) => res.json({ status: 'ok' }));
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/rooms', roomRoutes);

// Any other GET request falls back to the single-page app shell so
// client-side view switching survives a hard refresh or shared link.
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) return next();
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

app.use((req, res) => {
  res.status(404).json({ error: 'Not found.' });
});

// Central error handler — logs the real error server-side but never leaks
// stack traces or internals to the client.
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  if (!err.expose) console.error(err); // user-facing errors (e.g. an image was already used) are not crashes
  if (res.headersSent) return next(err);
  const status = err.status >= 400 && err.status < 500 ? err.status : 500;
  res.status(status).json({
    error:
      err.expose ? err.message : status === 413 ? 'That request is too large.' : status < 500 ? 'Bad request.' : 'Something went wrong on our end.',
  });
});

initSockets(io);

async function start() {
  try {
    await initDb();
  } catch (err) {
    console.error('Could not connect to the database / apply schema. Check DATABASE_URL in .env.');
    console.error(err);
    process.exit(1);
  }

  server.listen(port, () => {
    console.log(`SecureChat listening on http://localhost:${port} (${isProduction ? 'production' : 'development'})`);
  });
}

start();

module.exports = { app, server };
