# SecureChat

A self-hosted, real-time chat app with direct messages and group rooms, built
with security as a first-class concern rather than an afterthought.

## Features

- Register / log in / log out
- Direct messages (1-on-1), **end-to-end encrypted**, and group rooms (not encrypted — see below)
- Real-time delivery over WebSockets (Socket.io)
- Typing indicators
- Online / offline presence with "last seen"
- Message history with infinite scroll (loads older messages as you scroll up)
- Message editing and deletion (deleted messages leave a "Message deleted" tombstone, not a silent gap — and the content is actually cleared from the database, not just hidden)
- Unread message badges, updated live
- Email verification and password reset (via Resend — optional; the app works fine without it configured)
- Search for people to start a conversation with
- Browse and join public group rooms

## Tech stack

| Layer | Choice |
|---|---|
| Server | Node.js + Express |
| Real-time | Socket.io |
| Database | PostgreSQL via `pg` (see "Why not an ORM?" below) |
| Auth | bcrypt password hashing + JWT in an httpOnly cookie |
| Frontend | Vanilla HTML / CSS / JS (ES modules), no build step |

## Getting started (local development)

1. **Install dependencies**

   ```bash
   npm install
   ```

2. **Get a PostgreSQL database.** Two options:
   - **Local**: install Postgres yourself and create a database, e.g. `createdb securechat`.
   - **Free hosted**: [Neon](https://neon.tech) or [Supabase](https://supabase.com) both give you a connection string in under a minute, no credit card.

3. **Configure environment variables**

   ```bash
   cp .env.example .env
   ```

   Open `.env` and set:
   - `DATABASE_URL` to your Postgres connection string
   - `JWT_SECRET` to a real random value — generate one with:
     ```bash
     node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
     ```

   The server refuses to start with a missing/short `JWT_SECRET` or a missing
   `DATABASE_URL` — intentional, so you can't accidentally deploy insecurely.

4. **Run it**

   ```bash
   npm run dev     # auto-restarts on file changes
   # or
   npm start
   ```

   Then open **http://localhost:3000**. The database schema is created
   automatically on first run.

5. **Try it with two accounts** — open a second browser (or a private/
   incognito window) and register a second user to test DMs and group chat
   between two live sessions.

## Deploying to Render (free)

Render runs the app as a real, persistent Node process — unlike edge/
serverless platforms, Socket.io and a normal Express server work here with
no rewriting. The free tier has no credit card requirement; the one
trade-off is that a free web service spins down after 15 minutes of no
traffic and takes about a minute to wake back up on the next visit.

### Fastest path: Blueprint (one flow, both resources)

This repo includes `render.yaml`, which tells Render to provision the web
service **and** a Postgres database together, with the connection string and
a random `JWT_SECRET` wired up automatically — you don't create or copy
either by hand.

1. Push this project to a GitHub repository (create a new repo on GitHub,
   then either use `git push`, or just drag the extracted folder into
   GitHub's "uploading an existing file" web UI if you'd rather avoid the
   command line entirely).
2. Create a free account at [render.com](https://render.com) (no card needed).
3. In the Render Dashboard: **New +** → **Blueprint** → connect the GitHub repo.
4. Render reads `render.yaml` and shows you both resources it's about to
   create. When prompted for `CLIENT_ORIGIN`, enter your best guess at the
   URL (usually `https://securechat.onrender.com`, or whatever name you
   pick) — you can correct it afterward once you see the real one.
5. Click **Apply**. Render builds the app and provisions the database in one
   go. First build takes a few minutes.
6. Once live, open the URL Render gives you.

### Manual path (if you'd rather not use the Blueprint)

1. Push the code to GitHub, as above.
2. **New +** → **PostgreSQL** → free plan → note it expires after 30 days
   unless you upgrade (Neon/Supabase don't have this limit, if that matters
   to you) → once created, copy its **Internal Database URL**.
3. **New +** → **Web Service** → connect the repo → Build Command
   `npm install`, Start Command `npm start`.
4. Under **Environment**, add:
   - `DATABASE_URL` — the connection string from step 2
   - `JWT_SECRET` — a real random value (see the generate command above)
   - `NODE_ENV` — `production`
   - `CLIENT_ORIGIN` — your Render URL once you know it
5. Deploy.

### Why Postgres instead of a local SQLite file?

This app originally used SQLite, but Render's **free** web services have no
persistent disk — the filesystem resets on every restart, including the
15-minute idle spin-down. Any local database file would silently lose all
data on the very first spin-down/spin-up cycle. Postgres is a real,
separately-hosted database, so your data survives regardless of what happens
to the web service itself.

## Setting up email (optional)

Without this, the app works fully except for two things: verification
emails and password-reset emails don't actually send (they get logged to
the console instead, which is fine for local development, but not for a
real deployment). To enable real sending:

1. Create a free account at [resend.com](https://resend.com) — 3,000
   emails/month, no card required.
2. Generate an API key from their dashboard.
3. On Render, add `RESEND_API_KEY` to your web service's environment
   variables (Environment tab → Add → paste the key). Saving triggers an
   automatic redeploy.

**One catch worth knowing:** until you verify your own sending domain with
Resend, you can only send *to* the email address you signed up with —
Resend's shared address (`onboarding@resend.dev`) is meant for testing, not
for reaching arbitrary users. That's fine for trying this out solo, but if
you want real users to receive real verification/reset emails, you'll need
to verify a domain you own (Resend walks you through adding a couple of DNS
records) and set `FROM_EMAIL` to an address on that domain.

## Project structure

```
render.yaml               Render Blueprint (auto-provisions web service + database)
src/
  server.js               Express + Socket.io entrypoint
  config/env.js            Loads & validates environment variables
  db/
    schema.sql              Table definitions (applied automatically on boot)
    index.js                 Postgres connection pool + schema init
    repositories/            All SQL lives here, behind parameterized queries
  middleware/
    auth.js                  Verifies the JWT cookie, attaches req.user
    roomAccess.js             Confirms room membership before allowing access
    rateLimiter.js             Login/API rate limits
    validate.js                express-validator error formatting
  controllers/               Request handlers (one per resource)
  routes/                     Express routers, validation chains
  sockets/index.js            Real-time layer: auth, messaging, typing, presence
public/
  index.html                  Single-page app shell
  css/styles.css              All styling
  js/
    api.js                     Fetch wrapper for the REST API
    socket.js                   Thin Socket.io client wrapper
    app.js                      UI state, rendering, event wiring
```

## Security measures

- **Passwords** — hashed with bcrypt (cost factor 12), never logged or returned by the API.
- **Sessions** — JWTs stored in an `httpOnly`, `sameSite=lax` cookie (`secure` in production). Not readable by JavaScript, so an XSS bug elsewhere can't steal a session the way it could with a token in `localStorage`.
- **Timing-safe login** — a dummy bcrypt comparison runs even when the username/email doesn't exist, so response time doesn't leak which accounts are registered.
- **Authorization** — every room-scoped route and every socket event re-checks that the requesting user is actually a member of that room (`requireRoomMembership` / `roomRepo.isMember`). You cannot read another user's DMs or a group's history by guessing an ID.
- **Input validation** — all request bodies are validated with `express-validator` (username charset/length, email format, password length, etc.).
- **XSS prevention** — message content is stripped of all HTML server-side (`sanitize-html`) *and* rendered client-side via `textContent`, never `innerHTML` — two independent layers.
- **SQL injection** — not possible by construction; every query in `src/db/repositories/` uses parameterized queries (`$1, $2, ...`), never string concatenation.
- **Rate limiting** — auth endpoints: 10 requests / 15 minutes per IP. General API: 120 requests / minute. Socket messages: 20 / 10 seconds per connection.
- **Security headers** — Helmet sets a strict Content-Security-Policy (`default-src 'self'`, no external scripts/styles/fonts), so even a successful HTML-injection bug has nowhere to load a payload from.
- **Secrets** — read from `.env` only, never hardcoded; `.env` is gitignored. In production, secrets live in Render's environment variable store, not in the repo.
- **Socket auth** — every socket connection must present the same session cookie as the REST API; there is no separate, weaker auth path for real-time events.
- **Encrypted DB connections** — hosted Postgres connections use TLS (`sslmode=require`), so credentials and query data aren't sent in plaintext over the network between the app and the database.
- **Verification/reset tokens** — stored as SHA-256 hashes, never raw; the raw token only ever exists in the emailed link itself, so reading the database can't yield a usable token. Both are single-use (cleared on success) and time-limited (24h for verification, 1h for reset).
- **No account enumeration via password reset** — `/auth/forgot-password` returns the identical response whether or not the email exists, so it can't be used to check who has an account.
- **Password reset invalidates other sessions** — every user has a `token_version` that's bumped on reset; a JWT issued before that moment stops being accepted (checked on every request and every socket connection), so if an account was compromised, resetting the password actually logs the attacker out too — not just the person who reset it.

### End-to-end encryption for DMs

Direct messages are genuinely end-to-end encrypted — the server stores and
relays ciphertext it cannot itself decrypt, and this is enforced server-side
(a DM message arriving without encryption is rejected with a 400, not just
"usually" encrypted by client convention).

**How it works:** each browser generates its own ECDH (P-256) key pair the
first time you log in. The private key is stored in that browser's
IndexedDB and never transmitted anywhere. The public key is uploaded to the
server so others can find it. To message someone, your browser combines
your private key with their public key (ECDH) to derive a shared AES-256-GCM
key; they derive the exact same key independently using their private key
and your public key. This was confirmed with a full round-trip test: two
independent identities generated real keys, exchanged them only through the
live API, sent a real encrypted message over a real socket connection, and
decrypted it independently — while checking that the plaintext never once
appeared anywhere the server stores or returns data.

**Verifying it's really them — the safety number:** encryption alone
doesn't stop a *server* that's actively lying about someone's public key
(a "man in the middle"). Click the 🔒 in a DM's header to see a safety
number derived from both public keys. If you and the other person read it
to each other over a different channel (a phone call, in person) and it
matches, you've confirmed the server gave you their real key.

**Known, deliberate limitations** (stated plainly rather than glossed over):
- **No forward secrecy.** This uses one static derived key per conversation,
  not a rotating per-message key like Signal's Double Ratchet. If a private
  key is ever compromised, past messages become decryptable.
- **Single-device.** The private key lives in one browser's storage. Logging
  in on a different browser/device generates a new key pair, and old
  messages encrypted for the old key become unreadable there.
- **Group rooms are not encrypted** in this version — group E2EE (encrypting
  to multiple recipients, handling membership changes) is a meaningfully
  bigger undertaking than 1-to-1, and is listed under "Possible next steps."
- **Verification is opt-in.** If two people never compare their safety
  number, they're trusting the server not to be actively malicious — a
  weaker (but still real) guarantee than encryption plus verification.

## Why not an ORM?

Every query is hand-written SQL behind a small repository layer
(`src/db/repositories/`), using `pg`'s parameterized queries rather than an
ORM like Prisma. Two reasons: first, Prisma's CLI needs to download a
query-engine binary at build time, which failed in the sandboxed environment
this project was built and tested in — a good reminder that "it depends on
downloading a binary from a third party at build time" is itself a
production risk on any environment with restricted egress (including some
CI runners and corporate networks). Second, keeping the SQL explicit means
there's nothing hidden between "what query runs" and "what's in the code" —
useful when reasoning about exactly what's exposed to user input. The
trade-off is you lose auto-generated types and migrations; if you outgrow
this, the repository layer is the only place that would need to change.

## API reference (brief)

All endpoints are prefixed `/api`. Authenticated endpoints expect the session
cookie (the browser sends it automatically).

| Method | Path | Description |
|---|---|---|
| POST | `/auth/register` | Create an account |
| POST | `/auth/login` | Log in |
| POST | `/auth/logout` | Clear the session |
| GET | `/auth/me` | Current user |
| POST | `/auth/verify-email` | Confirm an email address `{ token }` |
| POST | `/auth/resend-verification` | Resend the verification email (authenticated) |
| POST | `/auth/forgot-password` | Request a reset link `{ email }` — always responds the same way whether or not the email exists |
| POST | `/auth/reset-password` | Set a new password `{ token, newPassword }` — logs out every other session on the account |
| GET | `/users/search?q=` | Find users by username (includes their public key, if set) |
| PUT | `/users/me/public-key` | Upload your E2EE public key `{ publicKey }` (JWK) — done automatically by the app on login |
| GET | `/rooms` | Your rooms (DMs + groups), with previews |
| GET | `/rooms/joinable` | Group rooms you haven't joined |
| POST | `/rooms/group` | Create a group room `{ name }` |
| POST | `/rooms/direct` | Start/open a DM `{ userId }` |
| POST | `/rooms/:id/join` | Join a group room |
| POST | `/rooms/:id/leave` | Leave a room |
| POST | `/rooms/:id/read` | Mark a room as read (clears its unread badge) |
| GET | `/rooms/:id/members` | List members |
| GET | `/rooms/:id/messages` | History (`?before=&limit=`) |
| POST | `/rooms/:id/messages` | Send a message (REST fallback — the app itself uses the socket event below) |
| PATCH | `/rooms/:id/messages/:messageId` | Edit a message you sent |
| DELETE | `/rooms/:id/messages/:messageId` | Delete a message you sent (leaves a tombstone, clears the content) |

### Socket.io events

| Direction | Event | Payload |
|---|---|---|
| emit | `message:send` | `{ roomId, content }` for group rooms, `{ roomId, content, iv }` for DMs (required — see E2EE section) → ack `{ message }` or `{ error }` |
| emit | `message:edit` | `{ roomId, messageId, content, iv? }` → ack `{ message }` or `{ error }` |
| emit | `message:delete` | `{ roomId, messageId }` → ack `{ ok: true }` or `{ error }` |
| emit | `room:read` | `{ roomId }` — marks the room read, no ack |
| emit | `typing:start` / `typing:stop` | `{ roomId }` |
| emit | `room:subscribe` / `room:unsubscribe` | `{ roomId }` |
| listen | `message:new` | full message object |
| listen | `message:updated` | full message object, post-edit |
| listen | `message:deleted` | `{ messageId, roomId, deletedAt }` |
| listen | `typing:update` | `{ roomId, userId, username, isTyping }` |
| listen | `presence:update` | `{ userId, online, lastSeenAt? }` |
| listen | `room:new` | `{ room }` — pushed when someone starts a DM with you or you're added to a room, so it appears without a page refresh |

## Possible next steps

- Forward secrecy (rotate the derived key per-message, Signal-style, instead of one static key per conversation)
- Multi-device support for encrypted DMs (currently: a new browser/device means a new key pair, and old encrypted messages can't be read there)
- Group room encryption (harder — needs encrypting to multiple recipients and handling membership changes)
- Cross-tab unread sync (right now, reading on one open tab doesn't clear the badge on another tab of the same account until it re-fetches)
