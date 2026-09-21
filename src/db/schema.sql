-- SecureChat database schema (PostgreSQL)
-- Applied automatically on server startup. All statements are idempotent.

CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,
  username      TEXT NOT NULL UNIQUE,
  email         TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  avatar_color  TEXT NOT NULL DEFAULT '#6FA88A',
  -- JSON-serialized ECDH public key (JWK format). NULL until the user's
  -- browser generates a key pair (happens automatically on first login) and
  -- uploads it. Public keys are, by definition, not secret.
  public_key    TEXT,
  -- Email verification. Tokens are stored as SHA-256 hashes, never raw —
  -- the raw token only ever exists in the emailed link itself.
  email_verified              BOOLEAN NOT NULL DEFAULT false,
  verification_token_hash     TEXT,
  verification_token_expires  TIMESTAMPTZ,
  -- Password reset, same hashing approach as verification.
  reset_token_hash    TEXT,
  reset_token_expires TIMESTAMPTZ,
  -- Bumped whenever the password is reset, so any JWT issued before that
  -- moment stops being accepted — this is what actually logs out a
  -- possibly-compromised session when someone resets their password.
  token_version INT NOT NULL DEFAULT 0,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS rooms (
  id         TEXT PRIMARY KEY,
  name       TEXT,
  is_group   BOOLEAN NOT NULL DEFAULT false,
  created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS room_memberships (
  id            TEXT PRIMARY KEY,
  user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  room_id       TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
  role          TEXT NOT NULL DEFAULT 'member',
  joined_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- Everything in this room sent after this timestamp counts as unread.
  last_read_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (user_id, room_id)
);

CREATE INDEX IF NOT EXISTS idx_membership_room ON room_memberships(room_id);
CREATE INDEX IF NOT EXISTS idx_membership_user ON room_memberships(user_id);

CREATE TABLE IF NOT EXISTS messages (
  id         TEXT PRIMARY KEY,
  -- For DMs: base64 AES-GCM ciphertext. For group rooms: plain text.
  content    TEXT NOT NULL,
  -- Base64 AES-GCM nonce. Present only for encrypted (DM) messages — its
  -- presence is what tells the app "this content is ciphertext."
  iv         TEXT,
  sender_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  room_id    TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  edited_at  TIMESTAMPTZ,
  deleted_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_messages_room_created ON messages(room_id, created_at);

-- Ephemeral, per-epoch public keys for forward secrecy. Each row is a
-- user's one-time ephemeral public key for a specific hour-long epoch.
-- The matching PRIVATE key lives only in that user's browser (IndexedDB),
-- never here, and is deleted client-side once it ages out — this table
-- only ever holds public material.
CREATE TABLE IF NOT EXISTS epoch_keys (
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  epoch_index BIGINT NOT NULL,
  public_key  TEXT NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, epoch_index)
);

-- Migration safety net: if this schema is being applied to a database that
-- was already created by an earlier version of the app (before public_key
-- and iv existed), CREATE TABLE IF NOT EXISTS above is a no-op on the
-- existing tables and would silently skip adding these columns. These
-- statements are idempotent — safe to run whether the columns already
-- exist or not — so upgrading an existing deployment just works.
ALTER TABLE users ADD COLUMN IF NOT EXISTS public_key TEXT;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS iv TEXT;
ALTER TABLE room_memberships ADD COLUMN IF NOT EXISTS last_read_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS verification_token_hash TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS verification_token_expires TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token_hash TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token_expires TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS token_version INT NOT NULL DEFAULT 0;
-- Forward secrecy: the sender's one-time ephemeral public key for the
-- message's epoch, and which of the recipient's keys it was combined with
-- ('mutual' = recipient's own ephemeral epoch key, the strong case;
-- 'identity' = recipient's static identity key, the fallback case).
ALTER TABLE messages ADD COLUMN IF NOT EXISTS sender_epoch_public_key TEXT;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS key_mode TEXT;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS epoch_index BIGINT;
