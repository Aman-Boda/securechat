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
-- Per-account security posture, chosen at signup:
-- 'standard' = ephemeral keys are never pruned, so history stays readable
--   forever and a password-encrypted backup can restore full history to a
--   new device. No forward-secrecy guarantee.
-- 'strict'   = ephemeral keys are pruned after 30 days: genuine forward
--   secrecy, at the cost of old messages eventually becoming unreadable
--   and no full-history device transfer.
ALTER TABLE users ADD COLUMN IF NOT EXISTS security_mode TEXT NOT NULL DEFAULT 'standard';

-- Encrypted group chats. A group has a shared AES key per "generation"; the key
-- is never stored in the clear: each member holds their own copy, wrapped
-- (encrypted) to their identity public key, in group_keys below.
--   join_policy    'open' (listed, anyone can join) | 'invite' (admin adds people)
--   history_policy 'after_join' (newcomers get a fresh key, so they cannot read
--                  older messages) | 'full' (newcomers also get the older keys)
--   needs_rotation set when someone leaves or is removed: the next member who
--                  holds the key replaces it so the leaver reads nothing new.
-- Existing groups keep encrypted = false and behave exactly as before.
ALTER TABLE rooms ADD COLUMN IF NOT EXISTS encrypted BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE rooms ADD COLUMN IF NOT EXISTS join_policy TEXT NOT NULL DEFAULT 'open';
ALTER TABLE rooms ADD COLUMN IF NOT EXISTS history_policy TEXT NOT NULL DEFAULT 'after_join';
ALTER TABLE rooms ADD COLUMN IF NOT EXISTS key_generation INTEGER NOT NULL DEFAULT 0;
ALTER TABLE rooms ADD COLUMN IF NOT EXISTS needs_rotation BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE IF NOT EXISTS group_keys (
  room_id            TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
  generation         INTEGER NOT NULL,
  user_id            TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  wrapped_key        TEXT NOT NULL,
  iv                 TEXT NOT NULL,
  wrapper_public_key TEXT NOT NULL,
  wrapped_for_fp     TEXT NOT NULL,
  wrapped_by         TEXT REFERENCES users(id) ON DELETE SET NULL,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (room_id, generation, user_id)
);
CREATE INDEX IF NOT EXISTS idx_group_keys_user_room ON group_keys(user_id, room_id);

-- Chat features inside ENCRYPTED conversations (DMs and encrypted groups).
-- Replies live inside the encrypted message itself, so they need no columns.
--   attachment_ids  ids of encrypted image blobs sent with a message (the keys
--                   to open them are inside the encrypted message, never here)
--   reactions       one per person per message; the emoji is encrypted exactly
--                   like a message body
--   attachments     opaque ciphertext blobs; removed with their message, and
--                   unsent uploads are cleaned up after a day
ALTER TABLE messages ADD COLUMN IF NOT EXISTS attachment_ids TEXT[] NOT NULL DEFAULT '{}';

CREATE TABLE IF NOT EXISTS reactions (
  message_id              TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  user_id                 TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  room_id                 TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
  content                 TEXT NOT NULL,
  iv                      TEXT NOT NULL,
  epoch_index             BIGINT,
  sender_epoch_public_key TEXT,
  key_mode                TEXT NOT NULL,
  created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (message_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_reactions_room ON reactions(room_id);

CREATE TABLE IF NOT EXISTS attachments (
  id          TEXT PRIMARY KEY,
  room_id     TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
  uploader_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  message_id  TEXT REFERENCES messages(id) ON DELETE SET NULL,
  size        INTEGER NOT NULL,
  data        BYTEA NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_attachments_message ON attachments(message_id);
CREATE INDEX IF NOT EXISTS idx_attachments_pending ON attachments(uploader_id) WHERE message_id IS NULL;

-- An opaque, password-encrypted backup of a user's local keys (identity +
-- retained ephemeral keys), letting them restore message-decryption
-- ability on a new device. The server only ever stores ciphertext: it
-- never sees the backup password or anything it can decrypt with.
CREATE TABLE IF NOT EXISTS key_backups (
  user_id    TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  ciphertext TEXT NOT NULL,
  salt       TEXT NOT NULL,
  iv         TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
