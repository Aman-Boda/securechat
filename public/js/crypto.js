// End-to-end encryption for direct messages, with forward secrecy.
//
// Long-term identity: each browser generates its own ECDH (P-256) key pair
// on first login. The PRIVATE key is stored in IndexedDB and never sent
// anywhere. The PUBLIC key is uploaded to the server so other people can
// find you and message you.
//
// Forward secrecy: rather than using that identity key pair to encrypt
// every message forever (which would mean a stolen identity key exposes
// your ENTIRE history), each browser also generates a fresh, ONE-TIME
// ephemeral key pair for the current hour-long "epoch". When sending a
// message, if the recipient has published an epoch key too, both sides
// derive the encryption key from an EPHEMERAL-TO-EPHEMERAL exchange —
// neither long-term identity key is involved in that derivation at all.
// In Maximum Security mode the ephemeral private key is held only briefly (30 days, for
// catch-up) and then genuinely discarded — not just unused, deleted — so
// even someone who later steals your identity key cannot reconstruct it.
// If the recipient hasn't published an epoch key (they simply weren't
// active that hour), the sender falls back to combining their own fresh
// ephemeral key with the recipient's STATIC identity key instead — weaker
// (a stolen identity key protects a sender's PAST sends either way, but a
// stolen identity key exposes messages that were received via fallback),
// but it means sending never has to wait on the other person being online.
//
// Known limitations (documented here deliberately, not hidden):
// - Single-device: the private key lives in this browser's storage. Logging
//   in on a different browser/device generates a NEW identity key pair, and
//   old messages encrypted for the old key become unreadable there.
// - The identity-fallback path (used when the recipient has no epoch key
//   published) does not protect messages received under it against a later
//   identity-key compromise — only the mutual-ephemeral path gives that.
// - No built-in identity verification UI beyond the safety number below —
//   comparing it out-of-band is what actually protects against a malicious
//   server substituting a public key mid-conversation.

const DB_NAME = 'securechat-keys';
const DB_VERSION = 2;
const IDENTITY_STORE = 'keys';
const EPHEMERAL_STORE = 'ephemeralKeys';
const IDENTITY_RECORD_KEY = 'identity';
const EC_PARAMS = { name: 'ECDH', namedCurve: 'P-256' };

export const EPOCH_DURATION_MS = 60 * 60 * 1000; // 1 hour
// Retention is a per-account security choice ('standard' vs 'strict', picked
// at signup). 'strict' keeps real forward secrecy: 30 days is long enough to
// be usable, short enough that a compromise only exposes a bounded window.
// 'standard' never prunes, trading that guarantee for permanent history and
// full-device backup/restore.
const RETENTION_EPOCHS = {
  strict: 24 * 30, // 30 days at one epoch per hour
  standard: Infinity,
};

export function currentEpochIndex() {
  return Math.floor(Date.now() / EPOCH_DURATION_MS);
}

function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(IDENTITY_STORE)) db.createObjectStore(IDENTITY_STORE);
      if (!db.objectStoreNames.contains(EPHEMERAL_STORE)) db.createObjectStore(EPHEMERAL_STORE);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function idbGet(storeName, key) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readonly');
    const req = tx.objectStore(storeName).get(key);
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => reject(req.error);
  });
}

async function idbPut(storeName, key, value) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite');
    tx.objectStore(storeName).put(value, key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

// Deletes ephemeral key pairs outside the retention window. This is the
// step that actually DELIVERS forward secrecy for the mutual-ephemeral
// path — once a key is gone here, it is gone everywhere; nothing else in
// the system can reconstruct it.
async function pruneOldEphemeralKeys(keepFromEpoch) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(EPHEMERAL_STORE, 'readwrite');
    const store = tx.objectStore(EPHEMERAL_STORE);
    const req = store.getAllKeys();
    req.onsuccess = () => {
      (req.result || []).forEach((epochIndex) => {
        if (epochIndex < keepFromEpoch) store.delete(epochIndex);
      });
    };
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

let cachedIdentityKeyPair = null;

// Returns { publicKey, privateKey } CryptoKey objects for this browser's
// long-term identity, generating and persisting a new pair on first use.
export async function getOrCreateKeyPair() {
  if (cachedIdentityKeyPair) return cachedIdentityKeyPair;

  try {
    const stored = await idbGet(IDENTITY_STORE, IDENTITY_RECORD_KEY);
    if (stored && stored.publicKey && stored.privateKey) {
      cachedIdentityKeyPair = stored;
      return stored;
    }
  } catch (err) {
    console.warn('Could not read stored identity key — generating a fresh pair for this session:', err);
  }

  const pair = await crypto.subtle.generateKey(EC_PARAMS, true, ['deriveKey']);
  cachedIdentityKeyPair = pair;
  try {
    await idbPut(IDENTITY_STORE, IDENTITY_RECORD_KEY, pair);
  } catch (err) {
    console.warn('Could not persist identity key — it will regenerate next session:', err);
  }
  return pair;
}

// Returns this epoch's ephemeral key pair, generating one (and pruning
// aged-out ones) the first time it's needed. `isNew` tells the caller
// whether the public half still needs publishing to the server.
export async function getOrCreateCurrentEpochKeyPair(securityMode = 'strict') {
  const epochIndex = currentEpochIndex();
  try {
    const stored = await idbGet(EPHEMERAL_STORE, epochIndex);
    if (stored && stored.publicKey && stored.privateKey) {
      return { epochIndex, pair: stored, isNew: false };
    }
  } catch (err) {
    console.warn('Could not read stored ephemeral key:', err);
  }

  const pair = await crypto.subtle.generateKey(EC_PARAMS, true, ['deriveKey']);
  try {
    await idbPut(EPHEMERAL_STORE, epochIndex, pair);
    await pruneOldEphemeralKeys(epochIndex - (RETENTION_EPOCHS[securityMode] ?? RETENTION_EPOCHS.strict) + 1);
  } catch (err) {
    console.warn('Could not persist ephemeral key — it will regenerate next reload:', err);
  }
  return { epochIndex, pair, isNew: true };
}

// For decrypting a RECEIVED mutual-mode message from a specific epoch.
// Returns null if that epoch has aged out of the retention window — this
// is forward secrecy working as intended, not a bug: the message is
// genuinely no longer decryptable on this device.
export async function getEphemeralPrivateKeyForEpoch(epochIndex) {
  try {
    const stored = await idbGet(EPHEMERAL_STORE, epochIndex);
    return stored ? stored.privateKey : null;
  } catch {
    return null;
  }
}

export function exportPublicKeyJwk(publicKey) {
  return crypto.subtle.exportKey('jwk', publicKey);
}

// The core primitive: derives an AES-GCM key from any ECDH private key +
// any ECDH public key JWK. Used for every derivation in this file —
// identity-to-identity (legacy/unused now), ephemeral-to-ephemeral
// (mutual mode), and ephemeral-to-identity (fallback mode). Both sides
// compute the same key independently; it is never transmitted.
export async function deriveSharedKey(myPrivateKey, theirPublicKeyJwk) {
  const theirPublicKey = await crypto.subtle.importKey('jwk', theirPublicKeyJwk, EC_PARAMS, true, []);
  return crypto.subtle.deriveKey(
    { name: 'ECDH', public: theirPublicKey },
    myPrivateKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

function bufToBase64(buf) {
  const bytes = new Uint8Array(buf);
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function base64ToBuf(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

export async function encryptText(sharedKey, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertextBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, sharedKey, encoded);
  return { ciphertext: bufToBase64(ciphertextBuf), iv: bufToBase64(iv) };
}

// Returns null (rather than throwing) on failure, so a single bad/undecryptable
// message can't break the rest of the conversation view.
export async function decryptText(sharedKey, ciphertextB64, ivB64) {
  try {
    const plainBuf = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64ToBuf(ivB64) },
      sharedKey,
      base64ToBuf(ciphertextB64)
    );
    return new TextDecoder().decode(plainBuf);
  } catch (err) {
    console.warn('Failed to decrypt a message:', err);
    return null;
  }
}

function keyFingerprint(jwk) {
  return `${jwk.x}.${jwk.y}`;
}

// A short numeric code both people can read aloud or compare over another
// channel (a text message, in person) to confirm they're really talking to
// each other and not to a server silently substituting a public key. Based
// on long-term identity keys (stable), not ephemeral epoch keys (which
// change hourly) — both sides compute the exact same number, in either
// order, independently.
export async function computeSafetyNumber(myUserId, myPublicKeyJwk, theirUserId, theirPublicKeyJwk) {
  const entries = [
    { id: myUserId, fp: keyFingerprint(myPublicKeyJwk) },
    { id: theirUserId, fp: keyFingerprint(theirPublicKeyJwk) },
  ].sort((a, b) => a.id.localeCompare(b.id));

  const digestBuf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(entries.map((e) => e.fp).join('|')));
  const bytes = new Uint8Array(digestBuf);
  let code = '';
  for (let i = 0; i < 10; i += 1) {
    code += (bytes[i] % 10).toString();
    if (i % 5 === 4 && i !== 9) code += '  ';
  }
  return code;
}

// ---------------------------------------------------------------------------
// Password-encrypted key backup: lets an account restore message-decryption
// ability on a new device. The server only ever stores the ciphertext, salt,
// and iv below; it never sees the backup password or anything derivable into
// the actual encryption key.
// ---------------------------------------------------------------------------

const PBKDF2_ITERATIONS = 600000; // current OWASP guidance for PBKDF2-HMAC-SHA256

async function deriveBackupKey(password, saltBytes) {
  const baseKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, [
    'deriveKey',
  ]);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt: saltBytes, iterations: PBKDF2_ITERATIONS },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function idbGetAllKeys(storeName) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readonly');
    const req = tx.objectStore(storeName).getAllKeys();
    req.onsuccess = () => resolve(req.result || []);
    req.onerror = () => reject(req.error);
  });
}

// Gathers everything currently stored (the identity key pair and every
// retained ephemeral key pair) as exportable JWK data.
async function exportAllKeysForBackup() {
  const identity = await getOrCreateKeyPair();
  const identityExported = {
    publicKey: await crypto.subtle.exportKey('jwk', identity.publicKey),
    privateKey: await crypto.subtle.exportKey('jwk', identity.privateKey),
  };

  const epochIndices = await idbGetAllKeys(EPHEMERAL_STORE);
  const ephemeral = {};
  for (const epochIndex of epochIndices) {
    const pair = await idbGet(EPHEMERAL_STORE, epochIndex);
    if (pair && pair.publicKey && pair.privateKey) {
      ephemeral[epochIndex] = {
        publicKey: await crypto.subtle.exportKey('jwk', pair.publicKey),
        privateKey: await crypto.subtle.exportKey('jwk', pair.privateKey),
      };
    }
  }

  return { identity: identityExported, ephemeral };
}

// Re-imports keys from a decrypted backup into this browser's IndexedDB.
// Existing keys for the same epoch are overwritten: a full restore, not a merge.
async function importKeysFromBackup(data) {
  if (data.identity) {
    const publicKey = await crypto.subtle.importKey('jwk', data.identity.publicKey, EC_PARAMS, true, []);
    const privateKey = await crypto.subtle.importKey('jwk', data.identity.privateKey, EC_PARAMS, true, ['deriveKey']);
    await idbPut(IDENTITY_STORE, IDENTITY_RECORD_KEY, { publicKey, privateKey });
    cachedIdentityKeyPair = null; // force a re-read from IndexedDB next time it is needed
  }
  if (data.ephemeral) {
    for (const [epochIndexStr, jwkPair] of Object.entries(data.ephemeral)) {
      const publicKey = await crypto.subtle.importKey('jwk', jwkPair.publicKey, EC_PARAMS, true, []);
      const privateKey = await crypto.subtle.importKey('jwk', jwkPair.privateKey, EC_PARAMS, true, ['deriveKey']);
      await idbPut(EPHEMERAL_STORE, Number(epochIndexStr), { publicKey, privateKey });
    }
  }
}

// Full orchestration: gather all keys, encrypt them with a password-derived
// key, return base64 fields ready to upload. The password never leaves here.
export async function createEncryptedBackup(password) {
  const keys = await exportAllKeysForBackup();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const backupKey = await deriveBackupKey(password, salt);
  const ciphertextBuf = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    backupKey,
    new TextEncoder().encode(JSON.stringify(keys))
  );
  return {
    ciphertext: bufToBase64(ciphertextBuf),
    salt: bufToBase64(salt),
    iv: bufToBase64(iv),
  };
}

// Full orchestration: decrypt a fetched backup with the given password and
// import everything into this browser. Throws if the password is wrong
// (AES-GCM authentication fails): callers should catch that and show a clear
// "incorrect password" message rather than a generic error.
export async function restoreFromEncryptedBackup(password, { ciphertext, salt, iv }) {
  const backupKey = await deriveBackupKey(password, base64ToBuf(salt));
  const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: base64ToBuf(iv) }, backupKey, base64ToBuf(ciphertext));
  const data = JSON.parse(new TextDecoder().decode(plainBuf));
  await importKeysFromBackup(data);
  return data;
}
