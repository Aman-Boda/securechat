// End-to-end encryption for direct messages.
//
// How it works: each browser generates its own ECDH (P-256) key pair. The
// PRIVATE key is stored in IndexedDB and never sent anywhere. The PUBLIC key
// is uploaded to the server so other people can find it. To message someone,
// your browser combines YOUR private key with THEIR public key (ECDH) to
// derive a shared AES-256-GCM key — the other person derives the exact same
// key using their private key and your public key. The server only ever
// sees ciphertext; it has neither private key, so it cannot decrypt.
//
// Known limitations (documented here deliberately, not hidden):
// - No forward secrecy: this uses one static derived key per conversation,
//   not a rotating per-message key like Signal's Double Ratchet. If a
//   private key is ever compromised, past messages become decryptable.
// - Single-device: the private key lives in this browser's storage. Logging
//   in on a different browser/device generates a NEW key pair, and old
//   messages encrypted for the old key become unreadable there.
// - No built-in identity verification UI beyond the safety number below —
//   comparing it out-of-band is what actually protects against a malicious
//   server substituting a public key mid-conversation.

const DB_NAME = 'securechat-keys';
const STORE_NAME = 'keys';
const RECORD_KEY = 'identity';
const EC_PARAMS = { name: 'ECDH', namedCurve: 'P-256' };

function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => {
      req.result.createObjectStore(STORE_NAME);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function getStoredKeyPair() {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly');
    const req = tx.objectStore(STORE_NAME).get(RECORD_KEY);
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => reject(req.error);
  });
}

async function storeKeyPair(pair) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    tx.objectStore(STORE_NAME).put(pair, RECORD_KEY);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

let cachedKeyPair = null;

// Returns { publicKey, privateKey } CryptoKey objects for this browser,
// generating and persisting a new pair on first use.
export async function getOrCreateKeyPair() {
  if (cachedKeyPair) return cachedKeyPair;

  try {
    const stored = await getStoredKeyPair();
    if (stored && stored.publicKey && stored.privateKey) {
      cachedKeyPair = stored;
      return stored;
    }
  } catch (err) {
    console.warn('Could not read stored encryption keys — generating a fresh pair for this session:', err);
  }

  const pair = await crypto.subtle.generateKey(EC_PARAMS, true, ['deriveKey']);
  cachedKeyPair = pair;

  try {
    await storeKeyPair(pair);
  } catch (err) {
    console.warn('Could not persist encryption keys — they will regenerate next session:', err);
  }

  return pair;
}

export function exportPublicKeyJwk(publicKey) {
  return crypto.subtle.exportKey('jwk', publicKey);
}

// Derives the shared AES-GCM key for a conversation. Both sides compute the
// same key independently — it is never transmitted.
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
// each other and not to a server silently substituting a public key. Both
// sides compute the exact same number, in either order, independently.
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
