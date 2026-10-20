const groupKeyRepo = require('../db/repositories/groupKeyRepo');

const MAX_CIPHERTEXT_LENGTH = 8000;

// Validates a message sent to an ENCRYPTED GROUP. As with DMs, the server never
// sees plaintext or the group key: it only checks that the payload is sane and
// that the sender actually holds the key generation they say they used.
async function validateGroupPayload(room, body, userId) {
  const { content, iv, epochIndex, keyMode } = body || {};
  if (typeof iv !== 'string' || !iv || typeof content !== 'string' || !content) {
    return { error: 'This group is end-to-end encrypted: messages must be sent encrypted.' };
  }
  if (content.length > MAX_CIPHERTEXT_LENGTH) return { error: 'Message too large.' };
  if (keyMode !== 'group') return { error: "keyMode must be 'group' for encrypted groups." };
  if (!Number.isInteger(epochIndex) || epochIndex < 1 || epochIndex > room.key_generation) {
    return { error: 'Unknown group key generation.' };
  }
  if (!(await groupKeyRepo.hasKey(room.id, userId, epochIndex))) {
    return { error: 'You do not hold that group key yet.' };
  }
  return { content, iv, epochIndex, keyMode: 'group' };
}

module.exports = { validateGroupPayload };
