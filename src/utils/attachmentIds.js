const ID_RE = /^[0-9a-fA-F-]{36}$/;

// Attachment ids sent alongside an encrypted message. Anything that is not a
// plain id is dropped; at most four images per message.
function parseAttachmentIds(raw) {
  if (!Array.isArray(raw)) return [];
  const out = [];
  for (const v of raw) {
    if (typeof v === 'string' && ID_RE.test(v) && !out.includes(v)) out.push(v);
  }
  return out.slice(0, 4);
}

module.exports = { parseAttachmentIds, ID_RE };
