// The "envelope" is what actually gets encrypted for a message. A plain message
// is just its text (exactly as before). A reply and/or attached images wrap the
// text in a small JSON object, so WHO is being replied to, the quoted snippet,
// and the keys to the images all stay inside the encryption.
const MARK = '{"v":1';
const ID_RE = /^[0-9a-fA-F-]{36}$/;
const MIME_OK = new Set(['image/jpeg', 'image/png', 'image/webp']);

const clampInt = (n) => (Number.isInteger(n) && n >= 0 && n <= 20000 ? n : 0);

export function buildEnvelopeText({ text = '', reply = null, attachments = [] } = {}) {
  if (!reply && attachments.length === 0 && !text.startsWith(MARK)) return text;
  const env = { v: 1, t: text };
  if (reply) env.r = { id: reply.id, n: reply.name || '', t: reply.snippet || '' };
  if (attachments.length > 0) {
    env.a = attachments.map((a) => ({ id: a.id, k: a.key, m: a.mime, w: a.width, h: a.height, s: a.size }));
  }
  return JSON.stringify(env);
}

function cleanReply(r) {
  if (!r || typeof r !== 'object' || typeof r.id !== 'string' || !r.id || r.id.length > 64) return null;
  return { id: r.id, name: typeof r.n === 'string' ? r.n.slice(0, 40) : '', snippet: typeof r.t === 'string' ? r.t.slice(0, 200) : '' };
}

// Anything that came out of a decrypted message is untrusted: ids end up in a
// URL, so only real ids are accepted.
function cleanAttachments(a) {
  if (!Array.isArray(a)) return [];
  return a
    .slice(0, 4)
    .filter((x) => x && typeof x === 'object' && typeof x.id === 'string' && ID_RE.test(x.id) &&
      typeof x.k === 'string' && x.k.length > 0 && x.k.length <= 64 && MIME_OK.has(x.m))
    .map((x) => ({ id: x.id, key: x.k, mime: x.m, width: clampInt(x.w), height: clampInt(x.h), size: clampInt(x.s) }));
}

export function parseEnvelope(plain) {
  if (typeof plain === 'string' && plain.startsWith(MARK)) {
    try {
      const env = JSON.parse(plain);
      if (env && env.v === 1 && typeof env.t === 'string') {
        return { isEnvelope: true, text: env.t, reply: cleanReply(env.r), attachments: cleanAttachments(env.a) };
      }
    } catch {
      // plain text that merely looks like JSON
    }
  }
  return { isEnvelope: false, text: plain, reply: null, attachments: [] };
}
