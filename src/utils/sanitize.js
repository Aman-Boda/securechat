const sanitizeHtml = require('sanitize-html');

const MAX_MESSAGE_LENGTH = 4000;

// This is a plain-text chat, not a rich-text editor, so we strip ALL HTML
// rather than trying to allow-list "safe" tags. Combined with the frontend
// rendering message text via textContent (never innerHTML), this gives
// defense-in-depth against stored XSS even if one layer has a bug.
function sanitizeMessageContent(raw) {
  if (typeof raw !== 'string') return '';
  const trimmed = raw.trim().slice(0, MAX_MESSAGE_LENGTH);
  return sanitizeHtml(trimmed, { allowedTags: [], allowedAttributes: {} });
}

module.exports = { sanitizeMessageContent, MAX_MESSAGE_LENGTH };
