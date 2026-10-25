// Images: shrunk in the browser, then encrypted with a fresh one-time AES-GCM
// key. The server only ever stores the ciphertext; the key travels inside the
// (end-to-end encrypted) message. Re-encoding through a canvas also strips
// camera metadata such as GPS location.
export const ACCEPTED_TYPES = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
const MAX_DIMENSION = 1280;
const MAX_BYTES = 900 * 1024;

function toB64(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(s);
}

function fromB64(b64) {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i += 1) out[i] = s.charCodeAt(i);
  return out;
}

// Returns { blob: iv + ciphertext, keyB64 }.
export async function encryptAttachmentBytes(bytes) {
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes));
  const blob = new Uint8Array(12 + ciphertext.length);
  blob.set(iv, 0);
  blob.set(ciphertext, 12);
  return { blob, keyB64: toB64(new Uint8Array(await crypto.subtle.exportKey('raw', key))) };
}

// Throws if the key is wrong or the blob was tampered with.
export async function decryptAttachmentBytes(blob, keyB64) {
  const key = await crypto.subtle.importKey('raw', fromB64(keyB64), 'AES-GCM', false, ['decrypt']);
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: blob.subarray(0, 12) }, key, blob.subarray(12)));
}

// Browser only. Shrinks to at most 1280px on the long side as a JPEG, lowering
// size/quality until it fits comfortably under the upload limit.
export async function resizeImageFile(file) {
  if (!ACCEPTED_TYPES.includes(file.type)) throw new Error('Choose a PNG, JPEG, WebP or GIF image.');
  const bitmap = await createImageBitmap(file);
  let scale = Math.min(1, MAX_DIMENSION / Math.max(bitmap.width, bitmap.height));
  for (let attempt = 0; attempt < 6; attempt += 1) {
    const width = Math.max(1, Math.round(bitmap.width * scale));
    const height = Math.max(1, Math.round(bitmap.height * scale));
    const canvas = document.createElement('canvas');
    canvas.width = width;
    canvas.height = height;
    const ctx = canvas.getContext('2d');
    ctx.fillStyle = '#ffffff'; // JPEG has no transparency
    ctx.fillRect(0, 0, width, height);
    ctx.drawImage(bitmap, 0, 0, width, height);
    const quality = Math.max(0.5, 0.85 - attempt * 0.08);
    const blob = await new Promise((resolve) => canvas.toBlob(resolve, 'image/jpeg', quality));
    if (blob && blob.size <= MAX_BYTES) {
      if (bitmap.close) bitmap.close();
      return { bytes: new Uint8Array(await blob.arrayBuffer()), mime: 'image/jpeg', width, height };
    }
    scale *= 0.8;
  }
  throw new Error('That image is still too large after shrinking.');
}
