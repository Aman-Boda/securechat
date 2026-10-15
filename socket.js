// Wraps the global `io` provided by /socket.io/socket.io.js (served by our
// own Socket.io server — no external CDN, so it works fully self-hosted and
// keeps the Content-Security-Policy locked to 'self').
let socket = null;
const listeners = new Map(); // event -> Set<callback>

export function connectSocket() {
  if (socket) return socket;
  socket = window.io({ withCredentials: true });
  return socket;
}

function ensureBinding(event) {
  if (listeners.has(event)) return;
  listeners.set(event, new Set());
  socket.on(event, (...args) => {
    listeners.get(event).forEach((cb) => cb(...args));
  });
}

export function onSocket(event, callback) {
  if (!socket) throw new Error('Socket is not connected yet.');
  ensureBinding(event);
  listeners.get(event).add(callback);
}

export function emitSocket(event, payload, ack) {
  if (!socket) return;
  if (typeof ack === 'function') socket.emit(event, payload, ack);
  else socket.emit(event, payload);
}

export function disconnectSocket() {
  if (socket) {
    socket.disconnect();
    socket = null;
  }
  listeners.clear();
}
