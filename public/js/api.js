async function apiFetch(path, options = {}) {
  const res = await fetch(path, {
    credentials: 'same-origin', // send the httpOnly auth cookie
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options,
  });

  const text = await res.text();
  let data = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = null;
    }
  }

  if (!res.ok) {
    const err = new Error((data && data.error) || `Request failed (${res.status})`);
    err.status = res.status;
    throw err;
  }

  return data;
}

export const api = {
  register: (payload) => apiFetch('/api/auth/register', { method: 'POST', body: JSON.stringify(payload) }),
  login: (payload) => apiFetch('/api/auth/login', { method: 'POST', body: JSON.stringify(payload) }),
  logout: () => apiFetch('/api/auth/logout', { method: 'POST' }),
  me: () => apiFetch('/api/auth/me'),
  verifyEmail: (token) => apiFetch('/api/auth/verify-email', { method: 'POST', body: JSON.stringify({ token }) }),
  resendVerification: () => apiFetch('/api/auth/resend-verification', { method: 'POST' }),
  forgotPassword: (email) => apiFetch('/api/auth/forgot-password', { method: 'POST', body: JSON.stringify({ email }) }),
  resetPassword: (token, newPassword) =>
    apiFetch('/api/auth/reset-password', { method: 'POST', body: JSON.stringify({ token, newPassword }) }),
  searchUsers: (q) => apiFetch(`/api/users/search?q=${encodeURIComponent(q)}`),
  uploadPublicKey: (publicKey) =>
    apiFetch('/api/users/me/public-key', { method: 'PUT', body: JSON.stringify({ publicKey }) }),
  publishEpochKey: (epochIndex, publicKey) =>
    apiFetch('/api/users/me/epoch-key', { method: 'PUT', body: JSON.stringify({ epochIndex, publicKey }) }),
  getEpochKey: (userId, epochIndex) => apiFetch(`/api/users/${userId}/epoch-key/${epochIndex}`),
  setSecurityMode: (securityMode) =>
    apiFetch('/api/users/me/security-mode', { method: 'PUT', body: JSON.stringify({ securityMode }) }),
  setKeyBackup: (backup) => apiFetch('/api/users/me/key-backup', { method: 'PUT', body: JSON.stringify(backup) }),
  getKeyBackup: () => apiFetch('/api/users/me/key-backup'),
  listRooms: () => apiFetch('/api/rooms'),
  listJoinableRooms: () => apiFetch('/api/rooms/joinable'),
  createGroup: (payload) => apiFetch('/api/rooms/group', { method: 'POST', body: JSON.stringify(payload) }),
  getGroupKeys: (roomId) => apiFetch(`/api/rooms/${roomId}/keys`),
  // Encrypted image bytes (iv + AES-GCM ciphertext). The server cannot read them.
  uploadAttachment: async (roomId, bytes) => {
    const res = await fetch(`/api/rooms/${roomId}/attachments`, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/octet-stream' },
      body: bytes,
    });
    let data = null;
    try {
      data = await res.json();
    } catch {
      data = null;
    }
    if (!res.ok) {
      const err = new Error((data && data.error) || `Upload failed (${res.status})`);
      err.status = res.status;
      throw err;
    }
    return data;
  },
  setReaction: (roomId, messageId, payload) =>
    apiFetch(`/api/rooms/${roomId}/messages/${messageId}/reaction`, { method: 'PUT', body: JSON.stringify(payload) }),
  removeReaction: (roomId, messageId) =>
    apiFetch(`/api/rooms/${roomId}/messages/${messageId}/reaction`, { method: 'DELETE' }),
  getGroupKeyStatus: (roomId) => apiFetch(`/api/rooms/${roomId}/key-status`),
  putGroupKeys: (roomId, body) => apiFetch(`/api/rooms/${roomId}/keys`, { method: 'PUT', body: JSON.stringify(body) }),
  addGroupMember: (roomId, userId) =>
    apiFetch(`/api/rooms/${roomId}/members`, { method: 'POST', body: JSON.stringify({ userId }) }),
  removeGroupMember: (roomId, userId) => apiFetch(`/api/rooms/${roomId}/members/${userId}`, { method: 'DELETE' }),
  updateGroupSettings: (roomId, settings) =>
    apiFetch(`/api/rooms/${roomId}/settings`, { method: 'PATCH', body: JSON.stringify(settings) }),
  startDirect: (userId) => apiFetch('/api/rooms/direct', { method: 'POST', body: JSON.stringify({ userId }) }),
  joinRoom: (roomId) => apiFetch(`/api/rooms/${roomId}/join`, { method: 'POST' }),
  leaveRoom: (roomId) => apiFetch(`/api/rooms/${roomId}/leave`, { method: 'POST' }),
  getMembers: (roomId) => apiFetch(`/api/rooms/${roomId}/members`),
  getMessages: (roomId, before) =>
    apiFetch(`/api/rooms/${roomId}/messages${before ? `?before=${encodeURIComponent(before)}` : ''}`),
};
