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
  listRooms: () => apiFetch('/api/rooms'),
  listJoinableRooms: () => apiFetch('/api/rooms/joinable'),
  createGroup: (name) => apiFetch('/api/rooms/group', { method: 'POST', body: JSON.stringify({ name }) }),
  startDirect: (userId) => apiFetch('/api/rooms/direct', { method: 'POST', body: JSON.stringify({ userId }) }),
  joinRoom: (roomId) => apiFetch(`/api/rooms/${roomId}/join`, { method: 'POST' }),
  leaveRoom: (roomId) => apiFetch(`/api/rooms/${roomId}/leave`, { method: 'POST' }),
  getMembers: (roomId) => apiFetch(`/api/rooms/${roomId}/members`),
  getMessages: (roomId, before) =>
    apiFetch(`/api/rooms/${roomId}/messages${before ? `?before=${encodeURIComponent(before)}` : ''}`),
};
