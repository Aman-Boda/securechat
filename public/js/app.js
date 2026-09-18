import { api } from './api.js';
import { connectSocket, onSocket, emitSocket, disconnectSocket } from './socket.js';
import { getOrCreateKeyPair, exportPublicKeyJwk, deriveSharedKey, encryptText, decryptText, computeSafetyNumber } from './crypto.js';

const state = {
  me: null,
  rooms: [],
  activeRoomId: null,
  messagesByRoom: new Map(),
  typingByRoom: new Map(), // roomId -> Map<userId, username>
  onlineUsers: new Set(),
  myKeyPair: null, // { publicKey, privateKey } CryptoKey objects, this browser's E2EE identity
  myPublicKeyJwk: null,
  sharedKeys: new Map(), // roomId -> derived AES-GCM CryptoKey, for DM rooms only
  roomPagination: new Map(), // roomId -> { hasMore: boolean, loading: boolean }
};

// ---------------------------------------------------------------------------
// Small DOM / formatting helpers. Every place that touches user-supplied
// text (usernames, room names, message content) uses textContent, never
// innerHTML — that's what makes the server-side sanitization defense-in-depth
// rather than the only layer.
// ---------------------------------------------------------------------------

const $ = (id) => document.getElementById(id);

function initials(name) {
  return (name || '?').trim().slice(0, 2).toUpperCase();
}

function applyAvatar(el, username, color) {
  el.style.background = color || '#6FA88A';
  el.textContent = initials(username);
}

function makeAvatarEl(username, color, extraClass) {
  const div = document.createElement('div');
  div.className = 'avatar' + (extraClass ? ` ${extraClass}` : '');
  applyAvatar(div, username, color);
  return div;
}

function formatTime(iso) {
  return new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function formatDay(iso) {
  return new Date(iso).toLocaleDateString([], { weekday: 'long', month: 'long', day: 'numeric' });
}

function timeAgo(iso) {
  if (!iso) return 'a while ago';
  const mins = Math.floor((Date.now() - new Date(iso).getTime()) / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

let toastTimeout = null;
function showToast(message) {
  const el = $('toast');
  el.textContent = message;
  el.classList.remove('hidden');
  clearTimeout(toastTimeout);
  toastTimeout = setTimeout(() => el.classList.add('hidden'), 3500);
}

function openModal(id) {
  $(id).classList.remove('hidden');
}
function closeModal(id) {
  $(id).classList.add('hidden');
}

// ---------------------------------------------------------------------------
// End-to-end encryption for DMs
// ---------------------------------------------------------------------------

// Generates (or loads) this browser's key pair and makes sure the server has
// our current public key on file. Called once, right after login.
async function initializeEncryption() {
  state.myKeyPair = await getOrCreateKeyPair();
  state.myPublicKeyJwk = await exportPublicKeyJwk(state.myKeyPair.publicKey);

  const serverKnowsThisKey =
    state.me.publicKey && JSON.stringify(state.me.publicKey) === JSON.stringify(state.myPublicKeyJwk);
  if (!serverKnowsThisKey) {
    try {
      await api.uploadPublicKey(state.myPublicKeyJwk);
    } catch (err) {
      console.error('Could not upload public key — secure messaging may not work yet:', err);
    }
  }
}

// Derives (and caches) the AES-GCM key shared with a DM partner. Returns
// null for group rooms, or if the other person hasn't generated a key yet
// (extremely rare in practice — key upload happens automatically moments
// after their first login, before they'd typically be searchable/messageable).
async function getSharedKeyForRoom(roomId) {
  if (state.sharedKeys.has(roomId)) return state.sharedKeys.get(roomId);

  const room = state.rooms.find((r) => r.id === roomId);
  if (!room || room.isGroup || !room.otherMember?.publicKey || !state.myKeyPair) return null;

  try {
    const key = await deriveSharedKey(state.myKeyPair.privateKey, room.otherMember.publicKey);
    state.sharedKeys.set(roomId, key);
    return key;
  } catch (err) {
    console.warn('Failed to derive shared key for room', roomId, err);
    return null;
  }
}

// Adds a `displayContent` field for rendering, without touching the
// original `content`/`iv` — those stay as the raw values so sidebar preview
// logic can tell encrypted from plain at a glance without decrypting.
async function decorateWithDisplayContent(msg) {
  if (!msg.iv) {
    return { ...msg, displayContent: msg.content };
  }
  const sharedKey = await getSharedKeyForRoom(msg.roomId);
  if (!sharedKey) {
    return { ...msg, displayContent: '🔒 Encrypted message (key not available yet)' };
  }
  const plaintext = await decryptText(sharedKey, msg.content, msg.iv);
  return { ...msg, displayContent: plaintext ?? '⚠️ Could not decrypt this message' };
}

function showSafetyNumberModal(username, code) {
  $('safety-number-username').textContent = username;
  $('safety-number-code').textContent = code;
  openModal('safety-number-modal');
}

// Enables/disables the composer based on whether we can actually encrypt to
// this room's partner yet (always enabled for group rooms, which aren't
// encrypted in this version).
function updateComposerAvailability(room) {
  const input = $('composer-input');
  const sendBtn = $('composer-send');

  if (room.isGroup) {
    input.disabled = false;
    sendBtn.disabled = false;
    input.placeholder = 'Message…';
    return;
  }

  const hasKey = !!room.otherMember?.publicKey;
  input.disabled = !hasKey;
  sendBtn.disabled = !hasKey;
  input.placeholder = hasKey
    ? 'Message…'
    : `Waiting for ${room.otherMember?.username || 'them'} to enable secure messaging…`;
}

// ---------------------------------------------------------------------------
// Room list rendering
// ---------------------------------------------------------------------------

function recencyOf(room) {
  const t = room.lastMessage ? room.lastMessage.createdAt : room.createdAt;
  return new Date(t).getTime();
}

function upsertRoom(partial) {
  const idx = state.rooms.findIndex((r) => r.id === partial.id);
  if (idx === -1) {
    state.rooms.push({
      name: null,
      otherMember: null,
      lastMessage: null,
      memberCount: partial.isGroup ? 1 : 2,
      unreadCount: 0,
      ...partial,
    });
  } else {
    state.rooms[idx] = { ...state.rooms[idx], ...partial };
  }
}

function renderRoomItem(room) {
  const el = document.createElement('div');
  el.className = 'room-item' + (room.id === state.activeRoomId ? ' active' : '') + (room.unreadCount > 0 ? ' has-unread' : '');
  el.dataset.roomId = room.id;

  const avatarName = room.isGroup ? room.name || 'Room' : room.otherMember?.username || '?';
  const avatarColor = room.isGroup ? '#7C93C7' : room.otherMember?.avatarColor;
  const avatar = makeAvatarEl(avatarName, avatarColor);

  if (!room.isGroup && room.otherMember) {
    const dot = document.createElement('span');
    dot.className = 'presence-dot' + (state.onlineUsers.has(room.otherMember.id) ? ' online' : '');
    dot.dataset.presenceFor = room.otherMember.id;
    avatar.appendChild(dot);
  }

  const textWrap = document.createElement('div');
  textWrap.className = 'room-item-text';

  const nameEl = document.createElement('div');
  nameEl.className = 'room-item-name';
  nameEl.textContent = room.isGroup ? `# ${room.name}` : room.otherMember?.username || 'Direct message';

  const previewEl = document.createElement('div');
  previewEl.className = 'room-item-preview';
  if (room.lastMessage) {
    const prefix = room.lastMessage.senderId === state.me.id ? 'You: ' : '';
    if (room.lastMessage.deletedAt) {
      previewEl.textContent = `${prefix}Message deleted`;
    } else if (room.lastMessage.iv) {
      previewEl.textContent = `${prefix}🔒 Encrypted message`;
    } else {
      previewEl.textContent = prefix + room.lastMessage.content;
    }
  } else {
    previewEl.textContent = room.isGroup
      ? `${room.memberCount} member${room.memberCount === 1 ? '' : 's'}`
      : 'No messages yet';
  }

  textWrap.append(nameEl, previewEl);
  el.append(avatar, textWrap);

  if (room.unreadCount > 0) {
    const badge = document.createElement('span');
    badge.className = 'unread-badge';
    badge.textContent = room.unreadCount > 99 ? '99+' : String(room.unreadCount);
    el.appendChild(badge);
  }

  el.addEventListener('click', () => selectRoom(room.id));
  return el;
}

function renderRoomLists() {
  const dmListEl = $('dm-list');
  const roomListEl = $('room-list');
  dmListEl.innerHTML = '';
  roomListEl.innerHTML = '';

  const sorted = [...state.rooms].sort((a, b) => recencyOf(b) - recencyOf(a));
  const dms = sorted.filter((r) => !r.isGroup);
  const groups = sorted.filter((r) => r.isGroup);

  if (dms.length === 0) {
    dmListEl.appendChild(emptyNote('Search above to start a conversation.'));
  } else {
    dms.forEach((r) => dmListEl.appendChild(renderRoomItem(r)));
  }

  if (groups.length === 0) {
    roomListEl.appendChild(emptyNote('Create or browse rooms to join one.'));
  } else {
    groups.forEach((r) => roomListEl.appendChild(renderRoomItem(r)));
  }
}

function emptyNote(text) {
  const note = document.createElement('div');
  note.className = 'empty-note';
  note.textContent = text;
  return note;
}

// ---------------------------------------------------------------------------
// Active room / messages
// ---------------------------------------------------------------------------

async function selectRoom(roomId) {
  state.activeRoomId = roomId;
  document.querySelectorAll('.room-item').forEach((el) => {
    el.classList.toggle('active', el.dataset.roomId === roomId);
  });

  $('chat-empty').classList.add('hidden');
  $('chat-active').classList.remove('hidden');
  $('app-screen').classList.add('show-chat');
  $('members-panel').classList.add('hidden');

  const room = state.rooms.find((r) => r.id === roomId);
  renderChatHeader(room);
  updateComposerAvailability(room);
  emitSocket('room:subscribe', { roomId });
  markRoomRead(roomId);

  if (!state.messagesByRoom.has(roomId)) {
    try {
      const data = await api.getMessages(roomId);
      const decorated = await Promise.all(data.messages.map(decorateWithDisplayContent));
      state.messagesByRoom.set(roomId, decorated);
      state.roomPagination.set(roomId, { hasMore: data.messages.length >= 50, loading: false });
    } catch (err) {
      showToast(err.message);
      state.messagesByRoom.set(roomId, []);
      state.roomPagination.set(roomId, { hasMore: false, loading: false });
    }
  }
  renderMessages(roomId, { anchorToBottom: true });
  renderTypingIndicator(roomId);
  $('composer-input').focus();
}

// Clears the unread badge immediately (optimistic) and tells the server,
// so it stays cleared next time this room's list loads.
function markRoomRead(roomId) {
  const room = state.rooms.find((r) => r.id === roomId);
  if (room && room.unreadCount > 0) {
    room.unreadCount = 0;
    renderRoomLists();
  }
  emitSocket('room:read', { roomId });
}

function renderChatHeader(room) {
  const avatarEl = $('chat-avatar');
  avatarEl.innerHTML = '';
  const membersBtn = $('members-btn');
  const encryptionBadge = $('encryption-badge');

  if (room.isGroup) {
    applyAvatar(avatarEl, room.name || 'Room', '#7C93C7');
    $('chat-title').textContent = `# ${room.name}`;
    $('chat-subtitle').textContent = `${room.memberCount} member${room.memberCount === 1 ? '' : 's'}`;
    membersBtn.classList.remove('hidden');
    encryptionBadge.classList.add('hidden');
  } else {
    const other = room.otherMember;
    applyAvatar(avatarEl, other?.username, other?.avatarColor);
    if (other) {
      const dot = document.createElement('span');
      dot.className = 'presence-dot' + (state.onlineUsers.has(other.id) ? ' online' : '');
      avatarEl.appendChild(dot);
    }
    $('chat-title').textContent = other?.username || 'Direct message';
    $('chat-subtitle').textContent = other
      ? state.onlineUsers.has(other.id)
        ? 'Online'
        : `Last seen ${timeAgo(other.lastSeenAt)}`
      : '';
    membersBtn.classList.add('hidden');
    encryptionBadge.classList.toggle('hidden', !other?.publicKey);
  }
}

function renderMessageRow(msg) {
  const mine = msg.senderId === state.me.id;
  const row = document.createElement('div');
  row.className = 'msg-row' + (mine ? ' mine' : '');
  row.dataset.messageId = msg.id;

  const avatar = makeAvatarEl(msg.senderUsername, msg.senderAvatarColor, 'sm');
  const body = document.createElement('div');
  body.className = 'msg-body';

  const meta = document.createElement('div');
  meta.className = 'msg-meta';
  const sender = document.createElement('span');
  sender.className = 'msg-sender';
  sender.textContent = mine ? 'You' : msg.senderUsername;
  const time = document.createElement('span');
  time.className = 'msg-time';
  time.textContent = formatTime(msg.createdAt);
  meta.append(sender, time);

  if (msg.editedAt && !msg.deletedAt) {
    const editedTag = document.createElement('span');
    editedTag.className = 'msg-edited-tag';
    editedTag.textContent = '(edited)';
    meta.appendChild(editedTag);
  }

  const bubble = document.createElement('div');
  bubble.className = 'msg-bubble';
  if (msg.deletedAt) {
    bubble.classList.add('deleted');
    bubble.textContent = 'Message deleted';
  } else {
    bubble.textContent = msg.displayContent ?? msg.content;
  }

  body.append(meta, bubble);
  row.append(avatar, body);

  if (mine && !msg.deletedAt) {
    const actions = document.createElement('div');
    actions.className = 'msg-actions';

    const editBtn = document.createElement('button');
    editBtn.type = 'button';
    editBtn.className = 'msg-action-btn';
    editBtn.title = 'Edit';
    editBtn.textContent = '✏️';
    editBtn.addEventListener('click', () => enterEditMode(msg, row));

    const deleteBtn = document.createElement('button');
    deleteBtn.type = 'button';
    deleteBtn.className = 'msg-action-btn';
    deleteBtn.title = 'Delete';
    deleteBtn.textContent = '🗑';
    deleteBtn.addEventListener('click', () => confirmDeleteMessage(msg));

    actions.append(editBtn, deleteBtn);
    row.appendChild(actions);
  }

  return row;
}

function replaceMessageRow(msg) {
  const container = $('messages-scroll');
  const existing = container.querySelector(`[data-message-id="${CSS.escape(msg.id)}"]`);
  if (existing) existing.replaceWith(renderMessageRow(msg));
}

function enterEditMode(msg, row) {
  const bubble = row.querySelector('.msg-bubble');
  const original = msg.displayContent ?? msg.content;

  const textarea = document.createElement('textarea');
  textarea.className = 'msg-edit-input';
  textarea.value = original;

  const actionsRow = document.createElement('div');
  actionsRow.className = 'msg-edit-actions';
  const saveBtn = document.createElement('button');
  saveBtn.type = 'button';
  saveBtn.className = 'msg-edit-link';
  saveBtn.textContent = 'Save';
  const cancelBtn = document.createElement('button');
  cancelBtn.type = 'button';
  cancelBtn.className = 'msg-edit-link';
  cancelBtn.textContent = 'Cancel';
  actionsRow.append(saveBtn, cancelBtn);

  bubble.replaceWith(textarea, actionsRow);
  textarea.focus();
  textarea.setSelectionRange(textarea.value.length, textarea.value.length);

  function cancel() {
    textarea.replaceWith(bubble);
    actionsRow.remove();
  }

  async function save() {
    const newContent = textarea.value.trim();
    if (!newContent || newContent === original) {
      cancel();
      return;
    }
    saveBtn.disabled = true;

    let payload = { roomId: msg.roomId, messageId: msg.id, content: newContent };
    const room = state.rooms.find((r) => r.id === msg.roomId);
    if (room && !room.isGroup) {
      const sharedKey = await getSharedKeyForRoom(msg.roomId);
      if (!sharedKey) {
        showToast('Cannot edit — secure messaging is not ready for this conversation.');
        saveBtn.disabled = false;
        return;
      }
      const encrypted = await encryptText(sharedKey, newContent);
      payload = { roomId: msg.roomId, messageId: msg.id, content: encrypted.ciphertext, iv: encrypted.iv };
    }

    emitSocket('message:edit', payload, (res) => {
      if (res && res.error) {
        showToast(res.error);
        saveBtn.disabled = false;
      }
      // On success the message:updated broadcast replaces this row for us.
    });
  }

  saveBtn.addEventListener('click', save);
  cancelBtn.addEventListener('click', cancel);
  textarea.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      save();
    } else if (e.key === 'Escape') {
      cancel();
    }
  });
}

function confirmDeleteMessage(msg) {
  if (!window.confirm('Delete this message? This cannot be undone.')) return;
  emitSocket('message:delete', { roomId: msg.roomId, messageId: msg.id }, (res) => {
    if (res && res.error) showToast(res.error);
  });
}

// anchorToBottom: true forces scroll-to-bottom (opening a room), false
// preserves the exact scroll offset (prepending older history), and null
// (the default) keeps whatever felt natural — sticks to bottom only if the
// user was already near it, so an incoming message doesn't yank someone back
// down while they're reading up through history.
function renderMessages(roomId, { anchorToBottom = null } = {}) {
  const container = $('messages-scroll');
  const oldScrollHeight = container.scrollHeight;
  const oldScrollTop = container.scrollTop;
  const wasNearBottom = oldScrollHeight - oldScrollTop - container.clientHeight < 80;

  container.innerHTML = '';
  const messages = state.messagesByRoom.get(roomId) || [];
  let lastDay = null;
  messages.forEach((msg) => {
    const day = formatDay(msg.createdAt);
    if (day !== lastDay) {
      const divider = document.createElement('div');
      divider.className = 'day-divider';
      divider.textContent = day;
      container.appendChild(divider);
      lastDay = day;
    }
    container.appendChild(renderMessageRow(msg));
  });

  const shouldStickToBottom = anchorToBottom === null ? wasNearBottom : anchorToBottom;
  if (shouldStickToBottom) {
    container.scrollTop = container.scrollHeight;
  } else {
    container.scrollTop = oldScrollTop + (container.scrollHeight - oldScrollHeight);
  }
}

async function maybeLoadOlderMessages(roomId) {
  if (!roomId) return;
  const pagination = state.roomPagination.get(roomId) || { hasMore: true, loading: false };
  if (!pagination.hasMore || pagination.loading) return;

  const messages = state.messagesByRoom.get(roomId) || [];
  if (messages.length === 0) return;

  pagination.loading = true;
  state.roomPagination.set(roomId, pagination);

  try {
    const oldest = messages[0];
    const data = await api.getMessages(roomId, oldest.createdAt);
    const decorated = await Promise.all(data.messages.map(decorateWithDisplayContent));

    pagination.hasMore = data.messages.length >= 50;
    if (decorated.length > 0) {
      state.messagesByRoom.set(roomId, [...decorated, ...messages]);
      if (roomId === state.activeRoomId) renderMessages(roomId, { anchorToBottom: false });
    }
  } catch {
    showToast('Could not load older messages.');
  } finally {
    pagination.loading = false;
    state.roomPagination.set(roomId, pagination);
  }
}

$('messages-scroll').addEventListener('scroll', (e) => {
  if (e.target.scrollTop < 100) maybeLoadOlderMessages(state.activeRoomId);
});

async function handleIncomingMessage(rawMsg) {
  const msg = await decorateWithDisplayContent(rawMsg);
  const list = state.messagesByRoom.get(msg.roomId);
  if (list) list.push(msg);

  const room = state.rooms.find((r) => r.id === msg.roomId);
  if (room) {
    room.lastMessage = {
      content: msg.content,
      iv: msg.iv,
      createdAt: msg.createdAt,
      senderId: msg.senderId,
      senderUsername: msg.senderUsername,
      deletedAt: null,
    };

    const isMine = msg.senderId === state.me.id;
    const isActive = msg.roomId === state.activeRoomId;
    if (!isMine && !isActive) {
      room.unreadCount = (room.unreadCount || 0) + 1;
    } else if (isActive) {
      emitSocket('room:read', { roomId: msg.roomId });
    }
  }
  renderRoomLists();

  if (msg.roomId === state.activeRoomId) {
    if (!list) state.messagesByRoom.set(msg.roomId, [msg]);
    renderMessages(msg.roomId);
  }
}

async function handleMessageUpdated(rawMsg) {
  const msg = await decorateWithDisplayContent(rawMsg);
  const list = state.messagesByRoom.get(msg.roomId);
  if (list) {
    const idx = list.findIndex((m) => m.id === msg.id);
    if (idx !== -1) list[idx] = msg;
  }

  const room = state.rooms.find((r) => r.id === msg.roomId);
  if (room && room.lastMessage && room.lastMessage.createdAt === msg.createdAt) {
    room.lastMessage = {
      content: msg.content,
      iv: msg.iv,
      createdAt: msg.createdAt,
      senderId: msg.senderId,
      senderUsername: msg.senderUsername,
      deletedAt: msg.deletedAt,
    };
    renderRoomLists();
  }

  if (msg.roomId === state.activeRoomId) replaceMessageRow(msg);
}

function handleMessageDeleted({ messageId, roomId, deletedAt }) {
  const list = state.messagesByRoom.get(roomId);
  let updatedMsg = null;
  if (list) {
    const idx = list.findIndex((m) => m.id === messageId);
    if (idx !== -1) {
      list[idx] = { ...list[idx], content: '', iv: null, deletedAt, displayContent: undefined };
      updatedMsg = list[idx];

      const room = state.rooms.find((r) => r.id === roomId);
      if (room && room.lastMessage && idx === list.length - 1) {
        room.lastMessage = { ...room.lastMessage, content: '', iv: null, deletedAt };
        renderRoomLists();
      }
    }
  }

  if (roomId === state.activeRoomId && updatedMsg) replaceMessageRow(updatedMsg);
}

// Fired when someone starts a DM with us, or (in principle) whenever the
// server wants to push a room we're now part of. This is what makes a new
// conversation show up in our sidebar immediately, instead of only after we
// refresh the page.
function handleNewRoom({ room }) {
  const isNew = !state.rooms.some((r) => r.id === room.id);
  upsertRoom(room);
  renderRoomLists();
  if (isNew) {
    const who = room.isGroup ? `#${room.name}` : room.otherMember?.username || 'Someone';
    showToast(room.isGroup ? `You were added to ${who}` : `${who} started a conversation with you`);
  }
}

// ---------------------------------------------------------------------------
// Typing indicator
// ---------------------------------------------------------------------------

function handleTypingUpdate({ roomId, userId, username, isTyping }) {
  if (userId === state.me.id) return;
  if (!state.typingByRoom.has(roomId)) state.typingByRoom.set(roomId, new Map());
  const map = state.typingByRoom.get(roomId);
  if (isTyping) map.set(userId, username);
  else map.delete(userId);

  if (roomId === state.activeRoomId) renderTypingIndicator(roomId);
}

function renderTypingIndicator(roomId) {
  const el = $('typing-indicator');
  const map = state.typingByRoom.get(roomId);
  el.innerHTML = '';
  if (!map || map.size === 0) return;

  const names = [...map.values()];
  const label = document.createElement('span');
  label.textContent = names.length === 1 ? `${names[0]} is typing` : `${names.join(', ')} are typing`;

  const dots = document.createElement('span');
  dots.className = 'typing-dots';
  dots.append(document.createElement('span'), document.createElement('span'), document.createElement('span'));

  el.append(label, dots);
}

// ---------------------------------------------------------------------------
// Presence
// ---------------------------------------------------------------------------

function handlePresenceUpdate({ userId, online, lastSeenAt }) {
  if (online) state.onlineUsers.add(userId);
  else state.onlineUsers.delete(userId);

  document.querySelectorAll('.presence-dot').forEach((dot) => {
    if (dot.dataset.presenceFor === userId) dot.classList.toggle('online', online);
  });

  const activeRoom = state.rooms.find((r) => r.id === state.activeRoomId);
  if (activeRoom && !activeRoom.isGroup && activeRoom.otherMember?.id === userId) {
    if (lastSeenAt) activeRoom.otherMember.lastSeenAt = lastSeenAt;
    renderChatHeader(activeRoom);
  }

  document.querySelectorAll('.member-row').forEach((row) => {
    if (row.dataset.userId === userId) {
      const status = row.querySelector('.status-text');
      if (status) status.textContent = online ? 'Online' : `Last seen ${timeAgo(lastSeenAt)}`;
      const dot = row.querySelector('.presence-dot');
      if (dot) dot.classList.toggle('online', online);
    }
  });
}

// ---------------------------------------------------------------------------
// Members panel
// ---------------------------------------------------------------------------

function renderMembersList(members) {
  const list = $('members-list');
  list.innerHTML = '';
  members.forEach((m) => {
    const row = document.createElement('div');
    row.className = 'member-row';
    row.dataset.userId = m.id;

    const avatar = makeAvatarEl(m.username, m.avatarColor, 'sm');
    const online = state.onlineUsers.has(m.id);
    if (online) {
      const dot = document.createElement('span');
      dot.className = 'presence-dot online';
      avatar.appendChild(dot);
    }

    const name = document.createElement('span');
    name.textContent = m.username;
    const status = document.createElement('span');
    status.className = 'status-text';
    status.textContent = online ? 'Online' : `Last seen ${timeAgo(m.lastSeenAt)}`;

    row.append(avatar, name, status);
    list.appendChild(row);
  });
}

$('members-btn').addEventListener('click', async () => {
  const panel = $('members-panel');
  if (!panel.classList.contains('hidden')) {
    panel.classList.add('hidden');
    return;
  }
  const room = state.rooms.find((r) => r.id === state.activeRoomId);
  if (!room || !room.isGroup) return;
  try {
    const data = await api.getMembers(room.id);
    renderMembersList(data.members);
    panel.classList.remove('hidden');
  } catch (err) {
    showToast(err.message);
  }
});

$('encryption-badge').addEventListener('click', async () => {
  const room = state.rooms.find((r) => r.id === state.activeRoomId);
  if (!room || room.isGroup || !room.otherMember?.publicKey || !state.myPublicKeyJwk) return;
  try {
    const code = await computeSafetyNumber(state.me.id, state.myPublicKeyJwk, room.otherMember.id, room.otherMember.publicKey);
    showSafetyNumberModal(room.otherMember.username, code);
  } catch (err) {
    showToast('Could not compute the safety number.');
  }
});

// ---------------------------------------------------------------------------
// User search -> start a DM
// ---------------------------------------------------------------------------

let searchDebounce = null;
$('user-search').addEventListener('input', (e) => {
  clearTimeout(searchDebounce);
  const q = e.target.value.trim();
  const resultsEl = $('search-results');
  if (!q) {
    resultsEl.classList.add('hidden');
    resultsEl.innerHTML = '';
    return;
  }
  searchDebounce = setTimeout(async () => {
    try {
      const data = await api.searchUsers(q);
      renderSearchResults(data.users);
    } catch {
      // Silent: search-as-you-type shouldn't surface transient errors.
    }
  }, 250);
});

function renderSearchResults(users) {
  const resultsEl = $('search-results');
  resultsEl.innerHTML = '';
  if (users.length === 0) {
    resultsEl.classList.add('hidden');
    return;
  }
  users.forEach((u) => {
    const item = document.createElement('div');
    item.className = 'search-result-item';
    const avatar = makeAvatarEl(u.username, u.avatarColor, 'sm');
    const name = document.createElement('span');
    name.textContent = u.username;
    item.append(avatar, name);
    item.addEventListener('click', () => startDirectMessage(u.id));
    resultsEl.appendChild(item);
  });
  resultsEl.classList.remove('hidden');
}

async function startDirectMessage(userId) {
  try {
    const data = await api.startDirect(userId);
    upsertRoom({
      id: data.room.id,
      isGroup: false,
      createdAt: data.room.createdAt,
      otherMember: data.room.otherMember,
    });
    emitSocket('room:subscribe', { roomId: data.room.id });
    $('user-search').value = '';
    $('search-results').classList.add('hidden');
    renderRoomLists();
    selectRoom(data.room.id);
  } catch (err) {
    showToast(err.message);
  }
}

// ---------------------------------------------------------------------------
// Group rooms: create + browse/join
// ---------------------------------------------------------------------------

$('new-room-btn').addEventListener('click', () => openModal('new-room-modal'));

$('new-room-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const input = $('new-room-name');
  const name = input.value.trim();
  if (!name) return;
  try {
    const data = await api.createGroup(name);
    upsertRoom({ id: data.room.id, name: data.room.name, isGroup: true, createdAt: data.room.createdAt, memberCount: 1 });
    emitSocket('room:subscribe', { roomId: data.room.id });
    input.value = '';
    closeModal('new-room-modal');
    renderRoomLists();
    selectRoom(data.room.id);
  } catch (err) {
    showToast(err.message);
  }
});

$('browse-rooms-btn').addEventListener('click', async () => {
  openModal('browse-rooms-modal');
  try {
    const data = await api.listJoinableRooms();
    renderJoinableList(data.rooms);
  } catch (err) {
    showToast(err.message);
  }
});

function renderJoinableList(rooms) {
  const list = $('joinable-list');
  list.innerHTML = '';
  if (rooms.length === 0) {
    list.appendChild(emptyNote('No other rooms to join right now.'));
    return;
  }
  rooms.forEach((r) => {
    const item = document.createElement('div');
    item.className = 'joinable-item';

    const info = document.createElement('div');
    const nameEl = document.createElement('span');
    nameEl.textContent = r.name;
    const countEl = document.createElement('span');
    countEl.className = 'count';
    countEl.textContent = ` · ${r.memberCount} member${r.memberCount === 1 ? '' : 's'}`;
    info.append(nameEl, countEl);

    const joinBtn = document.createElement('button');
    joinBtn.type = 'button';
    joinBtn.className = 'btn btn-ghost';
    joinBtn.textContent = 'Join';
    joinBtn.addEventListener('click', async () => {
      try {
        await api.joinRoom(r.id);
        upsertRoom({
          id: r.id,
          name: r.name,
          isGroup: true,
          createdAt: r.createdAt,
          memberCount: r.memberCount + 1,
        });
        emitSocket('room:subscribe', { roomId: r.id });
        renderRoomLists();
        closeModal('browse-rooms-modal');
        selectRoom(r.id);
      } catch (err) {
        showToast(err.message);
      }
    });

    item.append(info, joinBtn);
    list.appendChild(item);
  });
}

document.querySelectorAll('[data-close-modal]').forEach((btn) => {
  btn.addEventListener('click', (e) => e.target.closest('.modal-backdrop').classList.add('hidden'));
});
document.querySelectorAll('.modal-backdrop').forEach((backdrop) => {
  backdrop.addEventListener('click', (e) => {
    if (e.target === backdrop) backdrop.classList.add('hidden');
  });
});

// ---------------------------------------------------------------------------
// Composer: sending messages + typing signals
// ---------------------------------------------------------------------------

const composerForm = $('composer-form');
const composerInput = $('composer-input');
let typingTimeout = null;
let isCurrentlyTyping = false;

function autoGrow(el) {
  el.style.height = 'auto';
  el.style.height = `${Math.min(el.scrollHeight, 120)}px`;
}

composerInput.addEventListener('input', () => {
  autoGrow(composerInput);
  if (!state.activeRoomId) return;
  if (!isCurrentlyTyping) {
    isCurrentlyTyping = true;
    emitSocket('typing:start', { roomId: state.activeRoomId });
  }
  clearTimeout(typingTimeout);
  typingTimeout = setTimeout(() => {
    isCurrentlyTyping = false;
    emitSocket('typing:stop', { roomId: state.activeRoomId });
  }, 1500);
});

composerInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    composerForm.requestSubmit();
  }
});

composerForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const content = composerInput.value.trim();
  const roomId = state.activeRoomId;
  if (!content || !roomId) return;

  const room = state.rooms.find((r) => r.id === roomId);
  let payload = { roomId, content };

  if (room && !room.isGroup) {
    const sharedKey = await getSharedKeyForRoom(roomId);
    if (!sharedKey) {
      showToast('Cannot send yet — secure messaging is not ready for this conversation.');
      return;
    }
    const { ciphertext, iv } = await encryptText(sharedKey, content);
    payload = { roomId, content: ciphertext, iv };
  }

  emitSocket('message:send', payload, (res) => {
    if (res && res.error) showToast(res.error);
  });

  composerInput.value = '';
  autoGrow(composerInput);
  clearTimeout(typingTimeout);
  if (isCurrentlyTyping) {
    isCurrentlyTyping = false;
    emitSocket('typing:stop', { roomId });
  }
});

// ---------------------------------------------------------------------------
// Navigation / auth
// ---------------------------------------------------------------------------

$('back-btn').addEventListener('click', () => $('app-screen').classList.remove('show-chat'));

function switchAuthForm(which) {
  $('login-form').classList.toggle('hidden', which !== 'login');
  $('register-form').classList.toggle('hidden', which !== 'register');
  $('forgot-password-form').classList.toggle('hidden', which !== 'forgot-password');
  $('reset-password-form').classList.toggle('hidden', which !== 'reset-password');
  $('login-error').classList.add('hidden');
  $('register-error').classList.add('hidden');
  $('forgot-password-error').classList.add('hidden');
  $('forgot-password-success').classList.add('hidden');
  $('reset-password-error').classList.add('hidden');
}
$('show-register').addEventListener('click', () => switchAuthForm('register'));
$('show-login').addEventListener('click', () => switchAuthForm('login'));
$('show-forgot-password').addEventListener('click', () => switchAuthForm('forgot-password'));
$('show-login-from-forgot').addEventListener('click', () => switchAuthForm('login'));

$('forgot-password-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = $('forgot-password-email').value.trim();
  const btn = $('forgot-password-submit');
  const errorEl = $('forgot-password-error');
  const successEl = $('forgot-password-success');
  errorEl.classList.add('hidden');
  successEl.classList.add('hidden');
  btn.disabled = true;
  try {
    const data = await api.forgotPassword(email);
    successEl.textContent = data.message;
    successEl.classList.remove('hidden');
    $('forgot-password-form').reset();
  } catch (err) {
    errorEl.textContent = err.message;
    errorEl.classList.remove('hidden');
  } finally {
    btn.disabled = false;
  }
});

let pendingResetToken = null;

$('reset-password-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const newPassword = $('reset-password-new').value;
  const btn = $('reset-password-submit');
  const errorEl = $('reset-password-error');
  errorEl.classList.add('hidden');
  btn.disabled = true;
  try {
    const data = await api.resetPassword(pendingResetToken, newPassword);
    pendingResetToken = null;
    showToast('Password updated — you are now logged in.');
    await initApp(data.user);
  } catch (err) {
    errorEl.textContent = err.message;
    errorEl.classList.remove('hidden');
  } finally {
    btn.disabled = false;
  }
});

$('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const identifier = $('login-identifier').value.trim();
  const password = $('login-password').value;
  const btn = $('login-submit');
  const errorEl = $('login-error');
  errorEl.classList.add('hidden');
  btn.disabled = true;
  try {
    const data = await api.login({ identifier, password });
    await initApp(data.user);
  } catch (err) {
    errorEl.textContent = err.message;
    errorEl.classList.remove('hidden');
  } finally {
    btn.disabled = false;
  }
});

$('register-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const username = $('register-username').value.trim();
  const email = $('register-email').value.trim();
  const password = $('register-password').value;
  const btn = $('register-submit');
  const errorEl = $('register-error');
  errorEl.classList.add('hidden');
  btn.disabled = true;
  try {
    const data = await api.register({ username, email, password });
    await initApp(data.user);
  } catch (err) {
    errorEl.textContent = err.message;
    errorEl.classList.remove('hidden');
  } finally {
    btn.disabled = false;
  }
});

$('logout-btn').addEventListener('click', async () => {
  try {
    await api.logout();
  } catch {
    // Even if the request fails, still clear local state and log the UI out.
  }
  disconnectSocket();
  state.me = null;
  state.rooms = [];
  state.activeRoomId = null;
  state.messagesByRoom.clear();
  state.typingByRoom.clear();
  state.onlineUsers.clear();
  showAuthScreen();
});

function showAuthScreen() {
  $('app-screen').classList.add('hidden');
  $('auth-screen').classList.remove('hidden');
  switchAuthForm('login');
  $('login-form').reset();
  $('register-form').reset();
  $('forgot-password-form').reset();
  $('reset-password-form').reset();
}

async function initApp(user) {
  state.me = user;
  $('auth-screen').classList.add('hidden');
  $('app-screen').classList.remove('hidden');

  applyAvatar($('me-avatar'), user.username, user.avatarColor);
  $('me-name').textContent = user.username;
  updateVerifyBanner();

  try {
    await initializeEncryption();
  } catch (err) {
    console.error('Encryption setup failed — secure messaging may not work this session:', err);
    showToast('Secure messaging could not initialize in this browser.');
  }

  connectSocket();
  onSocket('message:new', handleIncomingMessage);
  onSocket('message:updated', handleMessageUpdated);
  onSocket('message:deleted', handleMessageDeleted);
  onSocket('presence:update', handlePresenceUpdate);
  onSocket('typing:update', handleTypingUpdate);
  onSocket('room:new', handleNewRoom);

  try {
    const data = await api.listRooms();
    state.rooms = data.rooms;
    renderRoomLists();
  } catch {
    showToast('Could not load your conversations.');
  }
}

// Dismissal is per-session only (a plain JS variable, not persisted) — the
// reminder comes back next time they open the app, since an unverified
// email is a standing thing worth resurfacing, not a one-time nag.
let verifyBannerDismissed = false;

function updateVerifyBanner() {
  const banner = $('verify-banner');
  const shouldShow = state.me && !state.me.emailVerified && !verifyBannerDismissed;
  banner.classList.toggle('hidden', !shouldShow);
}

$('resend-verification-btn').addEventListener('click', async () => {
  try {
    await api.resendVerification();
    showToast('Verification email sent — check your inbox.');
  } catch (err) {
    showToast(err.message);
  }
});

$('dismiss-verify-banner').addEventListener('click', () => {
  verifyBannerDismissed = true;
  updateVerifyBanner();
});

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

(async function bootstrap() {
  const params = new URLSearchParams(window.location.search);
  const verifyToken = params.get('verify');
  const resetToken = params.get('reset');

  if (verifyToken) {
    window.history.replaceState({}, '', window.location.pathname);
    try {
      await api.verifyEmail(verifyToken);
      showToast('Email verified!');
    } catch (err) {
      showToast(err.message);
    }
  }

  if (resetToken) {
    window.history.replaceState({}, '', window.location.pathname);
    pendingResetToken = resetToken;
    showAuthScreen();
    switchAuthForm('reset-password');
    return; // let them set a new password rather than auto-continuing any existing session
  }

  try {
    const data = await api.me();
    await initApp(data.user);
  } catch {
    showAuthScreen();
  }
})();
