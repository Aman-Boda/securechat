import { api } from './api.js';
import { connectSocket, onSocket, emitSocket, disconnectSocket } from './socket.js';
import {
  getOrCreateKeyPair,
  exportPublicKeyJwk,
  deriveSharedKey,
  encryptText,
  decryptText,
  computeSafetyNumber,
  currentEpochIndex,
  getOrCreateCurrentEpochKeyPair,
  getEphemeralPrivateKeyForEpoch,
  createEncryptedBackup,
  restoreFromEncryptedBackup,
  setKeyOwner,
  migrateLegacyKeys,
  purgeLegacyEphemeralKeys,
  generateGroupKey,
  wrapGroupKey,
  unwrapGroupKey,
  encryptGroupMessage,
  decryptGroupMessage,
  publicKeyFingerprint,
} from './crypto.js';
import { createKeyring } from './groupKeys.js';

const state = {
  me: null,
  rooms: [],
  activeRoomId: null,
  messagesByRoom: new Map(),
  typingByRoom: new Map(), // roomId -> Map<userId, username>
  onlineUsers: new Set(),
  myKeyPair: null, // { publicKey, privateKey } CryptoKey objects, this browser's E2EE identity
  myPublicKeyJwk: null,
  derivedKeyCache: new Map(), // composite key -> derived AES-GCM CryptoKey, avoids re-deriving per message
  theirEpochKeyCache: new Map(), // "userId:epochIndex" -> their published epoch public key JWK (positive hits only)
  publishedEpochIndex: null, // which epoch we've already told the server our current ephemeral public key for
  roomPagination: new Map(), // roomId -> { hasMore: boolean, loading: boolean }
};

// ---------------------------------------------------------------------------
// Small DOM / formatting helpers. Every place that touches user-supplied
// text (usernames, room names, message content) uses textContent, never
// innerHTML — that's what makes the server-side sanitization defense-in-depth
// rather than the only layer.
// ---------------------------------------------------------------------------

// Group chat keys (see groupKeys.js). `state` is only read when a method runs,
// so creating the keyring before anything has happened is safe.
const keyring = createKeyring({
  api,
  crypto: { generateGroupKey, wrapGroupKey, unwrapGroupKey, keyFingerprint: publicKeyFingerprint },
  getMyPublicJwk: () => state.myPublicKeyJwk,
});

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
  // Existing accounts: bring their keys across from the old shared key database
  // (copy only) before anything generates new ones.
  legacyMigrationOk = true;
  try {
    await migrateLegacyKeys(state.me.publicKey);
  } catch (err) {
    legacyMigrationOk = false;
    console.error('Could not migrate keys from the old storage:', err);
  }

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

// Publishes our ephemeral public key for the CURRENT epoch, but only once
// per epoch per session — the server upsert is idempotent anyway, this just
// avoids a redundant network call on every message.
async function ensureEpochKeyPublished() {
  const { epochIndex, pair } = await getOrCreateCurrentEpochKeyPair(state.me?.securityMode);
  if (state.publishedEpochIndex !== epochIndex) {
    try {
      const publicJwk = await exportPublicKeyJwk(pair.publicKey);
      await api.publishEpochKey(epochIndex, publicJwk);
      state.publishedEpochIndex = epochIndex;
    } catch (err) {
      console.error('Failed to publish ephemeral epoch key — will retry next send:', err);
    }
  }
  return { epochIndex, pair };
}

// Looks up (and caches positive results for) a DM partner's published
// epoch key. A null result isn't cached long-term — they may publish one
// moments later, so we just ask again next time rather than remembering
// "no key" for the rest of the epoch.
async function fetchTheirEpochKey(userId, epochIndex) {
  const cacheKey = `${userId}:${epochIndex}`;
  if (state.theirEpochKeyCache.has(cacheKey)) return state.theirEpochKeyCache.get(cacheKey);
  try {
    const data = await api.getEpochKey(userId, epochIndex);
    if (data.publicKey) state.theirEpochKeyCache.set(cacheKey, data.publicKey);
    return data.publicKey;
  } catch {
    return null;
  }
}

async function getCachedDerivedKey(cacheKey, myKey, theirJwk) {
  let key = state.derivedKeyCache.get(cacheKey);
  if (!key) {
    key = await deriveSharedKey(myKey, theirJwk);
    state.derivedKeyCache.set(cacheKey, key);
  }
  return key;
}

// Prepares everything needed to send an encrypted DM: our fresh ephemeral
// key for this epoch, the strongest key we can derive with the recipient
// (mutual-ephemeral if they've published one this epoch, their static
// identity key as a fallback otherwise), and the resulting ciphertext.
// Returns null only if we have no usable key for them at all.
async function prepareEncryptedPayload(room, plaintext) {
  const { epochIndex, pair: myEphPair } = await ensureEpochKeyPublished();
  const myEphPublicJwk = await exportPublicKeyJwk(myEphPair.publicKey);

  let theirKey = null;
  let keyMode = null;
  if (room.otherMember?.id) {
    theirKey = await fetchTheirEpochKey(room.otherMember.id, epochIndex);
  }
  if (theirKey) {
    keyMode = 'mutual';
  } else if (room.otherMember?.publicKey) {
    theirKey = room.otherMember.publicKey;
    keyMode = 'identity';
  } else {
    return null;
  }

  const cacheKey = `send:${epochIndex}:${keyMode}:${theirKey.x}:${theirKey.y}`;
  const sharedKey = await getCachedDerivedKey(cacheKey, myEphPair.privateKey, theirKey);
  const { ciphertext, iv } = await encryptText(sharedKey, plaintext);
  return { content: ciphertext, iv, epochIndex, senderEpochPublicKey: myEphPublicJwk, keyMode };
}

// Decrypts a received DM. 'mutual' messages need OUR ephemeral private key
// for that specific epoch — if it's aged out of local retention, this
// returns null, which is forward secrecy doing exactly what it's for, not
// a bug. 'identity' messages use our long-term identity key, which is
// always available.
async function decryptIncomingDm(msg) {
  let myKey;
  if (msg.keyMode === 'mutual') {
    myKey = await getEphemeralPrivateKeyForEpoch(msg.epochIndex);
    if (!myKey) return null;
  } else if (msg.keyMode === 'identity') {
    if (!state.myKeyPair) return null;
    myKey = state.myKeyPair.privateKey;
  } else {
    return null;
  }

  const cacheKey = `recv:${msg.epochIndex}:${msg.keyMode}:${msg.senderEpochPublicKey.x}:${msg.senderEpochPublicKey.y}`;
  const sharedKey = await getCachedDerivedKey(cacheKey, myKey, msg.senderEpochPublicKey);
  return decryptText(sharedKey, msg.content, msg.iv);
}

// Adds a `displayContent` field for rendering, without touching the
// original `content`/`iv` — those stay as the raw values so sidebar preview
// logic can tell encrypted from plain at a glance without decrypting.
// Group messages are encrypted under a shared per-generation key (see groupKeys.js).
async function decorateGroupMessage(msg) {
  let key = keyring.get(msg.roomId, msg.epochIndex);
  if (!key) {
    try {
      await keyring.load(msg.roomId);
    } catch {
      // offline, or no longer a member: fall through to the placeholder
    }
    key = keyring.get(msg.roomId, msg.epochIndex);
  }
  if (!key) {
    return {
      ...msg,
      displayContent: keyring.hasAnyKey(msg.roomId)
        ? '🔒 Sent before you joined, so it cannot be read.'
        : '🔒 Waiting for a member to share the group key…',
    };
  }
  const plaintext = await decryptGroupMessage(key, msg.content, msg.iv, msg.roomId, msg.epochIndex);
  return { ...msg, displayContent: plaintext ?? '⚠️ Could not decrypt this message' };
}

// Encrypts for an encrypted group using the newest key generation we hold.
// Returns null if we hold no key yet (a member has to share it with us first).
async function prepareGroupPayload(room, plaintext) {
  await keyring.load(room.id).catch(() => {});
  const generation = keyring.currentGeneration(room.id);
  const key = keyring.get(room.id, generation);
  if (!key) return null;
  const { ciphertext, iv } = await encryptGroupMessage(key, plaintext, room.id, generation);
  return { content: ciphertext, iv, epochIndex: generation, keyMode: 'group' };
}

// Any member who holds the group key can hand it to newcomers, replace it after
// someone leaves, and re-wrap it for members whose identity key changed.
function runReconcile(room) {
  if (!room || !room.isGroup || !room.encrypted) return;
  keyring.reconcile(room).catch((err) => console.warn('Group key check failed:', err));
}

function handleGroupKeysNeeded({ roomId }) {
  const room = state.rooms.find((r) => r.id === roomId);
  if (!room) return;
  // A little random delay so several online members do not all act at once
  // (the server serialises key rotations anyway).
  setTimeout(() => runReconcile(room), 100 + Math.random() * 900);
}

async function handleGroupKeysUpdated({ roomId, keyGeneration }) {
  const room = state.rooms.find((r) => r.id === roomId);
  if (!room) return;
  room.keyGeneration = keyGeneration;
  await keyring.load(roomId, { force: true }).catch(() => {});
  const list = state.messagesByRoom.get(roomId);
  if (list) state.messagesByRoom.set(roomId, await Promise.all(list.map(decorateWithDisplayContent)));
  if (state.activeRoomId === roomId) {
    updateComposerAvailability(room);
    renderMessages(roomId);
  }
}

function handleGroupSettingsUpdated({ roomId, joinPolicy, historyPolicy }) {
  const room = state.rooms.find((r) => r.id === roomId);
  if (!room) return;
  room.joinPolicy = joinPolicy;
  room.historyPolicy = historyPolicy;
}

function removeRoomLocally(roomId) {
  state.rooms = state.rooms.filter((r) => r.id !== roomId);
  state.messagesByRoom.delete(roomId);
  state.roomPagination.delete(roomId);
  keyring.forget(roomId);
  if (state.activeRoomId === roomId) {
    state.activeRoomId = null;
    $('chat-active').classList.add('hidden');
    $('chat-empty').classList.remove('hidden');
    $('app-screen').classList.remove('show-chat');
    $('members-panel').classList.add('hidden');
  }
  renderRoomLists();
}

function handleRoomRemoved({ roomId }) {
  const known = state.rooms.some((r) => r.id === roomId);
  removeRoomLocally(roomId);
  if (known) showToast('You were removed from a group.');
}

async function decorateWithDisplayContent(msg) {
  if (msg.keyMode === 'group') return decorateGroupMessage(msg);
  if (!msg.iv) {
    return { ...msg, displayContent: msg.content };
  }

  let plaintext = null;
  if (msg.epochIndex !== null && msg.epochIndex !== undefined && msg.keyMode && msg.senderEpochPublicKey) {
    plaintext = await decryptIncomingDm(msg);
  } else {
    // A message sent before forward secrecy shipped, under the old
    // static identity-to-identity scheme — kept decryptable for continuity.
    const room = state.rooms.find((r) => r.id === msg.roomId);
    if (room && !room.isGroup && room.otherMember?.publicKey && state.myKeyPair) {
      const legacyKey = await getCachedDerivedKey(
        `legacy:${room.id}`,
        state.myKeyPair.privateKey,
        room.otherMember.publicKey
      );
      plaintext = await decryptText(legacyKey, msg.content, msg.iv);
    }
  }

  const fallbackText =
    msg.keyMode === 'mutual' ? '🔒 Key has aged out — no longer decryptable on this device' : '⚠️ Could not decrypt this message';
  return { ...msg, displayContent: plaintext ?? fallbackText };
}

function showSafetyNumberModal(username, code, fsNote = '') {
  $('safety-number-username').textContent = username;
  $('safety-number-code').textContent = code;
  $('safety-number-fs-note').textContent = fsNote;
  openModal('safety-number-modal');
}

// Enables/disables the composer based on whether we can actually encrypt to
// this room's partner yet (always enabled for group rooms, which aren't
// encrypted in this version).
function updateComposerAvailability(room) {
  const input = $('composer-input');
  const sendBtn = $('composer-send');

  if (room.isGroup) {
    const waiting = !!room.encrypted && !keyring.hasCurrentKey(room.id);
    input.disabled = waiting;
    sendBtn.disabled = waiting;
    input.placeholder = waiting ? 'Waiting for a member to share the group key…' : 'Message…';
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

  if (room.isGroup && room.encrypted) {
    // Load our keys first so messages decrypt, then help anyone waiting for theirs.
    await keyring.load(roomId, { force: true }).catch(() => {});
    if (state.activeRoomId === roomId) updateComposerAvailability(room);
    runReconcile(room);
  }

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
    $('chat-subtitle').textContent = `${room.memberCount} member${room.memberCount === 1 ? '' : 's'}${
      room.encrypted ? ' · 🔒 encrypted' : ' · not encrypted'
    }`;
    membersBtn.classList.remove('hidden');
    encryptionBadge.classList.toggle('hidden', !room.encrypted);
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
    if (room && room.isGroup && room.encrypted) {
      const encrypted = await prepareGroupPayload(room, newContent);
      if (!encrypted) {
        showToast('Cannot edit yet: the group key is not available.');
        saveBtn.disabled = false;
        return;
      }
      payload = { roomId: msg.roomId, messageId: msg.id, ...encrypted };
    } else if (room && !room.isGroup) {
      const encrypted = await prepareEncryptedPayload(room, newContent);
      if (!encrypted) {
        showToast('Cannot edit — secure messaging is not ready for this conversation.');
        saveBtn.disabled = false;
        return;
      }
      payload = { roomId: msg.roomId, messageId: msg.id, ...encrypted };
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

async function refreshMembersPanel(room) {
  const data = await api.getMembers(room.id);
  room.memberCount = data.members.length;
  renderMembersList(data.members);
  renderGroupPanel(room, data.members);
  renderChatHeader(room);
  renderRoomLists();
}

// Group details inside the members panel: what the encryption settings are,
// admin controls (settings, add people, remove people) and Leave.
function renderGroupPanel(room, members) {
  const box = $('group-panel-extra');
  box.innerHTML = '';
  const isAdmin = members.find((m) => m.id === state.me.id)?.role === 'admin';

  const info = document.createElement('p');
  info.className = 'group-note';
  if (room.encrypted) {
    const who = room.joinPolicy === 'invite' ? 'Invite-only.' : 'Anyone can join.';
    const history =
      room.historyPolicy === 'full'
        ? 'New members can read the full history.'
        : 'New members can only read messages sent after they join.';
    info.textContent = `🔒 End-to-end encrypted. ${who} ${history} Groups have no forward secrecy.`;
  } else {
    info.textContent = 'This older group is not end-to-end encrypted. New groups always are.';
  }
  box.appendChild(info);

  document.querySelectorAll('#members-list .member-row').forEach((row) => {
    const m = members.find((x) => x.id === row.dataset.userId);
    if (!m) return;
    if (m.role === 'admin') {
      const tag = document.createElement('span');
      tag.className = 'role-tag';
      tag.textContent = 'admin';
      row.appendChild(tag);
    }
    if (isAdmin && m.id !== state.me.id) {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'btn btn-danger-text member-remove';
      btn.textContent = 'Remove';
      btn.addEventListener('click', async () => {
        if (!window.confirm(`Remove ${m.username} from this group? They will not be able to read anything sent after this.`)) return;
        try {
          await api.removeGroupMember(room.id, m.id);
          showToast(`${m.username} was removed.`);
          await refreshMembersPanel(room);
        } catch (err) {
          showToast(err.message);
        }
      });
      row.appendChild(btn);
    }
  });

  if (isAdmin) {
    const settings = document.createElement('div');
    settings.className = 'group-section';
    settings.innerHTML = `
      <h3>Group settings</h3>
      <div class="field">
        <label for="gs-join">Who can join</label>
        <select id="gs-join">
          <option value="open">Anyone (listed in Browse rooms)</option>
          <option value="invite">Invite-only (admin adds people)</option>
        </select>
      </div>
      <div class="field">
        <label for="gs-history">What new members can read</label>
        <select id="gs-history">
          <option value="after_join">Only messages sent after they join</option>
          <option value="full">The full history</option>
        </select>
      </div>
      <button type="button" class="btn btn-ghost" id="gs-save">Save settings</button>
      <div class="field-hint">Changes apply to people who join from now on.</div>`;
    box.appendChild(settings);
    $('gs-join').value = room.joinPolicy || 'open';
    $('gs-history').value = room.historyPolicy || 'after_join';
    $('gs-save').addEventListener('click', async () => {
      try {
        const saved = await api.updateGroupSettings(room.id, {
          joinPolicy: $('gs-join').value,
          historyPolicy: $('gs-history').value,
        });
        room.joinPolicy = saved.joinPolicy;
        room.historyPolicy = saved.historyPolicy;
        showToast('Settings saved.');
        await refreshMembersPanel(room);
      } catch (err) {
        showToast(err.message);
      }
    });

    const add = document.createElement('div');
    add.className = 'group-section';
    add.innerHTML = `
      <h3>Add people</h3>
      <div class="field"><input id="gs-add-search" type="text" placeholder="Search by username" autocomplete="off" /></div>
      <div class="group-add-results" id="gs-add-results"></div>`;
    box.appendChild(add);
    let timer = null;
    $('gs-add-search').addEventListener('input', (e) => {
      clearTimeout(timer);
      const q = e.target.value.trim();
      const results = $('gs-add-results');
      if (!q) {
        results.innerHTML = '';
        return;
      }
      timer = setTimeout(async () => {
        try {
          const data = await api.searchUsers(q);
          results.innerHTML = '';
          const inGroup = new Set(members.map((m) => m.id));
          const found = data.users.filter((u) => !inGroup.has(u.id));
          if (found.length === 0) {
            results.appendChild(emptyNote('No one to add.'));
            return;
          }
          found.forEach((u) => {
            const row = document.createElement('div');
            row.className = 'group-add-row';
            const label = document.createElement('span');
            label.textContent = u.username;
            const btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'btn btn-ghost';
            btn.textContent = 'Add';
            btn.addEventListener('click', async () => {
              try {
                await api.addGroupMember(room.id, u.id);
                showToast(`${u.username} was added.`);
                await refreshMembersPanel(room);
              } catch (err) {
                showToast(err.message);
              }
            });
            row.append(label, btn);
            results.appendChild(row);
          });
        } catch (err) {
          showToast(err.message);
        }
      }, 250);
    });
  }

  const leave = document.createElement('button');
  leave.type = 'button';
  leave.className = 'btn btn-danger-text group-leave';
  leave.textContent = 'Leave group';
  leave.addEventListener('click', async () => {
    if (!window.confirm('Leave this group? You will not be able to read anything sent after you leave.')) return;
    try {
      await api.leaveRoom(room.id);
      removeRoomLocally(room.id);
      showToast('You left the group.');
    } catch (err) {
      showToast(err.message);
    }
  });
  box.appendChild(leave);
}

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
    renderGroupPanel(room, data.members);
    panel.classList.remove('hidden');
  } catch (err) {
    showToast(err.message);
  }
});

$('encryption-badge').addEventListener('click', async () => {
  const room = state.rooms.find((r) => r.id === state.activeRoomId);
  if (room && room.isGroup) {
    $('members-btn').click(); // the members panel doubles as the group's encryption details
    return;
  }
  if (!room || !room.otherMember?.publicKey || !state.myPublicKeyJwk) return;
  try {
    const code = await computeSafetyNumber(state.me.id, state.myPublicKeyJwk, room.otherMember.id, room.otherMember.publicKey);
    const bothStrict = state.me.securityMode === 'strict' && room.otherMember.securityMode === 'strict';
    const fsNote = bothStrict
      ? 'Both of you use Maximum Security, so message keys are deleted after 30 days. (Messages sent while one of you had been inactive that hour use a weaker fallback.)'
      : 'Forward secrecy is OFF for this conversation. At least one of you uses Standard mode and keeps keys permanently, so old messages stay readable and recoverable. A conversation is only as strict as the less strict person.';
    showSafetyNumberModal(room.otherMember.username, code, fsNote);
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
    if (!state.myPublicKeyJwk) {
      showToast('Your encryption key is not ready yet. Try again in a moment.');
      return;
    }
    // The room id is chosen here because the group key's wrap is bound to it.
    const roomId = crypto.randomUUID();
    const { key, wrap } = await keyring.prepareNewGroup(roomId);
    const data = await api.createGroup({
      id: roomId,
      name,
      joinPolicy: $('new-room-join').value,
      historyPolicy: $('new-room-history').value,
      key: wrap,
    });
    keyring.remember(roomId, 1, key);
    upsertRoom({ ...data.room, memberCount: 1 });
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
    nameEl.textContent = r.encrypted ? `🔒 ${r.name}` : r.name;
    const countEl = document.createElement('span');
    countEl.className = 'count';
    countEl.textContent = ` · ${r.memberCount} member${r.memberCount === 1 ? '' : 's'}${
      r.encrypted ? (r.historyPolicy === 'full' ? ' · full history' : ' · history from when you join') : ' · not encrypted'
    }`;
    info.append(nameEl, countEl);

    const joinBtn = document.createElement('button');
    joinBtn.type = 'button';
    joinBtn.className = 'btn btn-ghost';
    joinBtn.textContent = 'Join';
    joinBtn.addEventListener('click', async () => {
      try {
        const joined = await api.joinRoom(r.id);
        upsertRoom(joined.room);
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

  if (room && room.isGroup && room.encrypted) {
    const encrypted = await prepareGroupPayload(room, content);
    if (!encrypted) {
      showToast('Cannot send yet: waiting for a member to share the group key.');
      return;
    }
    payload = { roomId, ...encrypted };
  } else if (room && !room.isGroup) {
    const encrypted = await prepareEncryptedPayload(room, content);
    if (!encrypted) {
      showToast('Cannot send yet — secure messaging is not ready for this conversation.');
      return;
    }
    payload = { roomId, ...encrypted };
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
    const securityMode = document.querySelector('input[name="securityMode"]:checked')?.value || 'standard';
    const data = await api.register({ username, email, password, securityMode });
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
  clearInterval(epochKeyTimer);
  state.me = null;
  setKeyOwner(null);
  keyring.clear();
  state.rooms = [];
  state.activeRoomId = null;
  state.messagesByRoom.clear();
  state.typingByRoom.clear();
  state.onlineUsers.clear();
  // Per-session key caches must not leak into the next login in this tab.
  state.publishedEpochIndex = null;
  state.derivedKeyCache.clear();
  state.theirEpochKeyCache.clear();
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

// Publishes our current hourly key on a timer as well, so an app left open
// across an hour boundary keeps counting as active.
let epochKeyTimer = null;
let legacyMigrationOk = true; // old-storage cleanup is skipped unless migration succeeded
function startEpochKeyRefresh() {
  clearInterval(epochKeyTimer);
  epochKeyTimer = setInterval(() => {
    if (state.me) ensureEpochKeyPublished().catch(() => {});
  }, 5 * 60 * 1000);
}

async function initApp(user) {
  state.me = user;
  setKeyOwner(user.id); // keys live in a per-account database (see crypto.js)
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

  // Maximum Security: drop any leftover copy of our ephemeral keys in the old shared
  // database, but only once migration succeeded and only if those keys are verifiably ours.
  if (legacyMigrationOk && state.me.securityMode === 'strict') {
    purgeLegacyEphemeralKeys().catch((err) => console.warn('Could not clear old key storage:', err));
  }

  // Being online counts as being active: publish this hour's key now (and keep
  // doing so hourly while the app stays open), not only when sending, so
  // senders can use the stronger mutual mode with us.
  ensureEpochKeyPublished().catch((err) => console.warn('Could not publish this hours key:', err));
  startEpochKeyRefresh();

  connectSocket();
  onSocket('message:new', handleIncomingMessage);
  onSocket('message:updated', handleMessageUpdated);
  onSocket('message:deleted', handleMessageDeleted);
  onSocket('presence:update', handlePresenceUpdate);
  onSocket('typing:update', handleTypingUpdate);
  onSocket('room:new', handleNewRoom);
  onSocket('group:keys-needed', handleGroupKeysNeeded);
  onSocket('group:keys-updated', handleGroupKeysUpdated);
  onSocket('group:settings-updated', handleGroupSettingsUpdated);
  onSocket('room:removed', handleRoomRemoved);

  try {
    const data = await api.listRooms();
    state.rooms = data.rooms;
    renderRoomLists();
    // Encrypted groups: if someone is waiting for a key we hold, hand it over.
    state.rooms
      .filter((r) => r.isGroup && r.encrypted)
      .forEach((r, i) => setTimeout(() => runReconcile(r), 800 + i * 400 + Math.random() * 600));
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
// Security settings: mode switching + key backup / restore
// ---------------------------------------------------------------------------

function describeSecurityMode(mode) {
  return mode === 'strict'
    ? 'Maximum Security: real forward secrecy. Keys older than 30 days are permanently deleted, so very old messages become unreadable, even to you. Full-history device transfer is not possible.'
    : 'Standard: your message history stays readable forever, and a backup password lets you restore it on a new device. No forward-secrecy guarantee.';
}

function renderSettingsModal() {
  const mode = state.me?.securityMode || 'standard';
  $('settings-mode-description').textContent = describeSecurityMode(mode);
  $('settings-switch-mode-btn').textContent = mode === 'strict' ? 'Switch to Standard' : 'Switch to Maximum Security';
  const note = $('settings-backup-scope-note');
  note.textContent =
    'On Maximum Security a backup only covers the last 30 days; older keys are already permanently deleted from this device.';
  note.classList.toggle('hidden', mode !== 'strict');
}

$('settings-btn').addEventListener('click', () => {
  renderSettingsModal();
  openModal('settings-modal');
});

$('settings-switch-mode-btn').addEventListener('click', async () => {
  const next = (state.me.securityMode || 'standard') === 'strict' ? 'standard' : 'strict';
  if (next === 'strict') {
    const ok = window.confirm(
      'Switch to Maximum Security? From now on, keys older than 30 days will be permanently deleted from this device, so old messages can eventually become unreadable. Messages that age out cannot be recovered.'
    );
    if (!ok) return;
  }
  try {
    await api.setSecurityMode(next);
    if (next === 'strict' && legacyMigrationOk) {
      // Choosing Maximum Security also clears any leftover copy of our ephemeral keys in the old shared database.
      await purgeLegacyEphemeralKeys().catch(() => {});
    }
    state.me.securityMode = next;
    renderSettingsModal();
    showToast(`Switched to ${next === 'strict' ? 'Maximum Security' : 'Standard'} mode.`);
  } catch (err) {
    showToast(err.message);
  }
});

$('create-backup-btn').addEventListener('click', async () => {
  const password = $('backup-password').value;
  const confirmation = $('backup-password-confirm').value;
  if (password.length < 8) {
    showToast('Backup password must be at least 8 characters.');
    return;
  }
  if (password !== confirmation) {
    showToast('The two backup passwords do not match.');
    return;
  }
  const btn = $('create-backup-btn');
  btn.disabled = true;
  try {
    const backup = await createEncryptedBackup(password);
    await api.setKeyBackup(backup);
    $('backup-password').value = '';
    $('backup-password-confirm').value = '';
    showToast('Backup created. Remember your backup password: it cannot be recovered.');
  } catch (err) {
    showToast(err.message || 'Could not create the backup.');
  } finally {
    btn.disabled = false;
  }
});

$('restore-backup-btn').addEventListener('click', async () => {
  const password = $('restore-password').value;
  if (!password) {
    showToast('Enter your backup password.');
    return;
  }
  const btn = $('restore-backup-btn');
  btn.disabled = true;
  try {
    const data = await api.getKeyBackup();
    if (!data.backup) {
      showToast('No backup was found for this account.');
      return;
    }
    try {
      await restoreFromEncryptedBackup(password, data.backup);
    } catch {
      showToast('Incorrect backup password.');
      return;
    }
    $('restore-password').value = '';
    // The keys under us just changed: drop everything derived from the old
    // ones, then reload so login re-publishes the restored identity key.
    state.myKeyPair = await getOrCreateKeyPair();
    state.myPublicKeyJwk = await exportPublicKeyJwk(state.myKeyPair.publicKey);
    state.derivedKeyCache.clear();
    state.messagesByRoom.clear();
    state.roomPagination.clear();
    showToast('Backup restored. Reloading...');
    setTimeout(() => window.location.reload(), 800);
  } catch (err) {
    showToast(err.message || 'Could not restore the backup.');
  } finally {
    btn.disabled = false;
  }
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
