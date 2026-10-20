// Client-side group key management.
//
// A group has a shared AES key per "generation". Nobody stores that key in the
// clear: every member holds their own copy, wrapped (encrypted) to their
// identity public key, and the server only ever sees those wrapped copies.
//
//  * load()       fetches this member's wrapped copies and unwraps them.
//  * reconcile()  is what ANY member who holds the current key runs to keep the
//                 group healthy: give keys to newcomers (full-history groups),
//                 rotate to a fresh key when someone joined an "after join"
//                 group or left/was removed, and re-wrap for members whose
//                 identity key changed. The server serialises rotations, so
//                 several members reconciling at once is safe.
//
// Dependencies are injected so the exact same code runs in the browser and in
// the Node protocol tests.
export function createKeyring({ api, crypto: c, getMyPublicJwk }) {
  const rooms = new Map(); // roomId -> { keyGeneration, keys: Map<generation, CryptoKey>, loadedAt, loading }
  const reconciling = new Map(); // roomId -> Promise

  function entryFor(roomId) {
    if (!rooms.has(roomId)) rooms.set(roomId, { keyGeneration: 0, keys: new Map(), loadedAt: 0, loading: null });
    return rooms.get(roomId);
  }

  // Loads (and unwraps) our keys for a room. Calls close together share one
  // request; `force` skips the short freshness window.
  function load(roomId, { force = false } = {}) {
    const entry = entryFor(roomId);
    if (entry.loading) {
      return force ? entry.loading.catch(() => {}).then(() => load(roomId, { force: true })) : entry.loading;
    }
    if (!force && entry.loadedAt && Date.now() - entry.loadedAt < 3000) return Promise.resolve(entry);
    entry.loading = (async () => {
      try {
        const data = await api.getGroupKeys(roomId);
        entry.keyGeneration = Math.max(entry.keyGeneration, data.keyGeneration);
        for (const row of data.keys) {
          if (entry.keys.has(row.generation)) continue;
          try {
            entry.keys.set(row.generation, await c.unwrapGroupKey(row, roomId, row.generation));
          } catch {
            // Wrapped for an identity key we no longer hold (or tampered with):
            // leave it out. Someone else's reconcile will re-wrap it.
          }
        }
        entry.loadedAt = Date.now();
        return entry;
      } finally {
        entry.loading = null;
      }
    })();
    return entry.loading;
  }

  const get = (roomId, generation) => (rooms.get(roomId) ? rooms.get(roomId).keys.get(generation) || null : null);
  const currentGeneration = (roomId) => (rooms.get(roomId) ? rooms.get(roomId).keyGeneration : 0);
  const hasCurrentKey = (roomId) => {
    const e = rooms.get(roomId);
    return !!(e && e.keyGeneration > 0 && e.keys.has(e.keyGeneration));
  };
  const hasAnyKey = (roomId) => !!(rooms.get(roomId) && rooms.get(roomId).keys.size > 0);

  function remember(roomId, generation, key) {
    const e = entryFor(roomId);
    e.keys.set(generation, key);
    e.keyGeneration = Math.max(e.keyGeneration, generation);
  }

  // A brand-new group: make the generation-1 key and wrap it for ourselves. The
  // room id is chosen by the client so the wrap can be bound to it.
  async function prepareNewGroup(roomId) {
    const key = await c.generateGroupKey();
    const wrap = await c.wrapGroupKey(key, getMyPublicJwk(), roomId, 1);
    return { key, wrap };
  }

  async function reconcileOnce(room) {
    const roomId = room.id;
    const status = await api.getGroupKeyStatus(roomId);
    const entry = await load(roomId, { force: true });
    const cur = status.keyGeneration;
    if (!entry.keys.has(cur)) return { acted: false, reason: 'not-a-keyholder' };

    const members = status.members.filter((m) => m.publicKey);
    const fp = (m) => c.keyFingerprint(m.publicKey);
    const hasGen = (m, g) => m.generations.some((x) => x.generation === g);
    const isStale = (m, g) => m.generations.some((x) => x.generation === g && x.wrappedForFp !== fp(m));
    // Newcomers: members who hold no key at all yet.
    const newcomers = new Set(members.filter((m) => m.generations.length === 0).map((m) => m.userId));

    let rotated = false;
    let nextGeneration = cur;
    const lackingCurrent = members.filter((m) => !hasGen(m, cur));
    if (status.needsRotation || (status.historyPolicy === 'after_join' && lackingCurrent.length > 0)) {
      const newKey = await c.generateGroupKey();
      const wraps = [];
      for (const m of members) {
        wraps.push({ userId: m.userId, ...(await c.wrapGroupKey(newKey, m.publicKey, roomId, cur + 1)) });
      }
      await api.putGroupKeys(roomId, { mode: 'rotate', expectedGeneration: cur, wraps });
      remember(roomId, cur + 1, newKey);
      rotated = true;
      nextGeneration = cur + 1;
    }

    // Older generations: hand them to newcomers in a full-history group, and
    // re-wrap anything made for an identity key a member no longer uses.
    const shares = [];
    for (const m of members) {
      for (const [g, key] of entry.keys) {
        if (g > cur) continue; // (the rotated generation was already wrapped for everyone)
        const newcomerFull = status.historyPolicy === 'full' && newcomers.has(m.userId) && !hasGen(m, g);
        const missingCurrent = !rotated && g === cur && !hasGen(m, cur);
        if (newcomerFull || missingCurrent || isStale(m, g)) {
          shares.push({ userId: m.userId, generation: g, ...(await c.wrapGroupKey(key, m.publicKey, roomId, g)) });
        }
      }
    }
    for (let i = 0; i < shares.length; i += 120) {
      await api.putGroupKeys(roomId, { mode: 'share', wraps: shares.slice(i, i + 120) });
    }

    if (!rotated && shares.length === 0) return { acted: false, reason: 'up-to-date' };
    return { acted: true, rotated, shared: shares.length, keyGeneration: nextGeneration };
  }

  // Serialised per room; if another member rotated first (409) we simply look
  // again and usually find there is nothing left to do.
  function reconcile(room) {
    if (reconciling.has(room.id)) return reconciling.get(room.id);
    const p = (async () => {
      for (let attempt = 0; attempt < 3; attempt += 1) {
        try {
          return await reconcileOnce(room);
        } catch (err) {
          if (err && err.status === 409 && attempt < 2) continue;
          throw err;
        }
      }
      return { acted: false, reason: 'gave-up' };
    })().finally(() => reconciling.delete(room.id));
    reconciling.set(room.id, p);
    return p;
  }

  const forget = (roomId) => rooms.delete(roomId);
  const clear = () => rooms.clear();

  return { load, get, currentGeneration, hasCurrentKey, hasAnyKey, remember, prepareNewGroup, reconcile, forget, clear };
}
