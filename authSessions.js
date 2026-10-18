/**
 * Sessions (access + refresh tokens) and one-time tokens (email verification, password reset).
 *
 *  - Access token  : short-lived JWT (15 min) carrying the session id. Checked against the session store, so
 *                    "sign out that device" takes effect immediately.
 *  - Refresh token : opaque random secret "<sessionId>.<secret>", valid 30 days, ROTATED on every use. Only its
 *                    SHA-256 is stored. Presenting an already-rotated token (stolen copy) after a short grace
 *                    window revokes the whole session.
 * Files live in the data folder (sessions.json / auth-tokens.json) and are mirrored like the rest of it.
 */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");
const rnd = (n = 32) => crypto.randomBytes(n).toString("base64url");
const eq = (a, b) => {
  const x = Buffer.from(String(a || ""));
  const y = Buffer.from(String(b || ""));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};

function readJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return fallback;
  }
}
function writeJson(file, data) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(data));
  fs.renameSync(tmp, file);
}

/** "Chrome on macOS" style label from a User-Agent (best effort, for the devices list). */
export function describeDevice(ua = "") {
  const s = String(ua);
  if (/Ovu\//i.test(s) || /Electron\//i.test(s)) {
    const os = /Windows/i.test(s) ? "Windows" : /Mac OS X|Macintosh/i.test(s) ? "macOS" : "";
    return `Ovu app${os ? ` on ${os}` : ""}`;
  }
  const browser = /Edg\//.test(s) ? "Edge" : /OPR\/|Opera/.test(s) ? "Opera" : /Firefox\//.test(s) ? "Firefox" : /Chrome\//.test(s) ? "Chrome" : /Safari\//.test(s) ? "Safari" : "";
  const os = /iPhone|iPad|iOS/i.test(s) ? "iOS" : /Windows/i.test(s) ? "Windows" : /Mac OS X|Macintosh/i.test(s) ? "macOS" : "";
  if (browser && os) return `${browser} on ${os}`;
  return browser || os || "Unknown device";
}

export function createSessions({
  dir,
  refreshTtlMs = 30 * 24 * 3600 * 1000,
  graceMs = 30 * 1000,
  maxPerUser = 20,
  touchEveryMs = 5 * 60 * 1000,
  now = () => Date.now(),
}) {
  const file = path.join(dir, "sessions.json");
  /** @type {Map<string, any>} */
  const map = new Map(Object.entries(readJson(file, {})));
  const save = () => writeJson(file, Object.fromEntries(map));

  const live = (s) => s && s.expiresAt > now();
  function sweep() {
    let changed = false;
    for (const [id, s] of map) if (!live(s)) (map.delete(id), (changed = true));
    if (changed) save();
  }
  sweep();

  const api = {
    /** New session for a user. Returns { session, refreshToken }. */
    create(userId, { ip = "", userAgent = "", claims = {} } = {}) {
      const id = crypto.randomUUID();
      const secret = rnd();
      const t = now();
      const s = {
        id,
        userId,
        refreshHash: sha(secret),
        used: [], // hashes of already-rotated refresh tokens: [{ h, at }]
        createdAt: t,
        lastUsedAt: t,
        expiresAt: t + refreshTtlMs,
        ip: String(ip).slice(0, 64),
        device: describeDevice(userAgent),
        claims,
      };
      map.set(id, s);
      // keep at most N sessions per user: drop the least recently used
      const mine = [...map.values()].filter((x) => x.userId === userId).sort((a, b) => a.lastUsedAt - b.lastUsedAt);
      while (mine.length > maxPerUser) map.delete(mine.shift().id);
      save();
      return { session: s, refreshToken: `${id}.${secret}` };
    },

    /** Session for a valid (not revoked, not expired) id, else null. Updates "last active" at most every few minutes. */
    get(id) {
      const s = map.get(String(id));
      if (!live(s)) return null;
      if (now() - s.lastUsedAt > touchEveryMs) {
        s.lastUsedAt = now();
        save();
      }
      return s;
    },

    /** Trade a refresh token for a new one (rotation). null = invalid/expired/reused. */
    refresh(token, { ip, userAgent } = {}) {
      const [id, secret] = String(token || "").split(".");
      const s = map.get(id);
      if (!s || !secret) return null;
      if (!live(s)) {
        map.delete(id);
        save();
        return null;
      }
      const h = sha(secret);
      const current = eq(h, s.refreshHash);
      if (!current) {
        const old = (s.used || []).find((u) => eq(u.h, h));
        // An already-rotated token is fine for a few seconds (the answer may have been lost on the way);
        // later it can only be a copy -> destroy the session.
        if (!old || now() - old.at > graceMs) {
          if (old) {
            map.delete(id);
            save();
          }
          return null;
        }
      }
      const next = rnd();
      s.used = [...(s.used || []), { h: s.refreshHash, at: now() }].slice(-10);
      s.refreshHash = sha(next);
      s.lastUsedAt = now();
      s.expiresAt = now() + refreshTtlMs; // sliding window: active devices stay signed in
      if (ip) s.ip = String(ip).slice(0, 64);
      if (userAgent) s.device = describeDevice(userAgent);
      save();
      return { session: s, refreshToken: `${id}.${next}` };
    },

    /** Session id a refresh token belongs to (without using it), or null. */
    idOfRefreshToken(token) {
      const [id, secret] = String(token || "").split(".");
      const s = map.get(id);
      return s && secret && (eq(sha(secret), s.refreshHash) || (s.used || []).some((u) => eq(u.h, sha(secret)))) ? id : null;
    },

    list(userId) {
      return [...map.values()]
        .filter((s) => s.userId === userId && live(s))
        .sort((a, b) => b.lastUsedAt - a.lastUsedAt)
        .map(({ id, device, ip, createdAt, lastUsedAt }) => ({ id, device, ip, createdAt, lastUsedAt }));
    },
    revoke(userId, id) {
      const s = map.get(String(id));
      if (!s || s.userId !== userId) return false;
      map.delete(s.id);
      save();
      return true;
    },
    revokeOthers(userId, keepId) {
      let n = 0;
      for (const [id, s] of map) if (s.userId === userId && id !== keepId) (map.delete(id), n++);
      if (n) save();
      return n;
    },
    revokeAll(userId) {
      return api.revokeOthers(userId, null);
    },
  };
  return api;
}

/** Single-use tokens for "verify my email" and "reset my password". */
export function createOneTimeTokens({ dir, now = () => Date.now() }) {
  const file = path.join(dir, "auth-tokens.json");
  let items = readJson(file, []);
  const prune = () => {
    const n = items.length;
    items = items.filter((t) => t.expiresAt > now());
    return n !== items.length;
  };
  if (prune()) writeJson(file, items);

  return {
    /** Issue a token for (user, purpose). Any older token of the same kind is replaced. */
    issue(userId, purpose, ttlMs) {
      prune();
      items = items.filter((t) => !(t.userId === userId && t.purpose === purpose));
      const id = rnd(9);
      const secret = rnd();
      items.push({ id, userId, purpose, hash: sha(secret), expiresAt: now() + ttlMs });
      writeJson(file, items);
      return `${id}.${secret}`;
    },
    /** Look at a token WITHOUT using it. Returns the userId or null. */
    peek(token, purpose) {
      const [id, secret] = String(token || "").trim().split(".");
      const t = items.find((x) => x.id === id && x.purpose === purpose);
      if (!t || !secret || t.expiresAt <= now() || !eq(sha(secret), t.hash)) return null;
      return t.userId;
    },
    /** Use a token once. Returns the userId, or null if wrong / expired / already used / other purpose. */
    consume(token, purpose) {
      const [id, secret] = String(token || "").trim().split(".");
      const i = items.findIndex((t) => t.id === id && t.purpose === purpose);
      if (i < 0 || !secret) return null;
      const t = items[i];
      if (t.expiresAt <= now() || !eq(sha(secret), t.hash)) return null;
      items.splice(i, 1);
      writeJson(file, items);
      return t.userId;
    },
  };
}
