import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import crypto from "node:crypto";

// Tiny JSON-file user store so the server runs with zero setup.
// For production swap this module for Postgres/SQLite/Mongo — the rest of
// the server only uses the functions exported here.
const __dirname = path.dirname(fileURLToPath(import.meta.url));
import { DATA_DIR } from "./dataDir.js";
const FILE = path.join(DATA_DIR, "users.json");

function load() {
  try {
    return JSON.parse(fs.readFileSync(FILE, "utf8"));
  } catch {
    return [];
  }
}

function save(users) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const tmp = FILE + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(users, null, 2));
  fs.renameSync(tmp, FILE); // atomic replace
}

let users = load();

export const publicUser = (u) => ({
  id: u.id,
  name: u.name,
  email: u.email,
  provider: u.provider,
  avatarUrl: u.avatarUrl ?? undefined,
});

export const findById = (id) => users.find((u) => u.id === id) ?? null;
export const findByEmail = (email) =>
  users.find((u) => u.email.toLowerCase() === email.toLowerCase()) ?? null;

/** Same Google/GitHub account -> same id, even if users.json is ever lost. */
export function oauthUserId(provider, providerId) {
  const h = crypto.createHash("sha256").update(`ovu:${provider}:${providerId}`).digest("hex");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
}

const TOMBSTONES = path.join(DATA_DIR, "deleted-users.json");
function loadTombstones() {
  try {
    return new Set(JSON.parse(fs.readFileSync(TOMBSTONES, "utf8")));
  } catch {
    return new Set();
  }
}
const deleted = loadTombstones();
export const wasDeleted = (id) => deleted.has(id);

export function createUser({ name, email, passwordHash = null, provider, providerId = null, avatarUrl = null, id = null }) {
  const user = {
    id: id || crypto.randomUUID(),
    name,
    email,
    passwordHash,
    provider,
    providerId,
    avatarUrl,
    createdAt: new Date().toISOString(),
  };
  users.push(user);
  save(users);
  return user;
}

/** Find the user for an OAuth login, linking by verified email if needed. */
export function upsertOAuthUser({ provider, providerId, email, name, avatarUrl }) {
  let user = users.find((u) => u.provider === provider && u.providerId === String(providerId));
  if (user) return user;

  // Same verified email already registered (email/password or other provider):
  // reuse that account so people don't end up with duplicates.
  user = findByEmail(email);
  if (user) {
    user.avatarUrl = user.avatarUrl ?? avatarUrl;
    save(users);
    return user;
  }
  return createUser({ name, email, provider, providerId: String(providerId), avatarUrl, id: oauthUserId(provider, providerId) });
}

export function updateUser(id, patch) {
  const user = findById(id);
  if (!user) return null;
  if (typeof patch.name === "string" && patch.name.trim()) user.name = patch.name.trim();
  if (typeof patch.passwordHash === "string") user.passwordHash = patch.passwordHash;
  if (typeof patch.avatarUrl === "string") user.avatarUrl = patch.avatarUrl;
  save(users);
  return user;
}

export function deleteUser(id) {
  deleted.add(id);
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(TOMBSTONES, JSON.stringify([...deleted]));
  } catch {
    /* best effort */
  }
  const before = users.length;
  users = users.filter((u) => u.id !== id);
  if (users.length === before) return false;
  save(users);
  return true;
}

// ---------------------------------------------------------------------------
// Portfolio / social (JSON file alongside users)
// ---------------------------------------------------------------------------
const SOCIAL_FILE = path.join(DATA_DIR, "social.json");

function loadSocial() {
  try {
    return JSON.parse(fs.readFileSync(SOCIAL_FILE, "utf8"));
  } catch {
    return { profiles: {}, works: [], follows: [], likes: [], comments: [] };
  }
}

function saveSocial(data) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const tmp = SOCIAL_FILE + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
  fs.renameSync(tmp, SOCIAL_FILE);
}

let social = loadSocial();

export function getProfile(userId) {
  const user = findById(userId);
  if (!user) return null;
  const p = social.profiles[userId] || {};
  const followerCount = social.follows.filter((f) => f.followingId === userId).length;
  const followingCount = social.follows.filter((f) => f.followerId === userId).length;
  return {
    id: user.id,
    name: user.name,
    avatarUrl: user.avatarUrl ?? undefined,
    bio: p.bio || "",
    isPublic: p.isPublic !== false,
    allowComments: p.allowComments !== false,
    followerCount,
    followingCount,
  };
}

export function updateProfile(userId, patch) {
  if (!findById(userId)) return null;
  social.profiles[userId] = {
    ...(social.profiles[userId] || {}),
    ...patch,
  };
  saveSocial(social);
  return getProfile(userId);
}

export function listWorks(userId) {
  return social.works
    .filter((w) => w.userId === userId && !w.deleted)
    .map(publicWork)
    .sort((a, b) => b.createdAt - a.createdAt);
}

export function getWork(workId) {
  const w = social.works.find((x) => x.id === workId && !x.deleted);
  return w ? publicWork(w) : null;
}

/** Full work including protected payload — only for owner or server-side view token. */
export function getWorkInternal(workId) {
  return social.works.find((x) => x.id === workId && !x.deleted) || null;
}

function publicWork(w) {
  const likeCount = social.likes.filter((l) => l.workId === w.id).length;
  const commentCount = social.comments.filter((c) => c.workId === w.id && !c.deleted).length;
  return {
    id: w.id,
    userId: w.userId,
    title: w.title,
    description: w.description || "",
    type: w.type, // "model" | "video" | "image"
    // Never expose raw downloadable URL in public API for models — only stream path
    hasModel: w.type === "model" && Boolean(w.modelData),
    is4d: Boolean(w.modelData && typeof w.modelData === "object" && w.modelData.format === "ovu-timelapse-v1"),
    thumbnailDataUrl: w.thumbnailDataUrl || null,
    videoDataUrl: w.type === "video" ? w.videoDataUrl : null,
    imageDataUrl: w.type === "image" ? w.imageDataUrl : null,
    allowDownload: false, // always false for others; owner uses local project
    watermark: true,
    likeCount,
    commentCount,
    createdAt: w.createdAt,
  };
}

export function createWork(userId, payload) {
  const work = {
    id: crypto.randomUUID(),
    userId,
    title: String(payload.title || "Untitled").slice(0, 120),
    description: String(payload.description || "").slice(0, 2000),
    type: payload.type === "video" || payload.type === "image" ? payload.type : "model",
    // modelData is base64 glb or JSON stroke snapshot — view only, never offered as download
    modelData: payload.modelData || null,
    thumbnailDataUrl: payload.thumbnailDataUrl || null,
    videoDataUrl: payload.videoDataUrl || null,
    imageDataUrl: payload.imageDataUrl || null,
    createdAt: Date.now(),
    deleted: false,
  };
  social.works.push(work);
  saveSocial(social);
  return publicWork(work);
}

export function deleteWork(userId, workId) {
  const w = social.works.find((x) => x.id === workId);
  if (!w || w.userId !== userId) return false;
  w.deleted = true;
  saveSocial(social);
  return true;
}

export function toggleFollow(followerId, followingId) {
  if (followerId === followingId) return { following: false };
  const idx = social.follows.findIndex(
    (f) => f.followerId === followerId && f.followingId === followingId
  );
  if (idx >= 0) {
    social.follows.splice(idx, 1);
    saveSocial(social);
    return { following: false };
  }
  social.follows.push({ followerId, followingId, at: Date.now() });
  saveSocial(social);
  return { following: true };
}

export function isFollowing(followerId, followingId) {
  return social.follows.some(
    (f) => f.followerId === followerId && f.followingId === followingId
  );
}

export function toggleLike(userId, workId) {
  const idx = social.likes.findIndex((l) => l.userId === userId && l.workId === workId);
  if (idx >= 0) {
    social.likes.splice(idx, 1);
    saveSocial(social);
    return { liked: false, count: social.likes.filter((l) => l.workId === workId).length };
  }
  social.likes.push({ userId, workId, at: Date.now() });
  saveSocial(social);
  return { liked: true, count: social.likes.filter((l) => l.workId === workId).length };
}

export function hasLiked(userId, workId) {
  return social.likes.some((l) => l.userId === userId && l.workId === workId);
}

export function listComments(workId) {
  return social.comments
    .filter((c) => c.workId === workId && !c.deleted)
    .map((c) => {
      const u = findById(c.userId);
      return {
        id: c.id,
        workId: c.workId,
        userId: c.userId,
        userName: u?.name || "User",
        text: c.text,
        createdAt: c.createdAt,
      };
    })
    .sort((a, b) => a.createdAt - b.createdAt);
}

export function addComment(userId, workId, text) {
  const cleaned = String(text || "").trim().slice(0, 1000);
  if (!cleaned) return null;
  if (!getWorkInternal(workId)) return null;
  const c = {
    id: crypto.randomUUID(),
    workId,
    userId,
    text: cleaned,
    createdAt: Date.now(),
    deleted: false,
  };
  social.comments.push(c);
  saveSocial(social);
  const u = findById(userId);
  return {
    id: c.id,
    workId,
    userId,
    userName: u?.name || "User",
    text: c.text,
    createdAt: c.createdAt,
  };
}

/** Re-creates an OAuth account record from a still-valid session token (users.json was lost). */
export function restoreOAuthUser({ id, name, email, provider, providerId, avatarUrl }) {
  if (!id || deleted.has(id) || findById(id)) return findById(id);
  if (!["google", "github"].includes(provider) || !providerId) return null;
  if (oauthUserId(provider, providerId) !== id) return null; // claims must match the deterministic id
  return createUser({ name: name || email, email, provider, providerId: String(providerId), avatarUrl, id });
}
