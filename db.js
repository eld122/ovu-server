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

// Admins are configured on the server, never by a client flag.
//   OVU_ADMIN_IDS     comma-separated user ids (safest)
//   OVU_ADMIN_EMAILS  comma-separated emails — only honoured for Google / GitHub accounts, because
//                     email+password sign-ups are not verified and anyone could claim the address.
const envList = (v) => String(v || "").split(",").map((x) => x.trim().toLowerCase()).filter(Boolean);
export function isAdmin(u) {
  if (!u) return false;
  if (envList(process.env.OVU_ADMIN_IDS).includes(String(u.id).toLowerCase())) return true;
  return (u.provider === "google" || u.provider === "github") && !!u.email && envList(process.env.OVU_ADMIN_EMAILS).includes(u.email.toLowerCase());
}

export const publicUser = (u) => ({
  id: u.id,
  name: u.name,
  email: u.email,
  provider: u.provider,
  avatarUrl: u.avatarUrl ?? undefined,
  isAdmin: isAdmin(u) || undefined,
  emailVerified: u.provider !== "email" ? true : u.emailVerified === true,
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

export function createUser({ name, email, passwordHash = null, provider, providerId = null, avatarUrl = null, id = null, emailVerified = false }) {
  const user = {
    id: id || crypto.randomUUID(),
    name,
    email,
    passwordHash,
    provider,
    providerId,
    avatarUrl,
    emailVerified, // Google/GitHub accounts arrive verified; email sign-ups prove the address via a mailed link
    createdAt: new Date().toISOString(),
  };
  users.push(user);
  save(users);
  return user;
}

/** Find the user for an OAuth login, linking by verified email if needed. */
export function upsertOAuthUser({ provider, providerId, email, name, avatarUrl, onTakeover }) {
  let user = users.find((u) => u.provider === provider && u.providerId === String(providerId));
  if (user) return user;

  // Same verified email already registered (email/password or other provider):
  // reuse that account so people don't end up with duplicates.
  user = findByEmail(email);
  if (user) {
    // A password account whose address was never confirmed may have been registered by someone who does NOT own
    // that mailbox. The provider just proved the real owner, so the owner takes the account over: the old password
    // is deleted and the caller signs out every session that existed (onTakeover). Confirmed accounts just link.
    if (user.provider === "email" && user.emailVerified !== true) {
      user.passwordHash = null;
      user.provider = provider;
      user.providerId = String(providerId);
      user.name = name || user.name;
      user.emailVerified = true;
      user.avatarUrl = avatarUrl ?? user.avatarUrl;
      save(users);
      onTakeover?.(user);
      return user;
    }
    user.avatarUrl = user.avatarUrl ?? avatarUrl;
    user.emailVerified = true; // the provider confirmed this address
    save(users);
    return user;
  }
  return createUser({ name, email, provider, providerId: String(providerId), avatarUrl, id: oauthUserId(provider, providerId), emailVerified: true });
}

export function updateUser(id, patch) {
  const user = findById(id);
  if (!user) return null;
  if (typeof patch.name === "string" && patch.name.trim()) user.name = patch.name.trim();
  if (typeof patch.passwordHash === "string") user.passwordHash = patch.passwordHash;
  if (typeof patch.avatarUrl === "string") user.avatarUrl = patch.avatarUrl;
  if (typeof patch.emailVerified === "boolean") user.emailVerified = patch.emailVerified;
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
// Older social.json files predate these collections.
for (const k of ["follows", "likes", "comments", "saves", "reports", "notifications", "works"]) social[k] ||= [];
social.profiles ||= {};

// ---- Short profile links: ovu/@name ----------------------------------------------------------
// A handle is 3-20 lowercase letters / digits / underscores. It is unique (case-insensitive) and
// optional. Reserved words are blocked so a handle can never look like an app route.
export const HANDLE_RE = /^[a-z0-9_]{3,20}$/;
const RESERVED_HANDLES = new Set([
  "admin", "administrator", "api", "app", "auth", "help", "home", "login", "logout", "mod", "moderator", "ovu", "profile",
  "room", "root", "settings", "signin", "signup", "staff", "support", "system", "team", "user", "users", "www", "work", "works",
]);

/** Lower-cases and strips a leading @ / spaces. Returns "" for non-strings. */
export function normalizeHandle(raw) {
  if (typeof raw !== "string") return "";
  return raw.trim().replace(/^@+/, "").toLowerCase();
}

/** { ok: true, handle } or { ok: false, error }. Does not check availability. */
export function validateHandle(raw) {
  const handle = normalizeHandle(raw);
  if (handle.length < 3 || handle.length > 20) return { ok: false, error: "Use 3 to 20 characters." };
  if (!HANDLE_RE.test(handle)) return { ok: false, error: "Only letters, numbers and underscores." };
  if (RESERVED_HANDLES.has(handle)) return { ok: false, error: "That name is reserved." };
  return { ok: true, handle };
}

/** The user id that owns a handle, or null. Handles of deleted accounts are ignored. */
export function userIdByHandle(raw) {
  const handle = normalizeHandle(raw);
  if (!handle) return null;
  for (const [id, p] of Object.entries(social.profiles)) {
    if (p && p.handle === handle && findById(id)) return id;
  }
  return null;
}

export function isHandleTaken(raw, exceptUserId = null) {
  const owner = userIdByHandle(raw);
  return owner !== null && owner !== exceptUserId;
}

/** { available, reason? } for the settings screen's live check. */
export function handleAvailability(raw, userId = null) {
  const v = validateHandle(raw);
  if (!v.ok) return { available: false, reason: v.error };
  if (isHandleTaken(v.handle, userId)) return { available: false, reason: "Already taken." };
  return { available: true, handle: v.handle };
}

/** Sets (or clears, with null / "") the handle. { ok, handle } or { ok: false, error, status }. */
export function setHandle(userId, raw) {
  if (!findById(userId)) return { ok: false, error: "User not found", status: 404 };
  if (raw === null || raw === "") {
    updateProfile(userId, { handle: null });
    return { ok: true, handle: null };
  }
  const v = validateHandle(raw);
  if (!v.ok) return { ok: false, error: v.error, status: 400 };
  if (isHandleTaken(v.handle, userId)) return { ok: false, error: "That name is already taken.", status: 409 };
  updateProfile(userId, { handle: v.handle });
  return { ok: true, handle: v.handle };
}

/** A free handle derived from a display name, for the "suggest one" button. */
export function suggestHandle(name, userId = null) {
  let base = String(name || "").toLowerCase().normalize("NFKD").replace(/[^a-z0-9_]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 16);
  if (base.length < 3) base = (base + "_ovu_user").slice(0, 12);
  for (let i = 0; i < 50; i++) {
    const candidate = i === 0 ? base : `${base}${Math.floor(10 + Math.random() * 990)}`.slice(0, 20);
    if (validateHandle(candidate).ok && !isHandleTaken(candidate, userId)) return candidate;
  }
  return null;
}

export function getProfile(userId) {
  const user = findById(userId);
  if (!user) return null;
  const p = social.profiles[userId] || {};
  const followerCount = social.follows.filter((f) => f.followingId === userId).length;
  const followingCount = social.follows.filter((f) => f.followerId === userId).length;
  return {
    id: user.id,
    name: user.name,
    handle: p.handle || null,
    // A picture chosen on the portfolio wins over the sign-in provider's avatar.
    avatarUrl: p.avatarDataUrl || user.avatarUrl || undefined,
    bannerUrl: p.bannerDataUrl || undefined,
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

/** Portfolio order: pinned first, then the owner's custom order; works never dragged yet (new ones) come first, newest first. */
function portfolioOrder(a, b) {
  if (a.pinned !== b.pinned) return Number(b.pinned) - Number(a.pinned);
  const ao = a.order, bo = b.order;
  if (ao == null && bo == null) return b.createdAt - a.createdAt;
  if (ao == null) return -1;
  if (bo == null) return 1;
  return ao - bo;
}

export const PORTFOLIO_CATEGORIES = ["Characters", "Environments", "Props", "Concept art", "Animation", "Experiments", "Other"];
const cleanCategory = (c) => PORTFOLIO_CATEGORIES.find((x) => x.toLowerCase() === String(c ?? "").trim().toLowerCase()) ?? "";

export function listWorks(userId, viewerId = null) {
  return social.works
    .filter((w) => w.userId === userId && !w.deleted && (!w.hidden || viewerId === userId))
    .map(publicWork)
    .sort(portfolioOrder);
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
  const saveCount = social.saves.filter((x) => x.workId === w.id).length;
  const remixCount = social.works.filter((x) => !x.deleted && x.remixOf && x.remixOf.workId === w.id).length;
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
    saveCount,
    remixCount,
    tags: Array.isArray(w.tags) ? w.tags : [],
    pinned: Boolean(w.pinned),
    category: w.category || "",
    order: Number.isFinite(w.order) ? w.order : null,
    remixOf: w.remixOf || null,
    allowRemix: Boolean(w.allowRemix),
    createdAt: w.createdAt,
  };
}

/** Lower-case, de-duplicated tags (max 8, 24 chars each). */
export function cleanTags(input) {
  const list = Array.isArray(input) ? input : String(input ?? "").split(",");
  return [...new Set(list.map((t) => String(t).trim().toLowerCase().replace(/^#/, "").slice(0, 24)).filter(Boolean))].slice(0, 8);
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
    tags: cleanTags(payload.tags),
    category: cleanCategory(payload.category),
    pinned: false,
    allowRemix: Boolean(payload.allowRemix),
    remixOf: null,
    createdAt: Date.now(),
    deleted: false,
  };
  const src = payload.remixOfWorkId ? social.works.find((x) => x.id === payload.remixOfWorkId && !x.deleted) : null;
  if (src) {
    const au = findById(src.userId);
    work.remixOf = { workId: src.id, userId: src.userId, userName: au?.name || "User", title: src.title };
  }
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
  return createUser({ name: name || email, email, provider, providerId: String(providerId), avatarUrl, id, emailVerified: true });
}


// ---------------------------------------------------------------------------
// Global search (users + published works). Guests never exist on the server, but
// guest-style ids are filtered anyway; private portfolios stay hidden.
// ---------------------------------------------------------------------------
const isGuestUser = (u) => u.provider === "guest" || String(u.id).startsWith("guest-");

export function searchAll(rawQuery, limit = 24) {
  const needle = String(rawQuery ?? "").trim().replace(/^@+/, "").toLowerCase().slice(0, 80);
  if (!needle) return { users: [], works: [] };
  const isPublic = (userId) => (social.profiles[userId] || {}).isPublic !== false;

  const matchedUsers = users
    .filter(
      (u) =>
        !isGuestUser(u) &&
        isPublic(u.id) &&
        (String(u.name || "").toLowerCase().includes(needle) || String((social.profiles[u.id] || {}).handle || "").includes(needle))
    )
    .slice(0, limit)
    .map((u) => {
      const p = getProfile(u.id);
      return {
        id: u.id,
        name: u.name,
        handle: p?.handle || null,
        avatarUrl: p?.avatarUrl,
        bio: p?.bio || "",
        followerCount: p?.followerCount ?? 0,
        workCount: social.works.filter((w) => w.userId === u.id && !w.deleted).length,
      };
    });

  const owners = new Map(users.map((u) => [u.id, u]));
  const matchedWorks = social.works
    .filter((w) => {
      if (w.deleted || w.hidden) return false;
      const owner = owners.get(w.userId);
      if (!owner || isGuestUser(owner) || !isPublic(w.userId)) return false;
      return (
        String(w.title || "").toLowerCase().includes(needle) ||
        String(w.description || "").toLowerCase().includes(needle) ||
        String(owner.name || "").toLowerCase().includes(needle)
      );
    })
    .sort((a, b) => b.createdAt - a.createdAt)
    .slice(0, limit)
    .map((w) => ({
      ...publicWork(w),
      videoDataUrl: null, // heavy; the viewer loads it when the work is opened
      imageDataUrl: null,
      authorName: owners.get(w.userId)?.name || "",
    }));

  return { users: matchedUsers, works: matchedWorks };
}


// ---------------------------------------------------------------------------
// Part 6: saves, comment moderation, explore feed, pins, reports, notifications
// ---------------------------------------------------------------------------
export function toggleSave(userId, workId) {
  const idx = social.saves.findIndex((x) => x.userId === userId && x.workId === workId);
  if (idx >= 0) social.saves.splice(idx, 1);
  else social.saves.push({ userId, workId, at: Date.now() });
  saveSocial(social);
  return { saved: idx < 0, count: social.saves.filter((x) => x.workId === workId).length };
}

export const hasSaved = (userId, workId) => social.saves.some((x) => x.userId === userId && x.workId === workId);

export function listSaved(userId) {
  return social.saves
    .filter((x) => x.userId === userId)
    .sort((a, b) => b.at - a.at)
    .map((x) => social.works.find((w) => w.id === x.workId && !w.deleted))
    .filter(Boolean)
    .map((w) => ({ ...publicWork(w), videoDataUrl: null, imageDataUrl: null, authorName: findById(w.userId)?.name || "" }));
}

/** The comment's author, or the owner of the work it is on, may delete it. */
export function deleteComment(userId, commentId) {
  const c = social.comments.find((x) => x.id === commentId && !x.deleted);
  if (!c) return false;
  const work = social.works.find((w) => w.id === c.workId);
  if (c.userId !== userId && work?.userId !== userId) return false;
  c.deleted = true;
  saveSocial(social);
  return true;
}

const isPublicProfile = (userId) => (social.profiles[userId] || {}).isPublic !== false;

/** Public feed: sort = "popular" (engagement with recency decay) | "new". days limits the age. */
export function exploreWorks({ sort = "popular", days = 0, tag = "", limit = 30 } = {}) {
  const now = Date.now();
  const t = String(tag || "").toLowerCase().replace(/^#/, "");
  const score = (w) => {
    const likes = social.likes.filter((l) => l.workId === w.id).length;
    const comments = social.comments.filter((c) => c.workId === w.id && !c.deleted).length;
    const saves = social.saves.filter((x) => x.workId === w.id).length;
    const ageDays = (now - w.createdAt) / 86400000;
    return (likes * 3 + comments * 2 + saves * 2 + 1) / Math.pow(ageDays + 2, 0.6);
  };
  return social.works
    .filter((w) => {
      if (w.deleted || w.hidden) return false;
      const owner = findById(w.userId);
      if (!owner || isGuestUser(owner) || !isPublicProfile(w.userId)) return false;
      if (days > 0 && now - w.createdAt > days * 86400000) return false;
      if (t && !(Array.isArray(w.tags) && w.tags.includes(t))) return false;
      return true;
    })
    .sort((a, b) => (sort === "new" ? b.createdAt - a.createdAt : score(b) - score(a)))
    .slice(0, limit)
    .map((w) => ({ ...publicWork(w), videoDataUrl: null, imageDataUrl: null, authorName: findById(w.userId)?.name || "" }));
}

/** Owner-only: pin (max 3) or unpin. */
export function setPinned(userId, workId, pinned) {
  const w = social.works.find((x) => x.id === workId && x.userId === userId && !x.deleted);
  if (!w) return null;
  if (pinned && social.works.filter((x) => x.userId === userId && x.pinned && !x.deleted && x.id !== workId).length >= 3) {
    return { error: "You can pin up to 3 works" };
  }
  w.pinned = Boolean(pinned);
  saveSocial(social);
  return { work: publicWork(w) };
}

export function setWorkTags(userId, workId, tags) {
  const w = social.works.find((x) => x.id === workId && x.userId === userId && !x.deleted);
  if (!w) return null;
  w.tags = cleanTags(tags);
  saveSocial(social);
  return publicWork(w);
}

/** Owner-only. "" clears the category. Returns undefined when the category is not one of PORTFOLIO_CATEGORIES. */
export function setWorkCategory(userId, workId, category) {
  const w = social.works.find((x) => x.id === workId && x.userId === userId && !x.deleted);
  if (!w) return null;
  const raw = String(category ?? "").trim();
  const c = cleanCategory(raw);
  if (raw && !c) return { error: "Unknown category" };
  w.category = c;
  saveSocial(social);
  return { work: publicWork(w) };
}

/**
 * Owner-only drag-and-drop order. `ids` is the new order of (some of) the owner's works; any work not
 * listed keeps its current relative order after them. Unknown / foreign ids are ignored.
 */
export function reorderWorks(userId, ids) {
  const mine = social.works.filter((w) => w.userId === userId && !w.deleted);
  const byId = new Map(mine.map((w) => [w.id, w]));
  const wanted = [...new Set((Array.isArray(ids) ? ids : []).map(String))].filter((id) => byId.has(id));
  const rest = mine
    .map(publicWork)
    .sort(portfolioOrder)
    .map((w) => w.id)
    .filter((id) => !wanted.includes(id));
  [...wanted, ...rest].forEach((id, i) => {
    byId.get(id).order = i;
  });
  saveSocial(social);
  return listWorks(userId, userId);
}

const isOpen = (r) => !r.status || r.status === "open";

export function addReport(userId, { targetType, targetId, reason }) {
  if (!["work", "comment", "user", "asset"].includes(targetType) || !targetId) return null;
  if (social.reports.some((r) => r.userId === userId && r.targetType === targetType && r.targetId === targetId)) return { duplicate: true };
  social.reports.push({
    id: crypto.randomUUID(), userId, targetType, targetId: String(targetId).slice(0, 80),
    reason: String(reason || "").slice(0, 300), at: Date.now(),
  });
  // Three independent reports hide a work from public lists until reviewed.
  if (targetType === "work") {
    const n = social.reports.filter((r) => r.targetType === "work" && r.targetId === targetId && isOpen(r)).length;
    const w = social.works.find((x) => x.id === targetId);
    if (w && n >= 3) w.hidden = true;
  }
  saveSocial(social);
  return { ok: true };
}


// ---------------------------------------------------------------------------
// Moderation (admins only — the routes check isAdmin)
// ---------------------------------------------------------------------------
const WORK_ACTIONS = ["dismiss", "hide", "restore", "delete"];
const ACTIONS = { work: WORK_ACTIONS, comment: ["dismiss", "delete"], user: ["dismiss", "hide_works"], asset: ["dismiss", "delete"] };

function targetPreview(type, id) {
  if (type === "work") {
    const w = social.works.find((x) => x.id === id);
    if (!w) return { missing: true };
    return { title: w.title, kind: w.type, authorId: w.userId, authorName: findById(w.userId)?.name || "", hidden: !!w.hidden, deleted: !!w.deleted };
  }
  if (type === "comment") {
    const c = social.comments.find((x) => x.id === id);
    if (!c) return { missing: true };
    return { text: c.text, workId: c.workId, authorId: c.userId, authorName: findById(c.userId)?.name || "", deleted: !!c.deleted };
  }
  if (type === "user") {
    const u = findById(id);
    if (!u) return { missing: true };
    return { authorId: u.id, authorName: u.name };
  }
  return null; // assets are described by the caller (they live in cloud.js)
}

/** Reports grouped per target, newest activity first. status: "open" | "resolved". */
export function listReportGroups({ status = "open" } = {}) {
  const groups = new Map();
  for (const r of social.reports) {
    const open = isOpen(r);
    if ((status === "open") !== open) continue;
    const key = `${r.targetType}:${r.targetId}`;
    let g = groups.get(key);
    if (!g) {
      g = { targetType: r.targetType, targetId: r.targetId, count: 0, reasons: [], firstAt: r.at, lastAt: r.at, actions: [] };
      groups.set(key, g);
    }
    g.count++;
    g.firstAt = Math.min(g.firstAt, r.at);
    g.lastAt = Math.max(g.lastAt, r.at);
    if (r.reason && g.reasons.length < 5 && !g.reasons.includes(r.reason)) g.reasons.push(r.reason);
    if (r.action && !g.actions.includes(r.action)) g.actions.push(r.action);
    if (r.resolvedAt) g.resolvedAt = Math.max(g.resolvedAt || 0, r.resolvedAt);
  }
  return [...groups.values()]
    .map((g) => ({ ...g, target: targetPreview(g.targetType, g.targetId) }))
    .sort((a, b) => (status === "open" ? b.count - a.count || b.lastAt - a.lastAt : (b.resolvedAt || 0) - (a.resolvedAt || 0)));
}

export const openReportCount = () => new Set(social.reports.filter(isOpen).map((r) => `${r.targetType}:${r.targetId}`)).size;

/**
 * Applies a moderator decision to one target and closes every open report about it.
 * For assets the caller removes the asset itself (cloud.js) — this only does the bookkeeping.
 */
export function resolveReports(adminId, { targetType, targetId, action }) {
  const allowed = ACTIONS[targetType];
  if (!allowed) return { error: "Unknown target type" };
  if (!allowed.includes(action)) return { error: `"${action}" is not available for a ${targetType}` };
  const open = social.reports.filter((r) => r.targetType === targetType && r.targetId === targetId && isOpen(r));
  if (!open.length) return { error: "No open reports for this item" };

  if (targetType === "work") {
    const w = social.works.find((x) => x.id === targetId);
    if (w) {
      if (action === "hide") w.hidden = true;
      if (action === "delete") w.deleted = true;
      if (action === "dismiss" || action === "restore") w.hidden = false; // undo the 3-reports auto-hide
    }
  } else if (targetType === "comment") {
    const c = social.comments.find((x) => x.id === targetId);
    if (c && action === "delete") c.deleted = true;
  } else if (targetType === "user" && action === "hide_works") {
    for (const w of social.works) if (w.userId === targetId && !w.deleted) w.hidden = true;
  }

  const now = Date.now();
  for (const r of open) {
    r.status = action === "dismiss" ? "dismissed" : "actioned";
    r.action = action;
    r.resolvedAt = now;
    r.resolvedBy = adminId;
  }
  saveSocial(social);
  return { ok: true, resolved: open.length };
}

// Notifications -------------------------------------------------------------
export function notify(toUserId, { type, fromUserId, workId = null, text = "" }) {
  if (!toUserId || toUserId === fromUserId) return;
  const from = findById(fromUserId);
  social.notifications.push({
    id: crypto.randomUUID(), userId: toUserId, type, fromUserId,
    fromName: from?.name || "Someone", workId, text: String(text).slice(0, 120), at: Date.now(), read: false,
  });
  // keep the log bounded per user
  const mine = social.notifications.filter((n) => n.userId === toUserId);
  if (mine.length > 100) {
    const drop = new Set(mine.slice(0, mine.length - 100).map((n) => n.id));
    social.notifications = social.notifications.filter((n) => !drop.has(n.id));
  }
  saveSocial(social);
}

export function listNotifications(userId) {
  const mine = social.notifications.filter((n) => n.userId === userId).sort((a, b) => b.at - a.at).slice(0, 50);
  return { items: mine, unread: social.notifications.filter((n) => n.userId === userId && !n.read).length };
}

export function markNotificationsRead(userId) {
  let changed = false;
  for (const n of social.notifications) if (n.userId === userId && !n.read) { n.read = true; changed = true; }
  if (changed) saveSocial(social);
}

export const ownerOfWork = (workId) => social.works.find((w) => w.id === workId)?.userId ?? null;

export function setAllowRemix(userId, workId, allow) {
  const w = social.works.find((x) => x.id === workId && x.userId === userId && !x.deleted);
  if (!w) return null;
  w.allowRemix = Boolean(allow);
  saveSocial(social);
  return publicWork(w);
}

/** Payload for "Remix": only when the owner opted in (or you are the owner). */
export function getRemixSource(viewerId, workId) {
  const w = social.works.find((x) => x.id === workId && !x.deleted && !x.hidden);
  if (!w || w.type !== "model" || !w.modelData) return null;
  if (!w.allowRemix && w.userId !== viewerId) return { error: "The author has not allowed remixing this work" };
  return { work: publicWork(w), modelData: w.modelData, authorName: findById(w.userId)?.name || "User" };
}

// Creator stats --------------------------------------------------------------
/** Counts a view unless the owner is looking. Cheap per-day de-dup by viewer key (user id or IP). */
const recentViews = new Map();
export function countView(workId, viewerKey, viewerId) {
  const w = social.works.find((x) => x.id === workId && !x.deleted);
  if (!w || (viewerId && viewerId === w.userId)) return;
  const day = new Date().toISOString().slice(0, 10);
  const key = `${workId}|${viewerKey}|${day}`;
  if (recentViews.has(key)) return;
  recentViews.set(key, 1);
  if (recentViews.size > 5000) recentViews.clear();
  w.views = (w.views || 0) + 1;
  w.viewLog ||= {};
  w.viewLog[day] = (w.viewLog[day] || 0) + 1;
  // keep the last 30 days only
  const keep = Object.keys(w.viewLog).sort().slice(-30);
  w.viewLog = Object.fromEntries(keep.map((k) => [k, w.viewLog[k]]));
  saveSocial(social);
}

export function getStats(userId) {
  const mine = social.works.filter((w) => w.userId === userId && !w.deleted);
  const ids = new Set(mine.map((w) => w.id));
  const count = (arr) => arr.filter((x) => ids.has(x.workId)).length;
  const days = [];
  for (let i = 29; i >= 0; i--) days.push(new Date(Date.now() - i * 86400000).toISOString().slice(0, 10));
  const perDay = days.map((d) => mine.reduce((s, w) => s + ((w.viewLog || {})[d] || 0), 0));
  const top = mine
    .map((w) => ({ id: w.id, title: w.title, views: w.views || 0, likes: social.likes.filter((l) => l.workId === w.id).length }))
    .sort((a, b) => b.views + b.likes * 3 - (a.views + a.likes * 3))
    .slice(0, 5);
  return {
    works: mine.length,
    views: mine.reduce((s, w) => s + (w.views || 0), 0),
    likes: count(social.likes),
    saves: count(social.saves),
    comments: social.comments.filter((c) => ids.has(c.workId) && !c.deleted).length,
    remixes: social.works.filter((w) => !w.deleted && w.remixOf && ids.has(w.remixOf.workId)).length,
    followers: social.follows.filter((f) => f.followingId === userId).length,
    viewsPerDay: perDay,
    top,
  };
}
