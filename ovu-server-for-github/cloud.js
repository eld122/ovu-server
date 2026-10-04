import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import crypto from "node:crypto";

// JSON-file storage for project version history (cloud "Time Machine") and the
// community asset marketplace. Same zero-setup approach as db.js.
const __dirname = path.dirname(fileURLToPath(import.meta.url));
import { DATA_DIR } from "./dataDir.js";

function readJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(path.join(DATA_DIR, file), "utf8"));
  } catch {
    return fallback;
  }
}
function writeJson(file, data) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const full = path.join(DATA_DIR, file);
  const tmp = full + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(data));
  fs.renameSync(tmp, full);
}

// ---------------------------------------------------------------------------
// Version history
// ---------------------------------------------------------------------------
const MAX_VERSIONS_PER_PROJECT = 60;
const MAX_VERSION_BYTES = 8 * 1024 * 1024;

let versions = readJson("versions.json", []);
const saveVersions = () => writeJson("versions.json", versions);

const meta = (v) => ({
  id: v.id,
  projectId: v.projectId,
  label: v.label,
  createdAt: v.createdAt,
  strokeCount: v.strokeCount,
});

export function listVersions(userId, projectId) {
  return versions
    .filter((v) => v.userId === userId && v.projectId === projectId)
    .sort((a, b) => b.createdAt - a.createdAt)
    .map(meta);
}

export function getVersion(userId, id) {
  const v = versions.find((x) => x.id === id && x.userId === userId);
  return v ? { ...meta(v), data: v.data } : null;
}

/** Idempotent: pushing the same version id twice updates nothing. */
export function putVersion(userId, body) {
  const id = String(body?.id ?? "");
  const projectId = String(body?.projectId ?? "");
  if (!/^[\w-]{8,64}$/.test(id) || !/^[\w-]{1,64}$/.test(projectId)) throw new Error("Invalid version id");
  const data = body?.data;
  if (!data || !Array.isArray(data.strokes)) throw new Error("Invalid version data");
  if (JSON.stringify(data).length > MAX_VERSION_BYTES) throw new Error("Version too large");

  const existing = versions.find((v) => v.id === id);
  if (existing) {
    if (existing.userId !== userId) throw new Error("Invalid version id");
    return meta(existing);
  }
  const v = {
    id,
    userId,
    projectId,
    label: String(body.label ?? "Checkpoint").slice(0, 120),
    createdAt: Number(body.createdAt) || Date.now(),
    strokeCount: data.strokes.length,
    data,
  };
  versions.push(v);

  // Prune per project: drop the oldest beyond the cap
  const mine = versions
    .filter((x) => x.userId === userId && x.projectId === projectId)
    .sort((a, b) => a.createdAt - b.createdAt);
  const drop = new Set(mine.slice(0, Math.max(0, mine.length - MAX_VERSIONS_PER_PROJECT)).map((x) => x.id));
  if (drop.size) versions = versions.filter((x) => !drop.has(x.id));
  saveVersions();
  return meta(v);
}

export function removeVersion(userId, id) {
  const before = versions.length;
  versions = versions.filter((v) => !(v.id === id && v.userId === userId));
  if (versions.length === before) return false;
  saveVersions();
  return true;
}

export function removeProjectVersions(userId, projectId) {
  const before = versions.length;
  versions = versions.filter((v) => !(v.userId === userId && v.projectId === projectId));
  if (versions.length !== before) saveVersions();
}

// ---------------------------------------------------------------------------
// Community asset marketplace (brushes, models, lighting presets)
// ---------------------------------------------------------------------------
const MAX_MODEL_BYTES = 8 * 1024 * 1024;

const BRUSH_NUMS = [
  "thickness", "opacity", "hardness", "pressureSensitivity", "taper", "bristleAmount",
  "softness", "flow", "grain", "stabilizer", "hueJitter", "satJitter", "valueJitter",
];

// Lighting presets = the lighting subset of the app's EffectsSettings.
const LIGHT_NUMS = {
  bloomStrength: [0, 3], bloomThreshold: [0, 1], bloomRadius: [0, 2],
  ambientIntensity: [0, 2], hemisphereIntensity: [0, 2],
  sunIntensity: [0, 5], sunAzimuth: [0, 360], sunElevation: [0, 90],
  shadowOpacity: [0, 1], shadowBlur: [0, 5],
  fillIntensity: [0, 3], rimIntensity: [0, 3],
  envIntensity: [0, 2], exposure: [0.2, 2.5],
  vignette: [0, 1], grain: [0, 1], fogDensity: [0, 1],
};
const LIGHT_COLORS = ["hemisphereSky", "hemisphereGround", "sunColor", "fillColor", "rimColor", "fogColor"];
const LIGHT_BOOLS = ["bloomEnabled", "sunEnabled", "sunCastShadow", "fillEnabled", "rimEnabled", "fogEnabled"];
const MAX_COVER_BYTES = 400 * 1024;
const SKY_PRESETS = ["none", "studio", "apartment", "city", "dawn", "forest", "lobby", "night", "park", "sunset", "warehouse", "space", "future", "woods"];

function sanitizeLighting(raw) {
  const src = raw && typeof raw === "object" ? raw : {};
  const out = {};
  for (const [k, [lo, hi]] of Object.entries(LIGHT_NUMS)) {
    if (src[k] === undefined) continue;
    const n = Number(src[k]);
    if (Number.isFinite(n)) out[k] = Math.min(hi, Math.max(lo, n));
  }
  for (const k of LIGHT_COLORS) if (/^#[0-9a-fA-F]{6}$/.test(src[k])) out[k] = src[k];
  for (const k of LIGHT_BOOLS) if (typeof src[k] === "boolean") out[k] = src[k];
  return out;
}

/** Cover image arrives as a small data URL (the client downsizes it). */
function sanitizeCover(raw) {
  if (!raw) return undefined;
  const c = String(raw);
  if (!/^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/.test(c)) throw new Error("Cover must be a JPEG, PNG or WebP image");
  if (Buffer.byteLength(c) > MAX_COVER_BYTES * 1.4) throw new Error("Cover image is too large");
  return c;
}

const SEED = [
  {
    id: "seed-ink-brush", name: "Sumi Ink", description: "Soft calligraphy-style brush with strong taper.",
    tags: ["ink", "calligraphy"], downloads: 128, daysAgo: 12,
    brush: { color: "#1d1d1f", thickness: 0.035, brushType: "handwriting", opacity: 0.92, hardness: 0.55, pressureSensitivity: 0.85, taper: 0.7, bristleAmount: 0.2, softness: 0.4, flow: 0.5, grain: 0.15, stabilizer: 0.35, hueJitter: 0, satJitter: 0, valueJitter: 0.05 },
  },
  {
    id: "seed-oil-rich", name: "Rich Oil", description: "Thick oil paint with visible bristles.",
    tags: ["oil", "paint"], downloads: 86, daysAgo: 8,
    brush: { color: "#b3231c", thickness: 0.05, brushType: "oil", opacity: 0.95, hardness: 0.4, pressureSensitivity: 0.6, taper: 0.2, bristleAmount: 0.75, softness: 0.3, flow: 0.4, grain: 0.2, stabilizer: 0.2, hueJitter: 0.03, satJitter: 0.05, valueJitter: 0.04 },
  },
];

let assets = readJson("assets.json", null);
if (!assets) {
  assets = SEED.map((s) => ({
    id: s.id, kind: "brush", name: s.name, description: s.description,
    authorId: "ovu", authorName: "Ovu Studio",
    createdAt: Date.now() - 86400000 * s.daysAgo, downloads: s.downloads,
    preview: s.brush.color, tags: s.tags, data: { brush: s.brush },
  }));
  writeJson("assets.json", assets);
}
const saveAssets = () => writeJson("assets.json", assets);

/** Listing never includes model bytes. `me` (user id) adds the viewer's own liked / saved flags. */
const publicAsset = (a, me = null) => ({
  id: a.id, kind: a.kind, name: a.name, description: a.description,
  authorId: a.authorId, authorName: a.authorName, createdAt: a.createdAt,
  downloads: a.downloads, preview: a.preview, tags: a.tags, cover: a.cover,
  ratingAvg: a.ratings && a.ratings.length ? Math.round((a.ratings.reduce((s, r) => s + r.stars, 0) / a.ratings.length) * 10) / 10 : 0,
  ratingCount: a.ratings ? a.ratings.length : 0,
  likeCount: a.likes ? a.likes.length : 0,
  saveCount: a.saves ? a.saves.length : 0,
  commentCount: a.comments ? a.comments.length : 0,
  liked: !!me && !!a.likes && a.likes.includes(me),
  saved: !!me && !!a.saves && a.saves.includes(me),
  data:
    a.kind === "brush" || a.kind === "lighting" || a.kind === "style"
      ? a.data
      : { model: { name: a.data.model.name, bytes: a.data.model.bytes } },
});

const avg = (a) => (a.ratings && a.ratings.length ? a.ratings.reduce((s, r) => s + r.stars, 0) / a.ratings.length : 0);

const WEEK_MS = 7 * 86400000;
const hot = (a) => (a.likes?.length || 0) * 3 + (a.saves?.length || 0) * 2 + (a.comments?.length || 0) + a.downloads;

/**
 * sort: "popular" (downloads) · "new" · "rating" · "week" = only items published in the last 7 days,
 * hottest first (likes, saves, comments, downloads) · "liked" = most liked.
 * `onlySaved` limits the list to what `me` saved.
 */
export function listAssets({ kind, q, sort, me = null, onlySaved = false } = {}) {
  const needle = String(q ?? "").trim().toLowerCase();
  const since = Date.now() - WEEK_MS;
  return assets
    .filter((a) => !kind || a.kind === kind)
    .filter((a) => sort !== "week" || a.createdAt >= since)
    .filter((a) => !onlySaved || (me && a.saves && a.saves.includes(me)))
    .filter(
      (a) =>
        !needle ||
        a.name.toLowerCase().includes(needle) ||
        a.description.toLowerCase().includes(needle) ||
        a.authorName.toLowerCase().includes(needle) ||
        a.tags.some((t) => t.toLowerCase().includes(needle))
    )
    .sort((a, b) => {
      if (sort === "new") return b.createdAt - a.createdAt;
      if (sort === "rating") return avg(b) - avg(a) || b.downloads - a.downloads;
      if (sort === "week") return hot(b) - hot(a) || b.createdAt - a.createdAt;
      if (sort === "liked") return (b.likes?.length || 0) - (a.likes?.length || 0) || b.downloads - a.downloads;
      return b.downloads - a.downloads || b.createdAt - a.createdAt;
    })
    .map((a) => publicAsset(a, me));
}

const clamp01 = (n, max = 1) => Math.min(max, Math.max(0, Number.isFinite(+n) ? +n : 0));

export function createAsset(user, body) {
  const kind = body?.kind;
  if (!["brush", "model", "lighting", "style"].includes(kind)) throw new Error("Only brushes, models, lighting presets and style packs can be shared");
  const name = String(body.name ?? "").trim().slice(0, 60);
  if (name.length < 2) throw new Error("Name must be at least 2 characters");
  const description = String(body.description ?? "").trim().slice(0, 300);
  const tags = (Array.isArray(body.tags) ? body.tags : [])
    .map((t) => String(t).trim().toLowerCase().slice(0, 24))
    .filter(Boolean)
    .slice(0, 5);

  const asset = {
    id: crypto.randomUUID(), kind, name,
    description: description || (kind === "brush" ? "Community brush" : kind === "lighting" ? "Community lighting preset" : kind === "style" ? "Community style pack" : "Community model"),
    authorId: user.id, authorName: user.name, createdAt: Date.now(), downloads: 0, tags,
  };
  const cover = sanitizeCover(body.cover);
  if (cover) asset.cover = cover;

  if (kind === "brush") {
    const b = body.brush ?? {};
    const brush = { color: /^#[0-9a-fA-F]{6}$/.test(b.color) ? b.color : "#1d1d1f", brushType: String(b.brushType ?? "handwriting").slice(0, 32) };
    for (const k of BRUSH_NUMS) brush[k] = clamp01(b[k], k === "thickness" ? 0.5 : 1);
    asset.preview = brush.color;
    asset.data = { brush };
  } else if (kind === "style") {
    // Style pack = brush + lighting + environment saved together.
    const st = body.style && typeof body.style === "object" ? body.style : {};
    const data = {};
    if (st.brush) {
      const b = st.brush;
      const brush = { color: /^#[0-9a-fA-F]{6}$/.test(b.color) ? b.color : "#1d1d1f", brushType: String(b.brushType ?? "handwriting").slice(0, 32) };
      for (const k of BRUSH_NUMS) brush[k] = clamp01(b[k], k === "thickness" ? 0.5 : 1);
      data.brush = brush;
    }
    if (st.lighting) {
      const l = sanitizeLighting(st.lighting);
      if (Object.keys(l).length) data.lighting = l;
    }
    if (st.skybox && SKY_PRESETS.includes(st.skybox.preset)) {
      data.skybox = {
        preset: st.skybox.preset,
        showBackground: st.skybox.showBackground !== false,
        backgroundBlur: clamp01(st.skybox.backgroundBlur),
        useAsEnvironment: st.skybox.useAsEnvironment !== false,
        autoLighting: Boolean(st.skybox.autoLighting),
      };
    }
    if (!data.brush && !data.lighting && !data.skybox) throw new Error("A style pack needs at least a brush, lighting or environment");
    asset.preview = data.brush?.color || data.lighting?.sunColor || "#888888";
    asset.data = { style: data };
  } else if (kind === "lighting") {
    const lighting = sanitizeLighting(body.lighting);
    if (Object.keys(lighting).length < 3) throw new Error("Missing lighting settings");
    asset.preview = lighting.sunColor || "#fff5e6";
    asset.data = { lighting };
  } else {
    const b64 = String(body.glbBase64 ?? "");
    const buf = Buffer.from(b64, "base64");
    if (buf.length === 0) throw new Error("Missing model file");
    if (buf.length > MAX_MODEL_BYTES) throw new Error("Model is larger than 8 MB");
    if (buf.subarray(0, 4).toString("ascii") !== "glTF") throw new Error("Only binary .glb files can be shared");
    asset.data = { model: { name: String(body.modelName ?? name).slice(0, 80), bytes: buf.length, glbBase64: b64 } };
  }
  assets.unshift(asset);
  saveAssets();
  return publicAsset(asset);
}

/** Brush payload for install; counts the download. */
export function downloadAsset(id, me = null) {
  const a = assets.find((x) => x.id === id);
  if (!a) return null;
  a.downloads += 1;
  saveAssets();
  return publicAsset(a, me);
}

/** One rating (1-5) per user; rating again replaces the previous one. Authors cannot rate themselves. */
export function rateAsset(userId, id, stars, review = "") {
  const a = assets.find((x) => x.id === id);
  if (!a) return null;
  if (a.authorId === userId) return { error: "You cannot rate your own asset" };
  const n = Math.round(Number(stars));
  if (!(n >= 1 && n <= 5)) return { error: "Rating must be 1-5" };
  a.ratings ||= [];
  const mine = a.ratings.find((r) => r.userId === userId);
  const text = String(review || "").trim().slice(0, 300);
  if (mine) { mine.stars = n; mine.review = text; mine.at = Date.now(); }
  else a.ratings.push({ userId, stars: n, review: text, at: Date.now() });
  saveAssets();
  return { asset: publicAsset(a, userId) };
}

export function listReviews(id) {
  const a = assets.find((x) => x.id === id);
  return (a?.ratings || []).filter((r) => r.review).sort((x, y) => y.at - x.at).slice(0, 30)
    .map((r) => ({ stars: r.stars, review: r.review, at: r.at }));
}

// ---- Likes, saves and comments on marketplace assets ----
const MAX_COMMENTS_PER_ASSET = 200;

export function toggleAssetLike(userId, id) {
  const a = assets.find((x) => x.id === id);
  if (!a) return null;
  a.likes ||= [];
  const i = a.likes.indexOf(userId);
  if (i >= 0) a.likes.splice(i, 1);
  else a.likes.push(userId);
  saveAssets();
  return { asset: publicAsset(a, userId), added: i < 0 };
}

export function toggleAssetSave(userId, id) {
  const a = assets.find((x) => x.id === id);
  if (!a) return null;
  a.saves ||= [];
  const i = a.saves.indexOf(userId);
  if (i >= 0) a.saves.splice(i, 1);
  else a.saves.push(userId);
  saveAssets();
  return { asset: publicAsset(a, userId), added: i < 0 };
}

export function listAssetComments(id) {
  const a = assets.find((x) => x.id === id);
  if (!a) return null;
  return (a.comments || []).slice().sort((x, y) => y.at - x.at).map((c) => ({ id: c.id, userId: c.userId, userName: c.userName, text: c.text, at: c.at }));
}

export function addAssetComment(user, id, text) {
  const a = assets.find((x) => x.id === id);
  if (!a) return null;
  const t = String(text ?? "").trim().slice(0, 400);
  if (!t) return { error: "Write something first" };
  a.comments ||= [];
  if (a.comments.length >= MAX_COMMENTS_PER_ASSET) return { error: "This item has reached its comment limit" };
  const c = { id: crypto.randomUUID(), userId: user.id, userName: user.name, text: t, at: Date.now() };
  a.comments.push(c);
  saveAssets();
  return { comment: c, asset: publicAsset(a, user.id), authorId: a.authorId, assetName: a.name };
}

/** The comment's author or the asset's author can delete it. */
export function removeAssetComment(userId, id, commentId) {
  const a = assets.find((x) => x.id === id);
  if (!a || !a.comments) return null;
  const c = a.comments.find((x) => x.id === commentId);
  if (!c) return null;
  if (c.userId !== userId && a.authorId !== userId) return { error: "Not allowed" };
  a.comments = a.comments.filter((x) => x.id !== commentId);
  saveAssets();
  return { asset: publicAsset(a, userId) };
}

// ---------------------------------------------------------------------------
// Collections: a user bundles brushes, lighting, styles and models into one pack
// that anyone can install in one click (private ones are visible only to the owner).
// ---------------------------------------------------------------------------
const MAX_COLLECTIONS_PER_USER = 30;
const MAX_ITEMS_PER_COLLECTION = 40;

let collections = readJson("collections.json", []);
const saveCollections = () => writeJson("collections.json", collections);

const liveItems = (c) => c.itemIds.map((id) => assets.find((a) => a.id === id)).filter(Boolean);

const collectionMeta = (c, me = null) => {
  const items = liveItems(c);
  const kinds = { brush: 0, model: 0, lighting: 0, style: 0 };
  for (const a of items) kinds[a.kind] += 1;
  return {
    id: c.id, name: c.name, description: c.description,
    ownerId: c.ownerId, ownerName: c.ownerName, public: c.public,
    createdAt: c.createdAt, updatedAt: c.updatedAt, downloads: c.downloads || 0,
    itemCount: items.length, kinds,
    itemIds: items.map((a) => a.id),
    tiles: items.slice(0, 4).map((a) => ({ kind: a.kind, cover: a.cover, preview: a.preview })),
    mine: !!me && c.ownerId === me,
  };
};

const canSee = (c, me) => c.public || (!!me && c.ownerId === me);

/** scope "mine" = the signed-in user's own (public + private); otherwise every public collection. */
export function listCollections({ me = null, scope = "all", q = "" } = {}) {
  const needle = String(q ?? "").trim().toLowerCase();
  return collections
    .filter((c) => (scope === "mine" ? !!me && c.ownerId === me : c.public))
    .filter((c) => !needle || c.name.toLowerCase().includes(needle) || c.description.toLowerCase().includes(needle) || c.ownerName.toLowerCase().includes(needle))
    .sort((a, b) => (b.downloads || 0) - (a.downloads || 0) || b.updatedAt - a.updatedAt)
    .map((c) => collectionMeta(c, me));
}

export function getCollection(id, me = null) {
  const c = collections.find((x) => x.id === id);
  if (!c || !canSee(c, me)) return null;
  return { ...collectionMeta(c, me), assets: liveItems(c).map((a) => publicAsset(a, me)) };
}

function cleanCollectionFields(body, partial = false) {
  const out = {};
  if (!partial || body?.name !== undefined) {
    const name = String(body?.name ?? "").trim().slice(0, 60);
    if (name.length < 2) throw new Error("Name must be at least 2 characters");
    out.name = name;
  }
  if (!partial || body?.description !== undefined) out.description = String(body?.description ?? "").trim().slice(0, 300);
  if (!partial || body?.public !== undefined) out.public = body?.public !== false;
  return out;
}

export function createCollection(user, body) {
  if (collections.filter((c) => c.ownerId === user.id).length >= MAX_COLLECTIONS_PER_USER) throw new Error("You reached the limit of 30 collections");
  const fields = cleanCollectionFields(body);
  const now = Date.now();
  const c = { id: crypto.randomUUID(), ownerId: user.id, ownerName: user.name, itemIds: [], downloads: 0, createdAt: now, updatedAt: now, ...fields };
  const first = typeof body?.assetId === "string" ? assets.find((a) => a.id === body.assetId) : null;
  if (first) c.itemIds.push(first.id);
  collections.unshift(c);
  saveCollections();
  return collectionMeta(c, user.id);
}

export function updateCollection(userId, id, body) {
  const c = collections.find((x) => x.id === id && x.ownerId === userId);
  if (!c) return null;
  Object.assign(c, cleanCollectionFields(body, true), { updatedAt: Date.now() });
  saveCollections();
  return collectionMeta(c, userId);
}

export function removeCollection(userId, id) {
  const before = collections.length;
  collections = collections.filter((c) => !(c.id === id && c.ownerId === userId));
  if (collections.length === before) return false;
  saveCollections();
  return true;
}

export function addToCollection(userId, id, assetId) {
  const c = collections.find((x) => x.id === id && x.ownerId === userId);
  if (!c) return null;
  if (!assets.some((a) => a.id === assetId)) return { error: "Asset not found" };
  if (c.itemIds.includes(assetId)) return { collection: collectionMeta(c, userId) };
  if (liveItems(c).length >= MAX_ITEMS_PER_COLLECTION) return { error: "A collection holds up to 40 items" };
  c.itemIds.push(assetId);
  c.updatedAt = Date.now();
  saveCollections();
  return { collection: collectionMeta(c, userId) };
}

export function removeFromCollection(userId, id, assetId) {
  const c = collections.find((x) => x.id === id && x.ownerId === userId);
  if (!c) return null;
  c.itemIds = c.itemIds.filter((x) => x !== assetId);
  c.updatedAt = Date.now();
  saveCollections();
  return { collection: collectionMeta(c, userId) };
}

/** One-click install: counts a download for the pack and for every item in it. */
export function downloadCollection(id, me = null) {
  const c = collections.find((x) => x.id === id);
  if (!c || !canSee(c, me)) return null;
  const items = liveItems(c);
  c.downloads = (c.downloads || 0) + 1;
  for (const a of items) a.downloads += 1;
  saveCollections();
  saveAssets();
  return { ...collectionMeta(c, me), assets: items.map((a) => publicAsset(a, me)) };
}

export function getModelFile(id) {
  const a = assets.find((x) => x.id === id && x.kind === "model");
  return a ? Buffer.from(a.data.model.glbBase64, "base64") : null;
}

export function removeAsset(userId, id) {
  const before = assets.length;
  assets = assets.filter((a) => !(a.id === id && a.authorId === userId));
  if (assets.length === before) return false;
  saveAssets();
  let touched = false;
  for (const c of collections) {
    if (c.itemIds.includes(id)) { c.itemIds = c.itemIds.filter((x) => x !== id); touched = true; }
  }
  if (touched) saveCollections();
  return true;
}

/** Moderators: what an asset looks like in the reports list (null if it no longer exists). */
export function assetBrief(id) {
  const a = assets.find((x) => x.id === id);
  return a ? { title: a.name, kind: a.kind, authorId: a.authorId, authorName: a.authorName || "" } : null;
}

/** Moderators: remove any asset (and drop it from collections). */
export function adminRemoveAsset(id) {
  const a = assets.find((x) => x.id === id);
  return a ? removeAsset(a.authorId, id) : false;
}

/** Called when an account is deleted. */
export function purgeUser(userId) {
  const vb = versions.length;
  versions = versions.filter((v) => v.userId !== userId);
  if (versions.length !== vb) saveVersions();
  const ab = assets.length;
  assets = assets.filter((a) => a.authorId !== userId);
  if (assets.length !== ab) saveAssets();
  const cb = collections.length;
  collections = collections.filter((c) => c.ownerId !== userId);
  if (collections.length !== cb) saveCollections();
}
