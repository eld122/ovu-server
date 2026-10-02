import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import crypto from "node:crypto";

// JSON-file storage for project version history (cloud "Time Machine") and the
// community asset marketplace. Same zero-setup approach as db.js.
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = path.join(__dirname, "data");

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
// Community asset marketplace (brushes + models only)
// ---------------------------------------------------------------------------
const MAX_MODEL_BYTES = 8 * 1024 * 1024;

const BRUSH_NUMS = [
  "thickness", "opacity", "hardness", "pressureSensitivity", "taper", "bristleAmount",
  "softness", "flow", "grain", "stabilizer", "hueJitter", "satJitter", "valueJitter",
];

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

/** Listing never includes model bytes. */
const publicAsset = (a) => ({
  id: a.id, kind: a.kind, name: a.name, description: a.description,
  authorId: a.authorId, authorName: a.authorName, createdAt: a.createdAt,
  downloads: a.downloads, preview: a.preview, tags: a.tags,
  data: a.kind === "brush" ? a.data : { model: { name: a.data.model.name, bytes: a.data.model.bytes } },
});

export function listAssets({ kind, q } = {}) {
  const needle = String(q ?? "").trim().toLowerCase();
  return assets
    .filter((a) => !kind || a.kind === kind)
    .filter(
      (a) =>
        !needle ||
        a.name.toLowerCase().includes(needle) ||
        a.description.toLowerCase().includes(needle) ||
        a.authorName.toLowerCase().includes(needle) ||
        a.tags.some((t) => t.toLowerCase().includes(needle))
    )
    .sort((a, b) => b.downloads - a.downloads || b.createdAt - a.createdAt)
    .map(publicAsset);
}

const clamp01 = (n, max = 1) => Math.min(max, Math.max(0, Number.isFinite(+n) ? +n : 0));

export function createAsset(user, body) {
  const kind = body?.kind;
  if (kind !== "brush" && kind !== "model") throw new Error("Only brushes and models can be shared");
  const name = String(body.name ?? "").trim().slice(0, 60);
  if (name.length < 2) throw new Error("Name must be at least 2 characters");
  const description = String(body.description ?? "").trim().slice(0, 300);
  const tags = (Array.isArray(body.tags) ? body.tags : [])
    .map((t) => String(t).trim().toLowerCase().slice(0, 24))
    .filter(Boolean)
    .slice(0, 5);

  const asset = {
    id: crypto.randomUUID(), kind, name,
    description: description || (kind === "brush" ? "Community brush" : "Community model"),
    authorId: user.id, authorName: user.name, createdAt: Date.now(), downloads: 0, tags,
  };

  if (kind === "brush") {
    const b = body.brush ?? {};
    const brush = { color: /^#[0-9a-fA-F]{6}$/.test(b.color) ? b.color : "#1d1d1f", brushType: String(b.brushType ?? "handwriting").slice(0, 32) };
    for (const k of BRUSH_NUMS) brush[k] = clamp01(b[k], k === "thickness" ? 0.5 : 1);
    asset.preview = brush.color;
    asset.data = { brush };
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
export function downloadAsset(id) {
  const a = assets.find((x) => x.id === id);
  if (!a) return null;
  a.downloads += 1;
  saveAssets();
  return publicAsset(a);
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
  return true;
}

/** Called when an account is deleted. */
export function purgeUser(userId) {
  const vb = versions.length;
  versions = versions.filter((v) => v.userId !== userId);
  if (versions.length !== vb) saveVersions();
  const ab = assets.length;
  assets = assets.filter((a) => a.authorId !== userId);
  if (assets.length !== ab) saveAssets();
}
