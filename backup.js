import fs from "node:fs";
import path from "node:path";
import { DATA_DIR } from "./dataDir.js";

// Full cloud backup: the latest complete snapshot of every project (+ its imported
// model / image files) per user. Complements the Time Machine (cloud.js), which only
// keeps stroke history. Last-write-wins by `savedAt`, so two devices never clobber
// a newer copy with an older one.
const ROOT = path.join(DATA_DIR, "backups");
const MAX_SNAPSHOT_BYTES = 12 * 1024 * 1024;
export const MAX_ASSET_BYTES = 25 * 1024 * 1024;
export const USER_QUOTA_BYTES = 200 * 1024 * 1024;

const ID_RE = /^[\w-]{1,64}$/;
const okId = (s) => typeof s === "string" && ID_RE.test(s);

const userDir = (u) => path.join(ROOT, String(u).replace(/[^\w-]/g, "_"));
const projDir = (u) => path.join(userDir(u), "projects");
const assetDir = (u) => path.join(userDir(u), "assets");

function atomicWrite(file, data) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = file + ".tmp";
  fs.writeFileSync(tmp, data);
  fs.renameSync(tmp, file);
}

function dirBytes(dir) {
  try {
    return fs.readdirSync(dir).reduce((n, f) => {
      try {
        return n + fs.statSync(path.join(dir, f)).size;
      } catch {
        return n;
      }
    }, 0);
  } catch {
    return 0;
  }
}

export const usedBytes = (userId) => dirBytes(projDir(userId)) + dirBytes(assetDir(userId));

const meta = (rec) => ({
  projectId: rec.projectId,
  name: rec.name,
  savedAt: rec.savedAt,
  createdAt: rec.createdAt,
  updatedAt: rec.updatedAt,
  folderId: rec.folderId ?? null,
  tags: rec.tags ?? [],
  thumbnail: rec.thumbnail ?? null,
  strokeCount: rec.strokeCount,
  assetIds: rec.assetIds ?? [],
});

function readRec(userId, projectId) {
  try {
    return JSON.parse(fs.readFileSync(path.join(projDir(userId), `${projectId}.json`), "utf8"));
  } catch {
    return null;
  }
}

export function listBackups(userId) {
  let files = [];
  try {
    files = fs.readdirSync(projDir(userId)).filter((f) => f.endsWith(".json"));
  } catch {
    /* none yet */
  }
  return files
    .map((f) => readRec(userId, f.slice(0, -5)))
    .filter(Boolean)
    .map(meta)
    .sort((a, b) => b.savedAt - a.savedAt);
}

export function getBackup(userId, projectId) {
  if (!okId(projectId)) return null;
  const rec = readRec(userId, projectId);
  return rec ? { ...meta(rec), data: rec.data } : null;
}

/**
 * Stores a project snapshot. Returns { meta, stale } — `stale: true` means the server already
 * holds a newer copy and nothing was written (the client should pull instead of push).
 */
export function putBackup(userId, body) {
  const projectId = String(body?.projectId ?? "");
  if (!okId(projectId)) throw new Error("Invalid project id");
  const data = body?.data;
  if (!data || !Array.isArray(data.strokes)) throw new Error("Invalid project data");
  const json = JSON.stringify(data);
  if (json.length > MAX_SNAPSHOT_BYTES) throw new Error("Project too large");

  const savedAt = Number(body.savedAt) || Date.now();
  const existing = readRec(userId, projectId);
  if (existing && existing.savedAt >= savedAt) return { meta: meta(existing), stale: true };

  const assetIds = [...new Set([...(data.models ?? []), ...(data.images ?? [])].map((x) => x?.assetId).filter(okId))];
  const rec = {
    projectId,
    name: String(body.name ?? "Untitled").slice(0, 120),
    savedAt,
    createdAt: Number(body.createdAt) || existing?.createdAt || savedAt,
    updatedAt: Number(body.updatedAt) || savedAt,
    folderId: body.folderId && okId(String(body.folderId)) ? String(body.folderId) : null,
    tags: Array.isArray(body.tags) ? body.tags.slice(0, 12).map((t) => String(t).slice(0, 32)) : [],
    thumbnail: typeof body.thumbnail === "string" && body.thumbnail.length < 200_000 ? body.thumbnail : null,
    strokeCount: data.strokes.length,
    assetIds,
    data,
  };
  const out = JSON.stringify(rec);
  const delta = out.length - (existing ? JSON.stringify(existing).length : 0);
  if (usedBytes(userId) + delta > USER_QUOTA_BYTES) throw new Error("Cloud storage full");
  atomicWrite(path.join(projDir(userId), `${projectId}.json`), out);
  return { meta: meta(rec), stale: false };
}

export function removeBackup(userId, projectId) {
  if (!okId(projectId)) return false;
  const file = path.join(projDir(userId), `${projectId}.json`);
  if (!fs.existsSync(file)) return false;
  fs.unlinkSync(file);
  pruneAssets(userId);
  return true;
}

/** Deletes asset files no remaining project references. */
function pruneAssets(userId) {
  const keep = new Set(listBackups(userId).flatMap((m) => m.assetIds));
  try {
    for (const f of fs.readdirSync(assetDir(userId))) {
      if (!keep.has(f.replace(/\.mime$/, ""))) fs.unlinkSync(path.join(assetDir(userId), f));
    }
  } catch {
    /* no assets */
  }
}

/** Which of these asset ids has the server NOT stored yet? */
export function missingAssets(userId, ids) {
  return (Array.isArray(ids) ? ids : []).filter(okId).filter((id) => !fs.existsSync(path.join(assetDir(userId), id)));
}

export function putBackupAsset(userId, id, buf, mime) {
  if (!okId(id)) throw new Error("Invalid asset id");
  if (!Buffer.isBuffer(buf) || !buf.length) throw new Error("Empty file");
  if (buf.length > MAX_ASSET_BYTES) throw new Error("File too large");
  const file = path.join(assetDir(userId), id);
  if (fs.existsSync(file)) return { stored: false };
  if (usedBytes(userId) + buf.length > USER_QUOTA_BYTES) throw new Error("Cloud storage full");
  atomicWrite(file, buf);
  atomicWrite(file + ".mime", String(mime || "application/octet-stream").slice(0, 100));
  return { stored: true };
}

export function getBackupAsset(userId, id) {
  if (!okId(id)) return null;
  const file = path.join(assetDir(userId), id);
  try {
    const buf = fs.readFileSync(file);
    let mime = "application/octet-stream";
    try {
      mime = fs.readFileSync(file + ".mime", "utf8");
    } catch {
      /* default */
    }
    return { buf, mime };
  } catch {
    return null;
  }
}

export function removeAllBackups(userId) {
  fs.rmSync(userDir(userId), { recursive: true, force: true });
}
