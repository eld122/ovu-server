import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { DATA_DIR } from "./dataDir.js";

// View-only share links: anyone with the link can look at a frozen snapshot of a project,
// no account needed. One link per (user, project): sharing again refreshes the snapshot and
// keeps the same URL. The owner can revoke it at any time.
const DIR = path.join(DATA_DIR, "shares");
const INDEX = path.join(DIR, "index.json");
export const MAX_SHARE_BYTES = 18 * 1024 * 1024;
export const TOKEN_RE = /^[\w-]{20,40}$/;
const ID_RE = /^[\w-]{1,64}$/;

function readJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return fallback;
  }
}
function writeJson(file, data) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = file + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(data));
  fs.renameSync(tmp, file);
}

let index = readJson(INDEX, {}); // token -> { token, userId, projectId, name, createdAt, updatedAt, views, seen: { viewerKey: dayNumber } }
const saveIndex = () => writeJson(INDEX, index);
const publicMeta = (m) => ({
  token: m.token,
  projectId: m.projectId,
  name: m.name,
  createdAt: m.createdAt,
  updatedAt: m.updatedAt,
  views: m.views,
});
const day = () => Math.floor(Date.now() / 86400000);

export function listShares(userId, projectId) {
  return Object.values(index)
    .filter((m) => m.userId === userId && (!projectId || m.projectId === projectId))
    .sort((a, b) => b.updatedAt - a.updatedAt)
    .map(publicMeta);
}

/** Creates the project's share link, or refreshes its snapshot (same token). */
export function putShare(userId, body) {
  const projectId = String(body?.projectId ?? "");
  if (!ID_RE.test(projectId)) throw new Error("Invalid project id");
  const snapshot = body?.snapshot;
  if (!snapshot || !Array.isArray(snapshot.strokes)) throw new Error("Invalid project data");
  const data = { format: "ovu-project-v1", snapshot };
  const json = JSON.stringify(data);
  if (json.length > MAX_SHARE_BYTES) throw new Error("Project is too large to share by link");

  const now = Date.now();
  let meta = Object.values(index).find((m) => m.userId === userId && m.projectId === projectId);
  if (!meta) {
    meta = { token: crypto.randomBytes(16).toString("base64url"), userId, projectId, createdAt: now, views: 0, seen: {} };
    index[meta.token] = meta;
  }
  meta.name = String(body.name ?? "Untitled").slice(0, 120);
  meta.updatedAt = now;
  fs.mkdirSync(DIR, { recursive: true });
  fs.writeFileSync(path.join(DIR, `${meta.token}.json`), json);
  saveIndex();
  return publicMeta(meta);
}

export function getShare(token) {
  if (!TOKEN_RE.test(token)) return null;
  const meta = index[token];
  if (!meta) return null;
  try {
    const data = JSON.parse(fs.readFileSync(path.join(DIR, `${token}.json`), "utf8"));
    return { meta, data };
  } catch {
    return null;
  }
}

/**
 * Counts a view. A given viewer (user id or IP) counts once per day per link.
 * Returns { counted, ownerId, name } so the caller can notify the owner.
 */
export function recordView(token, viewerKey) {
  const meta = index[token];
  if (!meta) return { counted: false };
  const today = day();
  const key = String(viewerKey).slice(0, 64);
  if (meta.seen[key] === today) return { counted: false, ownerId: meta.userId, name: meta.name };
  meta.seen[key] = today;
  // keep the dedupe table small
  const keys = Object.keys(meta.seen);
  if (keys.length > 500) for (const k of keys.filter((k) => meta.seen[k] < today)) delete meta.seen[k];
  meta.views += 1;
  saveIndex();
  return { counted: true, ownerId: meta.userId, name: meta.name };
}

export function revokeShare(userId, token) {
  const meta = index[token];
  if (!meta || meta.userId !== userId) return false;
  delete index[token];
  try {
    fs.unlinkSync(path.join(DIR, `${token}.json`));
  } catch {
    /* already gone */
  }
  saveIndex();
  return true;
}

export function removeUserShares(userId) {
  for (const m of Object.values(index)) if (m.userId === userId) revokeShare(userId, m.token);
}

export function removeProjectShares(userId, projectId) {
  for (const m of Object.values(index)) if (m.userId === userId && m.projectId === projectId) revokeShare(userId, m.token);
}
