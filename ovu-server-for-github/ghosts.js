import { DATA_DIR } from "./dataDir.js";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Async "ghost" recordings: what a collaborator did in a room, saved so others can watch it later.
// One JSON file per ghost + a small in-memory index. Same zero-setup approach as db.js / cloud.js.
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DIR = path.join(DATA_DIR, "ghosts");

const MAX_BYTES = 6 * 1024 * 1024;
const MAX_PER_ROOM = 30;
const TTL_MS = 30 * 24 * 3600 * 1000;

const ROOM_RE = /^[A-Za-z0-9_-]{4,64}$/;
const ID_RE = /^[A-Za-z0-9-]{8,64}$/;

/** @type {Map<string, {id:string, room:string, userId:string, name:string, color:string, startedAt:number, updatedAt:number, duration:number, strokes:number, bytes:number}>} */
let index = new Map();

function load() {
  try {
    fs.mkdirSync(DIR, { recursive: true });
    for (const f of fs.readdirSync(DIR)) {
      if (!f.endsWith(".json")) continue;
      try {
        const g = JSON.parse(fs.readFileSync(path.join(DIR, f), "utf8"));
        if (g && g.id) index.set(g.id, meta(g, fs.statSync(path.join(DIR, f)).size));
      } catch {
        /* skip corrupt file */
      }
    }
  } catch {
    /* read-only fs: ghosts just won't persist */
  }
}

function meta(g, bytes) {
  return {
    id: g.id,
    room: g.room,
    userId: g.userId,
    name: g.name,
    color: g.color,
    startedAt: g.startedAt,
    updatedAt: g.updatedAt,
    duration: g.recording?.duration ?? 0,
    strokes: g.recording?.strokes?.length ?? 0,
    bytes,
  };
}

function prune(room) {
  const now = Date.now();
  const mine = [...index.values()].filter((m) => m.room === room).sort((a, b) => b.updatedAt - a.updatedAt);
  mine.forEach((m, i) => {
    if (i >= MAX_PER_ROOM || now - m.updatedAt > TTL_MS) remove(m.id);
  });
}

function remove(id) {
  index.delete(id);
  try {
    fs.unlinkSync(path.join(DIR, `${id}.json`));
  } catch {
    /* already gone */
  }
}

load();

export function isValidRoom(room) {
  return ROOM_RE.test(String(room ?? ""));
}

export function listGhosts(room) {
  if (!isValidRoom(room)) return [];
  prune(room);
  return [...index.values()].filter((m) => m.room === room).sort((a, b) => b.updatedAt - a.updatedAt);
}

export function getGhost(id) {
  if (!ID_RE.test(id) || !index.has(id)) return null;
  try {
    return JSON.parse(fs.readFileSync(path.join(DIR, `${id}.json`), "utf8"));
  } catch {
    return null;
  }
}

/** Create or update (same id + same owner) a ghost. Returns the metadata. */
export function putGhost(user, body) {
  const id = String(body?.id ?? "");
  const room = String(body?.room ?? "");
  const rec = body?.recording;
  if (!ID_RE.test(id)) throw new Error("Bad ghost id");
  if (!isValidRoom(room)) throw new Error("Bad room");
  if (!rec || rec.format !== "ovu-ghost-v1" || !Array.isArray(rec.strokes)) throw new Error("Not a ghost recording");
  const existing = index.get(id);
  if (existing && existing.userId !== user.id) throw new Error("Not your ghost");

  const ghost = {
    id,
    room,
    userId: user.id,
    name: String(user.name || "Guest").slice(0, 80),
    color: String(body.color || "#7c5cff").slice(0, 16),
    startedAt: Number(body.startedAt) || Date.now(),
    updatedAt: Date.now(),
    recording: rec,
  };
  const json = JSON.stringify(ghost);
  if (json.length > MAX_BYTES) throw new Error("Recording too large");
  fs.mkdirSync(DIR, { recursive: true });
  const file = path.join(DIR, `${id}.json`);
  fs.writeFileSync(file + ".tmp", json);
  fs.renameSync(file + ".tmp", file);
  const m = meta(ghost, json.length);
  index.set(id, m);
  prune(room);
  return m;
}

export function deleteGhost(user, id) {
  const m = index.get(id);
  if (!m || m.userId !== user.id) return false;
  remove(id);
  return true;
}
