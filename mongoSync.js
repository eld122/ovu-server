import fs from "node:fs";
import path from "node:path";

/**
 * MongoDB persistence for hosts with an ephemeral disk (Render free, etc.).
 *
 * The server keeps working on plain files in DATA_DIR (fast, simple, already tested).
 * This module mirrors that folder into MongoDB:
 *   - on boot:      everything stored in MongoDB is restored into DATA_DIR (before any other module reads it)
 *   - while running: every few seconds, new/changed files are uploaded and deleted files are removed
 *   - on shutdown:  one last sync (Render sends SIGTERM on every deploy)
 * Files are stored with GridFS (any size, no 16MB document limit) in the "ovu_files" bucket.
 *
 * Enable it by setting MONGODB_URI. Without it nothing here runs.
 */

const SKIP = (name) => name.endsWith(".tmp");
const sigOf = (st) => `${st.size}:${Math.floor(st.mtimeMs)}`;

function* walk(dir, rel = "") {
  let entries = [];
  try {
    entries = fs.readdirSync(path.join(dir, rel), { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    const r = rel ? `${rel}/${e.name}` : e.name;
    if (e.isDirectory()) yield* walk(dir, r);
    // installers (can be hundreds of MB) are never mirrored into MongoDB
    else if (e.isFile() && !SKIP(e.name) && !r.startsWith("updates/files/")) yield r;
  }
}

/**
 * store = { list(): Promise<string[]>, get(name): Promise<Buffer>, put(name, buf): Promise<void>, del(name): Promise<void> }
 */
export function createSyncEngine({ dir, store, log = () => {} }) {
  const known = new Map(); // relative path -> signature of what MongoDB has
  let chain = Promise.resolve();
  let timer = null;
  let lastError = null;
  let lastOkAt = 0;

  async function restore() {
    const names = await store.list();
    for (const name of names) {
      const full = path.join(dir, name);
      // never write outside the data folder, whatever the database contains
      if (!path.resolve(full).startsWith(path.resolve(dir) + path.sep)) continue;
      const buf = await store.get(name);
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, buf);
      known.set(name, sigOf(fs.statSync(full)));
    }
    log(`restored ${names.length} file(s) from MongoDB`);
    return names.length;
  }

  async function syncOnce() {
    let up = 0;
    let del = 0;
    const present = new Set();
    for (const rel of walk(dir)) {
      present.add(rel);
      let st;
      try {
        st = fs.statSync(path.join(dir, rel));
      } catch {
        continue;
      }
      const sig = sigOf(st);
      if (known.get(rel) === sig) continue;
      const buf = fs.readFileSync(path.join(dir, rel));
      await store.put(rel, buf);
      known.set(rel, sig);
      up++;
    }
    for (const rel of [...known.keys()]) {
      if (present.has(rel)) continue;
      await store.del(rel);
      known.delete(rel);
      del++;
    }
    if (up || del) log(`synced to MongoDB: ${up} uploaded, ${del} removed`);
    return { up, del };
  }

  // one sync at a time; errors never crash the server, the next round retries
  function sync() {
    chain = chain.then(async () => {
      try {
        const r = await syncOnce();
        lastError = null;
        lastOkAt = Date.now();
        return r;
      } catch (err) {
        lastError = err;
        log(`sync failed: ${err.message}`);
      }
    });
    return chain;
  }

  function start(intervalMs = 4000) {
    stop();
    timer = setInterval(sync, intervalMs);
  }
  function stop() {
    if (timer) clearInterval(timer);
    timer = null;
  }

  return { restore, sync, start, stop, known, status: () => ({ ok: !lastError, lastOkAt, error: lastError?.message || null }) };
}

/** GridFS-backed store (needs the "mongodb" package). */
export async function createMongoStore(uri, dbName) {
  const { MongoClient, GridFSBucket } = await import("mongodb");
  const client = new MongoClient(uri, { serverSelectionTimeoutMS: 15000 });
  await client.connect();
  const db = client.db(dbName);
  const bucket = new GridFSBucket(db, { bucketName: "ovu_files" });

  const readAll = (stream) =>
    new Promise((resolve, reject) => {
      const chunks = [];
      stream.on("data", (c) => chunks.push(c));
      stream.on("error", reject);
      stream.on("end", () => resolve(Buffer.concat(chunks)));
    });

  return {
    async list() {
      const docs = await bucket.find({}, { projection: { filename: 1 } }).toArray();
      return [...new Set(docs.map((d) => d.filename))];
    },
    async get(name) {
      return readAll(bucket.openDownloadStreamByName(name)); // newest revision
    },
    async put(name, buf) {
      const up = bucket.openUploadStream(name);
      await new Promise((resolve, reject) => {
        up.on("error", reject);
        up.on("finish", resolve);
        up.end(buf);
      });
      // keep only the newest copy
      const old = await bucket.find({ filename: name, _id: { $ne: up.id } }, { projection: { _id: 1 } }).toArray();
      for (const d of old) await bucket.delete(d._id);
    },
    async del(name) {
      const docs = await bucket.find({ filename: name }, { projection: { _id: 1 } }).toArray();
      for (const d of docs) await bucket.delete(d._id);
    },
    async close() {
      await client.close();
    },
  };
}

let engine = null;
let state = { enabled: false, connected: false, error: null };
export const mongoStatus = () => ({ ...state, ...(engine ? engine.status() : {}) });

/** Called once from dataDir.js, before any other module reads DATA_DIR. */
export async function startMongoPersistence(dir) {
  const uri = process.env.MONGODB_URI?.trim();
  if (!uri) return;
  state.enabled = true;
  const log = (m) => console.log(`[ovu][mongo] ${m}`);
  let store = null;
  let lastErr = null;
  for (let i = 1; i <= 3 && !store; i++) {
    try {
      store = await createMongoStore(uri, process.env.MONGODB_DB?.trim() || "ovu");
    } catch (err) {
      lastErr = err;
      console.error(`[ovu][mongo] connect attempt ${i}/3 failed: ${err.message}`);
      if (i < 3) await new Promise((r) => setTimeout(r, 2000 * i));
    }
  }
  if (!store) {
    // Safe mode: keep serving, but do NOT sync (so nothing in MongoDB can be deleted by mistake).
    state.error = lastErr?.message || "could not connect";
    console.error(
      "[ovu][mongo] ERROR: could not connect to MongoDB, running WITHOUT persistence.\n" +
        "             Check MONGODB_URI and, on Atlas, Network Access -> allow 0.0.0.0/0."
    );
    return;
  }
  engine = createSyncEngine({ dir, store, log });
  try {
    await engine.restore();
  } catch (err) {
    state.error = `restore failed: ${err.message}`;
    console.error(`[ovu][mongo] ERROR: restore failed (${err.message}); running WITHOUT persistence.`);
    engine = null;
    return;
  }
  state.connected = true;
  engine.start(4000);

  let closing = false;
  const shutdown = async (sig) => {
    if (closing) return;
    closing = true;
    log(`${sig}: final sync`);
    engine.stop();
    await Promise.race([engine.sync(), new Promise((r) => setTimeout(r, 8000))]);
    process.exit(0);
  };
  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
  log(`connected, syncing ${dir} to MongoDB`);
}
