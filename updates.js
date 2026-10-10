/**
 * In-app update distribution.
 *
 * The admin uploads up to four installers (one per OS), writes release notes and publishes.
 * Apps ask GET /api/update/latest?platform=…&current=… on launch and download the file that
 * matches their OS from GET /api/update/download/:platform.
 *
 * Layout (inside <dir>):
 *   manifest.json                 small, safe to mirror to MongoDB
 *   files/draft/<name>            installers being prepared (not yet public)
 *   files/<version>/<name>        installers of the published release
 * Installers are NOT mirrored to MongoDB (see mongoSync.js); on an ephemeral host re-upload them
 * after a redeploy. A platform whose file is missing on disk is simply not offered.
 */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

export const PLATFORMS = {
  windows: { label: "Windows", file: "Ovu-windows.zip", ext: ".zip", magic: "zip" },
  mac: { label: "macOS", file: "Ovu-mac.dmg", ext: ".dmg", magic: null },
};
export const PLATFORM_IDS = Object.keys(PLATFORMS);
export const isPlatform = (p) => typeof p === "string" && Object.prototype.hasOwnProperty.call(PLATFORMS, p);

const MAGIC = { zip: Buffer.from([0x50, 0x4b, 0x03, 0x04]) };
export const MAX_NOTES = 5000;

export class UpdateError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

/** "1.2.3" or "v1.2.3" -> [1,2,3]; anything else -> null. */
export function parseVersion(v) {
  const m = /^v?(\d{1,6})\.(\d{1,6})\.(\d{1,6})$/.exec(String(v ?? "").trim());
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}
export const normalizeVersion = (v) => {
  const p = parseVersion(v);
  return p ? p.join(".") : null;
};
/** >0 if a is newer than b, <0 if older, 0 if equal. Unparseable versions compare as 0.0.0. */
export function compareVersions(a, b) {
  const pa = parseVersion(a) ?? [0, 0, 0];
  const pb = parseVersion(b) ?? [0, 0, 0];
  for (let i = 0; i < 3; i++) if (pa[i] !== pb[i]) return pa[i] - pb[i];
  return 0;
}

const emptyDraft = () => ({ version: "", notes: "", files: {} });

export function createUpdates({ dir, maxBytes = 1.5 * 1024 ** 3 }) {
  const manifestPath = path.join(dir, "manifest.json");
  const filesDir = path.join(dir, "files");
  const draftDir = path.join(filesDir, "draft");
  fs.mkdirSync(draftDir, { recursive: true });

  let manifest = { draft: emptyDraft(), live: null };
  try {
    const raw = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    manifest = { draft: { ...emptyDraft(), ...(raw.draft || {}) }, live: raw.live || null };
  } catch {
    /* first run */
  }

  function save() {
    const tmp = `${manifestPath}.${crypto.randomBytes(4).toString("hex")}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(manifest, null, 2));
    fs.renameSync(tmp, manifestPath);
  }

  const livePath = (platform) =>
    manifest.live?.files?.[platform] ? path.join(filesDir, manifest.live.version, PLATFORMS[platform].file) : null;
  const exists = (p) => {
    try {
      return !!p && fs.statSync(p).isFile();
    } catch {
      return false;
    }
  };
  const draftPath = (platform) => path.join(draftDir, PLATFORMS[platform].file);

  /** Drop file records whose file vanished (ephemeral disk) so the admin sees the truth. */
  function reconcile() {
    for (const p of Object.keys(manifest.draft.files)) if (!exists(draftPath(p))) delete manifest.draft.files[p];
  }

  const api = {
    adminView() {
      reconcile();
      const live = manifest.live
        ? {
            ...manifest.live,
            files: Object.fromEntries(
              Object.entries(manifest.live.files).map(([p, f]) => [p, { ...f, present: exists(livePath(p)) }])
            ),
          }
        : null;
      return {
        draft: manifest.draft,
        live,
        platforms: Object.fromEntries(PLATFORM_IDS.map((p) => [p, { label: PLATFORMS[p].label, file: PLATFORMS[p].file }])),
        maxBytes,
      };
    },

    saveDraft({ version, notes }) {
      const v = String(version ?? "").trim();
      if (v && !parseVersion(v)) throw new UpdateError(400, "Version must look like 1.2.3");
      const n = String(notes ?? "");
      if (n.length > MAX_NOTES) throw new UpdateError(400, `Release notes are limited to ${MAX_NOTES} characters`);
      manifest.draft.version = v ? normalizeVersion(v) : "";
      manifest.draft.notes = n;
      save();
      return api.adminView();
    },

    /** Stream an installer into the draft. Resolves with the stored file record. */
    putFile(platform, stream) {
      if (!isPlatform(platform)) throw new UpdateError(400, "Unknown platform");
      const spec = PLATFORMS[platform];
      return new Promise((resolve, reject) => {
        fs.mkdirSync(draftDir, { recursive: true });
        const tmp = path.join(draftDir, `${spec.file}.${crypto.randomBytes(4).toString("hex")}.part`);
        const out = fs.createWriteStream(tmp);
        const hash = crypto.createHash("sha256");
        let size = 0;
        let head = Buffer.alloc(0);
        let headChecked = !MAGIC[spec.magic];
        let settled = false;
        let ended = false;

        const fail = (err) => {
          if (settled) return;
          settled = true;
          out.destroy();
          fs.rm(tmp, { force: true }, () => reject(err));
        };
        const checkHead = () => {
          const magic = MAGIC[spec.magic];
          if (head.length < magic.length) return true; // wait for more bytes
          headChecked = true;
          return head.subarray(0, magic.length).equals(magic);
        };

        stream.on("data", (chunk) => {
          if (settled) return;
          if (!headChecked) {
            head = Buffer.concat([head, chunk]);
            if (!checkHead()) return fail(new UpdateError(400, `That file doesn't look like a valid ${spec.label} installer (${spec.file}).`));
          }
          size += chunk.length;
          if (size > maxBytes) return fail(new UpdateError(413, `File is larger than the ${Math.round(maxBytes / 1024 ** 2)} MB limit.`));
          hash.update(chunk);
          if (!out.write(chunk)) {
            stream.pause();
            out.once("drain", () => stream.resume());
          }
        });
        stream.on("end", () => {
          ended = true;
          if (settled) return;
          out.end(() => {
            if (settled) return;
            if (!size) return fail(new UpdateError(400, "The uploaded file is empty."));
            if (!headChecked) return fail(new UpdateError(400, `That file doesn't look like a valid ${spec.label} installer.`));
            try {
              fs.renameSync(tmp, draftPath(platform));
              const rec = { name: spec.file, size, sha256: hash.digest("hex"), uploadedAt: Date.now() };
              manifest.draft.files[platform] = rec;
              save();
              settled = true;
              resolve(rec);
            } catch (e) {
              fail(e);
            }
          });
        });
        stream.on("error", fail);
        stream.on("close", () => {
          if (!ended) fail(new UpdateError(499, "Upload interrupted."));
        });
        out.on("error", fail);
      });
    },

    deleteFile(platform) {
      if (!isPlatform(platform)) throw new UpdateError(400, "Unknown platform");
      fs.rmSync(draftPath(platform), { force: true });
      delete manifest.draft.files[platform];
      save();
    },

    /** Make the draft the live release. */
    publish({ version, notes }) {
      reconcile();
      const v = normalizeVersion(version);
      if (!v) throw new UpdateError(400, "Version must look like 1.2.3");
      const n = String(notes ?? "").trim();
      if (n.length > MAX_NOTES) throw new UpdateError(400, `Release notes are limited to ${MAX_NOTES} characters`);
      if (!n) throw new UpdateError(400, "Write release notes before publishing.");
      const platforms = Object.keys(manifest.draft.files);
      if (!platforms.length) throw new UpdateError(400, "Upload at least one installer before publishing.");
      if (manifest.live && compareVersions(v, manifest.live.version) <= 0) {
        throw new UpdateError(400, `Version must be higher than the live version (${manifest.live.version}). Unpublish first to roll back.`);
      }
      const dest = path.join(filesDir, v);
      fs.rmSync(dest, { recursive: true, force: true });
      fs.mkdirSync(dest, { recursive: true });
      const files = {};
      for (const p of platforms) {
        fs.renameSync(draftPath(p), path.join(dest, PLATFORMS[p].file));
        files[p] = manifest.draft.files[p];
      }
      const previous = manifest.live?.version;
      manifest.live = { version: v, notes: n, publishedAt: Date.now(), files };
      manifest.draft = emptyDraft();
      save();
      if (previous && previous !== v) fs.rmSync(path.join(filesDir, previous), { recursive: true, force: true });
      return api.adminView();
    },

    /** Stop offering the live release (apps stop prompting). Files are kept as a new draft. */
    unpublish() {
      if (!manifest.live) return api.adminView();
      const { version, notes, files } = manifest.live;
      // move the files back into the draft so the admin can fix and republish
      for (const p of Object.keys(files)) {
        const from = path.join(filesDir, version, PLATFORMS[p].file);
        if (exists(from)) {
          fs.renameSync(from, draftPath(p));
          manifest.draft.files[p] = files[p];
        }
      }
      manifest.draft.version = manifest.draft.version || version;
      manifest.draft.notes = manifest.draft.notes || notes;
      fs.rmSync(path.join(filesDir, version), { recursive: true, force: true });
      manifest.live = null;
      save();
      return api.adminView();
    },

    /** Public answer for one app: is there something newer that has a file for this OS? */
    latestFor({ platform, current }) {
      const live = manifest.live;
      if (!isPlatform(platform)) return { available: false };
      if (!live) return { available: false };
      const rec = live.files[platform];
      if (!rec || !exists(livePath(platform))) return { available: false, latest: live.version };
      const available = compareVersions(live.version, current) > 0;
      const base = { available, latest: live.version };
      if (!available) return base;
      return {
        ...base,
        version: live.version,
        notes: live.notes,
        publishedAt: live.publishedAt,
        platform,
        fileName: rec.name,
        size: rec.size,
        sha256: rec.sha256,
        downloadPath: `/api/update/download/${platform}?v=${encodeURIComponent(live.version)}`,
      };
    },

    /** Absolute path of the live installer for a platform, or null. */
    downloadFile(platform) {
      if (!isPlatform(platform)) return null;
      const p = livePath(platform);
      return exists(p) ? { path: p, name: PLATFORMS[platform].file } : null;
    },
  };
  return api;
}
