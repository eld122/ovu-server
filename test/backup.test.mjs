import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import assert from "node:assert";
process.env.OVU_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "ovu-bak-"));
const b = await import(new URL("../backup.js", import.meta.url).href);

const snap = (n, assetId) => ({
  strokes: Array.from({ length: n }, (_, i) => ({ id: "s" + i })),
  models: assetId ? [{ assetId }] : [],
  images: [],
});

// push + list + get
let r = b.putBackup("u1", { projectId: "p1", name: "Cat", savedAt: 100, data: snap(3, "asset-1") });
assert.equal(r.stale, false);
assert.equal(r.meta.strokeCount, 3);
assert.deepEqual(r.meta.assetIds, ["asset-1"]);
assert.equal(b.listBackups("u1").length, 1);
assert.equal(b.getBackup("u1", "p1").data.strokes.length, 3);
assert.equal(b.getBackup("u2", "p1"), null); // isolated per user

// last-write-wins: older copy is rejected, newer accepted
assert.equal(b.putBackup("u1", { projectId: "p1", savedAt: 50, data: snap(1) }).stale, true);
assert.equal(b.getBackup("u1", "p1").strokeCount, 3);
assert.equal(b.putBackup("u1", { projectId: "p1", name: "Cat 2", savedAt: 200, data: snap(5, "asset-1") }).stale, false);
assert.equal(b.getBackup("u1", "p1").name, "Cat 2");

// validation
assert.throws(() => b.putBackup("u1", { projectId: "../x", data: snap(1) }), /Invalid project id/);
assert.throws(() => b.putBackup("u1", { projectId: "p2", data: {} }), /Invalid project data/);

// assets
assert.deepEqual(b.missingAssets("u1", ["asset-1", "asset-2"]), ["asset-1", "asset-2"]);
assert.equal(b.putBackupAsset("u1", "asset-1", Buffer.from("glb-bytes"), "model/gltf-binary").stored, true);
assert.equal(b.putBackupAsset("u1", "asset-1", Buffer.from("again"), "x").stored, false); // idempotent
assert.deepEqual(b.missingAssets("u1", ["asset-1", "asset-2"]), ["asset-2"]);
const a = b.getBackupAsset("u1", "asset-1");
assert.equal(a.buf.toString(), "glb-bytes");
assert.equal(a.mime, "model/gltf-binary");
assert.equal(b.getBackupAsset("u2", "asset-1"), null);
assert.throws(() => b.putBackupAsset("u1", "../../etc", Buffer.from("x")), /Invalid asset id/);

// deleting the project prunes its now-unreferenced assets (and sidecars)
assert.equal(b.removeBackup("u1", "p1"), true);
assert.equal(b.removeBackup("u1", "p1"), false);
assert.deepEqual(b.missingAssets("u1", ["asset-1"]), ["asset-1"]);
assert.equal(b.usedBytes("u1"), 0);

// account deletion
b.putBackup("u3", { projectId: "p9", data: snap(1) });
b.removeAllBackups("u3");
assert.equal(b.listBackups("u3").length, 0);
console.log("backup ok");
