import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Readable } from "node:stream";
import { createUpdates, compareVersions, parseVersion, UpdateError } from "../updates.js";

const mk = (opts = {}) => createUpdates({ dir: fs.mkdtempSync(path.join(os.tmpdir(), "ovu-upd-")), ...opts });
const zip = (n = 100) => Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04]), Buffer.alloc(n, 1)]);

test("version parsing and ordering", () => {
  assert.deepEqual(parseVersion("v1.2.3"), [1, 2, 3]);
  assert.equal(parseVersion("1.2"), null);
  assert.ok(compareVersions("1.10.0", "1.9.9") > 0);
  assert.ok(compareVersions("1.0.0", "1.0.0") === 0);
  assert.ok(compareVersions("0.9.9", "1.0.0") < 0);
});

test("upload validates type, stores canonical name, hashes", async () => {
  const u = mk();
  const rec = await u.putFile("windows", Readable.from([zip(10), zip(10)]));
  assert.equal(rec.name, "Ovu-windows.zip");
  assert.equal(rec.size, zip(10).length * 2);
  assert.equal(rec.sha256.length, 64);
  await assert.rejects(u.putFile("windows", Readable.from([Buffer.from("not a zip")])), (e) => e instanceof UpdateError && e.status === 400);
  await assert.rejects(u.putFile("windows", Readable.from([Buffer.alloc(0)])), UpdateError);
  await u.putFile("mac", Readable.from([Buffer.from("any dmg bytes")])); // dmg has no magic check
  assert.deepEqual(Object.keys(u.adminView().draft.files).sort(), ["mac", "windows"]);
});

test("size limit", async () => {
  const u = mk({ maxBytes: 50 });
  await assert.rejects(u.putFile("windows", Readable.from([zip(200)])), (e) => e.status === 413);
  assert.equal(Object.keys(u.adminView().draft.files).length, 0);
});

test("publish flow, per-OS offer, rollback", async () => {
  const u = mk();
  assert.throws(() => u.publish({ version: "1.1.0", notes: "x" }), /at least one installer/);
  await u.putFile("windows", Readable.from([zip()]));
  await u.putFile("mac", Readable.from([Buffer.from("dmg bytes")]));
  assert.throws(() => u.publish({ version: "abc", notes: "x" }), /Version/);
  assert.throws(() => u.publish({ version: "1.1.0", notes: " " }), /release notes/i);
  assert.equal(u.latestFor({ platform: "windows", current: "1.0.0" }).available, false); // nothing live yet

  u.publish({ version: "1.1.0", notes: "- faster brushes" });
  const w = u.latestFor({ platform: "windows", current: "1.0.0" });
  assert.equal(w.available, true);
  assert.equal(w.notes, "- faster brushes");
  assert.match(w.downloadPath, /download\/windows/);
  assert.equal(u.latestFor({ platform: "windows", current: "1.1.0" }).available, false);
  assert.equal(u.latestFor({ platform: "mac", current: "1.0.0" }).available, true); // mac file was in this release
  assert.equal(u.latestFor({ platform: "ios", current: "1.0.0" }).available, false);
  assert.ok(fs.existsSync(u.downloadFile("mac").path));
  assert.equal(u.downloadFile("linux"), null); // no such platform any more

  await u.putFile("windows", Readable.from([zip(5)]));
  assert.throws(() => u.publish({ version: "1.0.5", notes: "old" }), /higher/);
  u.publish({ version: "1.2.0", notes: "next" });
  assert.equal(u.latestFor({ platform: "android", current: "1.0.0" }).available, false); // android is gone
  assert.equal(u.latestFor({ platform: "windows", current: "1.1.0" }).version, "1.2.0");

  u.unpublish();
  assert.equal(u.latestFor({ platform: "windows", current: "1.0.0" }).available, false);
  assert.ok(u.adminView().draft.files.windows); // kept as draft to fix + republish
  assert.equal(u.adminView().draft.version, "1.2.0");
});

test("manifest survives restart; missing file is not offered", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ovu-upd-"));
  const a = createUpdates({ dir });
  await a.putFile("windows", Readable.from([zip()]));
  a.saveDraft({ version: "2.0.0", notes: "n" });
  a.publish({ version: "2.0.0", notes: "n" });
  const b = createUpdates({ dir });
  assert.equal(b.latestFor({ platform: "windows", current: "1.0.0" }).available, true);
  fs.rmSync(path.join(dir, "files", "2.0.0"), { recursive: true });
  assert.equal(b.latestFor({ platform: "windows", current: "1.0.0" }).available, false);
});
