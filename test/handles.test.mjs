// Run with: npm test
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

process.env.OVU_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "ovu-handles-"));
const db = await import("../db.js");

const mk = (n) => db.createUser({ name: n, email: `${n.replace(/\W/g, "")}@t.io`, passwordHash: "x", provider: "email" });
const ann = mk("Ann Lee");
const bob = mk("Bob");

test("validation: length, characters, reserved words, @ and case", () => {
  assert.deepEqual(db.validateHandle("@Ann_Lee"), { ok: true, handle: "ann_lee" });
  assert.equal(db.validateHandle("ab").ok, false);
  assert.equal(db.validateHandle("a".repeat(21)).ok, false);
  assert.equal(db.validateHandle("ann lee").ok, false);
  assert.equal(db.validateHandle("ann-lee").ok, false);
  assert.equal(db.validateHandle("דני_לוי").ok, false);
  assert.equal(db.validateHandle("admin").ok, false);
  assert.equal(db.validateHandle("ROOM").ok, false);
  assert.equal(db.validateHandle(42).ok, false);
});

test("a handle is unique, case-insensitive, and resolves to its owner", () => {
  assert.deepEqual(db.setHandle(ann.id, "Ann_Lee"), { ok: true, handle: "ann_lee" });
  assert.equal(db.userIdByHandle("@ANN_LEE"), ann.id);
  const clash = db.setHandle(bob.id, "ann_LEE");
  assert.equal(clash.ok, false);
  assert.equal(clash.status, 409);
  assert.equal(db.getProfile(bob.id).handle, null, "a rejected handle is not saved");
  assert.equal(db.getProfile(ann.id).handle, "ann_lee");
});

test("setting your own handle again is fine; changing it frees the old one", () => {
  assert.equal(db.setHandle(ann.id, "ann_lee").ok, true);
  assert.equal(db.setHandle(ann.id, "ann2024").ok, true);
  assert.equal(db.userIdByHandle("ann_lee"), null);
  assert.equal(db.setHandle(bob.id, "ann_lee").ok, true);
  assert.equal(db.userIdByHandle("ann_lee"), bob.id);
});

test("clearing removes the link", () => {
  assert.deepEqual(db.setHandle(bob.id, null), { ok: true, handle: null });
  assert.equal(db.userIdByHandle("ann_lee"), null);
  assert.equal(db.getProfile(bob.id).handle, null);
});

test("availability check ignores your own handle", () => {
  assert.deepEqual(db.handleAvailability("ann2024", ann.id), { available: true, handle: "ann2024" });
  assert.equal(db.handleAvailability("ann2024", bob.id).available, false);
  assert.equal(db.handleAvailability("x", bob.id).available, false);
});

test("handles of deleted accounts are released", () => {
  const eve = mk("Eve");
  db.setHandle(eve.id, "eve_art");
  db.deleteUser(eve.id);
  assert.equal(db.userIdByHandle("eve_art"), null);
  assert.equal(db.isHandleTaken("eve_art"), false);
});

test("search finds people by handle (with or without @)", () => {
  db.setHandle(bob.id, "bobby_3d");
  for (const q of ["bobby", "@bobby_3d"]) {
    const hit = db.searchAll(q).users.find((u) => u.id === bob.id);
    assert.ok(hit, `query ${q}`);
    assert.equal(hit.handle, "bobby_3d");
  }
});

test("suggestHandle returns a valid, free name", () => {
  const h = db.suggestHandle("Ann Lee", ann.id);
  assert.ok(db.validateHandle(h).ok);
  assert.equal(db.isHandleTaken(h, ann.id), false);
  assert.ok(db.validateHandle(db.suggestHandle("דני", null)).ok, "non-latin names still get a valid suggestion");
});
