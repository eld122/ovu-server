// Run with: npm test  (uses only node:test, no extra dependencies)
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

process.env.OVU_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "ovu-test-"));
const db = await import("../db.js");
const cl = await import("../cloud.js");

const mk = (n) => db.createUser({ name: n, email: `${n}@t.io`, passwordHash: "x", provider: "email" });
const ann = mk("ann");
const bob = mk("bob");

test("tags are cleaned and works can be saved / liked / pinned", () => {
  const w = db.createWork(ann.id, { title: "Cat", type: "model", modelData: { a: 1 }, tags: "Art, #3D, art", allowRemix: true });
  assert.deepEqual(w.tags, ["art", "3d"]);
  assert.equal(db.toggleSave(bob.id, w.id).saved, true);
  assert.equal(db.toggleSave(bob.id, w.id).saved, false);
  assert.equal(db.toggleLike(bob.id, w.id).count, 1);
  assert.equal(db.setPinned(ann.id, w.id, true).work.pinned, true);
  assert.equal(db.setPinned(bob.id, w.id, true), null, "only the owner can pin");
});

test("comments can be deleted by the author or the work owner only", () => {
  const w = db.createWork(ann.id, { title: "C2", type: "model", modelData: {} });
  const c = db.addComment(bob.id, w.id, "hi");
  assert.equal(db.deleteComment(mk("eve").id, c.id), false);
  assert.equal(db.deleteComment(ann.id, c.id), true);
  assert.equal(db.listComments(w.id).length, 0);
});

test("remix needs the author's opt-in and keeps the credit", () => {
  const closed = db.createWork(ann.id, { title: "Closed", type: "model", modelData: { z: 1 } });
  assert.ok(db.getRemixSource(bob.id, closed.id).error);
  const open = db.createWork(ann.id, { title: "Open", type: "model", modelData: { z: 1 }, allowRemix: true });
  assert.equal(db.getRemixSource(bob.id, open.id).authorName, "ann");
  const r = db.createWork(bob.id, { title: "R", type: "model", modelData: {}, remixOfWorkId: open.id });
  assert.equal(r.remixOf.userName, "ann");
  assert.equal(db.getWork(open.id).remixCount, 1);
});

test("three reports hide a work from explore and public lists", () => {
  const w = db.createWork(ann.id, { title: "Bad", type: "model", modelData: {} });
  for (const n of ["r1", "r2", "r3"]) db.addReport(mk(n).id, { targetType: "work", targetId: w.id, reason: "spam" });
  assert.ok(!db.exploreWorks({}).some((x) => x.id === w.id));
  assert.ok(!db.listWorks(ann.id, bob.id).some((x) => x.id === w.id));
  assert.ok(db.listWorks(ann.id, ann.id).some((x) => x.id === w.id));
});

test("notifications are created for others, never for yourself", () => {
  const before = db.listNotifications(ann.id).items.length;
  db.notify(ann.id, { type: "like", fromUserId: ann.id });
  assert.equal(db.listNotifications(ann.id).items.length, before);
  db.notify(ann.id, { type: "follow", fromUserId: bob.id });
  assert.equal(db.listNotifications(ann.id).unread > 0, true);
  db.markNotificationsRead(ann.id);
  assert.equal(db.listNotifications(ann.id).unread, 0);
});

test("style packs are sanitised; ratings are 1-5, one per user, not for your own asset", () => {
  const a = cl.createAsset(ann, {
    kind: "style", name: "Dusk",
    style: { brush: { color: "nope", brushType: "oil", opacity: 9 }, lighting: { sunColor: "#ffaa00", sunIntensity: 99, exposure: 1, bloomStrength: 1 }, skybox: { preset: "sunset" } },
  });
  assert.equal(a.data.style.brush.color, "#1d1d1f");
  assert.equal(a.data.style.brush.opacity, 1);
  assert.equal(a.data.style.lighting.sunIntensity, 5);
  assert.throws(() => cl.createAsset(ann, { kind: "style", name: "Empty", style: {} }));
  assert.equal(cl.rateAsset(bob.id, a.id, 4).asset.ratingAvg, 4);
  assert.equal(cl.rateAsset(bob.id, a.id, 2).asset.ratingCount, 1, "re-rating replaces");
  assert.ok(cl.rateAsset(ann.id, a.id, 5).error);
  assert.ok(cl.rateAsset(bob.id, a.id, 9).error);
});

test("creator stats count views once per viewer per day and ignore the owner", () => {
  const w = db.createWork(ann.id, { title: "Stat", type: "model", modelData: {} });
  db.countView(w.id, "ip1", null);
  db.countView(w.id, "ip1", null);
  db.countView(w.id, "x", ann.id);
  db.countView(w.id, "ip2", bob.id);
  const s = db.getStats(ann.id);
  assert.equal(s.top.find((t) => t.id === w.id).views, 2);
  assert.equal(s.viewsPerDay.length, 30);
});

test("light / flicker brush settings survive publishing and are clamped", () => {
  const a = cl.createAsset(ann, { kind: "brush", name: "Neon test", brush: { color: "#ff00aa", brushType: "flicker", opacity: 1, glow: 9, glowColor: "#00ffcc", impasto: 0.3, volume: 0.4 } });
  assert.equal(a.data.brush.brushType, "flicker");
  assert.equal(a.data.brush.glow, 3);
  assert.equal(a.data.brush.glowColor, "#00ffcc");
  assert.equal(a.data.brush.impasto, 0.3);
  const b = cl.createAsset(ann, { kind: "brush", name: "Neon low", brush: { brushType: "light", glow: 0, glowColor: "red" } });
  assert.equal(b.data.brush.glow, 0.2);
  assert.equal(b.data.brush.glowColor, "");
  const c = cl.createAsset(ann, { kind: "brush", name: "Plain old", brush: { brushType: "oil" } });
  assert.equal("glow" in c.data.brush, false, "old brushes stay unchanged");
  const st = cl.createAsset(ann, { kind: "style", name: "Neon style", style: { brush: { brushType: "light", glow: 1.5, glowColor: "#ffffff" } } });
  assert.equal(st.data.style.brush.glow, 1.5);
});
