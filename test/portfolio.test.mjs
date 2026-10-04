import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

process.env.OVU_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "ovu-pf-"));
const db = await import("../db.js");
const mk = (n) => db.createUser({ name: n, email: `${n}@t.io`, passwordHash: "x", provider: "email" });
const ann = mk("ann"), bob = mk("bob");
const work = (u, title, extra = {}) => db.createWork(u.id, { title, type: "model", modelData: {}, ...extra });
const titles = (u) => db.listWorks(u.id, u.id).map((w) => w.title);

test("categories: only known ones, case-insensitive, clearable, owner-only", () => {
  const w = work(ann, "Hero", { category: "characters" });
  assert.equal(w.category, "Characters");
  assert.equal(db.setWorkCategory(ann.id, w.id, "Props").work.category, "Props");
  assert.match(db.setWorkCategory(ann.id, w.id, "Nonsense").error, /Unknown/);
  assert.equal(db.setWorkCategory(ann.id, w.id, "").work.category, "");
  assert.equal(db.setWorkCategory(bob.id, w.id, "Props"), null);
});

test("new works come first; drag order is saved; pinned stays on top", async () => {
  const a = work(bob, "A"); await new Promise((r) => setTimeout(r, 3));
  const b = work(bob, "B"); await new Promise((r) => setTimeout(r, 3));
  const c = work(bob, "C");
  assert.deepEqual(titles(bob), ["C", "B", "A"], "newest first until the owner reorders");

  db.reorderWorks(bob.id, [a.id, c.id, b.id]);
  assert.deepEqual(titles(bob), ["A", "C", "B"]);

  const d = work(bob, "D");
  assert.deepEqual(titles(bob), ["D", "A", "C", "B"], "a brand-new work lands on top of the custom order");

  db.setPinned(bob.id, b.id, true);
  assert.deepEqual(titles(bob), ["B", "D", "A", "C"]);

  // partial list: unlisted works keep their relative order after the listed ones
  db.reorderWorks(bob.id, [c.id]);
  assert.deepEqual(titles(bob), ["B", "C", "D", "A"]);
  void d;
});

test("reordering ignores other people's works and junk ids", () => {
  const mine = work(ann, "Mine"), theirs = work(bob, "Theirs");
  const before = titles(bob);
  db.reorderWorks(ann.id, [theirs.id, "nope", mine.id, mine.id]);
  assert.deepEqual(titles(bob), before);
  assert.equal(db.listWorks(ann.id, ann.id)[0].title, "Mine");
  assert.deepEqual(db.reorderWorks(ann.id, "garbage").map((w) => w.id).sort(), db.listWorks(ann.id, ann.id).map((w) => w.id).sort());
});
