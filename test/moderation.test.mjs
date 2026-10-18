import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

process.env.OVU_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "ovu-mod-"));
const db = await import("../db.js");

const mk = (n, provider = "email") => db.createUser({ name: n, email: `${n}@t.io`, passwordHash: "x", provider });
const ann = mk("ann"), bob = mk("bob"), cy = mk("cy"), dee = mk("dee"), root = mk("root");

test("admins come from server config only; emails count only for verified providers", () => {
  process.env.OVU_ADMIN_IDS = root.id;
  assert.equal(db.isAdmin(root), true);
  assert.equal(db.isAdmin(ann), false);
  process.env.OVU_ADMIN_EMAILS = "ann@t.io, gg@t.io";
  assert.equal(db.isAdmin(ann), false, "unverified email sign-up must not become admin");
  assert.equal(db.isAdmin({ ...ann, provider: "google" }), true);
  assert.equal(db.publicUser(root).isAdmin, true);
  assert.equal(db.publicUser(bob).isAdmin, undefined);
});

test("3 reports auto-hide a work; dismissing restores it and resets the count", () => {
  const w = db.createWork(ann.id, { title: "Spam", type: "model", modelData: {} });
  for (const u of [bob, cy, dee]) db.addReport(u.id, { targetType: "work", targetId: w.id, reason: "spam" });
  assert.equal(db.getWorkInternal(w.id).hidden, true);

  const g = db.listReportGroups({ status: "open" }).find((x) => x.targetId === w.id);
  assert.equal(g.count, 3);
  assert.equal(g.target.title, "Spam");
  assert.deepEqual(g.reasons, ["spam"]);
  assert.equal(db.openReportCount(), 1);

  assert.equal(db.resolveReports(root.id, { targetType: "work", targetId: w.id, action: "dismiss" }).resolved, 3);
  assert.equal(db.getWorkInternal(w.id).hidden, false);
  assert.equal(db.listReportGroups({ status: "open" }).length, 0);
  assert.equal(db.listReportGroups({ status: "resolved" })[0].actions[0], "dismiss");

  // a single new report must not instantly re-hide it (old, dismissed reports no longer count)
  const eve = mk("eve");
  db.addReport(eve.id, { targetType: "work", targetId: w.id, reason: "again" });
  assert.equal(db.getWorkInternal(w.id).hidden, false);
});

test("delete actions per target type, and invalid actions are rejected", () => {
  const w = db.createWork(ann.id, { title: "Bad", type: "model", modelData: {} });
  db.addReport(bob.id, { targetType: "work", targetId: w.id, reason: "abuse" });
  assert.match(db.resolveReports(root.id, { targetType: "work", targetId: w.id, action: "hide_works" }).error, /not available/);
  assert.equal(db.resolveReports(root.id, { targetType: "work", targetId: w.id, action: "delete" }).ok, true);
  assert.equal(db.getWork(w.id), null, "deleted work is gone");
  assert.match(db.resolveReports(root.id, { targetType: "work", targetId: w.id, action: "delete" }).error, /No open reports/);

  const w2 = db.createWork(ann.id, { title: "Ok", type: "model", modelData: {} });
  const c = db.addComment(bob.id, w2.id, "rude");
  db.addReport(cy.id, { targetType: "comment", targetId: c.id, reason: "rude" });
  db.resolveReports(root.id, { targetType: "comment", targetId: c.id, action: "delete" });
  assert.equal(db.listComments(w2.id).length, 0);

  db.addReport(bob.id, { targetType: "user", targetId: ann.id, reason: "harassment" });
  db.resolveReports(root.id, { targetType: "user", targetId: ann.id, action: "hide_works" });
  assert.equal(db.getWorkInternal(w2.id).hidden, true);

  assert.match(db.resolveReports(root.id, { targetType: "nope", targetId: "x", action: "delete" }).error, /Unknown/);
});
