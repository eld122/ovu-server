import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

process.env.OVU_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "ovu-take-"));
const db = await import("../db.js");

test("owner signing in with Google takes over an unconfirmed password account", () => {
  const squatter = db.createUser({ name: "Mallory", email: "victim@x.io", passwordHash: "attacker-hash", provider: "email" });
  let revoked = null;
  const u = db.upsertOAuthUser({ provider: "google", providerId: "g-1", email: "victim@x.io", name: "Victim", avatarUrl: null, onTakeover: (x) => (revoked = x.id) });
  assert.equal(u.id, squatter.id);
  assert.equal(u.passwordHash, null); // attacker's password is gone
  assert.equal(u.provider, "google");
  assert.equal(db.publicUser(u).emailVerified, true);
  assert.equal(revoked, squatter.id); // existing sessions get signed out
  // next Google login finds the account directly, no second takeover
  let again = false;
  assert.equal(db.upsertOAuthUser({ provider: "google", providerId: "g-1", email: "victim@x.io", name: "V", onTakeover: () => (again = true) }).id, squatter.id);
  assert.equal(again, false);
});

test("a confirmed password account keeps its password when linked", () => {
  const real = db.createUser({ name: "Real", email: "real@x.io", passwordHash: "mine", provider: "email", emailVerified: true });
  let called = false;
  const u = db.upsertOAuthUser({ provider: "github", providerId: "h-1", email: "real@x.io", name: "Real", onTakeover: () => (called = true) });
  assert.equal(u.id, real.id);
  assert.equal(u.passwordHash, "mine");
  assert.equal(u.provider, "email");
  assert.equal(called, false);
});
