import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import assert from "node:assert";
process.env.OVU_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "ovu-share-"));
const s = await import(new URL("../shares.js", import.meta.url).href);

const snap = (n) => ({ strokes: Array.from({ length: n }, (_, i) => ({ id: "s" + i })), models: [], images: [] });

const a = s.putShare("u1", { projectId: "p1", name: "Cat", snapshot: snap(2) });
assert.match(a.token, s.TOKEN_RE);
assert.equal(a.views, 0);

// same project -> same link, refreshed snapshot
const b = s.putShare("u1", { projectId: "p1", name: "Cat v2", snapshot: snap(5) });
assert.equal(b.token, a.token);
assert.equal(s.getShare(a.token).data.snapshot.strokes.length, 5);
assert.equal(s.getShare(a.token).meta.name, "Cat v2");
// another user's project -> different link
assert.notEqual(s.putShare("u2", { projectId: "p1", snapshot: snap(1) }).token, a.token);
assert.equal(s.listShares("u1").length, 1);

// validation
assert.throws(() => s.putShare("u1", { projectId: "../x", snapshot: snap(1) }), /Invalid project id/);
assert.throws(() => s.putShare("u1", { projectId: "p2", snapshot: {} }), /Invalid project data/);
assert.equal(s.getShare("short"), null);
assert.equal(s.getShare("x".repeat(22)), null);

// view counting: once per viewer per day
assert.equal(s.recordView(a.token, "ip1").counted, true);
assert.equal(s.recordView(a.token, "ip1").counted, false);
const r = s.recordView(a.token, "user-9");
assert.equal(r.counted, true);
assert.equal(r.ownerId, "u1");
assert.equal(s.listShares("u1")[0].views, 2);

// revoke: only the owner; link then dies
assert.equal(s.revokeShare("u2", a.token), false);
assert.equal(s.revokeShare("u1", a.token), true);
assert.equal(s.getShare(a.token), null);
assert.equal(s.recordView(a.token, "ip1").counted, false);

// cleanup helpers
const c = s.putShare("u3", { projectId: "p7", snapshot: snap(1) });
s.removeProjectShares("u3", "p7");
assert.equal(s.getShare(c.token), null);
s.putShare("u3", { projectId: "p8", snapshot: snap(1) });
s.removeUserShares("u3");
assert.equal(s.listShares("u3").length, 0);
console.log("shares ok");
