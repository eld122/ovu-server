import fs from "node:fs"; import os from "node:os"; import path from "node:path";
process.env.OVU_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "ovu-"));
const c = await import(new URL("../cloud.js", import.meta.url).href);
const assert = (await import("node:assert")).default;
const a = c.listAssets({})[0];
const l1 = c.toggleAssetLike("u1", a.id); assert.equal(l1.added, true); assert.equal(l1.asset.likeCount, 1); assert.equal(l1.asset.liked, true);
assert.equal(c.toggleAssetLike("u1", a.id).asset.likeCount, 0);
c.toggleAssetSave("u1", a.id);
assert.equal(c.listAssets({ me: "u1", onlySaved: true }).length, 1);
assert.equal(c.listAssets({ me: "u2", onlySaved: true }).length, 0);
const cm = c.addAssetComment({ id: "u1", name: "A" }, a.id, "  hi  "); assert.equal(cm.comment.text, "hi");
assert.ok(c.addAssetComment({ id: "u1", name: "A" }, a.id, "  ").error);
assert.equal(c.removeAssetComment("u2", a.id, cm.comment.id).error, "Not allowed");
assert.equal(c.removeAssetComment("u1", a.id, cm.comment.id).asset.commentCount, 0);
assert.equal(c.listAssets({ sort: "week" }).length, 0); // seeds are 8-12 days old
console.log("social OK");
