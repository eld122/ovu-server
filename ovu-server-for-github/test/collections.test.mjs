import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import assert from "node:assert";
process.env.OVU_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "ovu-coll-"));
const c = await import(new URL("../cloud.js", import.meta.url).href);

const [a1, a2] = c.listAssets({});
const owner = { id: "u1", name: "Ann" };

const col = c.createCollection(owner, { name: "  Ink pack ", description: "d", assetId: a1.id });
assert.equal(col.name, "Ink pack");
assert.equal(col.itemCount, 1);
assert.throws(() => c.createCollection(owner, { name: "x" }), /at least 2/);

assert.equal(c.addToCollection(owner.id, col.id, a2.id).collection.itemCount, 2);
assert.equal(c.addToCollection(owner.id, col.id, a2.id).collection.itemCount, 2); // no duplicates
assert.ok(c.addToCollection(owner.id, col.id, "nope").error);
assert.equal(c.addToCollection("u2", col.id, a1.id), null); // not the owner

assert.equal(c.listCollections({ scope: "all" }).length, 1);
c.updateCollection(owner.id, col.id, { public: false });
assert.equal(c.listCollections({ scope: "all" }).length, 0); // private is hidden
assert.equal(c.listCollections({ me: "u1", scope: "mine" }).length, 1);
assert.equal(c.getCollection(col.id, "u2"), null);
assert.equal(c.getCollection(col.id, "u1").assets.length, 2);

c.updateCollection(owner.id, col.id, { public: true });
const before = c.listAssets({}).find((a) => a.id === a1.id).downloads;
const pack = c.downloadCollection(col.id, "u2");
assert.equal(pack.assets.length, 2);
assert.equal(pack.downloads, 1);
assert.equal(c.listAssets({}).find((a) => a.id === a1.id).downloads, before + 1);
assert.ok(pack.assets[0].data.brush); // brush data is included for install

assert.equal(c.removeFromCollection(owner.id, col.id, a1.id).collection.itemCount, 1);
assert.equal(c.removeCollection("u2", col.id), false);
assert.equal(c.removeCollection(owner.id, col.id), true);
console.log("collections OK");
