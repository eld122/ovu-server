import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import assert from "node:assert";
import test from "node:test";
import { createSyncEngine } from "../mongoSync.js";

const fakeStore = (init = {}) => {
  const m = new Map(Object.entries(init).map(([k, v]) => [k, Buffer.from(v)]));
  return {
    m,
    list: async () => [...m.keys()],
    get: async (n) => m.get(n),
    put: async (n, b) => void m.set(n, Buffer.from(b)),
    del: async (n) => void m.delete(n),
  };
};
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), "ovu-mongo-"));

test("restore writes DB files into the data folder, including subfolders", async () => {
  const dir = tmp();
  const store = fakeStore({ "users.json": "[1]", "backups/u/projects/p.json": "{}" });
  const e = createSyncEngine({ dir, store });
  assert.equal(await e.restore(), 2);
  assert.equal(fs.readFileSync(path.join(dir, "users.json"), "utf8"), "[1]");
  assert.equal(fs.readFileSync(path.join(dir, "backups/u/projects/p.json"), "utf8"), "{}");
  // restored files are not re-uploaded
  const r = await e.sync();
  assert.deepEqual(r, { up: 0, del: 0 });
});

test("new, changed and deleted files are mirrored; .tmp files are ignored", async () => {
  const dir = tmp();
  const store = fakeStore();
  const e = createSyncEngine({ dir, store });
  await e.restore();
  fs.writeFileSync(path.join(dir, "a.json"), "one");
  fs.writeFileSync(path.join(dir, "b.json.tmp"), "partial");
  assert.deepEqual(await e.sync(), { up: 1, del: 0 });
  assert.equal(store.m.get("a.json").toString(), "one");
  assert.ok(!store.m.has("b.json.tmp"));
  assert.deepEqual(await e.sync(), { up: 0, del: 0 });
  fs.writeFileSync(path.join(dir, "a.json"), "twotwo");
  assert.deepEqual(await e.sync(), { up: 1, del: 0 });
  assert.equal(store.m.get("a.json").toString(), "twotwo");
  fs.unlinkSync(path.join(dir, "a.json"));
  assert.deepEqual(await e.sync(), { up: 0, del: 1 });
  assert.equal(store.m.size, 0);
});

test("a second boot sees what the first one saved (simulated redeploy)", async () => {
  const store = fakeStore();
  const dir1 = tmp();
  const e1 = createSyncEngine({ dir: dir1, store });
  await e1.restore();
  fs.mkdirSync(path.join(dir1, "shares"));
  fs.writeFileSync(path.join(dir1, "shares", "t.json"), '{"x":1}');
  await e1.sync();
  const dir2 = tmp(); // new empty disk
  const e2 = createSyncEngine({ dir: dir2, store });
  await e2.restore();
  assert.equal(fs.readFileSync(path.join(dir2, "shares", "t.json"), "utf8"), '{"x":1}');
});

test("never writes outside the data folder", async () => {
  const dir = tmp();
  const store = fakeStore({ "../evil.txt": "x", "ok.json": "1" });
  const e = createSyncEngine({ dir, store });
  await e.restore();
  assert.ok(!fs.existsSync(path.join(dir, "..", "evil.txt")));
  assert.ok(fs.existsSync(path.join(dir, "ok.json")));
});

test("a failing store does not throw and is retried next round", async () => {
  const dir = tmp();
  const store = fakeStore();
  let fail = true;
  const put = store.put;
  store.put = async (...a) => { if (fail) throw new Error("db down"); return put(...a); };
  const e = createSyncEngine({ dir, store });
  await e.restore();
  fs.writeFileSync(path.join(dir, "a.json"), "1");
  await e.sync();
  assert.equal(e.status().ok, false);
  fail = false;
  await e.sync();
  assert.equal(e.status().ok, true);
  assert.equal(store.m.get("a.json").toString(), "1");
});
