import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createSessions, createOneTimeTokens, describeDevice } from "../authSessions.js";
import { createMailer } from "../mailer.js";

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), "ovu-auth-"));

test("device labels", () => {
  assert.equal(describeDevice("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17 Safari/605.1.15"), "Safari on macOS");
  assert.equal(describeDevice("Mozilla/5.0 (Windows NT 10.0) Chrome/120 Safari/537 Edg/120"), "Edge on Windows");
  assert.equal(describeDevice(""), "Unknown device");
});

test("refresh rotates, survives a lost response, and detects a stolen old token", () => {
  let t = 1_000_000;
  const s = createSessions({ dir: tmp(), now: () => t });
  const { session, refreshToken: r1 } = s.create("u1", { userAgent: "Chrome/1 Windows" });
  assert.ok(s.get(session.id));

  const a = s.refresh(r1);
  assert.ok(a && a.refreshToken !== r1);
  // client never received the answer and retries with r1 inside the grace window -> still allowed
  t += 5_000;
  const b = s.refresh(r1);
  assert.ok(b, "grace window");
  // the newest token works
  assert.ok(s.refresh(b.refreshToken));
  // r1 replayed long after rotation = copied token -> session is destroyed
  t += 120_000;
  assert.equal(s.refresh(r1), null);
  assert.equal(s.get(session.id), null);
});

test("expiry, revoke one / others / all, per-user isolation", () => {
  let t = 0;
  const s = createSessions({ dir: tmp(), now: () => t, refreshTtlMs: 1000 });
  const a = s.create("u1"), b = s.create("u1"), c = s.create("u2");
  assert.equal(s.list("u1").length, 2);
  assert.equal(s.revoke("u2", a.session.id), false); // not yours
  assert.equal(s.revokeOthers("u1", a.session.id), 1);
  assert.equal(s.get(b.session.id), null);
  assert.ok(s.get(a.session.id) && s.get(c.session.id));
  assert.equal(s.revokeAll("u1"), 1);
  t = 5000;
  assert.equal(s.get(c.session.id), null); // expired
  assert.equal(s.refresh(c.refreshToken), null);
});

test("sessions persist across restarts; garbage tokens are rejected", () => {
  const dir = tmp();
  const a = createSessions({ dir });
  const { session, refreshToken } = a.create("u1");
  const b = createSessions({ dir });
  assert.ok(b.get(session.id));
  assert.ok(b.refresh(refreshToken));
  assert.equal(b.refresh("nope"), null);
  assert.equal(b.refresh(`${session.id}.wrong`), null);
});

test("one-time tokens: single use, purpose-bound, expiring, replaced on reissue", () => {
  let t = 0;
  const o = createOneTimeTokens({ dir: tmp(), now: () => t });
  const k = o.issue("u1", "reset", 1000);
  assert.equal(o.consume(k, "verify"), null);
  assert.equal(o.consume(k, "reset"), "u1");
  assert.equal(o.consume(k, "reset"), null); // used
  const k2 = o.issue("u1", "reset", 1000);
  const k3 = o.issue("u1", "reset", 1000);
  assert.equal(o.consume(k2, "reset"), null); // replaced by k3
  t = 2000;
  assert.equal(o.consume(k3, "reset"), null); // expired
});

test("mailer: logs without config, calls Resend with config, never throws", async () => {
  const logs = [];
  const quiet = { log: (m) => logs.push(m), error: (m) => logs.push(m) };
  const none = createMailer({ env: {}, log: quiet });
  assert.equal(none.configured, false);
  assert.deepEqual(await none.resetPassword({ to: "a@b.c", name: "A", url: "http://x/?reset=1", code: "1" }), { sent: false, reason: "not-configured" });
  assert.match(logs[0], /http:\/\/x/);

  let seen;
  const ok = createMailer({ env: { RESEND_API_KEY: "k", MAIL_FROM: "Ovu <n@o.vu>" }, log: quiet, fetchImpl: async (url, init) => ((seen = { url, init }), { ok: true }) });
  assert.deepEqual(await ok.verifyEmail({ to: "a@b.c", name: "<b>x</b>", url: "https://s/auth/verify?token=1" }), { sent: true });
  assert.equal(seen.url, "https://api.resend.com/emails");
  assert.equal(JSON.parse(seen.init.body).to[0], "a@b.c");
  assert.doesNotMatch(JSON.parse(seen.init.body).html, /<b>x<\/b>/); // name is escaped

  const bad = createMailer({ env: { RESEND_API_KEY: "k", MAIL_FROM: "f" }, log: quiet, fetchImpl: async () => { throw new Error("down"); } });
  assert.equal((await bad.send({ to: "a@b.c", subject: "s", text: "t" })).sent, false);
});

test("mailer: Brevo is used when BREVO_API_KEY is set", async () => {
  const quiet = { log() {}, error() {} };
  let seen;
  const m = createMailer({ env: { BREVO_API_KEY: "k", MAIL_FROM: "Ovu <me@gmail.com>" }, log: quiet, fetchImpl: async (url, init) => ((seen = { url, init }), { ok: true }) });
  assert.equal(m.provider, "brevo");
  assert.deepEqual(await m.resetPassword({ to: "a@b.c", name: "x", url: "https://s/r", code: "c" }), { sent: true });
  assert.equal(seen.url, "https://api.brevo.com/v3/smtp/email");
  const body = JSON.parse(seen.init.body);
  assert.deepEqual(body.sender, { name: "Ovu", email: "me@gmail.com" });
  assert.deepEqual(body.to, [{ email: "a@b.c" }]);
  assert.equal(seen.init.headers["api-key"], "k");
});
