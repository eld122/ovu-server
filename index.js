import { DATA_DIR_PERSISTENT, MONGO_ENABLED } from "./dataDir.js";
import { mongoStatus } from "./mongoSync.js";
import "dotenv/config";
import crypto from "node:crypto";
import { createServer } from "node:http";
import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { WebSocketServer } from "ws";
import {
  createUser,
  findByEmail,
  findById,
  publicUser,
  upsertOAuthUser,
  restoreOAuthUser,
  updateUser,
  deleteUser,
  getProfile,
  updateProfile,
  listWorks,
  getWork,
  getWorkInternal,
  createWork,
  deleteWork,
  toggleFollow,
  isFollowing,
  toggleLike,
  hasLiked,
  listComments,
  addComment,
  searchAll,
  toggleSave,
  hasSaved,
  listSaved,
  deleteComment,
  exploreWorks,
  setPinned,
  setWorkTags,
  setWorkCategory,
  reorderWorks,
  PORTFOLIO_CATEGORIES,
  setAllowRemix,
  getRemixSource,
  addReport,
  isAdmin,
  listReportGroups,
  openReportCount,
  resolveReports,
  notify,
  listNotifications,
  markNotificationsRead,
  ownerOfWork,
  countView,
  getStats,
  handleAvailability,
  setHandle,
  suggestHandle,
  userIdByHandle,
} from "./db.js";
import {
  listVersions,
  getVersion,
  putVersion,
  removeVersion,
  removeProjectVersions,
  listAssets,
  createAsset,
  downloadAsset,
  getModelFile,
  removeAsset,
  assetBrief,
  adminRemoveAsset,
  rateAsset,
  listReviews,
  toggleAssetLike,
  toggleAssetSave,
  listAssetComments,
  addAssetComment,
  removeAssetComment,
  listCollections,
  getCollection,
  createCollection,
  updateCollection,
  removeCollection,
  addToCollection,
  removeFromCollection,
  downloadCollection,
  purgeUser,
} from "./cloud.js";
import { listShares, putShare, getShare, recordView, revokeShare, removeUserShares, removeProjectShares, TOKEN_RE, MAX_SHARE_BYTES } from "./shares.js";
import path from "node:path";
import { DATA_DIR } from "./dataDir.js";
import { createUpdates, UpdateError } from "./updates.js";
import { createSessions, createOneTimeTokens } from "./authSessions.js";
import { createMailer } from "./mailer.js";
import {
  listBackups, getBackup, putBackup, removeBackup, missingAssets, putBackupAsset, getBackupAsset,
  usedBytes, USER_QUOTA_BYTES, MAX_ASSET_BYTES, removeAllBackups,
} from "./backup.js";

const {
  PORT = "3000",
  CLIENT_URL = "https://ovu-bice.vercel.app",
  SERVER_URL = "http://localhost:3000",
  JWT_SECRET,
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  GITHUB_CLIENT_ID,
  GITHUB_CLIENT_SECRET,
  NODE_ENV,
} = process.env;

if (!JWT_SECRET || JWT_SECRET.length < 24) {
  console.error("Missing/short JWT_SECRET. Copy .env.example to .env and set a long random value.");
  process.exit(1);
}

// CLIENT_URL may be a comma-separated list (web app origin(s)). The packaged app is always allowed:
//   ovu://app            -> Electron (Mac / Windows)
const CLIENT_ORIGINS = CLIENT_URL.split(",").map((s) => s.trim().replace(/\/$/, "")).filter(Boolean);
const PRIMARY_CLIENT = CLIENT_ORIGINS[0] || "https://ovu-bice.vercel.app";
const NATIVE_ORIGINS = ["ovu://app"];
const ALLOWED_ORIGINS = new Set([...CLIENT_ORIGINS, ...NATIVE_ORIGINS]);
const APP_DEEP_LINK = "ovu://auth";

const isProd = NODE_ENV === "production";
const SESSION_COOKIE = "ovu_session";
const STATE_COOKIE = "ovu_oauth_state";
const APP_COOKIE = "ovu_oauth_app"; // "1" when the sign-in was started from the packaged app
const SESSION_MS = 7 * 24 * 60 * 60 * 1000;

const app = express();
app.set("trust proxy", 1);
app.use(express.json({ limit: "10mb" }));
app.use(cookieParser());
app.use(
  cors({
    origin(origin, cb) {
      // No Origin header (curl, server-to-server) is fine; browsers must be on the allow-list.
      cb(null, !origin || ALLOWED_ORIGINS.has(origin));
    },
    credentials: true,
    allowedHeaders: ["Content-Type", "Authorization"],
    exposedHeaders: ["X-Ovu-Session", "X-Ovu-Refresh"],
  })
);

// ---------- helpers ----------
const cookieBase = { httpOnly: true, sameSite: "lax", secure: isProd, path: "/" };
// The login cookie must also be sent when the app page and this API are on different sites
// (e.g. http://localhost:5173 or a Vercel domain calling https://….onrender.com). SameSite=Lax cookies
// are dropped on such requests, which made every signed-in call answer 401. "None" requires Secure (https).
const sessionCookieBase = isProd ? { ...cookieBase, sameSite: "none", secure: true } : cookieBase;

const ACCESS_TTL_SEC = 15 * 60; // short-lived; the refresh token (30 days, rotated) keeps people signed in
const REFRESH_COOKIE = "ovu_refresh";
const sessions = createSessions({ dir: DATA_DIR });
const oneTime = createOneTimeTokens({ dir: DATA_DIR });
const mailer = createMailer();
const VERIFY_TTL = 24 * 3600 * 1000;
const RESET_TTL = 3600 * 1000;

const sessionClaims = (user) => {
  // Claims let an OAuth session survive a lost users.json (see restoreOAuthUser in db.js).
  const claims = {};
  if (user.provider === "google" || user.provider === "github") {
    Object.assign(claims, { n: user.name, e: user.email, p: user.provider, pid: user.providerId, a: user.avatarUrl ?? undefined });
  }
  return claims;
};

/** Does this response go to a page that can't rely on cookies (installed app, or web app on another site)? */
function wantsTokenHeaders(res) {
  const origin = res.req?.headers?.origin;
  if (!origin) return false;
  if (NATIVE_ORIGINS.includes(origin)) return true;
  try {
    return ALLOWED_ORIGINS.has(origin) && new URL(origin).host !== res.req?.headers?.host;
  } catch {
    return false;
  }
}

/** Put a fresh access token + refresh token on the response (cookies, and headers for cookie-less clients). */
function sendTokens(res, user, session, refreshToken) {
  const access = jwt.sign({ sub: user.id, sid: session.id, ...session.claims }, JWT_SECRET, { expiresIn: ACCESS_TTL_SEC });
  res.cookie(SESSION_COOKIE, access, { ...sessionCookieBase, maxAge: ACCESS_TTL_SEC * 1000 });
  res.cookie(REFRESH_COOKIE, refreshToken, { ...sessionCookieBase, path: "/auth", maxAge: SESSION_MS * 30 / 7 });
  // Packaged apps and cross-site web pages (e.g. localhost:5173 -> onrender.com) lose cookies (Safari always),
  // so they get the tokens in headers and send "Authorization: Bearer ...". Same-site web keeps httpOnly cookies only.
  if (wantsTokenHeaders(res)) {
    res.setHeader("X-Ovu-Session", access);
    res.setHeader("X-Ovu-Refresh", refreshToken);
  }
}

function startSession(res, user) {
  const req = res.req;
  const { session, refreshToken } = sessions.create(user.id, {
    ip: req?.ip,
    userAgent: req?.headers?.["user-agent"],
    claims: sessionClaims(user),
  });
  sendTokens(res, user, session, refreshToken);
  return session;
}

const clearAuthCookies = (res) => {
  res.clearCookie(SESSION_COOKIE, sessionCookieBase);
  res.clearCookie(REFRESH_COOKIE, { ...sessionCookieBase, path: "/auth" });
};

function currentUser(req) {
  const auth = req.headers?.authorization;
  const bearer = typeof auth === "string" && auth.startsWith("Bearer ") ? auth.slice(7).trim() : null;
  const token = bearer || req.cookies?.[SESSION_COOKIE];
  if (!token) return null;
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.purpose) return null; // short-lived bridge tokens are not sessions
    // Tokens issued before sessions existed have no "sid" and simply run out (<= 7 days). New ones must belong
    // to a live session: signing a device out takes effect at once.
    if (payload.sid) {
      const s = sessions.get(payload.sid);
      if (!s || s.userId !== payload.sub) return null;
      req.sessionId = s.id;
    }
    return (
      findById(payload.sub) ??
      restoreOAuthUser({ id: payload.sub, name: payload.n, email: payload.e, provider: payload.p, providerId: payload.pid, avatarUrl: payload.a })
    );
  } catch {
    return null;
  }
}

// Real hash used to keep login timing similar for unknown emails.
const DUMMY_HASH = bcrypt.hashSync("ovu-dummy-password", 12);

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Minimal in-memory rate limit for the credential endpoints (per IP).
const hits = new Map();
function rateLimit(max, windowMs) {
  return (req, res, next) => {
    const now = Date.now();
    const key = `${req.ip}:${req.path}`;
    const entry = (hits.get(key) ?? []).filter((t) => now - t < windowMs);
    if (entry.length >= max) return res.status(429).json({ error: "Too many attempts. Try again in a few minutes." });
    entry.push(now);
    hits.set(key, entry);
    next();
  };
}

// ---------- email + password ----------
app.post("/auth/register", rateLimit(10, 15 * 60 * 1000), async (req, res) => {
  const name = String(req.body?.name ?? "").trim();
  const email = String(req.body?.email ?? "").trim().toLowerCase();
  const password = String(req.body?.password ?? "");

  if (name.length < 2) return res.status(400).json({ error: "Please enter your name." });
  if (!EMAIL_RE.test(email)) return res.status(400).json({ error: "Please enter a valid email address." });
  if (password.length < 8) return res.status(400).json({ error: "Password must be at least 8 characters." });
  const existing = findByEmail(email);
  // A real, confirmed account (or a Google/GitHub one): this is NOT a new user -> no email, no "check your inbox" screen.
  if (existing && !(existing.provider === "email" && existing.emailVerified !== true)) {
    return res.status(409).json({ error: "An account with this email already exists. Try signing in." });
  }

  const passwordHash = await bcrypt.hash(password, 12);
  let user;
  if (existing) {
    // Same address signed up before but never confirmed it: whoever confirms from the mailbox owns it.
    user = updateUser(existing.id, { name, passwordHash });
  } else {
    user = createUser({ name, email, passwordHash, provider: "email" });
  }
  // No session yet: the account only opens after the mailbox is confirmed.
  const sent = await sendVerification(user);
  res.status(202).json({
    pendingVerification: true,
    email: user.email,
    pollToken: oneTime.issue(user.id, "pending", VERIFY_TTL),
    delivered: sent.sent === true,
  });
});

app.post("/auth/login", rateLimit(10, 15 * 60 * 1000), async (req, res) => {
  const email = String(req.body?.email ?? "").trim().toLowerCase();
  const password = String(req.body?.password ?? "");
  const user = findByEmail(email);

  // Same message for "no such user" and "wrong password" (no account probing).
  const invalid = () => res.status(401).json({ error: "Incorrect email or password." });
  if (!user) {
    await bcrypt.compare(password, DUMMY_HASH); // equalise timing
    return invalid();
  }
  if (!user.passwordHash) {
    return res.status(400).json({ error: `This account uses ${user.provider} sign-in. Use that button instead.` });
  }
  if (!(await bcrypt.compare(password, user.passwordHash))) return invalid();

  // Correct password but the mailbox was never confirmed (e.g. an account made before verification existed).
  if (user.provider === "email" && user.emailVerified !== true) {
    await sendVerification(user);
    return res.status(403).json({
      error: "Please confirm your email address first. We sent you a new link.",
      code: "EMAIL_NOT_VERIFIED",
      email: user.email,
      pollToken: oneTime.issue(user.id, "pending", VERIFY_TTL),
    });
  }

  startSession(res, user);
  res.json({ user: publicUser(user) });
});

app.get("/auth/me", (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ user: null });
  res.json({ user: publicUser(user) });
});

app.patch("/auth/me", (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "Not signed in" });
  const name = String(req.body?.name ?? "").trim();
  if (!name || name.length > 80) return res.status(400).json({ error: "Invalid name" });
  const updated = updateUser(user.id, { name });
  res.json({ user: publicUser(updated) });
});

app.delete("/auth/me", (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "Not signed in" });
  deleteUser(user.id);
  purgeUser(user.id);
  removeAllBackups(user.id);
  removeUserShares(user.id);
  sessions.revokeAll(user.id);
  clearAuthCookies(res);
  res.json({ ok: true });
});

app.post("/auth/password", rateLimit(8, 15 * 60 * 1000), async (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "Not signed in" });
  if (user.provider !== "email" || !user.passwordHash) {
    return res.status(400).json({ error: "Password not available for this account" });
  }
  const currentPassword = String(req.body?.currentPassword ?? "");
  const newPassword = String(req.body?.newPassword ?? "");
  if (newPassword.length < 8) return res.status(400).json({ error: "New password must be at least 8 characters" });
  const ok = await bcrypt.compare(currentPassword, user.passwordHash);
  if (!ok) return res.status(400).json({ error: "Current password is wrong" });
  const passwordHash = await bcrypt.hash(newPassword, 12);
  updateUser(user.id, { passwordHash });
  sessions.revokeOthers(user.id, req.sessionId ?? null); // a changed password signs every OTHER device out
  res.json({ ok: true });
});

// ---------- sessions: refresh, logout, devices ----------
const refreshTokenOf = (req) => String(req.body?.refreshToken || req.cookies?.[REFRESH_COOKIE] || "");

app.post("/auth/refresh", rateLimit(120, 15 * 60 * 1000), (req, res) => {
  const out = sessions.refresh(refreshTokenOf(req), { ip: req.ip, userAgent: req.headers["user-agent"] });
  const fail = () => {
    clearAuthCookies(res);
    res.status(401).json({ error: "Session expired. Please sign in again." });
  };
  if (!out) return fail();
  const { session, refreshToken } = out;
  const c = session.claims || {};
  const user =
    findById(session.userId) ??
    restoreOAuthUser({ id: session.userId, name: c.n, email: c.e, provider: c.p, providerId: c.pid, avatarUrl: c.a });
  if (!user) {
    sessions.revoke(session.userId, session.id);
    return fail();
  }
  sendTokens(res, user, session, refreshToken);
  res.json({ user: publicUser(user) });
});

app.post("/auth/logout", (req, res) => {
  // works with an access token or only a refresh token (e.g. the access token already expired)
  const me = currentUser(req);
  const sid = me ? req.sessionId : sessions.idOfRefreshToken(refreshTokenOf(req));
  const owner = me?.id ?? (sid ? sessions.get(sid)?.userId : null);
  if (sid && owner) sessions.revoke(owner, sid);
  clearAuthCookies(res);
  res.json({ ok: true });
});

app.get("/auth/sessions", (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "Not signed in" });
  res.json({ sessions: sessions.list(user.id).map((s) => ({ ...s, current: s.id === req.sessionId })) });
});

app.delete("/auth/sessions/:id", (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "Not signed in" });
  if (!sessions.revoke(user.id, req.params.id)) return res.status(404).json({ error: "Device not found" });
  if (req.params.id === req.sessionId) clearAuthCookies(res);
  res.json({ ok: true });
});

app.post("/auth/sessions/revoke-others", (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "Not signed in" });
  res.json({ ok: true, revoked: sessions.revokeOthers(user.id, req.sessionId ?? null) });
});

app.post("/auth/logout-all", (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "Not signed in" });
  const revoked = sessions.revokeAll(user.id);
  clearAuthCookies(res);
  res.json({ ok: true, revoked });
});

// ---------- email verification + password reset ----------
const lastVerifyMail = new Map(); // userId -> time of the last verification email (60 s cooldown against spam)
async function sendVerification(user) {
  if (user.provider !== "email" || user.emailVerified === true) return { sent: false, reason: "not-needed" };
  const last = lastVerifyMail.get(user.id) ?? 0;
  if (Date.now() - last < 60_000) return { sent: false, reason: "cooldown" };
  lastVerifyMail.set(user.id, Date.now());
  const token = oneTime.issue(user.id, "verify", VERIFY_TTL);
  const url = `${SERVER_URL.replace(/\/+$/, "")}/auth/verify?token=${encodeURIComponent(token)}`;
  return mailer.verifyEmail({ to: user.email, name: user.name, url });
}

// Signed-in user asks for another link (Settings -> Devices).
app.post("/auth/verify/send", rateLimit(3, 15 * 60 * 1000), async (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "Not signed in" });
  if (user.provider !== "email" || user.emailVerified === true) return res.json({ ok: true, alreadyVerified: true });
  const r = await sendVerification(user);
  res.json({ ok: true, delivered: r.sent });
});

// "Resend" on the check-your-email screen. Needs the secret pollToken that only that screen holds.
app.post("/auth/verify/resend", rateLimit(6, 15 * 60 * 1000), async (req, res) => {
  const userId = oneTime.peek(String(req.body?.pollToken ?? ""), "pending");
  const user = userId ? findById(userId) : null;
  if (!user) return res.status(400).json({ error: "This sign-up expired. Please start again." });
  const r = await sendVerification(user);
  res.json({ ok: true, delivered: r.sent === true, cooldown: r.reason === "cooldown" });
});

// The check-your-email screen polls this. Once the link was clicked (on any device) it signs this device in.
app.post("/auth/verify/status", rateLimit(600, 15 * 60 * 1000), (req, res) => {
  const pollToken = String(req.body?.pollToken ?? "");
  const userId = oneTime.peek(pollToken, "pending");
  const user = userId ? findById(userId) : null;
  if (!user) return res.json({ status: "expired" });
  if (user.emailVerified !== true) return res.json({ status: "pending" });
  oneTime.consume(pollToken, "pending");
  startSession(res, user);
  res.json({ status: "verified", user: publicUser(user) });
});

const verifyPage = (ok) => {
  const title = ok ? "Email confirmed" : "Link expired";
  const msg = ok
    ? "You're all set. Go back to the Ovu app — it signs you in automatically within a few seconds."
    : "This confirmation link is invalid or has already been used. Open Ovu and ask for a new one.";
  const web = /localhost|127\.0\.0\.1/.test(PRIMARY_CLIENT) ? "" : `<a class="b" href="${PRIMARY_CLIENT}">Open Ovu on the web</a>`;
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Ovu</title>
<style>body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f4f4f5;font-family:-apple-system,'Segoe UI',system-ui,sans-serif;color:#0a0a0b}
.c{max-width:380px;margin:24px;padding:38px 34px;background:#fff;border:1px solid rgba(10,10,11,.1);border-radius:20px;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,.10)}
.l{font-size:28px;font-weight:800;letter-spacing:-1.2px;color:#0a0a0b}.i{font-size:34px;margin:16px 0 4px}h1{font-size:20px;margin:6px 0;letter-spacing:-.3px}p{font-size:14px;line-height:1.6;color:rgba(10,10,11,.62)}
.b{display:inline-block;margin-top:12px;padding:13px 24px;border-radius:12px;background:#0a0a0b;color:#fff;text-decoration:none;font-weight:600;font-size:14px}</style></head>
<body><div class="c"><div class="l">Ovu</div><div class="i">${ok ? "✓" : "!"}</div><h1>${title}</h1><p>${msg}</p>${web}</div></body></html>`;
};

app.get("/auth/verify", (req, res) => {
  const userId = oneTime.consume(String(req.query.token ?? ""), "verify");
  const ok = !!(userId && findById(userId));
  if (ok) updateUser(userId, { emailVerified: true });
  res.setHeader("Cache-Control", "no-store");
  res.status(ok ? 200 : 400).type("html").send(verifyPage(ok));
});

app.post("/auth/forgot", rateLimit(5, 15 * 60 * 1000), (req, res) => {
  const email = String(req.body?.email ?? "").trim().toLowerCase();
  const user = EMAIL_RE.test(email) ? findByEmail(email) : null;
  // Same answer whether or not the address has an account (no account probing); only password accounts can reset.
  if (user && user.provider === "email") {
    const code = oneTime.issue(user.id, "reset", RESET_TTL);
    const url = `${PRIMARY_CLIENT}/?reset=${encodeURIComponent(code)}`;
    void mailer.resetPassword({ to: user.email, name: user.name, url, code });
  }
  res.json({ ok: true });
});

app.post("/auth/reset", rateLimit(10, 15 * 60 * 1000), async (req, res) => {
  const password = String(req.body?.password ?? "");
  if (password.length < 8) return res.status(400).json({ error: "Password must be at least 8 characters." });
  const userId = oneTime.consume(String(req.body?.token ?? ""), "reset");
  const user = userId ? findById(userId) : null;
  if (!user) return res.status(400).json({ error: "This reset link or code is invalid or has expired. Request a new one." });
  updateUser(user.id, { passwordHash: await bcrypt.hash(password, 12), emailVerified: true }); // they just proved the mailbox
  sessions.revokeAll(user.id); // everyone must sign in again with the new password
  res.json({ ok: true });
});

// ---------- OAuth (shared) ----------
function beginOAuth(res, buildUrl) {
  const state = crypto.randomBytes(24).toString("hex");
  res.cookie(STATE_COOKIE, state, { ...cookieBase, maxAge: 10 * 60 * 1000 });
  // /auth/google?app=1 and /auth/github?app=1 come from the packaged app (opened in the system browser).
  if (res.req?.query?.app === "1") {
    res.cookie(APP_COOKIE, "1", { ...cookieBase, maxAge: 10 * 60 * 1000 });
  } else {
    res.clearCookie(APP_COOKIE, cookieBase);
  }
  res.redirect(buildUrl(state));
}

const isAppFlow = (res) => res.req?.cookies?.[APP_COOKIE] === "1";

/** Browser landing page that hands control back to the installed app via ovu://auth?... */
function sendToApp(res, params) {
  const target = `${APP_DEEP_LINK}?${new URLSearchParams(params).toString()}`;
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.status(200).type("html").send(
    `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">` +
      `<title>Ovu</title><style>body{font-family:system-ui,sans-serif;background:#f4f4f5;color:#0a0a0b;display:flex;` +
      `min-height:100vh;align-items:center;justify-content:center;margin:0;text-align:center}a{display:inline-block;` +
      `margin-top:16px;padding:13px 24px;border-radius:12px;background:#0a0a0b;color:#fff;text-decoration:none;font-weight:600}</style></head>` +
      `<body><div><h2>Opening Ovu…</h2><p>If the app doesn't open by itself, tap the button.</p>` +
      `<a id="go" href="#">Open Ovu</a><p style="font-size:12px;opacity:.6">You can close this tab afterwards.</p></div>` +
      `<script>var t=${JSON.stringify(target)};document.getElementById("go").href=t;setTimeout(function(){location.href=t},150);</script>` +
      `</body></html>`
  );
}

function failRedirect(res, message) {
  const fromApp = isAppFlow(res);
  res.clearCookie(STATE_COOKIE, cookieBase);
  res.clearCookie(APP_COOKIE, cookieBase);
  if (fromApp) return sendToApp(res, { auth_error: message });
  res.redirect(`${PRIMARY_CLIENT}/?auth_error=${encodeURIComponent(message)}`);
}

/** Validates ?state against the cookie (CSRF protection). Returns the code or null. */
function checkCallback(req, res) {
  const { code, state, error } = req.query;
  if (error) {
    failRedirect(res, "Sign-in was cancelled.");
    return null;
  }
  if (!code || !state || state !== req.cookies?.[STATE_COOKIE]) {
    failRedirect(res, "Sign-in expired or was invalid. Please try again.");
    return null;
  }
  res.clearCookie(STATE_COOKIE, cookieBase);
  return String(code);
}

function finishOAuth(res, profile) {
  if (!profile.email) return failRedirect(res, "Your account has no verified email address.");
  const fromApp = isAppFlow(res);
  res.clearCookie(APP_COOKIE, cookieBase);
  const user = upsertOAuthUser({ ...profile, onTakeover: (u) => sessions.revokeAll(u.id) });
  startSession(res, user);
  // One-time bridge token: the SPA on another port can exchange this via XHR
  // (Set-Cookie on a cross-port 302 is unreliable; XHR with credentials is not).
  const bridge = jwt.sign(
    { sub: user.id, purpose: "oauth_bridge" },
    JWT_SECRET,
    { expiresIn: "2m" }
  );
  if (fromApp) return sendToApp(res, { oauth_token: bridge });
  res.redirect(`${PRIMARY_CLIENT}/?oauth_token=${encodeURIComponent(bridge)}`);
}

app.post("/auth/exchange", (req, res) => {
  const token = String(req.body?.token ?? "");
  if (!token) return res.status(400).json({ error: "Missing token" });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.purpose !== "oauth_bridge" || !payload.sub) {
      return res.status(400).json({ error: "Invalid token" });
    }
    const user = findById(payload.sub);
    if (!user) return res.status(401).json({ error: "User not found" });
    startSession(res, user);
    res.json({ user: publicUser(user) });
  } catch {
    return res.status(401).json({ error: "Token expired or invalid. Please sign in again." });
  }
});

// ---------- Google ----------
app.get("/auth/google", (_req, res) => {
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) return failRedirect(res, "Google sign-in isn't configured on the server.");
  beginOAuth(res, (state) => {
    const p = new URLSearchParams({
      client_id: GOOGLE_CLIENT_ID,
      redirect_uri: `${SERVER_URL}/auth/google/callback`,
      response_type: "code",
      scope: "openid email profile",
      state,
      prompt: "select_account",
    });
    return `https://accounts.google.com/o/oauth2/v2/auth?${p}`;
  });
});

app.get("/auth/google/callback", async (req, res) => {
  const code = checkCallback(req, res);
  if (!code) return;
  try {
    const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code,
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri: `${SERVER_URL}/auth/google/callback`,
        grant_type: "authorization_code",
      }),
    });
    const token = await tokenRes.json();
    if (!token.access_token) throw new Error(token.error_description || "token exchange failed");

    const infoRes = await fetch("https://openidconnect.googleapis.com/v1/userinfo", {
      headers: { Authorization: `Bearer ${token.access_token}` },
    });
    const info = await infoRes.json();
    if (!info.email_verified) return failRedirect(res, "Your Google email is not verified.");

    finishOAuth(res, {
      provider: "google",
      providerId: info.sub,
      email: String(info.email).toLowerCase(),
      name: info.name || String(info.email).split("@")[0],
      avatarUrl: info.picture,
    });
  } catch (err) {
    console.error("Google OAuth error:", err);
    failRedirect(res, "Google sign-in failed. Please try again.");
  }
});

// ---------- GitHub ----------
app.get("/auth/github", (_req, res) => {
  if (!GITHUB_CLIENT_ID || !GITHUB_CLIENT_SECRET) return failRedirect(res, "GitHub sign-in isn't configured on the server.");
  beginOAuth(res, (state) => {
    const p = new URLSearchParams({
      client_id: GITHUB_CLIENT_ID,
      redirect_uri: `${SERVER_URL}/auth/github/callback`,
      scope: "read:user user:email",
      state,
    });
    return `https://github.com/login/oauth/authorize?${p}`;
  });
});

app.get("/auth/github/callback", async (req, res) => {
  const code = checkCallback(req, res);
  if (!code) return;
  try {
    const tokenRes = await fetch("https://github.com/login/oauth/access_token", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({
        client_id: GITHUB_CLIENT_ID,
        client_secret: GITHUB_CLIENT_SECRET,
        code,
        redirect_uri: `${SERVER_URL}/auth/github/callback`,
      }),
    });
    const token = await tokenRes.json();
    if (!token.access_token) throw new Error(token.error_description || "token exchange failed");

    const headers = {
      Authorization: `Bearer ${token.access_token}`,
      Accept: "application/vnd.github+json",
      "User-Agent": "ovu-server",
    };
    const profile = await (await fetch("https://api.github.com/user", { headers })).json();
    const emails = await (await fetch("https://api.github.com/user/emails", { headers })).json();
    const primary = Array.isArray(emails) ? emails.find((e) => e.primary && e.verified) : null;

    finishOAuth(res, {
      provider: "github",
      providerId: profile.id,
      email: primary ? primary.email.toLowerCase() : null,
      name: profile.name || profile.login,
      avatarUrl: profile.avatar_url,
    });
  } catch (err) {
    console.error("GitHub OAuth error:", err);
    failRedirect(res, "GitHub sign-in failed. Please try again.");
  }
});

// ---------- Portfolio & social ----------
function sendProfile(req, res, userId) {
  const profile = getProfile(userId);
  const me = currentUser(req);
  if (!profile || (!profile.isPublic && (!me || me.id !== userId))) return res.status(404).json({ error: "Profile not found" });
  res.json({
    profile,
    works: listWorks(userId, me?.id ?? null),
    following: me ? isFollowing(me.id, userId) : false,
  });
}

app.get("/api/profile/:userId", (req, res) => sendProfile(req, res, req.params.userId));

// ---------- Short profile links: ovu/@name ----------
// Resolve a handle to the same payload as /api/profile/:id (the client only needs profile.id).
app.get("/api/u/:handle", (req, res) => {
  const id = userIdByHandle(req.params.handle);
  if (!id) return res.status(404).json({ error: "Profile not found" });
  sendProfile(req, res, id);
});

// Live availability check for the settings screen.
app.get("/api/handle/check", (req, res) => {
  const me = currentUser(req);
  res.json(handleAvailability(String(req.query.name ?? ""), me?.id ?? null));
});

app.get("/api/handle/suggest", (req, res) => {
  const me = currentUser(req);
  if (!me) return res.status(401).json({ error: "Not signed in" });
  res.json({ handle: suggestHandle(me.name, me.id) });
});

app.patch("/api/profile", (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "Not signed in" });
  // Only touch the fields the client actually sent, so saving a picture never wipes the bio.
  const patch = {};
  if (typeof req.body?.bio === "string") patch.bio = req.body.bio.slice(0, 500);
  if (typeof req.body?.isPublic === "boolean") patch.isPublic = req.body.isPublic;
  const imageField = (key, field, maxBytes) => {
    if (!(key in (req.body || {}))) return null;
    const v = req.body[key];
    if (v === null || v === "") {
      patch[field] = null; // remove
      return null;
    }
    if (typeof v !== "string" || !/^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/.test(v)) {
      return "Pictures must be JPEG, PNG or WebP";
    }
    if (Buffer.byteLength(v) > maxBytes) return "Picture is too large";
    patch[field] = v;
    return null;
  };
  const imgErr = imageField("avatarDataUrl", "avatarDataUrl", 400 * 1024) || imageField("bannerDataUrl", "bannerDataUrl", 1200 * 1024);
  if (imgErr) return res.status(400).json({ error: imgErr });
  // Short link name (ovu/@name). null / "" removes it. Checked after the pictures, so a rejected picture never leaves a half-saved profile.
  if ("handle" in (req.body || {})) {
    const raw = req.body.handle;
    if (raw !== null && typeof raw !== "string") return res.status(400).json({ error: "Invalid name" });
    const h = setHandle(user.id, raw);
    if (!h.ok) return res.status(h.status || 400).json({ error: h.error });
  }
  // Only touch allowComments when the client actually sent it
  if (typeof req.body?.allowComments === "boolean") patch.allowComments = req.body.allowComments;
  const profile = updateProfile(user.id, patch);
  res.json({ profile });
});

app.get("/api/works/:workId", (req, res) => {
  const work = getWork(req.params.workId);
  if (!work) return res.status(404).json({ error: "Work not found" });
  const me = currentUser(req);
  if (getWorkInternal(work.id)?.hidden && me?.id !== work.userId) return res.status(404).json({ error: "Work not found" });
  const ownerProfile = getProfile(work.userId);
  // Private portfolios are not viewable by link, only by their owner.
  if (ownerProfile && ownerProfile.isPublic === false && me?.id !== work.userId) return res.status(404).json({ error: "Work not found" });
  countView(work.id, me?.id || req.ip || "anon", me?.id);
  res.json({
    work,
    liked: me ? hasLiked(me.id, work.id) : false,
    saved: me ? hasSaved(me.id, work.id) : false,
    authorName: ownerProfile?.name || "",
    comments: listComments(work.id),
    isOwner: me ? me.id === work.userId : false,
  });
});

/** Protected model stream — never sets Content-Disposition attachment; watermark flag forced. */
app.get("/api/works/:workId/model", (req, res) => {
  const internal = getWorkInternal(req.params.workId);
  if (!internal || internal.type !== "model" || !internal.modelData) {
    return res.status(404).json({ error: "Model not available" });
  }
  {
    const viewer = currentUser(req);
    const ownerProfile = getProfile(internal.userId);
    if (internal.hidden && viewer?.id !== internal.userId) return res.status(404).json({ error: "Model not available" });
    if (ownerProfile && ownerProfile.isPublic === false && viewer?.id !== internal.userId) return res.status(404).json({ error: "Model not available" });
  }
  // No download headers — browsers should not offer "Save as"
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Cache-Control", "private, no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Content-Disposition", "inline");
  // Payload is view-token style: client must render with watermark
  res.json({
    format: "ovu-protected-v1",
    workId: internal.id,
    watermark: true,
    allowDownload: false,
    data: internal.modelData,
  });
});

app.post("/api/works", express.json({ limit: "10mb" }), (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "Not signed in" });
  try {
    const work = createWork(user.id, req.body || {});
    res.status(201).json({ work });
  } catch (e) {
    res.status(400).json({ error: e instanceof Error ? e.message : "Could not publish" });
  }
});

app.delete("/api/works/:workId", (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "Not signed in" });
  if (!deleteWork(user.id, req.params.workId)) return res.status(404).json({ error: "Not found" });
  res.json({ ok: true });
});

app.post("/api/works/:workId/like", (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "Not signed in" });
  if (!getWork(req.params.workId)) return res.status(404).json({ error: "Not found" });
  const r = toggleLike(user.id, req.params.workId);
  if (r.liked) notify(ownerOfWork(req.params.workId), { type: "like", fromUserId: user.id, workId: req.params.workId, text: getWork(req.params.workId)?.title });
  res.json(r);
});

app.post("/api/works/:workId/comments", (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "Not signed in" });
  const target = getWorkInternal(req.params.workId);
  if (target && target.userId !== user.id) {
    const owner = getProfile(target.userId);
    if (owner && owner.allowComments === false) {
      return res.status(403).json({ error: "Comments are turned off for this portfolio." });
    }
  }
  const comment = addComment(user.id, req.params.workId, req.body?.text);
  if (!comment) return res.status(400).json({ error: "Invalid comment" });
  notify(ownerOfWork(req.params.workId), { type: "comment", fromUserId: user.id, workId: req.params.workId, text: comment.text });
  res.status(201).json({ comment });
});

app.post("/api/follow/:userId", (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "Not signed in" });
  if (!getProfile(req.params.userId)) return res.status(404).json({ error: "User not found" });
  const r = toggleFollow(user.id, req.params.userId);
  if (r.following) notify(req.params.userId, { type: "follow", fromUserId: user.id });
  res.json(r);
});

// ---------- Part 6: saves, explore, pins, tags, remix, reports, notifications ----------
const needUser = (req, res) => {
  const u = currentUser(req);
  if (!u) res.status(401).json({ error: "Not signed in" });
  return u;
};

app.post("/api/works/:workId/save", (req, res) => {
  const user = needUser(req, res); if (!user) return;
  if (!getWork(req.params.workId)) return res.status(404).json({ error: "Not found" });
  res.json(toggleSave(user.id, req.params.workId));
});
app.get("/api/saved", (req, res) => {
  const user = needUser(req, res); if (!user) return;
  res.json({ works: listSaved(user.id) });
});

app.delete("/api/comments/:commentId", (req, res) => {
  const user = needUser(req, res); if (!user) return;
  if (!deleteComment(user.id, req.params.commentId)) return res.status(404).json({ error: "Not found" });
  res.json({ ok: true });
});

app.get("/api/explore", (req, res) => {
  const sort = req.query.sort === "new" ? "new" : "popular";
  const days = Math.min(365, Math.max(0, parseInt(req.query.days, 10) || 0));
  res.json({ works: exploreWorks({ sort, days, tag: String(req.query.tag ?? "").slice(0, 24) }) });
});

app.post("/api/works/:workId/pin", (req, res) => {
  const user = needUser(req, res); if (!user) return;
  const r = setPinned(user.id, req.params.workId, req.body?.pinned !== false);
  if (!r) return res.status(404).json({ error: "Not found" });
  if (r.error) return res.status(400).json({ error: r.error });
  res.json(r);
});
app.patch("/api/works/:workId", (req, res) => {
  const user = needUser(req, res); if (!user) return;
  let work = null;
  if (Array.isArray(req.body?.tags) || typeof req.body?.tags === "string") work = setWorkTags(user.id, req.params.workId, req.body.tags);
  if (typeof req.body?.allowRemix === "boolean") work = setAllowRemix(user.id, req.params.workId, req.body.allowRemix);
  if (typeof req.body?.category === "string") {
    const r = setWorkCategory(user.id, req.params.workId, req.body.category);
    if (r?.error) return res.status(400).json({ error: r.error });
    work = r?.work ?? null;
  }
  if (!work) return res.status(404).json({ error: "Not found" });
  res.json({ work });
});

app.get("/api/portfolio/categories", (_req, res) => res.json({ categories: PORTFOLIO_CATEGORIES }));

/** Drag-and-drop order of your own works. */
app.put("/api/portfolio/order", (req, res) => {
  const user = needUser(req, res); if (!user) return;
  res.json({ works: reorderWorks(user.id, req.body?.ids) });
});

// Remix: only works whose author opted in. Returns the project payload so the client can open it as a copy.
app.get("/api/works/:workId/remix", (req, res) => {
  const user = needUser(req, res); if (!user) return;
  const src = getRemixSource(user.id, req.params.workId);
  if (!src) return res.status(404).json({ error: "Work not found" });
  if (src.error) return res.status(403).json({ error: src.error });
  notify(src.work.userId, { type: "remix", fromUserId: user.id, workId: src.work.id, text: src.work.title });
  res.setHeader("Cache-Control", "private, no-store");
  res.json(src);
});

app.post("/api/reports", rateLimit(20, 60 * 60 * 1000), (req, res) => {
  const user = needUser(req, res); if (!user) return;
  const r = addReport(user.id, req.body || {});
  if (!r) return res.status(400).json({ error: "Invalid report" });
  res.json(r);
});

app.get("/api/stats", (req, res) => {
  const user = needUser(req, res); if (!user) return;
  res.json(getStats(user.id));
});

app.get("/api/notifications", (req, res) => {
  const user = needUser(req, res); if (!user) return;
  res.json(listNotifications(user.id));
});
app.post("/api/notifications/read", (req, res) => {
  const user = needUser(req, res); if (!user) return;
  markNotificationsRead(user.id);
  res.json({ ok: true });
});

// ---------- Cloud version history ("Time Machine") ----------
app.get("/api/versions", (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "Not signed in" });
  const projectId = String(req.query.projectId ?? "");
  res.json({ versions: listVersions(user.id, projectId) });
});

app.get("/api/versions/:id", (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "Not signed in" });
  const v = getVersion(user.id, req.params.id);
  if (!v) return res.status(404).json({ error: "Version not found" });
  res.json({ version: v });
});

app.post("/api/versions", (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "Not signed in" });
  try {
    res.status(201).json({ version: putVersion(user.id, req.body) });
  } catch (e) {
    res.status(400).json({ error: e instanceof Error ? e.message : "Could not save version" });
  }
});

app.delete("/api/versions/:id", (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "Not signed in" });
  if (!removeVersion(user.id, req.params.id)) return res.status(404).json({ error: "Not found" });
  res.json({ ok: true });
});

app.delete("/api/projects/:projectId/versions", (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "Not signed in" });
  removeProjectVersions(user.id, req.params.projectId);
  res.json({ ok: true });
});

// ---------- Full cloud backup (latest snapshot of every project + its imported files) ----------
const backupUser = (req, res) => {
  const user = currentUser(req);
  if (!user) res.status(401).json({ error: "Not signed in" });
  return user;
};

app.get("/api/backup", (req, res) => {
  const user = backupUser(req, res);
  if (!user) return;
  res.json({ projects: listBackups(user.id), usedBytes: usedBytes(user.id), quotaBytes: USER_QUOTA_BYTES });
});

app.get("/api/backup/:projectId", (req, res) => {
  const user = backupUser(req, res);
  if (!user) return;
  const b = getBackup(user.id, req.params.projectId);
  if (!b) return res.status(404).json({ error: "Backup not found" });
  res.json({ backup: b });
});

app.put("/api/backup/:projectId", (req, res) => {
  const user = backupUser(req, res);
  if (!user) return;
  try {
    const { meta, stale } = putBackup(user.id, { ...req.body, projectId: req.params.projectId });
    res.status(stale ? 409 : 200).json({ meta, stale });
  } catch (e) {
    res.status(400).json({ error: e instanceof Error ? e.message : "Could not back up" });
  }
});

app.delete("/api/backup/:projectId", (req, res) => {
  const user = backupUser(req, res);
  if (!user) return;
  removeProjectShares(user.id, req.params.projectId); // a deleted project must not stay viewable by link
  if (!removeBackup(user.id, req.params.projectId)) return res.status(404).json({ error: "Not found" });
  res.json({ ok: true });
});

app.post("/api/backup/assets/missing", (req, res) => {
  const user = backupUser(req, res);
  if (!user) return;
  res.json({ missing: missingAssets(user.id, req.body?.ids) });
});

app.put(
  "/api/backup/assets/:id",
  express.raw({ type: () => true, limit: MAX_ASSET_BYTES }),
  (req, res) => {
    const user = backupUser(req, res);
    if (!user) return;
    try {
      res.json(putBackupAsset(user.id, req.params.id, req.body, req.get("content-type")));
    } catch (e) {
      res.status(400).json({ error: e instanceof Error ? e.message : "Could not store file" });
    }
  }
);

app.get("/api/backup/assets/:id", (req, res) => {
  const user = backupUser(req, res);
  if (!user) return;
  const a = getBackupAsset(user.id, req.params.id);
  if (!a) return res.status(404).json({ error: "File not found" });
  res.type(a.mime).send(a.buf);
});

// ---------- View-only share links (no account needed to open) ----------
app.get("/api/shares", (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "Not signed in" });
  res.json({ shares: listShares(user.id, req.query.projectId ? String(req.query.projectId) : undefined) });
});

app.post("/api/shares", rateLimit(30, 60 * 60 * 1000), (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "Not signed in" });
  try {
    res.status(201).json({ share: putShare(user.id, req.body) });
  } catch (e) {
    res.status(400).json({ error: e instanceof Error ? e.message : "Could not create link" });
  }
});

app.delete("/api/shares/:token", (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "Not signed in" });
  if (!revokeShare(user.id, req.params.token)) return res.status(404).json({ error: "Not found" });
  res.json({ ok: true });
});

// Public: anyone with the link. Read-only, never exposes the owner's id or email.
app.get("/api/s/:token", rateLimit(120, 60 * 60 * 1000), (req, res) => {
  if (!TOKEN_RE.test(req.params.token)) return res.status(404).json({ error: "Link not found" });
  const found = getShare(req.params.token);
  if (!found) return res.status(404).json({ error: "This link is no longer available" });
  const me = currentUser(req);
  const v = recordView(req.params.token, me?.id || req.ip || "anon");
  if (v.counted && me && v.ownerId && v.ownerId !== me.id) {
    notify(v.ownerId, { type: "view", fromUserId: me.id, text: v.name });
  }
  res.setHeader("Cache-Control", "private, no-store");
  res.json({
    name: found.meta.name,
    authorName: getProfile(found.meta.userId)?.name || "",
    updatedAt: found.meta.updatedAt,
    data: found.data,
  });
});

// ---------- Moderation (admins only; configured with OVU_ADMIN_IDS / OVU_ADMIN_EMAILS) ----------
const requireAdmin = (req, res) => {
  const user = currentUser(req);
  if (!user) {
    res.status(401).json({ error: "Not signed in" });
    return null;
  }
  if (!isAdmin(user)) {
    res.status(403).json({ error: "Moderators only" });
    return null;
  }
  return user;
};

app.get("/api/admin/reports", (req, res) => {
  if (!requireAdmin(req, res)) return;
  const status = req.query.status === "resolved" ? "resolved" : "open";
  const groups = listReportGroups({ status }).map((g) =>
    g.targetType === "asset" ? { ...g, target: assetBrief(g.targetId) ?? { missing: true } } : g
  );
  res.json({ groups: groups.slice(0, 200), openCount: openReportCount() });
});

app.post("/api/admin/reports/resolve", (req, res) => {
  const admin = requireAdmin(req, res);
  if (!admin) return;
  const { targetType, targetId, action } = req.body || {};
  const r = resolveReports(admin.id, { targetType, targetId: String(targetId ?? ""), action });
  if (r.error) return res.status(400).json({ error: r.error });
  if (targetType === "asset" && action === "delete") adminRemoveAsset(String(targetId));
  res.json({ ok: true, resolved: r.resolved, openCount: openReportCount() });
});


// ---------- In-app updates: public check + download, admin publishing ----------
const updates = createUpdates({
  dir: path.join(DATA_DIR, "updates"),
  maxBytes: (Number(process.env.OVU_MAX_UPDATE_MB) || 1536) * 1024 * 1024,
});
const updateErr = (res, e) => {
  if (e instanceof UpdateError) return res.status(e.status).set("Connection", "close").json({ error: e.message });
  console.error("[ovu] update error:", e);
  return res.status(500).json({ error: "Update storage error" });
};

app.get("/api/update/latest", (req, res) => {
  res.set("Cache-Control", "no-store");
  res.json(updates.latestFor({ platform: String(req.query.platform ?? ""), current: String(req.query.current ?? "0.0.0") }));
});

app.get("/api/update/download/:platform", (req, res) => {
  const f = updates.downloadFile(req.params.platform);
  if (!f) return res.status(404).json({ error: "No installer published for this platform" });
  res.set("Content-Type", "application/octet-stream");
  res.set("Content-Disposition", `attachment; filename="${f.name}"`);
  res.sendFile(f.path, { cacheControl: false, headers: { "Cache-Control": "no-store" } });
});

app.get("/api/admin/update", (req, res) => {
  if (!requireAdmin(req, res)) return;
  res.json(updates.adminView());
});

app.put("/api/admin/update/draft", (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    res.json(updates.saveDraft(req.body || {}));
  } catch (e) {
    updateErr(res, e);
  }
});

// Raw body (octet-stream) streamed straight to disk: installers are far too big for JSON/base64.
app.put("/api/admin/update/file/:platform", async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    const file = await updates.putFile(req.params.platform, req);
    res.json({ ok: true, file, ...updates.adminView() });
  } catch (e) {
    if (!res.headersSent) updateErr(res, e);
  }
});

app.delete("/api/admin/update/file/:platform", (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    updates.deleteFile(req.params.platform);
    res.json(updates.adminView());
  } catch (e) {
    updateErr(res, e);
  }
});

app.post("/api/admin/update/publish", (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    res.json(updates.publish(req.body || {}));
  } catch (e) {
    updateErr(res, e);
  }
});

app.post("/api/admin/update/unpublish", (req, res) => {
  if (!requireAdmin(req, res)) return;
  res.json(updates.unpublish());
});

// ---------- Real-time collaboration (WebSocket rooms) ----------
const server = createServer(app);
const wss = new WebSocketServer({ server, path: "/collab" });

/** @type {Map<string, Map<WebSocket, { userId: string, name: string, color: string, avatarUrl?: string, spectator?: boolean }>>} */
const rooms = new Map();
/** roomId -> userId of the host (the person who created the invite link) */
const roomHosts = new Map();
/** roomId -> Map<userId, name> of people the host banned */
const roomBans = new Map();
/** roomId -> Set<userId> of people the host muted (they can't send chat) */
const roomMutes = new Map();

const CLOSE_KICKED = 4001;
const CLOSE_BANNED = 4003;
const HOST_GRACE_MS = 15000;

function roomPeers(roomId) {
  const map = rooms.get(roomId);
  if (!map) return [];
  return [...map.values()].filter((p) => !p.spectator).map((p) => ({
    userId: p.userId,
    name: p.name,
    color: p.color,
    avatarUrl: p.avatarUrl,
  }));
}

function broadcast(roomId, data, except = null) {
  const map = rooms.get(roomId);
  if (!map) return;
  const payload = typeof data === "string" ? data : JSON.stringify(data);
  for (const [ws] of map) {
    if (ws !== except && ws.readyState === 1) ws.send(payload);
  }
}

function sendTo(ws, data) {
  if (ws && ws.readyState === 1) ws.send(JSON.stringify(data));
}

/** Finds the socket + metadata of a (non-spectator) person in a room. */
function findEntry(roomId, userId) {
  const map = rooms.get(roomId);
  if (!map) return null;
  for (const [ws, p] of map) {
    if (p.userId === userId && !p.spectator) return [ws, p];
  }
  return null;
}

function hostOf(roomId) {
  return roomHosts.get(roomId) ?? null;
}

/** Sends the host their moderation lists (bans + mutes). Only the host ever receives this. */
function sendModerationState(roomId) {
  const entry = findEntry(roomId, hostOf(roomId));
  if (!entry) return;
  const bans = roomBans.get(roomId) ?? new Map();
  const mutes = roomMutes.get(roomId) ?? new Set();
  sendTo(entry[0], {
    type: "moderation",
    bans: [...bans.entries()].map(([userId, name]) => ({ userId, name })),
    mutes: [...mutes],
  });
}

/**
 * If the host has left (and the grace period has passed without them coming back),
 * the oldest remaining person becomes host.
 */
function electHostIfNeeded(roomId) {
  const map = rooms.get(roomId);
  if (!map) {
    roomHosts.delete(roomId);
    roomBans.delete(roomId);
    roomMutes.delete(roomId);
    return;
  }
  const current = hostOf(roomId);
  if (current && findEntry(roomId, current)) return; // host is still here
  const next = [...map.values()].find((p) => !p.spectator);
  if (!next) {
    roomHosts.delete(roomId);
    return;
  }
  roomHosts.set(roomId, next.userId);
  broadcast(roomId, { type: "host_changed", hostId: next.userId });
  sendModerationState(roomId);
}

/** Host-only moderation: kick, ban, unban, mute, unmute. */
function handleModeration(roomId, ws, meta, msg) {
  if (hostOf(roomId) !== meta.userId) {
    sendTo(ws, { type: "error", message: "Only the host can do that." });
    return;
  }
  const target = String(msg.userId || "");
  if (!target || target === meta.userId) return;
  const targetEntry = findEntry(roomId, target);

  const kick = () => {
    if (!targetEntry) return;
    sendTo(targetEntry[0], { type: "removed", reason: "kicked" });
    targetEntry[0].close(CLOSE_KICKED, "kicked");
  };

  switch (msg.action) {
    case "kick":
      kick();
      break;
    case "ban": {
      if (!roomBans.has(roomId)) roomBans.set(roomId, new Map());
      roomBans.get(roomId).set(target, targetEntry ? targetEntry[1].name : "Guest");
      kick();
      break;
    }
    case "unban":
      roomBans.get(roomId)?.delete(target);
      break;
    case "mute": {
      if (!roomMutes.has(roomId)) roomMutes.set(roomId, new Set());
      roomMutes.get(roomId).add(target);
      if (targetEntry) sendTo(targetEntry[0], { type: "notice", message: "The host muted you. You can't send chat messages." });
      break;
    }
    case "unmute": {
      roomMutes.get(roomId)?.delete(target);
      if (targetEntry) sendTo(targetEntry[0], { type: "notice", message: "The host unmuted you." });
      break;
    }
    default:
      return;
  }
  sendModerationState(roomId);
}

/** Private message. Allowed when the sender is the host, or when the recipient is the host. */
function handlePrivate(roomId, ws, meta, msg) {
  const host = hostOf(roomId);
  const target = String(msg.to || "");
  if (meta.userId !== host && target !== host) {
    sendTo(ws, { type: "error", message: "You can only send private messages to the host." });
    return;
  }
  const text = String(msg.text || "").trim().slice(0, 280);
  if (!text) return;
  const targetEntry = findEntry(roomId, target);
  if (!targetEntry) {
    sendTo(ws, { type: "error", message: "That person left the room." });
    return;
  }
  const payload = {
    type: "dm",
    from: meta.userId,
    fromName: meta.name,
    to: target,
    toName: targetEntry[1].name,
    text,
    at: Date.now(),
  };
  sendTo(targetEntry[0], payload);
  sendTo(ws, payload);
}

wss.on("connection", (ws, req) => {
  const url = new URL(req.url || "", "http://localhost");
  const roomId = url.searchParams.get("room");
  if (!roomId || roomId.length > 64) {
    ws.close(1008, "Invalid room");
    return;
  }

  if (!rooms.has(roomId)) rooms.set(roomId, new Map());
  const room = rooms.get(roomId);
  let meta = null;

  ws.on("message", (raw) => {
    let msg;
    try {
      msg = JSON.parse(String(raw));
    } catch {
      return;
    }
    if (msg.type === "hello" && msg.user?.id) {
      const userId = String(msg.user.id);
      if (roomBans.get(roomId)?.has(userId)) {
        sendTo(ws, { type: "removed", reason: "banned" });
        ws.close(CLOSE_BANNED, "banned");
        return;
      }
      meta = {
        userId,
        name: String(msg.user.name || "Guest").slice(0, 80),
        color: String(msg.color || "#888"),
        avatarUrl: msg.user.avatarUrl,
        // Portal viewers: watch a room read-only, invisible to the people inside it
        spectator: msg.spectator === true,
      };
      // The creator of a brand-new invite link becomes host; otherwise the first person in becomes host
      if (msg.create === true && !roomHosts.has(roomId) && !meta.spectator) roomHosts.set(roomId, userId);
      if (!meta.spectator && !roomHosts.has(roomId)) roomHosts.set(roomId, userId);
      room.set(ws, meta);
      sendTo(ws, { type: "peers", peers: roomPeers(roomId), hostId: hostOf(roomId) });
      if (!meta.spectator) broadcast(roomId, { type: "peer_joined", peer: meta }, ws);
      if (hostOf(roomId) === userId) sendModerationState(roomId);
      return;
    }
    if (!meta) return;
    // Spectators may only ask for the current state.
    if (meta.spectator && msg.type !== "request_state") return;

    switch (msg.type) {
      case "mod":
        handleModeration(roomId, ws, meta, msg);
        return;
      case "dm":
        handlePrivate(roomId, ws, meta, msg);
        return;
      case "chat":
        if (roomMutes.get(roomId)?.has(meta.userId)) {
          sendTo(ws, { type: "notice", message: "You are muted by the host." });
          return;
        }
        broadcast(roomId, msg, ws);
        sendTo(ws, msg); // echo so the sender sees their own line too
        return;
      default:
        broadcast(roomId, msg, ws);
    }
  });

  ws.on("close", () => {
    if (meta && room.has(ws)) {
      room.delete(ws);
      if (!meta.spectator) broadcast(roomId, { type: "peer_left", userId: meta.userId });
      if (room.size === 0) {
        rooms.delete(roomId);
        roomHosts.delete(roomId);
        roomBans.delete(roomId);
        roomMutes.delete(roomId);
      } else if (!meta.spectator && hostOf(roomId) === meta.userId) {
        // Give the host a short grace period to reconnect before handing over the seat
        setTimeout(() => electHostIfNeeded(roomId), HOST_GRACE_MS);
      }
    }
  });
});

server.listen(Number(PORT), () => {
  console.log(`Ovu auth + collab server on ${SERVER_URL}`);
  console.log(`  Google: ${GOOGLE_CLIENT_ID ? "configured" : "NOT configured"}`);
  console.log(`  GitHub: ${GITHUB_CLIENT_ID ? "configured" : "NOT configured"}`);
  console.log(`  WebSocket collab: /collab?room=...`);
});
