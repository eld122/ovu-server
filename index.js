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
import { listGhosts, getGhost, putGhost, deleteGhost, isValidRoom } from "./ghosts.js";
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
import {
  listBackups, getBackup, putBackup, removeBackup, missingAssets, putBackupAsset, getBackupAsset,
  usedBytes, USER_QUOTA_BYTES, MAX_ASSET_BYTES, removeAllBackups,
} from "./backup.js";

const {
  PORT = "3000",
  CLIENT_URL = "http://localhost:5173",
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

// CLIENT_URL may be a comma-separated list (web app origin(s)). The packaged apps are always allowed:
//   ovu://app            -> Electron (Mac / Windows / Linux)
//   https://localhost    -> Android (Capacitor, androidScheme "https")
//   capacitor://localhost-> iOS (Capacitor)
const CLIENT_ORIGINS = CLIENT_URL.split(",").map((s) => s.trim().replace(/\/$/, "")).filter(Boolean);
const PRIMARY_CLIENT = CLIENT_ORIGINS[0] || "http://localhost:5173";
const NATIVE_ORIGINS = ["ovu://app", "https://localhost", "capacitor://localhost"];
const ALLOWED_ORIGINS = new Set([...CLIENT_ORIGINS, ...NATIVE_ORIGINS]);
const APP_DEEP_LINK = "ovu://auth";

const isProd = NODE_ENV === "production";
const SESSION_COOKIE = "ovu_session";
const STATE_COOKIE = "ovu_oauth_state";
const APP_COOKIE = "ovu_oauth_app"; // "1" when the sign-in was started from the packaged app
const SESSION_MS = 7 * 24 * 60 * 60 * 1000;

const app = express();
app.set("trust proxy", 1);
app.use(express.json({ limit: "20mb" }));
app.use(cookieParser());
app.use(
  cors({
    origin(origin, cb) {
      // No Origin header (curl, server-to-server) is fine; browsers must be on the allow-list.
      cb(null, !origin || ALLOWED_ORIGINS.has(origin));
    },
    credentials: true,
    allowedHeaders: ["Content-Type", "Authorization"],
    exposedHeaders: ["X-Ovu-Session"],
  })
);

// ---------- helpers ----------
const cookieBase = { httpOnly: true, sameSite: "lax", secure: isProd, path: "/" };

function startSession(res, user) {
  // Claims let an OAuth session survive a lost users.json (see restoreOAuthUser in db.js).
  const claims = { sub: user.id };
  if (user.provider === "google" || user.provider === "github") {
    Object.assign(claims, { n: user.name, e: user.email, p: user.provider, pid: user.providerId, a: user.avatarUrl ?? undefined });
  }
  const token = jwt.sign(claims, JWT_SECRET, { expiresIn: "7d" });
  res.cookie(SESSION_COOKIE, token, { ...cookieBase, maxAge: SESSION_MS });
  // Packaged apps (Electron / Android WebView) run on a different origin than the API, and
  // browsers/WebViews often drop cross-site cookies. For THOSE origins only, also hand the
  // session token back in a header; the app then sends it as "Authorization: Bearer ...".
  // (Not done for the normal web origin, so the httpOnly cookie stays the only copy there.)
  const origin = res.req?.headers?.origin;
  if (origin && NATIVE_ORIGINS.includes(origin)) res.setHeader("X-Ovu-Session", token);
}

function currentUser(req) {
  const auth = req.headers?.authorization;
  const bearer = typeof auth === "string" && auth.startsWith("Bearer ") ? auth.slice(7).trim() : null;
  const token = bearer || req.cookies?.[SESSION_COOKIE];
  if (!token) return null;
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.purpose) return null; // short-lived bridge tokens are not sessions
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
  if (findByEmail(email)) return res.status(409).json({ error: "An account with this email already exists." });

  const passwordHash = await bcrypt.hash(password, 12);
  const user = createUser({ name, email, passwordHash, provider: "email" });
  startSession(res, user);
  res.status(201).json({ user: publicUser(user) });
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
  res.clearCookie(SESSION_COOKIE, cookieBase);
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
  res.json({ ok: true });
});

app.post("/auth/logout", (_req, res) => {
  res.clearCookie(SESSION_COOKIE, cookieBase);
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
      `<title>Ovu</title><style>body{font-family:system-ui,sans-serif;background:#f6f3ea;color:#1d1d1f;display:flex;` +
      `min-height:100vh;align-items:center;justify-content:center;margin:0;text-align:center}a{display:inline-block;` +
      `margin-top:16px;padding:12px 22px;border-radius:12px;background:#1d1d1f;color:#f6f3ea;text-decoration:none;font-weight:600}</style></head>` +
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
  const user = upsertOAuthUser(profile);
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

// ---------- Global search ----------
app.get("/api/search", (req, res) => {
  const q = String(req.query.q ?? "");
  const { users, works } = searchAll(q);
  res.json({ users, works, assets: listAssets({ q }).slice(0, 24) });
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

app.post("/api/works", express.json({ limit: "20mb" }), (req, res) => {
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

// ---------- Async ghosts (recorded co-op sessions) ----------
app.get("/api/ghosts", (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "Not signed in" });
  const room = String(req.query.room ?? "");
  if (!isValidRoom(room)) return res.status(400).json({ error: "Bad room" });
  res.json({ ghosts: listGhosts(room) });
});

app.get("/api/ghosts/:id", (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "Not signed in" });
  const g = getGhost(req.params.id);
  if (!g) return res.status(404).json({ error: "Ghost not found" });
  res.json({ ghost: g });
});

app.put("/api/ghosts/:id", (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "Not signed in" });
  try {
    res.json({ ghost: putGhost(user, { ...req.body, id: req.params.id }) });
  } catch (e) {
    res.status(400).json({ error: e instanceof Error ? e.message : "Could not save ghost" });
  }
});

app.delete("/api/ghosts/:id", (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "Not signed in" });
  if (!deleteGhost(user, req.params.id)) return res.status(404).json({ error: "Not found" });
  res.json({ ok: true });
});

// ---------- Community asset marketplace (brushes + models + lighting) ----------
app.get("/api/assets", (req, res) => {
  const kind = ["brush", "model", "lighting", "style"].includes(req.query.kind) ? req.query.kind : undefined;
  const sort = ["new", "rating", "popular", "week", "liked"].includes(req.query.sort) ? req.query.sort : "popular";
  const me = currentUser(req);
  res.json({ assets: listAssets({ kind, q: req.query.q, sort, me: me?.id ?? null, onlySaved: req.query.saved === "1" }) });
});

app.post("/api/assets", (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "Not signed in" });
  try {
    res.status(201).json({ asset: createAsset(user, req.body || {}) });
  } catch (e) {
    res.status(400).json({ error: e instanceof Error ? e.message : "Could not publish" });
  }
});

// Counts one download and returns the asset (brush settings / model info).
app.post("/api/assets/:id/download", (req, res) => {
  const me0 = currentUser(req);
  const asset = downloadAsset(req.params.id, me0?.id ?? null);
  if (!asset) return res.status(404).json({ error: "Asset not found" });
  res.json({ asset });
  const me = currentUser(req);
  if (me && asset.authorId && asset.authorId !== "ovu") notify(asset.authorId, { type: "download", fromUserId: me.id, text: asset.name });
});

// Rating 1-5 (+ optional short review). One per user.
app.post("/api/assets/:id/rate", (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "Not signed in" });
  const r = rateAsset(user.id, req.params.id, req.body?.stars, req.body?.review);
  if (!r) return res.status(404).json({ error: "Asset not found" });
  if (r.error) return res.status(400).json({ error: r.error });
  res.json(r);
});
// Likes / saves / comments on assets. Likes and comments notify the author.
app.post("/api/assets/:id/like", (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "Sign in to like" });
  const r = toggleAssetLike(user.id, req.params.id);
  if (!r) return res.status(404).json({ error: "Asset not found" });
  res.json({ asset: r.asset });
  const a = r.asset;
  if (r.added && a.authorId && a.authorId !== "ovu" && a.authorId !== user.id) notify(a.authorId, { type: "like", fromUserId: user.id, text: a.name });
});
app.post("/api/assets/:id/save", (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "Sign in to save" });
  const r = toggleAssetSave(user.id, req.params.id);
  if (!r) return res.status(404).json({ error: "Asset not found" });
  res.json({ asset: r.asset });
});
app.get("/api/assets/:id/comments", (req, res) => {
  const list = listAssetComments(req.params.id);
  if (!list) return res.status(404).json({ error: "Asset not found" });
  res.json({ comments: list });
});
app.post("/api/assets/:id/comments", rateLimit(30, 60 * 60 * 1000), (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "Sign in to comment" });
  const r = addAssetComment(user, req.params.id, req.body?.text);
  if (!r) return res.status(404).json({ error: "Asset not found" });
  if (r.error) return res.status(400).json({ error: r.error });
  res.status(201).json({ comment: r.comment, asset: r.asset });
  if (r.authorId && r.authorId !== "ovu" && r.authorId !== user.id) notify(r.authorId, { type: "comment", fromUserId: user.id, text: `${r.assetName} — ${r.comment.text}` });
});
app.delete("/api/assets/:id/comments/:commentId", (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "Not signed in" });
  const r = removeAssetComment(user.id, req.params.id, req.params.commentId);
  if (!r) return res.status(404).json({ error: "Not found" });
  if (r.error) return res.status(403).json({ error: r.error });
  res.json({ asset: r.asset });
});
app.get("/api/assets/:id/reviews", (req, res) => res.json({ reviews: listReviews(req.params.id) }));

// Raw .glb bytes. Models added to a project point here, so they survive reloads.
app.get("/api/assets/:id/file", (req, res) => {
  const buf = getModelFile(req.params.id);
  if (!buf) return res.status(404).json({ error: "Model not found" });
  res.setHeader("Content-Type", "model/gltf-binary");
  res.setHeader("Cache-Control", "public, max-age=3600");
  res.send(buf);
});

app.delete("/api/assets/:id", (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "Not signed in" });
  if (!removeAsset(user.id, req.params.id)) return res.status(404).json({ error: "Not found" });
  res.json({ ok: true });
});

// ---------- Collections (packs of brushes / lighting / styles / models) ----------
app.get("/api/collections", (req, res) => {
  const me = currentUser(req);
  const scope = req.query.scope === "mine" ? "mine" : "all";
  if (scope === "mine" && !me) return res.status(401).json({ error: "Sign in to see your collections" });
  res.json({ collections: listCollections({ me: me?.id ?? null, scope, q: req.query.q }) });
});
app.post("/api/collections", rateLimit(30, 60 * 60 * 1000), (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "Sign in to create a collection" });
  try {
    res.status(201).json({ collection: createCollection(user, req.body || {}) });
  } catch (e) {
    res.status(400).json({ error: e instanceof Error ? e.message : "Could not create" });
  }
});
app.get("/api/collections/:id", (req, res) => {
  const c = getCollection(req.params.id, currentUser(req)?.id ?? null);
  if (!c) return res.status(404).json({ error: "Collection not found" });
  res.json({ collection: c });
});
app.patch("/api/collections/:id", (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "Not signed in" });
  try {
    const c = updateCollection(user.id, req.params.id, req.body || {});
    if (!c) return res.status(404).json({ error: "Not found" });
    res.json({ collection: c });
  } catch (e) {
    res.status(400).json({ error: e instanceof Error ? e.message : "Could not update" });
  }
});
app.delete("/api/collections/:id", (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "Not signed in" });
  if (!removeCollection(user.id, req.params.id)) return res.status(404).json({ error: "Not found" });
  res.json({ ok: true });
});
app.post("/api/collections/:id/items", (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "Not signed in" });
  const r = addToCollection(user.id, req.params.id, String(req.body?.assetId ?? ""));
  if (!r) return res.status(404).json({ error: "Collection not found" });
  if (r.error) return res.status(400).json({ error: r.error });
  res.json({ collection: r.collection });
});
app.delete("/api/collections/:id/items/:assetId", (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "Not signed in" });
  const r = removeFromCollection(user.id, req.params.id, req.params.assetId);
  if (!r) return res.status(404).json({ error: "Collection not found" });
  res.json({ collection: r.collection });
});
// One-click install: returns every item with its data and counts the downloads.
app.post("/api/collections/:id/download", (req, res) => {
  const me = currentUser(req);
  const c = downloadCollection(req.params.id, me?.id ?? null);
  if (!c) return res.status(404).json({ error: "Collection not found" });
  res.json({ collection: c });
  if (me && c.ownerId !== me.id) notify(c.ownerId, { type: "download", fromUserId: me.id, text: c.name });
});

app.get("/health", (_req, res) => res.json({ ok: true, persistentStorage: DATA_DIR_PERSISTENT, mongo: MONGO_ENABLED ? mongoStatus() : false, webUrl: /^https?:\/\//.test(PRIMARY_CLIENT) ? PRIMARY_CLIENT : null }));

// ---------- Real-time collaboration (WebSocket rooms) ----------
const server = createServer(app);
const wss = new WebSocketServer({ server, path: "/collab" });

/** @type {Map<string, Map<WebSocket, { userId: string, name: string, color: string, avatarUrl?: string }>>} */
const rooms = new Map();

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
      meta = {
        userId: String(msg.user.id),
        name: String(msg.user.name || "Guest").slice(0, 80),
        color: String(msg.color || "#888"),
        avatarUrl: msg.user.avatarUrl,
        // Portal viewers: watch a room read-only, invisible to the people inside it
        spectator: msg.spectator === true,
      };
      room.set(ws, meta);
      ws.send(JSON.stringify({ type: "peers", peers: roomPeers(roomId) }));
      if (!meta.spectator) broadcast(roomId, { type: "peer_joined", peer: meta }, ws);
      return;
    }
    // Relay everything else to the room. Spectators may only ask for the current state.
    if (meta) {
      if (meta.spectator && msg.type !== "request_state") return;
      broadcast(roomId, msg, ws);
    }
  });

  ws.on("close", () => {
    if (meta && room.has(ws)) {
      room.delete(ws);
      if (!meta.spectator) broadcast(roomId, { type: "peer_left", userId: meta.userId });
      if (room.size === 0) rooms.delete(roomId);
    }
  });
});

server.listen(Number(PORT), () => {
  console.log(`Ovu auth + collab server on ${SERVER_URL}`);
  console.log(`  Google: ${GOOGLE_CLIENT_ID ? "configured" : "NOT configured"}`);
  console.log(`  GitHub: ${GITHUB_CLIENT_ID ? "configured" : "NOT configured"}`);
  console.log(`  WebSocket collab: /collab?room=...`);
});
