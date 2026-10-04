# Ovu auth server

Real sign-in for the Ovu app: **Google**, **GitHub**, and **email + password**.
Sessions are stored in an httpOnly cookie (`ovu_session`, 7 days).

## Run it

```bash
cd server
npm install
cp .env.example .env      # then fill in the values
npm run dev               # http://localhost:3000
```

In another terminal, run the React app (`npm run dev` in the project root, http://localhost:5173).

## .env

| Variable | What it is |
| --- | --- |
| `JWT_SECRET` | long random string (`node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"`) |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | from Google Cloud Console |
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | from GitHub OAuth Apps |
| `CLIENT_URL` | where the React app runs (default `http://localhost:5173`) |
| `SERVER_URL` | where this server runs (default `http://localhost:3000`) |

## Callback URLs to register

- Google → Authorized redirect URI: `http://localhost:3000/auth/google/callback`
  (and Authorized JavaScript origin `http://localhost:5173`)
- GitHub → Authorization callback URL: `http://localhost:3000/auth/github/callback`

For production, replace `localhost` with your real domains, set `NODE_ENV=production`
(secure cookies; serve over HTTPS) and add the same URLs in both consoles.

## Endpoints

`POST /auth/register` · `POST /auth/login` · `GET /auth/me` · `POST /auth/logout`
`GET /auth/google` · `GET /auth/google/callback` · `GET /auth/github` · `GET /auth/github/callback`

Users are kept in `users.json` inside the data folder (zero setup). Swap `db.js` for a real
database before going to production.

## Persistent data (REQUIRED in production)
Everything the server stores (`users.json`, `social.json`, cloud versions, ghosts) lives in ONE folder:

1. `OVU_DATA_DIR` if set, else
2. `/data` if it exists (volume mount convention), else
3. `./data` (local dev only).

On a host with an ephemeral disk, a restart/deploy deletes that folder: every user is signed out,
email/password accounts are gone and Google/GitHub users get a new id on next login. Mount a volume and
set `OVU_DATA_DIR=/data`. Ready-made configs: `Dockerfile`, `fly.toml`, `render.yaml`, `railway.json`.

Check it after deploying: open `https://<your-server>/health` -> must show `"persistentStorage":true`,
then restart the service and confirm you are still signed in.

Google/GitHub accounts get an id derived from the provider account, and their session token carries enough
to re-create the account record if `users.json` is ever lost (see `restoreOAuthUser` in `db.js`).
Email/password accounts cannot be restored that way — back up the data folder.


## Installed apps (Electron / Android)
`/auth/google?app=1` and `/auth/github?app=1` are used by the packaged apps: after sign-in the server answers
with a small page that opens `ovu://auth?oauth_token=...`. CORS allows `ovu://app`, `https://localhost` and
`capacitor://localhost` automatically; for those origins the session is also returned in the `X-Ovu-Session`
header and accepted as `Authorization: Bearer <token>` (cross-site cookies are unreliable there). `CLIENT_URL`
may be a comma-separated list for web origins. See `../APP_LOGIN_SETUP.md`.

## Moderators (reports)

Reported works, comments, users and marketplace items are reviewed in the app under
**Settings → Reports** (visible only to moderators). Set one of these on the server:

```
OVU_ADMIN_IDS=<user id>,<user id>        # safest: ids from /auth/me
OVU_ADMIN_EMAILS=you@gmail.com           # only honoured for Google / GitHub sign-ins (email sign-ups are unverified)
```

Three reports hide a work automatically until a moderator dismisses or removes it.

## Share links from the installed apps

Share links must open in a normal browser, so set `CLIENT_URL` to your website address
(e.g. `https://ovu.example.com`). The apps read it from `/health`. For a build-time override use
`VITE_WEB_URL=https://ovu.example.com` when building the client.


## MongoDB persistence (free hosts without a disk)
Set `MONGODB_URI` (and optionally `MONGODB_DB`, default `ovu`). The server keeps using files in the data folder, and mirrors them to MongoDB (GridFS bucket `ovu_files`):
restored on boot, uploaded every ~4 s when something changes, final sync on SIGTERM (every Render deploy).
- Atlas: Database -> Connect -> Drivers -> copy the URI, replace `<password>`; Network Access -> allow `0.0.0.0/0`.
- If MongoDB can't be reached the server still starts, without persistence, and logs `[ovu][mongo] ERROR`. `/health` shows `mongo`.
- Atlas free (M0) is 512 MB: the cloud backups/shares count against it.
