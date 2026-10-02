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

Users are kept in `server/data/users.json` (zero setup). Swap `db.js` for a real
database before going to production.

## Installed apps (Electron / Android)
`/auth/google?app=1` and `/auth/github?app=1` are used by the packaged apps: after sign-in the server answers
with a small page that opens `ovu://auth?oauth_token=...`. CORS allows `ovu://app`, `https://localhost` and
`capacitor://localhost` automatically; for those origins the session is also returned in the `X-Ovu-Session`
header and accepted as `Authorization: Bearer <token>` (cross-site cookies are unreliable there). `CLIENT_URL`
may be a comma-separated list for web origins. See `../APP_LOGIN_SETUP.md`.
