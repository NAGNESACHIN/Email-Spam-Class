# MailGuard AI — Production Deployment

This project is split into a Vercel-hosted React frontend, a containerized FastAPI backend, and PostgreSQL.

## Target deployment

- Frontend: Vercel
- Backend: Render (Docker)
- Database: Neon PostgreSQL
- Optional URL reputation: VirusTotal

The repository includes `render.yaml` as a deployment blueprint. Secrets are intentionally not stored in Git.

## 1. Neon PostgreSQL

Create a Neon PostgreSQL database and copy its standard PostgreSQL connection string into the backend's `DATABASE_URL` environment variable.

For a production API, prefer Neon's pooled connection URI when your deployment uses multiple concurrent connections.

Do not commit the connection string because it contains database credentials.

## 2. Render backend

Create a Render Blueprint/Web Service from this repository using `render.yaml`.

Set these secret values in Render:

- `DATABASE_URL` = your Neon PostgreSQL connection string
- `JWT_SECRET` = a unique random secret of at least 32 characters
- `VIRUSTOTAL_API_KEY` = optional
- `REDIS_URL` = optional shared Redis URL for multi-instance rate limiting

Authentication sessions are issued as HttpOnly, Secure, SameSite cookies in production. Do not expose JWT values to the frontend or store them in browser storage.

The blueprint already sets:

- `ENVIRONMENT=production`
- `FRONTEND_URL=https://email-spam-class.vercel.app`
- explicit Vercel CORS configuration
- optional Google, Yahoo, and Microsoft OAuth configuration
- `RDAP_LOOKUP_ENABLED=true`
- authentication throttling
- PostgreSQL pool settings
- `/health` as the health-check endpoint

After deployment, verify:

`https://<your-render-service>.onrender.com/health`

Expected response contains:

`{"status":"ok", ...}`

## 3. Vercel frontend

Import this GitHub repository into Vercel.

Set the Vercel **Root Directory** to:

`frontend`

Production uses the Vercel same-origin `/api` proxy defined in `frontend/vercel.json`, which routes API requests to the Render backend. No production `VITE_API_URL` value is required.

After saving frontend settings, redeploy the frontend.

## 4. Google, Yahoo, and Microsoft SSO

The backend implements OAuth/OIDC authorization-code flows with server-side client secrets and a short-lived, one-time exchange code. Provider credentials must be stored only in Render.

### Google

Create a Web application OAuth client in Google Cloud Console. Add this exact authorized redirect URI:

`https://mailguard-ai-api.onrender.com/auth/google/callback`

Set in Render:

- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `GOOGLE_REDIRECT_URI` = the callback URL above

The application requests the `openid email profile` scopes and uses Google's userinfo endpoint after exchanging the authorization code. Google requires the redirect URI to exactly match a registered URI. citeturn185304search0

### Yahoo

Create an application in the Yahoo Developer Network and register this exact redirect URI:

`https://mailguard-ai-api.onrender.com/auth/yahoo/callback`

Set in Render:

- `YAHOO_CLIENT_ID`
- `YAHOO_CLIENT_SECRET`
- `YAHOO_REDIRECT_URI` = the callback URL above

The implementation uses Yahoo's authorization-code flow and UserInfo endpoint with OpenID Connect scopes. Yahoo documents the authorization endpoint at `https://api.login.yahoo.com/oauth2/request_auth`, the token endpoint at `https://api.login.yahoo.com/oauth2/get_token`, and the UserInfo endpoint at `https://api.login.yahoo.com/openid/v1/userinfo`. citeturn185304search3turn185304search1

### Microsoft

Create a Microsoft Entra app registration and add this exact Web redirect URI:

`https://mailguard-ai-api.onrender.com/auth/microsoft/callback`

Set in Render:

- `MICROSOFT_CLIENT_ID`
- `MICROSOFT_CLIENT_SECRET`
- `MICROSOFT_TENANT=common`
- `MICROSOFT_REDIRECT_URI` = the callback URL above

The implementation uses the Microsoft identity platform authorization-code flow and the UserInfo endpoint. Microsoft documents `https://graph.microsoft.com/oidc/userinfo` as the UserInfo endpoint and supports the `common` tenant for multi-account sign-in scenarios. citeturn161741search0turn878762search2

Do not paste client secrets into GitHub, Vercel, frontend code, or chat.
## 5. CORS

The blueprint allows the canonical Vercel production origin and a narrow preview-domain regex. Keep the trusted-origin configuration explicit; do not use `*` with credentials.

For multiple trusted origins, provide a comma-separated list.

## 6. Database initialization and migrations

MailGuard bootstraps the current schema with SQLAlchemy metadata. Alembic is now included for reviewed schema evolution. For a fresh database, run `alembic upgrade head`. For the existing Neon database created by previous deployments, first run `alembic stamp 0001_baseline`, then `alembic upgrade head` to apply the hardening migration. Review the target database before applying foreign-key constraints.

## 7. Performance and production notes

- Batch prediction writes are committed as one database transaction rather than once per message.
- If `REDIS_URL` is configured, API/auth throttling is shared across backend instances; otherwise the service uses an in-process limiter.
- Analytics uses SQL aggregation and only fetches the latest 20 scans.
- CSV imports accept quoted/multiline RFC-style fields and support common message column names.
- Docker uses a separate model-builder stage so the runtime image does not contain the ML training toolchain.
- Local model training is explicit with `python run.py --train`; normal API startup no longer retrains the model.

## 8. Smoke-test checklist

1. Open the Vercel frontend.
2. Register a new account.
3. Log in.
4. Submit a test message.
5. Confirm prediction/history works.
6. Upload a safe test `.eml` file.
7. Test URL intelligence with a benign URL.
8. Open the analytics/evaluation pages.
9. Check Render logs for startup/database errors.
10. Confirm `/health` remains healthy.

## Security rules

- Never commit `DATABASE_URL`, `JWT_SECRET`, or API keys.
- Use HTTPS for both frontend and backend.
- Keep `CORS_ORIGINS` explicit.
- Keep VirusTotal optional and secret-managed.
- Do not execute uploaded attachments.
- Do not fetch arbitrary user-controlled URLs server-side.
- Use a shared rate-limit store such as Redis when running multiple backend instances.
