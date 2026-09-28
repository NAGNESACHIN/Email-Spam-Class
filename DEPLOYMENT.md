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
OAuth/OIDC is implemented as a backend-driven authorization-code flow. The browser never receives provider access tokens, ID tokens, refresh tokens, or a MailGuard bearer token. After a successful callback, the backend creates the same production HttpOnly session cookie used by password login.

The public callback origin is the Vercel application, and Vercel rewrites `/api/*` to the Render API. Register these exact callback URIs with the providers:

- Google: `https://email-spam-class.vercel.app/api/auth/google/callback`
- Yahoo: `https://email-spam-class.vercel.app/api/auth/yahoo/callback`
- Microsoft: `https://email-spam-class.vercel.app/api/auth/microsoft/callback`

Before entering production credentials, verify that the Render environment contains the matching `*_CLIENT_ID`, `*_CLIENT_SECRET`, and `*_REDIRECT_URI` values. Keep all provider secrets in Render; never put them in Vercel frontend variables or source control.

### OAuth/OIDC security flow

Each authorization attempt creates a short-lived database transaction containing a SHA-256 state hash, browser-binding hash, PKCE challenge where supported, OIDC nonce hash, exact redirect URI, and expiry. The raw transaction values are held only in short-lived HttpOnly Secure SameSite cookies in production.

Google and Microsoft use PKCE with `S256`. Yahoo uses its documented authorization-code/OIDC flow with cryptographically browser-bound `state` and a required `nonce`; PKCE should not be enabled for Yahoo until its provider configuration explicitly advertises support for it.

At callback, MailGuard validates the transaction and consumes it once, exchanges the code server-to-server, then validates the returned OIDC ID token signature using the provider's trusted JWKS. Validation includes issuer, audience, authorized party when present, expiration/timestamps, subject, and nonce. Microsoft `common` sign-in additionally binds the issuer to the signed tenant identifier.

OAuth identities are keyed by provider + issuer + subject. Email is an account attribute, not the stable OAuth identity key. A new OAuth identity is not automatically merged with an existing password account that happens to use the same email; explicit account-linking can be added later.

The callback finishes with a `303` redirect to the fixed `FRONTEND_URL#details` location and sets the normal MailGuard session cookie. There is no frontend `oauth_code` exchange endpoint and no OAuth token storage in localStorage or sessionStorage.

### Google
Create a Web application OAuth client in Google Cloud Console. Register the exact Vercel callback URI above. Set:
- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `GOOGLE_REDIRECT_URI=https://email-spam-class.vercel.app/api/auth/google/callback`

### Yahoo
Create a Yahoo application and register the exact Vercel callback URI above. Set:
- `YAHOO_CLIENT_ID`
- `YAHOO_CLIENT_SECRET`
- `YAHOO_REDIRECT_URI=https://email-spam-class.vercel.app/api/auth/yahoo/callback`

### Microsoft
Create a Microsoft Entra app registration and register the exact Vercel Web redirect URI above. Set:
- `MICROSOFT_CLIENT_ID`
- `MICROSOFT_CLIENT_SECRET`
- `MICROSOFT_TENANT=common`
- `MICROSOFT_REDIRECT_URI=https://email-spam-class.vercel.app/api/auth/microsoft/callback`

Use authorization code + OIDC. For a `common` tenant configuration, the callback validator checks the signed `tid` claim and requires the ID token issuer to be the corresponding `https://login.microsoftonline.com/{tid}/v2.0` issuer.
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
