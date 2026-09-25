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

The blueprint already sets:

- `ENVIRONMENT=production`
- `CORS_ORIGINS=https://frontend-two-alpha-51.vercel.app`
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

Set the production environment variable:

`VITE_API_URL=https://<your-render-service>.onrender.com`

Do not put the backend URL in source code.

After saving environment variables, redeploy the frontend.

## 4. CORS

The backend must allow the exact production frontend origin:

`https://frontend-two-alpha-51.vercel.app`

If the Vercel production domain changes, update Render's `CORS_ORIGINS` value and redeploy/restart the backend.

For multiple trusted origins, provide a comma-separated list.

## 5. Database initialization

MailGuard currently creates its SQLAlchemy tables at application startup. After the first successful PostgreSQL connection, verify registration/login and a prediction request.

A migration framework such as Alembic should be added before making schema changes in a long-lived production environment.

## 6. Smoke-test checklist

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
