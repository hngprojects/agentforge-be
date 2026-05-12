# AgentForge BE Postman Pack

This pack is for local backend testing against `http://localhost:8000`.

## Files

- `agentforge-be-local.postman_collection.json`
- `agentforge-be-local.postman_environment.json`

## Local setup

Run the backend first:

```powershell
uv sync
uv run alembic upgrade head
uv run fastapi dev app/main.py
```

Current `dev` uses Brevo for verification emails. Add these values to `.env` before starting the app:

```env
BREVO_API_KEY=your-brevo-api-key
SMTP_FROM_NAME=Agent Forge
SMTP_FROM_EMAIL=verified-sender@example.com
```

Import both Postman files, then select the `AgentForge BE - Local` environment.

## Recommended flow

1. Run `GET /health`.
2. Run `POST /auth/register`.
3. Verify the user before password login.
4. Run `POST /auth/login`.
5. Run `GET /auth/me`.
6. Run `POST /auth/refresh`.
7. Run `POST /auth/logout`.

The current email service sends verification emails through Brevo and intentionally does not print verification or reset tokens. For pure local testing without delivery access, either supply a real token manually in the environment or mark the test user verified in your local database:

```powershell
psql "postgresql://agentforge:agentforge@localhost:5432/agentforge" -c "update users set email_verified = true where email = 'postman.local@example.com';"
```

## Cookie notes

The refresh token is stored as an HttpOnly cookie on `/api/v1/auth`. Postman should keep it in its cookie jar after `POST /auth/login`, then send it automatically for `POST /auth/refresh` and `POST /auth/logout`.

Use the same host consistently. The current local OAuth defaults use `localhost`; mixing `localhost` and `127.0.0.1` creates separate cookie jars and can also mismatch provider redirect URIs.

## OAuth notes

The Google and GitHub start requests have redirects disabled in the collection. Run the start request first; it stores the provider authorization URL and state variables in the environment.

Manual callback testing requires a real provider `code`:

1. Run the provider start request.
2. Copy the generated `*_authorize_url` from the environment and complete provider login in a browser.
3. Copy the returned `code` into `google_code` or `github_code`.
4. Run the matching callback request.

For GitHub, configure the local OAuth app callback URL to:

```text
http://localhost:8000/api/v1/auth/github/callback
```

If the team changes the agreed callback flow to frontend-first, keep the frontend callback in the provider app and use the backend callback request here only for direct backend smoke tests.
