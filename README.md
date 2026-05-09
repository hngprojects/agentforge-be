# fastapi-starter

A standard FastAPI + Postgres starter using async SQLAlchemy 2.0, Alembic migrations, and `uv` for dependency management.

---

## Stack

| Layer | Choice |
|---|---|
| Web framework | FastAPI (`fastapi[standard]`) |
| Server | Uvicorn (via `fastapi dev` / `fastapi run`) |
| ORM | SQLAlchemy 2.0 (async) |
| DB driver | `asyncpg` |
| Migrations | Alembic (async-aware) |
| Config | `pydantic-settings` (reads `.env`) |
| Package manager | `uv` |
| Tests | `pytest` + `pytest-asyncio` + `httpx.AsyncClient` |
| Python | 3.13+ |

---

## Project structure

```
fastapi-starter/
├── app/
│   ├── main.py                # FastAPI() instance, mounts the API router
│   ├── core/
│   │   └── config.py          # Settings (env-driven via pydantic-settings)
│   ├── api/
│   │   ├── deps.py            # Shared FastAPI dependencies (DB session, ...)
│   │   └── v1/
│   │       ├── router.py      # Aggregates all v1 endpoint routers
│   │       └── endpoints/
│   │           └── health.py  # Sample DB-backed endpoint
│   ├── db/
│   │   └── session.py         # Async engine + session factory
│   ├── models/                # SQLAlchemy ORM models
│   │   └── base.py            # DeclarativeBase
│   ├── schemas/               # Pydantic request/response models
│   └── services/              # Business logic layer
├── alembic/
│   ├── env.py                 # Wired to app.models.Base.metadata + settings
│   ├── script.py.mako
│   └── versions/              # Migration files land here
├── tests/
│   ├── conftest.py            # AsyncClient fixture
│   └── test_health.py
├── .env.example
├── alembic.ini
├── pyproject.toml
└── uv.lock
```

### Why this layout

- **`app/` package** — keeps imports absolute and clean (`from app.core.config import settings`).
- **`api/v1/`** — versioning is free; add `v2/` later without touching `v1/`.
- **`models` / `schemas` / `services` split** — DB shape, API shape, and business logic stay decoupled. They diverge sooner than you'd think.
- **`db/session.py` separate from `models/`** — engine setup is an infra concern; models are domain. Don't mix them.

---

## Getting started

### 1. Prerequisites

- Python 3.13+
- [uv](https://docs.astral.sh/uv/) (`curl -LsSf https://astral.sh/uv/install.sh | sh`)
- A running Postgres instance (local, Docker, or remote)

### 2. Install

```bash
uv sync
```

This installs both runtime and dev dependencies (`pytest`, `httpx`, etc.).

### 3. Configure

```bash
cp .env.example .env
```

Edit `.env` and set `DATABASE_URL`. The driver **must** be `postgresql+asyncpg`:

```env
DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/fastapi_starter
```

Spin up a local Postgres instance with Docker. Copy and run this:

```bash
docker run -d \
  --name agentforge-db \
  -e POSTGRES_USER=agentforge \
  -e POSTGRES_PASSWORD=agentforge \
  -e POSTGRES_DB=agentforge \
  -p 5432:5432 \
  postgres:15
```

```bash
docker stop agentforge-db
docker start agentforge-db
```

To wipe it and start fresh:

```bash
docker rm -f agentforge-db
```

Your db url becomes: `DATABASE_URL=postgresql+asyncpg://agentforge:agentforge@localhost:5432/agentforge`

### 4. Create the database

```bash
createdb fastapi_starter
# or, with psql:
psql -U postgres -c "CREATE DATABASE fastapi_starter;"
```

### 5. Run migrations

The starter ships with no migrations. Once you add a model, generate the first one:

```bash
uv run alembic revision --autogenerate -m "init"
uv run alembic upgrade head
```

### 6. Start the dev server

```bash
uv run fastapi dev app/main.py
```

Open:

- App root → http://127.0.0.1:8000
- Health check → http://127.0.0.1:8000/api/v1/health
- Swagger UI → http://127.0.0.1:8000/docs
- ReDoc → http://127.0.0.1:8000/redoc

---

## Running tests

```bash
uv run pytest
```

`pytest-asyncio` is set to `auto` mode in `pyproject.toml`, so async tests don't need a decorator. Tests use `httpx.AsyncClient` with `ASGITransport` — no live server required.

---

## Migrations workflow

Migrations are the single source of truth for your schema. Treat them as code: review, commit, and never edit applied ones.

### Typical cycle

```bash
# 1. Edit a model in app/models/
# 2. Generate a migration
uv run alembic revision --autogenerate -m "add user table"

# 3. Open alembic/versions/<hash>_add_user_table.py and REVIEW it.
#    Autogenerate is not perfect — check column types, indexes, defaults.

# 4. Apply
uv run alembic upgrade head
```

### Useful commands

| Command | What it does |
|---|---|
| `alembic revision --autogenerate -m "msg"` | Diff models vs DB and write a migration |
| `alembic revision -m "msg"` | Empty migration (write SQL by hand) |
| `alembic upgrade head` | Apply all pending migrations |
| `alembic upgrade +1` / `downgrade -1` | Step forward/back one revision |
| `alembic current` | Show what's applied |
| `alembic history` | Full migration chain |
| `alembic downgrade base` | Wipe back to empty (dev only) |

### Rules of thumb

- **Always review** the autogenerated file before applying. Alembic misses enum changes, server-side defaults, and some index renames.
- **Never edit a migration after it's been applied** to a shared environment. Write a new one instead.
- **Fill in `downgrade()`**, even if you never plan to run it. It's the cheapest safety net you'll get.
- **Run migrations during deploy, not at app startup**. Run `alembic upgrade head` in CI/CD before booting the new app.
- **Commit `alembic/versions/`** to git so the migration chain stays consistent across machines.

---

## Adding new code

### A new endpoint

1. Create the route module: `app/api/v1/endpoints/users.py`
2. Define an `APIRouter()` and your routes
3. Register it in `app/api/v1/router.py`:

   ```python
   from app.api.v1.endpoints import health, users

   api_router.include_router(users.router, prefix="/users", tags=["users"])
   ```

### A new model

1. Create `app/models/user.py`
2. Subclass `Base` from `app.models.base`
3. Re-export from `app/models/__init__.py` so Alembic discovers it:

   ```python
   from app.models.base import Base
   from app.models.user import User

   __all__ = ["Base", "User"]
   ```

4. Generate + apply a migration

### A new Pydantic schema

Put request/response models in `app/schemas/`. Keep them separate from ORM models — your API shape will not stay identical to your table shape.

### Business logic

Put non-trivial logic in `app/services/`. Endpoints should stay thin: parse input → call a service → return output.

---

## Configuration

All settings live in `app/core/config.py` and are loaded from environment variables (with `.env` as a fallback).

To add a new setting:

```python
class Settings(BaseSettings):
    ...
    REDIS_URL: str
    JWT_SECRET: str
    ACCESS_TOKEN_TTL_MINUTES: int = 30
```

Then add it to `.env.example`. `pydantic-settings` will fail loudly at startup if a required setting is missing — which is what you want.

---

## Conventions

- **Absolute imports only** (`from app.foo import bar`), never relative.
- **Type hints everywhere.** FastAPI uses them for validation and OpenAPI generation.
- **Endpoints return Pydantic models or dicts**, never raw ORM objects.
- **Use `Annotated[..., Depends(...)]`** for dependencies (see `app/api/deps.py`).
- **`async def` everything that touches I/O** (DB, HTTP, files). Sync `def` is fine for pure CPU work.

---
## Linting and Formatting

We use Ruff for both linting and formatting. Rules are pinned in `ruff.toml`.

Check formatting:

```bash
uv run ruff format --check .
```

Auto-fix formatting:

```bash
uv run ruff format .
```

Run lint:

```bash
uv run ruff check .
```

Auto-fix lint where possible:

```bash
uv run ruff check --fix .
```

CI runs format check and lint on every PR. Fix both locally before pushing.

---

## Production notes

The starter is dev-friendly out of the box. Before deploying:

- Replace `fastapi dev` with `fastapi run` (or `uvicorn app.main:app --workers N`).
- Run `alembic upgrade head` as a deploy step, **before** new app instances boot.
- Set `echo=False` on the engine (already the default) and configure pool size to match your worker count.
- Add CORS, request logging, and any middleware you need in `app/main.py`.
- Keep `.env` out of git (already in `.gitignore`); use your platform's secret store in production.
