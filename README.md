# Trilha

Security remediation management platform: turns vulnerabilities found on infrastructure assets into
contextualized, prioritized, assigned, remediated, validated and auditable work.

> Status: platform foundation only. No business features yet.

## Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.13, Django 5.2 LTS, Django REST Framework |
| Async | Celery + Redis |
| Database | PostgreSQL 18 (also stores file content) |
| Frontend | Next.js 16, React 19, TypeScript, Tailwind CSS, TanStack Query, Zod |
| Infrastructure | Docker Compose, Nginx reverse proxy |

Modular monolith. Free and open-source components only.

## Running locally

Requirements: Docker (or Podman) with Compose.

```sh
cp .env.example .env
# Replace every "change-me" value, e.g. with:
python3 -c "import secrets; print(secrets.token_urlsafe(64))"
docker compose up --build
```

Open http://localhost:8080. Only the proxy publishes a port, bound to `127.0.0.1` by default.
To reach PostgreSQL and Redis from the host during development, add the override:
`docker compose -f compose.yaml -f compose.dev.yaml up`.

## Development

Backend (requires [uv](https://docs.astral.sh/uv/) and a PostgreSQL instance for tests):

```sh
cd backend
uv sync
uv run pytest            # POSTGRES_HOST / POSTGRES_PORT point to the test database
uv run ruff check . && uv run ruff format --check .
```

Frontend (requires Node.js 24 and pnpm 12):

```sh
cd frontend
pnpm install --frozen-lockfile
pnpm dev                 # pnpm lint | pnpm typecheck | pnpm test | pnpm build
```

## Security baseline

- Every API endpoint is denied unless it explicitly declares its permissions.
- Session authentication only, CSRF enforced, same-origin frontend and API (no CORS).
- Production settings refuse to start with missing or placeholder secrets.
- Containers run as non-root, without capabilities, with read-only filesystems where possible.
- CI runs tests, CodeQL, dependency audits, secret scanning, workflow linting and image scanning.

Production deployments must terminate TLS in front of the proxy; that setup is not provided yet.

## Reporting vulnerabilities

See [SECURITY.md](SECURITY.md).
