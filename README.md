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

## Accounts

There is no sign-up and no email. An operator manages accounts with audited commands in the backend
container:

```sh
# Create an account. Prints a one-time link where its owner sets a password.
docker compose exec backend python manage.py accounts_create_user alice --first-name Alice
# Print a new link for an account whose owner forgot the password.
docker compose exec backend python manage.py accounts_password_link alice
# Disable an account: its password is removed and every session ends.
docker compose exec backend python manage.py accounts_disable_user alice
# Re-enable it: prints a setup link; the old password never comes back.
docker compose exec backend python manage.py accounts_enable_user alice
```

- Usernames are lowercase ASCII: `a-z`, `0-9` and `. _ @ + -`.
- Commands that issue a link print a JSON log line (no secrets), the link, and a delivery reminder.
- Send links only through an authorized internal channel.
  - A link works once and expires after one hour; set `DJANGO_PASSWORD_RESET_TIMEOUT` to change this
    (300-86400 seconds).
  - Links start with `TRILHA_BASE_URL`.
- `createsuperuser` and `changepassword` are disabled because they bypass the audit trail.
- Sessions last at most 8 hours and end when the browser closes. Remove expired sessions daily, for
  example from cron: `docker compose exec -T backend python manage.py clearsessions`.

## Teams and roles

Access is granted per team: a user sees a team only through a role assigned in that team, and a role
held in one team never grants anything in another. Existing users start with no access. Configure it
with audited commands in the backend container:

```sh
# Create a team (it starts inactive) and a reusable role, then give the role a permission.
docker compose exec backend python manage.py teams_create soc --name "Security Operations"
docker compose exec backend python manage.py rbac_create_role reader --name Reader
docker compose exec backend python manage.py rbac_grant_permission reader teams.view_team
# Add a member and assign the role in that team.
docker compose exec backend python manage.py teams_add_member soc alice
docker compose exec backend python manage.py rbac_assign_role soc alice reader
# Activate: prints what will be restored and asks you to type the team code.
docker compose exec backend python manage.py teams_activate soc
```

- Revoke with `rbac_revoke_role`, `rbac_revoke_permission`, `teams_remove_member` or
  `teams_deactivate`. Changes apply to the next request; users stay signed in.
- Removing a member drops their role assignments. Adding them again starts with no roles.
- Deactivating keeps the configuration. Reactivating restores it: review the printed counts before
  you confirm. Activation needs an interactive terminal (do not pass `-T`) and has no `--yes`.
- A role is shared: changing its permissions changes them in every team that assigns it.
- Inspect with `teams_list`, `teams_members <team>`, `rbac_list_roles` and `rbac_list_permissions`.
- Users see their own access at `/account/access`.

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

Only local use is supported so far. Running Trilha on a network needs TLS for every connection to
the proxy and separate database owner and runtime roles. Both are planned and not provided yet.

## Reporting vulnerabilities

See [SECURITY.md](SECURITY.md).
