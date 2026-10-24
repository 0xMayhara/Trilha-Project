# Trilha

Security remediation management platform: turns vulnerabilities found on infrastructure assets into
contextualized, prioritized, assigned, remediated, validated and auditable work.

> Status: local use only. Implemented: accounts and session sign-in, team-scoped access, the asset
> inventory and platform administration. Findings and remediation workflows come next.

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

Requirements: Docker with Compose, or Podman with `podman-compose`. Every `docker compose` command in
this README works the same with `podman-compose`.

```sh
cp .env.example .env
# Replace every "change-me" value (all passwords must differ), e.g. with:
python3 -c "import secrets; print(secrets.token_urlsafe(64))"
# AUDIT_DIGEST_KEYS needs its own format (id:32 random bytes in base64url); .env.example shows how.
# Recommended: pin the Compose project so every command targets the same volumes.
echo "COMPOSE_PROJECT_NAME=trilha" >> .env
docker compose up --build -d
```

Open http://localhost:8080. Only the proxy publishes a port, bound to `127.0.0.1` by default.

- Use the host name in `NGINX_SERVER_NAME` (default `localhost`). The proxy drops requests for any
  other name, so http://127.0.0.1:8080 shows nothing.
- To reach PostgreSQL and Redis from the host during development, add the override:
  `docker compose -f compose.yaml -f compose.dev.yaml up`.

### Updating, stopping and data

```sh
git pull
docker compose up --build -d     # rebuild the images; the migrate service applies new migrations first
docker compose logs migrate      # check which migrations ran
docker compose logs -f backend   # follow one service
docker compose down              # stop and remove the containers; database and Redis volumes stay
```

- With `podman-compose`, run `down` and then `up -d` after a rebuild so every container uses the new
  images.
- `down -v` deletes the volumes: every account, team, asset and audit event is lost. Do not use it
  unless that is what you want.

## Database roles, backups and recovery

PostgreSQL uses three roles (SPEC-0013):

| Role | Used by | Can |
|---|---|---|
| `postgres` (superuser) | the `db` container only: provisioning, backups | everything |
| `POSTGRES_USER` (schema owner, `trilha`) | the `migrate` service only | own the schema, run migrations, grant the runtime role |
| `POSTGRES_RUNTIME_USER` (`trilha_app`) | `backend`, `worker`, management commands | read and write application rows; insert and read audit events and logbook entries; edit findings but never delete them. No DDL, no `TRUNCATE`, no changes to audit events or logbook entries, no other databases |

- The `migrate` service runs `manage.py db_migrate`: migrations as the owner, then the runtime role's
  grants from `backend/apps/core/db_privileges.py`.
- **Every table must be classified there.** A migration that adds a table without classifying it
  makes `migrate` fail, and the stack does not start.
- `backend` and `worker` report unhealthy if they connect with any privileged role.
- Provisioning also stops PostgreSQL from logging the text or row content of the runtime role's
  failed statements (they could quote a comment). Re-run it after upgrading to apply this.

**What this does not do:**

- The schema owner and the superuser can still change history.
- The runtime role can insert events; it cannot change or delete them.
- Nothing here makes the audit trail tamper-proof.

### Upgrading an installation created before role separation (one-time)

**1. Identify the deployment.** Nothing is guessed from the current directory: the project name
selects the volumes.

```sh
podman ps --filter label=com.docker.compose.service=db --format '{{.Names}} {{.Labels}}'
# Note the com.docker.compose.project value of the running db, for example trilha.
```

**2. Back up, then prove the backup restores**, with the stack still running:

```sh
deploy/postgres/backup.sh --project <project> ~/trilha-backups
deploy/postgres/restore-verify.sh ~/trilha-backups/trilha-<UTC>.dump   # must end with RESULT: PASS
```

**3. Configure.** In `.env`:

- set `COMPOSE_PROJECT_NAME=<project>`;
- add `POSTGRES_RUNTIME_USER=trilha_app` and a new `POSTGRES_RUNTIME_PASSWORD`;
- set a **new** `POSTGRES_PASSWORD`. The old one was visible to `backend` and `worker`.

**4. Apply** (maintenance window, a few minutes). Volumes are kept, and `down -v` is never used:

```sh
git pull && docker compose build
docker compose down
docker compose up -d db
docker compose exec -T db sh /docker-entrypoint-initdb.d/01-provision.sh   # roles, passwords, database grants
docker compose up -d                                                          # db_migrate applies table grants
```

**5. Verify:**

```sh
docker compose ps                                              # every service healthy
docker compose exec backend python manage.py check_ready       # "ready": restricted role in use
docker compose logs migrate | grep db_grants                   # db_grants_applied or db_grants_unchanged
```

Then sign in, edit an asset and open the audit trail.

Provisioning is idempotent and never changes an owner. If the database belongs to a different role,
it stops without changing anything.

### Upgrading to the findings release (SPEC-0007 slice B)

1. Back up and verify (`backup.sh`, then `restore-verify.sh` until `RESULT: PASS`), as above.
2. Add `AUDIT_DIGEST_KEYS` and `AUDIT_DIGEST_ACTIVE_KEY_ID` to `.env` (see
   [Audit digest keys](#audit-digest-keys)). The backend does not start without them.
3. Apply:

   ```sh
   git pull && docker compose build
   docker compose up -d db
   docker compose exec -T db sh /docker-entrypoint-initdb.d/01-provision.sh   # runtime-role log settings
   docker compose up -d                                                          # findings tables and grants
   ```

### Rollback

**Rollback below the findings release.** The previous release's `db_migrate` refuses tables it does
not know, so park them first. Rows, constraints and the append-only trigger are kept; while parked,
nothing but the owner can read them. Each run needs the owner's go-ahead.

```sh
deploy/postgres/backup.sh --project <project> ~/trilha-backups   # then restore-verify.sh: PASS
docker compose stop backend worker
docker compose exec -T db sh -s park findings < deploy/postgres/park-tables.sh
# check out the previous release, restore its .env, then:
docker compose up --build -d
```

To roll forward again: `docker compose stop backend worker`, then
`docker compose exec -T db sh -s unpark findings < deploy/postgres/park-tables.sh`, then deploy this
release (`up --build -d`); its `db_migrate` re-applies the tables' grants. The script refuses unknown
slices and half-parked states without changing anything, and repeating it is harmless. Backups taken
while parked include the parked tables, and `restore-verify.sh` checks that they stay private.

**Application rollback.** Check out the previous release and restore its `.env`. If you rotated the
owner password, put the **new** value in `POSTGRES_PASSWORD`, because the previous release connects
as the owner. Then run `docker compose down && docker compose up -d`. No data or owner changed during
the upgrade, so nothing needs restoring.

**Optional privilege rollback**, after the application rollback:

```sh
docker compose exec -T db sh -s < deploy/postgres/rollback-runtime-role.sh
```

It removes `trilha_app` and its privileges and changes no data.

### Backups

```sh
deploy/postgres/backup.sh --project <project> <directory-outside-the-repository>
```

- **Output:** `trilha-<UTC>.dump` (`pg_dump` custom format), plus `.manifest` (owner, grants and row
  count per table) and `.sha256`, all mode 0600.
- **Sessions are not backed up:** after a restore, everyone signs in again.
- **The file holds everything else**, including password hashes and the audit trail. Keep backups in
  an owner-only directory on encrypted storage. Keep the last 7 daily backups, plus every pre-upgrade
  backup until a newer verified one exists.
- **Checksums:** `.sha256` detects corruption, **not tampering**. Anyone who can change the dump can
  change it too. Record the checksum somewhere else, or sign it (`gpg --detach-sign`).
- **Off the host:** copies should be encrypted first (`gpg --symmetric`), stored with access limited
  to operators, and restore-tested periodically. Nothing uploads backups automatically.
- **Daily example (cron):**
  `15 3 * * * cd /srv/trilha && deploy/postgres/backup.sh --project trilha /srv/trilha-backups`

### Verifying and restoring a backup

- `deploy/postgres/restore-verify.sh <dump>` restores into a throwaway PostgreSQL container with no
  network and no volume, then removes it. It checks the checksum, migration state, owners, grants,
  row counts, the audit trigger and the runtime role's restrictions, and prints `PASS`/`FAIL` per
  check.
- **Into a new installation:**
  1. Prepare `.env`, then `docker compose up -d db` only.
  2. `docker compose exec -T db pg_restore -U postgres -d trilha --exit-on-error < trilha-<UTC>.dump`
  3. `docker compose up -d`. `db_migrate` re-applies grants and any newer migrations.
- **After data loss on an existing installation:**
  1. Back up the damaged state first.
  2. `docker compose down`, then `docker compose up -d db`.
  3. As `postgres`, rename the damaged database rather than dropping it:
     `ALTER DATABASE trilha RENAME TO trilha_damaged_<date>;`
  4. Create an empty one, `CREATE DATABASE trilha OWNER trilha;`, and re-run provisioning.
  5. `pg_restore` as above, then `docker compose up -d`.
  6. Delete the renamed database only once you are satisfied.

### Audit digest keys

Audit events never hold finding descriptions or comments, only a keyed digest (HMAC-SHA256) that
proves the stored text has not changed. The keys live only in the backend's environment, apart from
`DJANGO_SECRET_KEY`:

- `AUDIT_DIGEST_KEYS`: comma-separated `id:key` pairs; each key is 32 random bytes in base64url.
  `AUDIT_DIGEST_ACTIVE_KEY_ID` names the one that signs.
- **Rotate** by appending a new pair and switching the active ID. Keep the old pairs as long as the
  audit events they signed are kept; removing one is an owner decision.
- **Back them up** with the other deployment secrets, separately from database dumps. A lost key does
  not lose data; its digests just become unverifiable.
- **Verify** (read-only, prints counts only):
  `docker compose exec backend python manage.py verify_logbook_digests [--finding <uuid>]`. A digest
  whose key is no longer configured is reported as unverifiable, never as a mismatch.

### Emergency logbook redaction

Logbook entries cannot be edited or deleted, by anyone, through the application. For a pasted secret
or sensitive personal data there is one owner-controlled procedure, run by the infrastructure operator
with the schema-owner credential:

1. **Ticket:** record the owner's decision. For a secret, **rotate it first**: redaction does not
   undo exposure.
2. **Dry run** (prints the entry ID, kind, author, time and length, never the content):
   `docker compose run --rm migrate python manage.py redact_logbook_entry --finding <uuid> --sequence <n> --reason secret|personal_data --ticket <ref>`
3. **Execute:** the same command with `--execute`. It blanks the content once, adds a visible
   "removed by the platform owner" notice to the logbook and records an audit event. Open browser
   tabs drop the content at their next refresh.
4. **New verified backup**, then decide (in the ticket) what to do with older dumps, snapshots and
   off-site copies: they still hold the content.
5. **Optional, announced maintenance window:** `VACUUM (FULL) findings_findinglogentry; CHECKPOINT;`
   as `postgres`. It blocks every logbook read while it runs.

This is not secure erasure: copies can survive in WAL segments, old table files on the disk, dumps,
volume snapshots and PostgreSQL logs from before the runtime-role log settings.

### Rotating database passwords

Edit `.env`, then:

```sh
docker compose up -d db
docker compose exec -T db sh /docker-entrypoint-initdb.d/01-provision.sh
docker compose up -d
```

### First sign-in

1. Start the stack as above.
2. Create your account. The command prints a one-time link:
   `docker compose exec backend python manage.py accounts_create_user alice --first-name Alice`
3. Open the link in the browser and choose a password.
4. Make the account a platform Admin:
   `docker compose exec backend python manage.py rbac_grant_admin alice`
5. Log in at http://localhost:8080/login. "Administration" appears in the header.

**Forgot your password?** Print a new one-time link and open it:
`docker compose exec backend python manage.py accounts_password_link alice`. Setting the new password
ends every other session of that account.

## Accounts

There is no sign-up and no email. Platform Admins manage accounts at `/admin/users` (see
[Administration](#administration)); the operator can do the same with audited commands in the backend
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

## Administration

A platform Admin manages users, teams, memberships, roles, positions and other Admins at `/admin`, and
searches the audit trail at `/admin/audit`. Admin is an explicit grant, not a Django flag, a group or a
team role.

```sh
# Bootstrap the first Admin (no Admin exists after installation, and there is no web sign-up).
docker compose exec backend python manage.py accounts_create_user alice --first-name Alice
docker compose exec backend python manage.py rbac_grant_admin alice
# Operational position: analyst, engineer or none. A position grants no permission by itself.
docker compose exec backend python manage.py rbac_set_position alice engineer
# Revoke Admin authority. At least one other enabled Admin must remain.
docker compose exec backend python manage.py rbac_revoke_admin bob
```

- Every administrative change in the web UI asks for your password if you have not confirmed it in the
  last 10 minutes. Confirming starts a fresh session key and restarts the 8-hour session lifetime.
- An Admin cannot revoke their own grant or disable their own account, and the last enabled Admin can
  never be revoked or disabled, from the web UI or the commands.
- Disabling an account removes its Admin grant. Enabling it again never restores it: grant it anew.
- Admins read every team's assets but change them only through ordinary team roles.
- Administrative changes are limited per user (`DJANGO_THROTTLE_ADMIN_WRITE_RATE`, default `60/min`).
  Password confirmations share the password-change budget (`DJANGO_THROTTLE_PASSWORD_CHANGE_RATE`).
- Password links created in the web UI (new user, enable, "Issue password link") are shown once.
  Copy the link before you choose Done; it is not stored anywhere.
- A new team starts inactive. Open it under Administration > Teams, choose "Review activation", check
  the counts and type the team code to activate it.
- Positions (Analyst, Engineer) are set on the user's page. They grant no access by themselves: team
  roles do.
- The audit trail search matches filters exactly (action, actor ID, resource type and ID, outcome,
  source). Without dates it shows the last 30 days; one search covers at most 366 days.

**Recovery** when no Admin can sign in (lost password or disabled account): issue a link with
`accounts_password_link <admin>`, or `accounts_enable_user <admin>` followed by `rbac_grant_admin <admin>`.
To replace an Admin, create and grant the new one first, then `rbac_revoke_admin` or
`accounts_disable_user` the old one.

## Teams and roles

Access is granted per team: a user sees a team only through a role assigned in that team, and a role
held in one team never grants anything in another. Existing users start with no access. Configure it
at `/admin/teams` and `/admin/roles`, or with audited commands in the backend container:

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

## Assets

Each asset belongs to exactly one team. A team's assets are managed at `/assets` by members whose
role in that team holds the asset permissions. Every action also needs `assets.view_asset`:

| Permission | Allows |
|---|---|
| `assets.view_asset` | List, search and read the team's assets, including retired ones |
| `assets.add_asset` | Register assets in the team |
| `assets.change_asset` | Edit an active asset's attributes |
| `assets.retire_asset` | Retire an asset, or restore a retired one |
| `assets.transfer_asset` | Move an asset to another team; needed in **both** teams |

```sh
# A role that can manage the soc team's inventory.
docker compose exec backend python manage.py rbac_create_role asset-manager --name "Asset manager"
for code in view_asset add_asset change_asset retire_asset transfer_asset; do
  docker compose exec backend python manage.py rbac_grant_permission asset-manager "assets.$code"
done
docker compose exec backend python manage.py rbac_assign_role soc alice asset-manager
```

- Assets are never deleted. Retire an asset instead; it stays readable through the "Retired" filter.
- An asset name is unique among the team's active assets (case-insensitive). Hostnames and IP
  addresses are attributes, not identities, and may repeat.
- Asset changes are limited per user (`DJANGO_THROTTLE_ASSET_WRITE_RATE`, default `60/min`).
- Security posture is declared by the team and edited like any other attribute: criticality,
  environment, hardening (hardened, partially hardened, not hardened) and internet exposure
  (exposed, not exposed). An empty value means *not assessed* (criticality, hardening) or *unknown*
  (exposure). It is never read as a negative answer, and Trilha does not verify declared values.

## Findings

A finding is a security issue reported on one asset. It belongs to the asset's **current** team: it
moves when the asset moves, and only that team's members (with the permissions below) see it. Admins
read every finding but change none through Admin authority.

| Permission | Allows |
|---|---|
| `findings.view_finding` | List and read the team's findings and their logbooks |
| `findings.add_finding` | Report a finding on an active asset (also needs `assets.view_asset`) |
| `findings.change_finding` | Edit title, description, category, severity and CVE IDs |
| `findings.comment_finding`, `findings.work_finding`, `findings.override_priority` | Reserved for upcoming releases |

- Report from the asset's page ("Report finding"); browse at `/findings`. New findings are open.
- Status, assignee, reporter and priority are never edited through the form or the API body.
- The **Operational Logbook** of each finding records system events (reported, edited, asset moved).
  It is read-only here; comments arrive in a later release. Entries are never edited or deleted.
- Transferring an asset with findings also needs `findings.view_finding` in both teams, and the
  transfer request must confirm the current number of findings (`finding_count`). Assets without
  findings transfer as before.
- Retiring an asset keeps its findings readable and editable; new findings cannot be reported on it.
- Finding changes are limited per user (`DJANGO_THROTTLE_FINDING_WRITE_RATE`, default `60/min`).

## Development

Backend (requires [uv](https://docs.astral.sh/uv/) and a PostgreSQL instance for tests):

```sh
# A throwaway PostgreSQL 18 for the tests, separate from the Compose database.
podman run -d --name trilha-test-pg -p 127.0.0.1:55432:5432 \
  -e POSTGRES_DB=trilha -e POSTGRES_USER=trilha -e POSTGRES_PASSWORD=trilha-test \
  docker.io/library/postgres:18-trixie
cd backend
uv sync
POSTGRES_PORT=55432 uv run pytest   # POSTGRES_HOST / POSTGRES_PORT point to the test database
uv run ruff check . && uv run ruff format --check .
```

- `tests/test_db_roles.py` also needs Podman or Docker. It starts disposable PostgreSQL containers to
  prove role separation, upgrades, backups and restores, then removes them. It never touches a
  Compose project.
- A migration that creates a table must classify it in `backend/apps/core/db_privileges.py` in the
  same commit; otherwise `db_migrate` refuses to grant and the stack does not start.

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
- The application connects to PostgreSQL as a restricted runtime role that owns nothing; migrations
  run as a separate schema owner (see [Database roles, backups and recovery](#database-roles-backups-and-recovery)).

Only local use is supported so far. Running Trilha on a network still needs TLS for every connection
to the proxy, which is planned and not provided yet.

## Reporting vulnerabilities

See [SECURITY.md](SECURITY.md).
