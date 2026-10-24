"""SPEC-0013 / TM-0013: PostgreSQL role separation, proven on disposable PostgreSQL 18 containers.

Every container runs the Compose image digest with the real deploy/postgres scripts, random
passwords and a random loopback port, and is removed with its volume afterwards; no Compose project
is touched.
Privilege checks log in as the role they test and assert session_user: none borrows a role through
SET ROLE from a superuser session, which can switch to any role and proves nothing."""

import hashlib
import os
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import psycopg
import pytest
from psycopg import errors, sql

from apps.core import db_privileges
from apps.core.management.commands.db_migrate import LOCK_KEY

REPO = Path(__file__).resolve().parents[2]
BACKEND = REPO / "backend"
DEPLOY = REPO / "deploy" / "postgres"
IMAGE = re.search(
    r"image: (docker\.io/library/postgres:\S+@sha256:[0-9a-f]{64})",
    (REPO / "compose.yaml").read_text(),
)[1]
RUNTIME = os.environ.get("CONTAINER_RUNTIME") or shutil.which("podman") or shutil.which("docker")
OWNER, APP, DB = "trilha", "trilha_app", "trilha"
PROVISION = (DEPLOY / "init" / "01-provision.sh").read_text()
ROLLBACK = (DEPLOY / "rollback-runtime-role.sh").read_text()
PARK = (DEPLOY / "park-tables.sh").read_text()
# The runtime privilege policy of the release before SPEC-0007 slice B (main at f8bc56f), copied
# here as the "previous release" a rollback below slice B runs (SPEC-0007 SEC-52).
PREVIOUS_POLICY = {
    **{
        table: db_privileges.STANDARD
        for table in (
            "accounts_user",
            "accounts_user_groups",
            "accounts_user_user_permissions",
            "assets_asset",
            "auth_group",
            "auth_group_permissions",
            "auth_permission",
            "django_content_type",
            "django_session",
            "rbac_platformaccess",
            "rbac_role",
            "rbac_role_permissions",
            "rbac_roleassignment",
            "teams_membership",
            "teams_team",
        )
    },
    "audit_auditevent": db_privileges.APPEND_ONLY,
    "django_migrations": db_privileges.NO_ACCESS,
}
PARKED = ("findings_finding", "findings_findinglogentry")
# deploy/postgres/init/01-create-app-role.sh before SPEC-0013: one role owns and serves everything.
LEGACY_INIT = """#!/bin/sh
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \\
    -v app_user="$APP_DB_USER" -v app_password="$APP_DB_PASSWORD" -v app_db="$APP_DB_NAME" <<'SQL'
CREATE ROLE :"app_user" LOGIN PASSWORD :'app_password' NOSUPERUSER NOCREATEDB NOCREATEROLE;
CREATE DATABASE :"app_db" OWNER :"app_user";
REVOKE ALL ON DATABASE :"app_db" FROM PUBLIC;
SQL
"""
AUDIT_INSERT = """
    INSERT INTO audit_auditevent (event_id, occurred_at, actor_type, actor_label, action, outcome,
        resource_type, resource_id, source, changes, metadata)
    VALUES (gen_random_uuid(), now(), 'system', 'privtest', 'privtest.event_recorded', 'success',
        '', '', 'command', '{}', '{}')
    RETURNING id
"""

if not RUNTIME:
    if os.environ.get("CI"):
        pytest.fail("SPEC-0013 role tests need docker or podman in CI", pytrace=False)
    pytest.skip("needs podman or docker", allow_module_level=True)


def run(*args, check=True, **kwargs):
    kwargs.setdefault("text", True)
    result = subprocess.run(args, check=False, capture_output=True, timeout=300, **kwargs)
    if check:
        assert result.returncode == 0, (args[:3], result.stdout[-1500:], result.stderr[-1500:])
    return result


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class Instance:
    """A disposable PostgreSQL labelled like a Compose `db` service of its own project."""

    def __init__(self, tmp, *, legacy=False, server_args=()):
        self.name = f"trilha-test-{uuid.uuid4().hex[:12]}"
        self.project, self.volume = self.name, f"{self.name}_db-data"
        self.port = free_port()
        self.passwords = {role: secrets.token_urlsafe(24) for role in ("postgres", OWNER, APP)}
        environment = {"POSTGRES_USER": "postgres", "POSTGRES_DB": "postgres"}
        environment["POSTGRES_PASSWORD"] = self.passwords["postgres"]
        init = DEPLOY / "init"
        if legacy:
            init = tmp / f"{self.name}-init"
            init.mkdir()
            (init / "01-create-app-role.sh").write_text(LEGACY_INIT)
            environment |= {"APP_DB_NAME": DB, "APP_DB_USER": OWNER}
            environment["APP_DB_PASSWORD"] = self.passwords[OWNER]
        else:
            environment |= self.provisioning_env()
        self.tmp, self.server_args = tmp, server_args
        self._start(init, environment)

    def _start(self, init, environment):
        env_file = self.tmp / f"{self.name}.env"
        env_file.write_text("".join(f"{key}={value}\n" for key, value in environment.items()))
        env_file.chmod(0o600)
        run(
            RUNTIME, "run", "-d", "--name", self.name, "--user", "postgres",
            "--label", f"com.docker.compose.project={self.project}",
            "--label", "com.docker.compose.service=db",
            "-p", f"127.0.0.1:{self.port}:5432", "--env-file", str(env_file),
            "-v", f"{self.volume}:/var/lib/postgresql",
            "-v", f"{init}:/docker-entrypoint-initdb.d:ro,z",
            IMAGE, *(("postgres", *self.server_args) if self.server_args else ()),
        )  # fmt: skip
        env_file.unlink()
        self._wait()

    def recreate(self):
        """`compose down` then `compose up -d db` on the new release: a new container with the
        provisioning environment and init scripts, on the same data volume."""
        run(RUNTIME, "rm", "-f", self.name)
        environment = {"POSTGRES_USER": "postgres", "POSTGRES_DB": "postgres"}
        environment["POSTGRES_PASSWORD"] = self.passwords["postgres"]
        self._start(DEPLOY / "init", environment | self.provisioning_env())

    def provisioning_env(self, **overrides):
        return {
            "APP_DB_NAME": DB,
            "APP_DB_OWNER": OWNER,
            "APP_DB_OWNER_PASSWORD": self.passwords[OWNER],
            "APP_DB_RUNTIME": APP,
            "APP_DB_RUNTIME_PASSWORD": self.passwords[APP],
            **overrides,
        }

    def _wait(self):
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            ready = run(RUNTIME, "exec", self.name, "pg_isready", "-q", check=False)
            logs = self.logs()  # a new volume is initialized; an existing one is reused
            started = "init process complete" in logs or "Skipping initialization" in logs
            if started and ready.returncode == 0:
                return
            time.sleep(0.5)
        raise AssertionError(f"PostgreSQL did not start: {self.logs()[-1500:]}")

    def logs(self):
        result = run(RUNTIME, "logs", self.name, check=False)
        return result.stdout + result.stderr

    def connect(self, role, dbname=DB, password=None):
        connection = psycopg.connect(
            host="127.0.0.1",
            port=self.port,
            user=role,
            password=password or self.passwords[role],
            dbname=dbname,
            autocommit=True,
            connect_timeout=10,
        )
        assert connection.execute("SELECT session_user, current_user").fetchone() == (role, role)
        return connection

    def _env(self, role, env):
        return {
            **os.environ,
            "DJANGO_SETTINGS_MODULE": "config.settings.test",
            "POSTGRES_HOST": "127.0.0.1",
            "POSTGRES_PORT": str(self.port),
            "POSTGRES_DB": DB,
            "POSTGRES_USER": role,
            "POSTGRES_PASSWORD": self.passwords[role],
            "POSTGRES_RUNTIME_USER": APP,
            **(env or {}),
        }

    def manage(self, *args, role=OWNER, env=None, check=True):
        result = subprocess.run(
            [sys.executable, "manage.py", *args],
            cwd=BACKEND,
            env=self._env(role, env),
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        if check:
            assert result.returncode == 0, result.stdout[-2000:] + result.stderr[-2000:]
        return result

    def manage_async(self, *args, role=OWNER):
        return subprocess.Popen(
            [sys.executable, "manage.py", *args],
            cwd=BACKEND,
            env=self._env(role, None),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def exec_script(self, script, *args, **env):
        """Runs a deploy script inside the container as `compose exec -T db sh -s` does."""
        options = [part for key, value in env.items() for part in ("-e", f"{key}={value}")]
        return run(
            RUNTIME, "exec", "-i", *options, self.name, "sh", "-s", *args, input=script,
            check=False,
        )  # fmt: skip

    def provision(self, **overrides):
        return self.exec_script(PROVISION, **self.provisioning_env(**overrides))

    def remove(self):
        run(RUNTIME, "rm", "-f", "-v", self.name, check=False)
        run(RUNTIME, "volume", "rm", "-f", self.volume, check=False)


def acl_snapshot(connection):
    return connection.execute(
        """SELECT c.relname, pg_get_userbyid(c.relowner),
                  coalesce(c.relacl, acldefault('r', c.relowner))::text
           FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE n.nspname = 'public' ORDER BY 1"""
    ).fetchall()


def fingerprint(connection):
    """Row counts per table (sessions excepted: never backed up) and a digest of the audit trail."""
    tables = connection.execute(
        """SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relname <> 'django_session'
           ORDER BY 1"""
    ).fetchall()
    counts = {
        table: connection.execute(
            sql.SQL("SELECT count(*) FROM {}").format(sql.Identifier(table))
        ).fetchone()[0]
        for (table,) in tables
    }
    counts["audit_digest"] = connection.execute(
        "SELECT md5(string_agg(event_id::text || action, ',' ORDER BY id)) FROM audit_auditevent"
    ).fetchone()[0]
    return counts


@contextmanager
def django_connected(instance, role, django_db_blocker):
    """Points Django's default connection at the instance, logged in as `role`."""
    from django.db import connections

    connection = connections["default"]
    saved = dict(connection.settings_dict)
    with django_db_blocker.unblock():
        connection.close()
        connection.settings_dict.update(
            NAME=DB,
            USER=role,
            PASSWORD=instance.passwords[role],
            HOST="127.0.0.1",
            PORT=str(instance.port),
        )
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT session_user")
                assert cursor.fetchone()[0] == role
            yield
        finally:
            connection.close()
            connection.settings_dict.clear()
            connection.settings_dict.update(saved)


def seed():
    """Representative data written through the application services (each write is audited)."""
    from apps.assets import services
    from apps.audit.context import audit_source
    from apps.rbac.principals import UserPrincipal
    from tests.test_assets_security import ASSET_CODES, grant, make_team, make_user

    with audit_source("command"):
        alpha, beta = make_team("alpha"), make_team("beta")
        manager = make_user("manager")
        grant(manager, alpha, *ASSET_CODES)
        grant(manager, beta, *ASSET_CODES)
        principal = UserPrincipal(manager.pk)
        for number in range(6):
            team = alpha if number % 2 else beta
            services.create_asset(principal, team_id=team.pk, name=f"Web {number}", kind="server")


def backup(instance, directory, **env):
    return run(
        str(DEPLOY / "backup.sh"), "--project", instance.project, str(directory),
        env={**os.environ, "CONTAINER_RUNTIME": RUNTIME, **env}, check=False,
    )  # fmt: skip


def restore_verify(dump):
    return run(
        str(DEPLOY / "restore-verify.sh"), str(dump),
        env={**os.environ, "CONTAINER_RUNTIME": RUNTIME}, check=False,
    )  # fmt: skip


@pytest.fixture(scope="module")
def fresh(tmp_path_factory):
    """A fresh installation: provisioning on first start, then db_migrate as the schema owner."""
    instance = Instance(tmp_path_factory.mktemp("fresh"))
    try:
        assert "db_grants_applied" in instance.manage("db_migrate").stdout
        yield instance
    finally:
        instance.remove()


@pytest.fixture(scope="module")
def legacy(tmp_path_factory, django_db_blocker):
    """A pre-SPEC-0013 installation with data, and its backup taken before the upgrade."""
    tmp = tmp_path_factory.mktemp("legacy")
    instance = Instance(tmp, legacy=True)
    try:
        instance.manage("migrate", "--noinput")
        with django_connected(instance, OWNER, django_db_blocker):
            seed()
        backups = tmp_path_factory.mktemp("backups")
        result = backup(instance, backups)
        assert result.returncode == 0, result.stderr
        with instance.connect("postgres") as superuser:
            before = fingerprint(superuser)
        yield SimpleNamespace(
            instance=instance,
            backups=backups,
            dump=next(backups.glob("*.dump")),
            before=before,
            output=result.stdout + result.stderr,
        )
    finally:
        instance.remove()


@pytest.fixture(scope="module")
def upgraded(legacy):
    """The documented in-place upgrade: the db container is recreated with the new release's
    environment (owner password rotated, D-9), provisioning runs on the existing volume through the
    mounted script, then db_migrate runs as the owner."""
    instance = legacy.instance
    old_owner_password = instance.passwords[OWNER]
    instance.passwords[OWNER] = secrets.token_urlsafe(24)
    instance.recreate()
    provisioned = run(
        RUNTIME, "exec", instance.name, "sh", "/docker-entrypoint-initdb.d/01-provision.sh",
        check=False,
    )  # fmt: skip
    assert provisioned.returncode == 0, provisioned.stderr
    applied = instance.manage("db_migrate")
    return SimpleNamespace(**vars(legacy), old_owner_password=old_owner_password, applied=applied)


# Fresh installation and the migration owner


def test_migration_owner_runs_migrations_and_grants(fresh):
    assert "db_grants_unchanged" in fresh.manage("db_migrate").stdout  # a re-run changes nothing
    with fresh.connect(OWNER) as owner:
        owners = {row[1] for row in acl_snapshot(owner)}
        assert owners == {OWNER}
        assert owner.execute("SELECT count(*) FROM django_migrations").fetchone()[0] > 0


# SEC-01 / SEC-02 / SEC-03 — audit rows and protections (T-01-T-03)


def test_runtime_cannot_update_or_delete_audit_events_cwe_471(fresh):
    with fresh.connect(APP) as app:
        event = app.execute(AUDIT_INSERT).fetchone()[0]
        for statement in (
            "UPDATE audit_auditevent SET actor_label = 'forged' WHERE id = %s",
            "DELETE FROM audit_auditevent WHERE id = %s",
        ):
            with pytest.raises(errors.InsufficientPrivilege):
                app.execute(statement, [event])
        stored = app.execute("SELECT actor_label FROM audit_auditevent WHERE id = %s", [event])
        assert stored.fetchone() == ("privtest",)


def test_runtime_cannot_truncate_any_table_cwe_471(fresh):
    with fresh.connect(APP) as app:
        for table in db_privileges.TABLE_PRIVILEGES:
            with pytest.raises(errors.InsufficientPrivilege):
                app.execute(sql.SQL("TRUNCATE {}").format(sql.Identifier(table)))


def test_runtime_cannot_alter_drop_or_disable_audit_protection_cwe_693(fresh):
    with fresh.connect(APP) as app:
        for statement in (
            "ALTER TABLE audit_auditevent DISABLE TRIGGER audit_auditevent_append_only",
            "ALTER TABLE audit_auditevent DISABLE TRIGGER ALL",
            "DROP TRIGGER audit_auditevent_append_only ON audit_auditevent",
            "ALTER TABLE audit_auditevent ADD COLUMN forged text",
            f"ALTER TABLE audit_auditevent OWNER TO {APP}",
            "DROP TABLE audit_auditevent",
            "CREATE OR REPLACE FUNCTION audit_auditevent_append_only() RETURNS trigger"
            " LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$",
            f"ALTER FUNCTION audit_auditevent_append_only() OWNER TO {APP}",
            "DROP FUNCTION audit_auditevent_append_only() CASCADE",
        ):
            with pytest.raises(errors.InsufficientPrivilege):
                app.execute(statement)
    with fresh.connect("postgres") as superuser:
        trigger = superuser.execute(
            "SELECT tgenabled FROM pg_trigger WHERE tgname = 'audit_auditevent_append_only'"
        )
        assert trigger.fetchone() == ("O",)


# SPEC-0007 SEC-24 / SEC-43 — findings and logbook rows as the runtime role (T-24, T-43)


def _finding_rows(instance, django_db_blocker):
    """A finding and its first logbook entry, written through the ORM as the runtime role."""
    from apps.assets.models import Asset
    from apps.audit.context import audit_source
    from apps.findings.models import Finding, FindingLogEntry
    from tests.test_assets_security import make_team, make_user

    suffix = uuid.uuid4().hex[:8]
    with django_connected(instance, APP, django_db_blocker):
        with audit_source("command"):
            team = make_team(f"f{suffix}")
        user = make_user(f"reporter-{suffix}")
        asset = Asset.objects.create(team=team, name=f"Asset {suffix}", kind="server")
        finding = Finding.objects.create(
            asset=asset, title="Probe", category="other", severity="low", reported_by=user,
            log_sequence=1,
        )  # fmt: skip
        entry = FindingLogEntry.objects.create(
            finding=finding, sequence=1, kind="system", event="finding_created", actor=user
        )
        return finding.pk, entry.pk


def test_runtime_cannot_update_or_delete_logbook_entries_cwe_471(fresh, django_db_blocker):
    finding, entry = _finding_rows(fresh, django_db_blocker)
    with fresh.connect(APP) as app:
        for statement in (
            "UPDATE findings_findinglogentry SET event = 'assigned' WHERE id = %s",
            "UPDATE findings_findinglogentry SET body = '', redacted_at = now(),"
            " redaction_reason = 'secret' WHERE id = %s",  # not even the redaction shape
            "DELETE FROM findings_findinglogentry WHERE id = %s",
        ):
            with pytest.raises(errors.InsufficientPrivilege):
                app.execute(statement, [entry])
        with pytest.raises(errors.InsufficientPrivilege):
            app.execute("TRUNCATE findings_findinglogentry")
        with pytest.raises(errors.InsufficientPrivilege):  # no row lock on history either
            app.execute("SELECT id FROM findings_findinglogentry WHERE id = %s FOR UPDATE", [entry])
        with app.transaction(force_rollback=True):  # appending works
            app.execute(
                "INSERT INTO findings_findinglogentry (id, finding_id, sequence, kind, event, body,"
                " metadata, created_at) VALUES (gen_random_uuid(), %s, 2, 'system', 'probe', '',"
                " '{}', now())",
                [finding],
            )
        stored = app.execute(
            "SELECT event, body FROM findings_findinglogentry WHERE id = %s", [entry]
        ).fetchone()
        assert stored == ("finding_created", "")


def test_database_error_logs_exclude_row_content_cwe_532(fresh, django_db_blocker):
    from django.db import IntegrityError

    from apps.findings.models import Finding, FindingLogEntry

    finding, _ = _finding_rows(fresh, django_db_blocker)
    app_marker, owner_marker = f"APP-{secrets.token_hex(8)}", f"OWNER-{secrets.token_hex(8)}"
    with django_connected(fresh, APP, django_db_blocker):
        row = Finding.objects.get(pk=finding)
        for invalid in (
            {"kind": "comment", "actor": None, "body": app_marker, "idempotency_key": uuid.uuid4()},
            {"kind": "system", "event": "finding_updated", "body": app_marker},
        ):  # violations of logentry_comment_shape and logentry_system_shape, with the body bound
            with pytest.raises(IntegrityError):
                FindingLogEntry.objects.create(finding=row, sequence=99, **invalid)
    insert = (
        "INSERT INTO findings_findinglogentry (id, finding_id, sequence, kind, event, body,"
        " metadata, created_at) VALUES (gen_random_uuid(), %s, 99, 'system', 'probe', %s, '{}',"
        " now())"
    )
    with fresh.connect(APP) as app, pytest.raises(errors.CheckViolation):
        psycopg.ClientCursor(app).execute(insert, [finding, app_marker])
    # Control: the owner keeps PostgreSQL's defaults, so the same failure logs the row content.
    with fresh.connect(OWNER) as owner, pytest.raises(errors.CheckViolation):
        psycopg.ClientCursor(owner).execute(insert, [finding, owner_marker])
    with fresh.connect(APP) as app:
        for setting in ("log_min_error_statement", "log_error_verbosity"):
            with pytest.raises(errors.InsufficientPrivilege):
                app.execute(f"SET {setting} = DEFAULT")
    deadline = time.monotonic() + 10
    while owner_marker not in (logs := fresh.logs()) and time.monotonic() < deadline:
        time.sleep(0.2)
    assert owner_marker in logs
    assert (
        'violates check constraint "logentry_comment_shape"' in logs
    )  # the error itself is logged
    assert app_marker not in logs
    with fresh.connect("postgres") as superuser:
        settings = superuser.execute(
            "SELECT s.setconfig FROM pg_db_role_setting s JOIN pg_roles r ON r.oid = s.setrole"
            " WHERE r.rolname = %s AND s.setdatabase = 0",
            [APP],
        ).fetchone()[0]
        assert sorted(settings) == ["log_error_verbosity=terse", "log_min_error_statement=panic"]


def test_emergency_redaction_is_owner_only_one_way_and_audited_cwe_471(fresh, django_db_blocker):
    from apps.audit.context import audit_source
    from apps.findings.models import Finding
    from tests.test_findings_commands import comment

    marker = f"MARKER-{secrets.token_hex(8)}"
    finding, _ = _finding_rows(fresh, django_db_blocker)
    with django_connected(fresh, APP, django_db_blocker), audit_source("command"):
        row = Finding.objects.select_related("reported_by").get(pk=finding)
        entry = comment(row, row.reported_by, f"token {marker}")
        spare = comment(row, row.reported_by, f"second {marker}")
    args = ["redact_logbook_entry", "--finding", str(finding), "--sequence", str(entry.sequence)]
    args += ["--reason", "secret", "--ticket", "OPS-7"]
    as_runtime = fresh.manage(*args, "--execute", role=APP, check=False)
    assert as_runtime.returncode != 0 and "Redaction refused; nothing changed." in as_runtime.stderr
    dry = fresh.manage(*args, role=OWNER)
    assert "dry run" in dry.stdout and "kind=comment" in dry.stdout
    done = fresh.manage(*args, "--execute", role=OWNER)
    assert f"redacted entry {entry.pk}" in done.stdout
    again = fresh.manage(*args, "--execute", role=OWNER, check=False)
    assert again.returncode != 0 and "already redacted" in again.stderr
    for result in (as_runtime, dry, done, again):
        assert marker not in result.stdout + result.stderr
    with fresh.connect(OWNER) as owner:
        stored = owner.execute(
            "SELECT body, redaction_reason, redacted_at IS NOT NULL FROM findings_findinglogentry"
            " WHERE id = %s",
            [entry.pk],
        ).fetchone()
        assert stored == ("", "secret", True)
        assert owner.execute(
            "SELECT count(*) FROM audit_auditevent WHERE action = 'findings.logbook_entry_redacted'"
            " AND resource_id = %s AND actor_label = 'trilha-operator' AND source = 'command'",
            [str(entry.pk)],
        ).fetchone() == (1,)
        # Even the owner cannot reword, restore, re-redact or delete: only the one-way shape, once.
        for statement in (
            "UPDATE findings_findinglogentry SET body = 'reworded' WHERE id = %s",
            "UPDATE findings_findinglogentry SET redacted_at = NULL, redaction_reason = NULL"
            " WHERE id = %s",
            "UPDATE findings_findinglogentry SET redacted_at = now() WHERE id = %s",
            "DELETE FROM findings_findinglogentry WHERE id = %s",
        ):
            with pytest.raises(errors.RestrictViolation):
                owner.execute(statement, [entry.pk])
        with pytest.raises(errors.RestrictViolation):
            owner.execute("DELETE FROM findings_findinglogentry WHERE id = %s", [spare.pk])
    # The superuser is not the table owner: the trigger refuses the redaction shape for it too.
    with fresh.connect("postgres") as superuser:
        with pytest.raises(errors.RestrictViolation):
            superuser.execute(
                "UPDATE findings_findinglogentry SET body = '', redacted_at = now(),"
                " redaction_reason = 'secret' WHERE id = %s",
                [spare.pk],
            )
    assert marker not in fresh.logs()


def test_runtime_cannot_delete_findings_or_lifecycle_rows_cwe_471(fresh, django_db_blocker):
    finding, _ = _finding_rows(fresh, django_db_blocker)
    with fresh.connect(APP) as app:
        with pytest.raises(errors.InsufficientPrivilege):
            app.execute("DELETE FROM findings_finding WHERE id = %s", [finding])
        with pytest.raises(errors.InsufficientPrivilege):
            app.execute("TRUNCATE findings_finding")
        with app.transaction(force_rollback=True):  # updatable: edits and row locks work
            app.execute("SELECT id FROM findings_finding WHERE id = %s FOR UPDATE", [finding])
            app.execute(
                "UPDATE findings_finding SET version = version + 1 WHERE id = %s", [finding]
            )
        assert app.execute(
            "SELECT count(*) FROM findings_finding WHERE id = %s", [finding]
        ).fetchone() == (1,)
    assert db_privileges.TABLE_PRIVILEGES["findings_finding"] == ("SELECT", "INSERT", "UPDATE")
    assert db_privileges.TABLE_PRIVILEGES["findings_findinglogentry"] == ("SELECT", "INSERT")


# SEC-04 / SEC-05 / SEC-06 / SEC-10 — DDL, escalation, other databases (T-04-T-06, T-10)


def test_runtime_cannot_create_objects_or_temp_tables_cwe_250(fresh):
    with fresh.connect(APP) as app:
        for statement in (
            "CREATE TABLE public.planted (id int)",
            "CREATE VIEW public.planted_view AS SELECT 1",
            "CREATE FUNCTION public.planted() RETURNS int LANGUAGE sql AS 'SELECT 1'",
            "CREATE SEQUENCE public.planted_sequence",
            "CREATE SCHEMA planted",
            "CREATE TEMP TABLE planted_temp (id int)",
        ):
            with pytest.raises(errors.InsufficientPrivilege):
                app.execute(statement)


def test_runtime_cannot_escalate_through_roles_cwe_269(fresh):
    with fresh.connect("postgres") as superuser:
        flags = superuser.execute(
            "SELECT rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls"
            " FROM pg_roles WHERE rolname = %s",
            [APP],
        )
        assert flags.fetchone() == (False,) * 6
        memberships = superuser.execute(
            "SELECT count(*) FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.member"
            " WHERE r.rolname = %s",
            [APP],
        )
        assert memberships.fetchone() == (0,)
    with fresh.connect(APP) as app:
        for statement in (
            f"SET ROLE {OWNER}",
            "SET ROLE postgres",
            "SET SESSION AUTHORIZATION postgres",
            "CREATE ROLE planted",
            f"GRANT {OWNER} TO {APP}",
            f"ALTER ROLE {APP} SUPERUSER",
            f"ALTER ROLE {APP} CREATEROLE",
        ):
            with pytest.raises(errors.InsufficientPrivilege):
                app.execute(statement)
        before = acl_snapshot(app)
        app.execute("GRANT SELECT ON teams_team TO PUBLIC")  # no grant option: a no-op warning
        assert acl_snapshot(app) == before


def test_runtime_cannot_connect_to_other_databases_cwe_284(fresh):
    for dbname in ("postgres", "template1"):
        with pytest.raises(psycopg.OperationalError, match="permission denied for database"):
            fresh.connect(APP, dbname=dbname)


def test_schema_has_no_security_definer_functions_cwe_427(fresh):
    with fresh.connect(OWNER) as owner:
        definers = owner.execute(
            "SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace"
            " WHERE n.nspname = 'public' AND p.prosecdef"
        )
        assert definers.fetchone() == (0,)
    with fresh.connect(APP) as app:
        rights = app.execute(
            "SELECT has_schema_privilege('public', 'CREATE'),"
            " has_database_privilege(current_database(), 'TEMPORARY'),"
            " has_database_privilege(current_database(), 'CREATE')"
        )
        assert rights.fetchone() == (False, False, False)


# SEC-07 / SEC-08 / SEC-09 / SEC-15 — the grant policy (T-07-T-09, T-15)


def test_runtime_privileges_match_policy_inventory_cwe_732(fresh):
    with fresh.connect(OWNER) as owner:
        assert db_privileges.drift(owner.cursor(), APP) == []
        tables = owner.execute(
            "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace"
            " WHERE n.nspname = 'public' AND c.relkind = 'r'"
        )
        assert {row[0] for row in tables} == set(db_privileges.TABLE_PRIVILEGES)
    with fresh.connect(APP) as app:
        for table, privileges in db_privileges.TABLE_PRIVILEGES.items():
            granted = {
                privilege
                for privilege in db_privileges.TABLE_PRIVILEGE_NAMES
                if app.execute("SELECT has_table_privilege(%s, %s)", [table, privilege]).fetchone()[
                    0
                ]
            }
            assert granted == set(privileges), table
        with pytest.raises(errors.InsufficientPrivilege):
            app.execute("SELECT * FROM django_migrations")  # migration metadata is the owner's
        with app.transaction(force_rollback=True):  # ordinary DML on a standard table
            app.execute("INSERT INTO django_content_type (app_label, model) VALUES ('t', 'probe')")
            app.execute("UPDATE django_content_type SET model = 'probe2' WHERE app_label = 't'")
            app.execute("DELETE FROM django_content_type WHERE app_label = 't'")


def test_db_migrate_grants_new_tables_and_is_idempotent_cwe_732(fresh):
    policy = {**db_privileges.TABLE_PRIVILEGES, "privtest_log": db_privileges.APPEND_ONLY}
    with fresh.connect(OWNER) as owner:
        owner.execute("CREATE TABLE privtest_log (id int)")
        try:
            with owner.transaction():
                db_privileges.apply(owner.cursor(), APP, policy)
            assert db_privileges.drift(owner.cursor(), APP, policy) == []
            with fresh.connect(APP) as app:
                app.execute("INSERT INTO privtest_log VALUES (1)")
                assert app.execute("SELECT count(*) FROM privtest_log").fetchone() == (1,)
                with pytest.raises(errors.InsufficientPrivilege):
                    app.execute("UPDATE privtest_log SET id = 2")
        finally:
            owner.execute("DROP TABLE privtest_log")
        # Stray grants (a manual fix, or a stale ACL restored from a dump) are removed.
        owner.execute(f"GRANT TRUNCATE ON teams_team TO {APP}")
        owner.execute("GRANT SELECT ON accounts_user TO PUBLIC")
        assert db_privileges.drift(owner.cursor(), APP) != []
    assert "db_grants_applied" in fresh.manage("db_migrate").stdout
    assert "db_grants_unchanged" in fresh.manage("db_migrate").stdout
    with fresh.connect(OWNER) as owner:
        assert db_privileges.drift(owner.cursor(), APP) == []
        stale = db_privileges.refusal_reasons(owner.cursor(), APP, {**policy, "teams_gone": ()})
        assert "classified tables that do not exist: privtest_log, teams_gone" in stale


def test_unclassified_table_blocks_deployment_cwe_732(fresh):
    with fresh.connect(OWNER) as owner:
        owner.execute("CREATE TABLE privtest_unreviewed (id int)")
        before = acl_snapshot(owner)
    try:
        refused = fresh.manage("db_migrate", check=False)
        assert refused.returncode != 0
        assert "unclassified tables: privtest_unreviewed" in refused.stderr
        with fresh.connect(OWNER) as owner:
            assert acl_snapshot(owner) == before  # nothing granted, nothing revoked
        with fresh.connect(APP) as app, pytest.raises(errors.InsufficientPrivilege):
            app.execute("SELECT * FROM privtest_unreviewed")
    finally:
        with fresh.connect(OWNER) as owner:
            owner.execute("DROP TABLE privtest_unreviewed")
    fresh.manage("db_migrate")


def test_db_migrate_refuses_ownership_drift_cwe_708(fresh):
    with fresh.connect(OWNER) as owner:
        before = acl_snapshot(owner)
    with fresh.connect("postgres") as superuser:
        superuser.execute("CREATE TABLE public.superuser_made (id int)")
    try:
        refused = fresh.manage("db_migrate", check=False)
        assert refused.returncode != 0
        assert "not owned by the migrating role: superuser_made" in refused.stderr
    finally:
        with fresh.connect("postgres") as superuser:
            superuser.execute("DROP TABLE public.superuser_made")
    for role, env, reason in (
        ("postgres", None, "the migrating role is a superuser"),
        (OWNER, {"POSTGRES_RUNTIME_USER": "ghost_role"}, "the runtime role is missing"),
        (OWNER, {"POSTGRES_RUNTIME_USER": OWNER}, "the runtime role is the migrating role"),
        (APP, None, "django_migrations"),  # the runtime cannot even read the migration state
    ):
        result = fresh.manage("db_migrate", role=role, env=env, check=False)
        assert result.returncode != 0 and reason in result.stderr, role
    with fresh.connect(OWNER) as owner:
        assert acl_snapshot(owner) == before


def test_db_migrate_serializes_concurrent_runs_cwe_362(fresh):
    with fresh.connect(OWNER) as holder:
        holder.execute("SELECT pg_advisory_lock(%s)", [LOCK_KEY])
        waiting = fresh.manage_async("db_migrate")
        try:
            deadline = time.monotonic() + 60
            blocked = 0
            while time.monotonic() < deadline and not blocked:
                blocked = holder.execute(
                    "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted"
                ).fetchone()[0]
                time.sleep(0.2)
            assert blocked == 1 and waiting.poll() is None
        finally:
            holder.execute("SELECT pg_advisory_unlock(%s)", [LOCK_KEY])
        assert waiting.wait(timeout=300) == 0
    runs = [fresh.manage_async("db_migrate") for _ in range(2)]
    assert [run.wait(timeout=300) for run in runs] == [0, 0]
    with fresh.connect(OWNER) as owner:
        assert db_privileges.drift(owner.cursor(), APP) == []


# SEC-11 — readiness refuses privileged roles (T-11, T-21)


def test_check_ready_rejects_privileged_database_role_cwe_250(fresh):
    strict = {"DB_REQUIRE_RESTRICTED_ROLE": "true"}
    assert fresh.manage("check_ready", role=APP, env=strict).stdout.strip().endswith("ready")
    for role, failed_check in ((OWNER, "owns_objects"), ("postgres", "superuser")):
        refused = fresh.manage("check_ready", role=role, env=strict, check=False)
        output = refused.stdout + refused.stderr
        assert refused.returncode != 0 and "Not ready." in output and failed_check in output
        assert fresh.passwords[role] not in output


# Regression: the application works as the runtime role


def test_application_flows_work_as_runtime_role(fresh, django_db_blocker):
    from apps.audit.context import audit_source
    from tests.platform_support import Browser, make_admin
    from tests.test_assets_security import ASSET_CODES, grant, make_team, make_user

    with django_connected(fresh, APP, django_db_blocker):
        with audit_source("command"):
            team = make_team("ops")
            grant(make_user("analyst"), team, *ASSET_CODES)
        analyst = Browser().login("analyst")  # session written
        created = analyst.post(
            "/api/v1/assets/",
            {"team_id": str(team.pk), "name": "Db 01", "kind": "server", "os_product": "debian"},
        )
        assert created.status_code == 201, created.content
        updated = analyst.patch(  # row locks: FOR NO KEY UPDATE on roles, teams, user and asset
            f"/api/v1/assets/{created.json()['id']}/", {"version": 1, "os_version": "12"}
        )
        assert updated.status_code == 200, updated.content
        make_admin("root")  # account administration, audited
        root = Browser(address="203.0.113.20").login("root")
        assert root.reauthenticate().status_code == 204
        trail = root.get("/api/v1/admin/audit-events/")
        assert trail.status_code == 200 and trail.json()["count"] >= 3
        assert analyst.post("/api/v1/auth/logout/").status_code in (200, 204)  # session deleted


# SEC-13 / SEC-14 — provisioning (T-13, T-14)


def test_provisioning_is_idempotent_and_least_privilege_cwe_665(fresh):
    def state():
        with fresh.connect("postgres", dbname="postgres") as superuser:
            return (
                superuser.execute(
                    "SELECT rolname, rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolcanlogin,"
                    " rolreplication, rolbypassrls FROM pg_roles"
                    " WHERE rolname IN (%s, %s, 'someone_else') ORDER BY 1",
                    [OWNER, APP],
                ).fetchall(),
                superuser.execute(
                    "SELECT count(*) FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.member"
                    " WHERE r.rolname IN (%s, %s)",
                    [OWNER, APP],
                ).fetchone()[0],
                superuser.execute(
                    "SELECT datname, pg_get_userbyid(datdba), datacl::text,"
                    " has_database_privilege('public', datname, 'CONNECT')"
                    " FROM pg_database WHERE datname IN ('postgres', 'template1', %s) ORDER BY 1",
                    [DB],
                ).fetchall(),
            )

    before = state()
    for _ in range(2):
        result = fresh.provision()
        assert result.returncode == 0, result.stderr
    assert state() == before
    roles, memberships, databases = before
    assert roles == [
        (OWNER, False, True, False, False, True, False, False),
        (APP, False, False, False, False, True, False, False),
    ]
    assert memberships == 0
    assert [(name, owner, public) for name, owner, _, public in databases] == [
        ("postgres", "postgres", False),
        ("template1", "postgres", False),
        (DB, OWNER, False),
    ]
    with fresh.connect(OWNER) as owner:
        schema = owner.execute(
            "SELECT has_schema_privilege('public', 'public', 'CREATE'),"
            " has_schema_privilege(%s, 'public', 'USAGE')",
            [APP],
        )
        assert schema.fetchone() == (False, True)
    refused = fresh.provision(APP_DB_OWNER="someone_else")
    assert refused.returncode != 0 and "belongs to another role" in refused.stderr
    shared = fresh.provision(APP_DB_RUNTIME_PASSWORD=fresh.passwords[OWNER])
    assert shared.returncode != 0 and "identical passwords" in shared.stderr
    assert state() == before  # refused runs changed nothing, and created no role


def test_provisioning_never_exposes_passwords_cwe_532(tmp_path_factory):
    # The server logs every statement: only the script's own session settings keep passwords out.
    server = ("-c", "log_statement=all", "-c", "log_min_error_statement=info")
    instance = Instance(tmp_path_factory.mktemp("logging"), server_args=server)
    try:
        assert instance.provision().returncode == 0
        failed = instance.provision(APP_DB_OWNER="someone_else")
        assert failed.returncode != 0
        logs = instance.logs()
        assert "statement: SET log_statement" in logs  # statement logging was active
        for password in (instance.passwords[OWNER], instance.passwords[APP]):
            assert password not in logs
            assert password not in failed.stdout + failed.stderr
    finally:
        instance.remove()
    assert "\\getenv owner_password APP_DB_OWNER_PASSWORD" in PROVISION
    assert not re.search(r"-v \w*password", PROVISION)  # never on psql's command line


# SEC-16 / SEC-17 — backup and restore verification (T-16-T-18)


def test_backup_writes_private_checksummed_file_outside_repository_cwe_530(legacy, tmp_path):
    files = sorted(legacy.backups.iterdir())
    assert [path.suffix for path in files] == [".dump", ".manifest", ".sha256"]
    assert {stat.S_IMODE(path.stat().st_mode) for path in files} == {0o600}
    manifest = (legacy.backups / files[1].name).read_text().splitlines()
    assert manifest[0] == f"# database={DB} owner={OWNER} runtime="
    assert any(
        line.startswith("django_session|") and line.endswith("|excluded") for line in manifest
    )
    for password in legacy.instance.passwords.values():
        assert password not in legacy.output
        assert password.encode() not in files[0].read_bytes()
    target = legacy.instance
    refusals = [
        (backup(target, REPO), "git work tree"),
        (backup(target, DEPLOY), "git work tree"),  # any depth inside the checkout
        (run(str(DEPLOY / "backup.sh"), "--project", "Bad Name", str(tmp_path), check=False),
         "invalid"),
        (run(str(DEPLOY / "backup.sh"), "--project", "nosuchproject", str(tmp_path), check=False,
             env={**os.environ, "CONTAINER_RUNTIME": RUNTIME}), "no running db container"),
    ]  # fmt: skip
    for result, reason in refusals:
        assert result.returncode != 0 and reason in result.stderr
    assert not list(REPO.glob("trilha-*.dump")) and not list(tmp_path.iterdir())


def test_backup_validates_volume_identity_and_leaves_no_partial_files(legacy, tmp_path):
    project = f"trilha-test-{uuid.uuid4().hex[:12]}"
    run(
        RUNTIME, "run", "-d", "--name", project, "--entrypoint", "sleep",
        "--label", f"com.docker.compose.project={project}",
        "--label", "com.docker.compose.service=db",
        "-v", f"{project}_other:/var/lib/postgresql", IMAGE, "300",
    )  # fmt: skip
    try:
        result = run(
            str(DEPLOY / "backup.sh"), "--project", project, str(tmp_path), check=False,
            env={**os.environ, "CONTAINER_RUNTIME": RUNTIME},
        )  # fmt: skip
        assert result.returncode != 0 and f"expected {project}_db-data" in result.stderr
    finally:
        run(RUNTIME, "rm", "-f", project, check=False)
        run(RUNTIME, "volume", "rm", "-f", f"{project}_other", check=False)
    # A dump failing halfway leaves nothing behind, not even the temporary files.
    fake = tmp_path / "runtime"
    fake.write_text(
        f'#!/bin/sh\ncase "$*" in *pg_dump*) echo partial; exit 1;; esac\nexec {RUNTIME} "$@"\n'
    )
    fake.chmod(0o700)
    out = tmp_path / "out"
    out.mkdir()
    failed = backup(legacy.instance, out, CONTAINER_RUNTIME=str(fake))
    assert failed.returncode != 0 and list(out.iterdir()) == []


def test_restore_verify_passes_on_complete_backup(legacy):
    result = restore_verify(legacy.dump)
    assert result.returncode == 0, result.stdout + result.stderr
    for check in (
        "checksum",
        "restore",
        "migrations",
        "manifest",
        "sessions_excluded",
        "owners",
        "no_public_grants",
        "audit_trigger",
        "audit_rejects_update",
    ):
        assert f"PASS  {check}" in result.stdout, check
    assert result.stdout.strip().endswith("RESULT: PASS")
    leftovers = run(RUNTIME, "ps", "-a", "--filter", "name=trilha-restore-verify", "-q")
    assert leftovers.stdout.strip() == ""


def test_restore_verify_rejects_tampered_or_incomplete_dump_cwe_354(legacy, tmp_path):
    def case(name, change):
        directory = tmp_path / name
        directory.mkdir()
        for path in legacy.backups.iterdir():
            shutil.copy(path, directory / path.name)
        dump = directory / legacy.dump.name
        change(dump, dump.with_suffix(".manifest"))
        return restore_verify(dump)

    def rewrite_checksums(dump, manifest):  # an attacker who can edit the dump can edit this too
        (dump.with_suffix(".sha256")).write_text(
            "".join(
                f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
                for path in (dump, manifest)
            )
        )

    def flip_byte(dump, manifest):
        data = bytearray(dump.read_bytes())
        data[len(data) // 2] ^= 0xFF
        dump.write_bytes(bytes(data))

    def truncate(dump, manifest):
        dump.write_bytes(dump.read_bytes()[: len(dump.read_bytes()) // 2])
        rewrite_checksums(dump, manifest)

    def miscount(dump, manifest):
        lines = manifest.read_text().splitlines()
        lines = [re.sub(r"\|(\d+)$", lambda m: f"|{int(m[1]) + 1}", line, count=1)
                 if line.startswith("assets_asset|") else line for line in lines]  # fmt: skip
        manifest.write_text("\n".join(lines) + "\n")
        rewrite_checksums(dump, manifest)

    tampered = case("flipped", flip_byte)
    assert tampered.returncode != 0 and "FAIL  checksum" in tampered.stdout
    assert "restore" not in tampered.stdout  # nothing was restored from it
    missing = case("missing", lambda dump, manifest: dump.with_suffix(".sha256").unlink())
    assert missing.returncode != 0 and "missing" in missing.stderr
    truncated = case("truncated", truncate)
    assert truncated.returncode != 0 and "FAIL  restore" in truncated.stdout
    miscounted = case("miscounted", miscount)
    assert miscounted.returncode != 0 and "FAIL  manifest: assets_asset rows" in miscounted.stdout


# SEC-19 / AC-F5 — in-place upgrade and recovery (T-20)


def test_upgrade_from_single_role_database_preserves_data_and_restricts_runtime_cwe_665(
    upgraded, tmp_path
):
    instance = upgraded.instance
    assert "db_grants_applied" in upgraded.applied.stdout
    with pytest.raises(psycopg.OperationalError):  # the owner password was rotated
        instance.connect(OWNER, password=upgraded.old_owner_password)
    with instance.connect("postgres") as superuser:
        assert fingerprint(superuser) == upgraded.before
        assert {row[1] for row in acl_snapshot(superuser)} == {OWNER}  # no owner changed
    with instance.connect(OWNER) as owner:
        assert db_privileges.drift(owner.cursor(), APP) == []
    with instance.connect(APP) as app:
        for statement in (
            "UPDATE audit_auditevent SET actor_label = 'forged'",
            "DELETE FROM audit_auditevent",
            "TRUNCATE audit_auditevent",
            "ALTER TABLE audit_auditevent DISABLE TRIGGER ALL",
        ):
            with pytest.raises(errors.InsufficientPrivilege):
                app.execute(statement)
    # A backup of the upgraded database restores with the runtime's restrictions intact.
    result = backup(instance, tmp_path)
    assert result.returncode == 0, result.stderr
    verified = restore_verify(next(tmp_path.glob("*.dump")))
    assert verified.returncode == 0, verified.stdout
    assert "PASS  runtime_cannot_modify_audit" in verified.stdout


def test_rollback_and_real_restore_recover_service_on_disposable_instances(
    upgraded, tmp_path_factory, django_db_blocker
):
    from django.db import transaction

    from apps.audit.context import audit_source
    from tests.test_assets_security import make_team

    instance = upgraded.instance
    # Application rollback: the previous release connects as the owner, with the rotated password.
    instance.manage("migrate", "--check")
    with django_connected(instance, OWNER, django_db_blocker), transaction.atomic():
        with audit_source("command"):
            make_team("rollback")  # an audited write, as the previous release performs it
        transaction.set_rollback(True)  # proven, then discarded: the data stays as backed up
    # Privilege rollback: the runtime role and all its privileges go; data and owners stay.
    rolled = instance.exec_script(ROLLBACK)  # compose exec -T db sh -s < rollback-runtime-role.sh
    assert rolled.returncode == 0, rolled.stderr
    with instance.connect("postgres") as superuser:
        assert superuser.execute(
            "SELECT count(*) FROM pg_roles WHERE rolname = %s", [APP]
        ).fetchone() == (0,)
        assert fingerprint(superuser) == upgraded.before
        assert {row[1] for row in acl_snapshot(superuser)} == {OWNER}
    # Real restore of the pre-upgrade backup into a fresh installation of the new release.
    target = Instance(tmp_path_factory.mktemp("restore-target"))
    try:
        restored = subprocess.run(
            [RUNTIME, "exec", "-i", target.name, "pg_restore", "-U", "postgres", "-d", DB,
             "--exit-on-error"],
            input=upgraded.dump.read_bytes(), capture_output=True, timeout=300, check=False,
        )  # fmt: skip
        assert restored.returncode == 0, restored.stderr[-1500:]
        assert "db_grants_applied" in target.manage("db_migrate").stdout
        with target.connect("postgres") as superuser:
            assert fingerprint(superuser) == upgraded.before
        with target.connect(APP) as app, pytest.raises(errors.InsufficientPrivilege):
            app.execute("UPDATE audit_auditevent SET actor_label = 'forged'")
    finally:
        target.remove()


# SPEC-0007 SEC-52 / AC-B5 — park and unpark for a code rollback below slice B (T-52)


def _parked_tables(connection):
    return connection.execute(
        "SELECT n.nspname, c.relname, pg_get_userbyid(c.relowner) FROM pg_class c"
        " JOIN pg_namespace n ON n.oid = c.relnamespace"
        " WHERE c.relkind = 'r' AND c.relname = ANY (%s) ORDER BY 2",
        [list(PARKED)],
    ).fetchall()


def _content(connection, schema):
    """Row count and a digest of every column of every row, per table."""
    return {
        table: connection.execute(
            sql.SQL(
                "SELECT count(*), md5(coalesce(string_agg(t::text, '|' ORDER BY t.id), ''))"
                " FROM {}.{} t"
            ).format(sql.Identifier(schema), sql.Identifier(table))
        ).fetchone()
        for table in PARKED
    }


def _structure(connection):
    return connection.execute(
        "SELECT r.relname, (SELECT count(*) FROM pg_constraint WHERE conrelid = r.oid),"
        " (SELECT count(*) FROM pg_index WHERE indrelid = r.oid),"
        " (SELECT string_agg(tgname || ':' || tgenabled::text, ',') FROM pg_trigger"
        "  WHERE tgrelid = r.oid AND NOT tgisinternal)"
        " FROM pg_class r WHERE r.relkind = 'r' AND r.relname = ANY (%s) ORDER BY 1",
        [list(PARKED)],
    ).fetchall()


def test_rollback_park_and_restore_preserve_rows_and_least_privilege_cwe_732(
    tmp_path_factory, django_db_blocker
):
    from apps.audit.context import audit_source
    from apps.findings.models import Finding
    from tests.test_findings_commands import comment

    instance = Instance(tmp_path_factory.mktemp("park"))
    try:
        assert "db_grants_applied" in instance.manage("db_migrate").stdout
        finding, _ = _finding_rows(instance, django_db_blocker)
        _finding_rows(instance, django_db_blocker)
        with django_connected(instance, APP, django_db_blocker), audit_source("command"):
            row = Finding.objects.select_related("reported_by").get(pk=finding)
            comment(row, row.reported_by, "kept byte for byte")
        with instance.connect("postgres") as superuser:
            content, structure = _content(superuser, "public"), _structure(superuser)
        assert content["findings_finding"][0] == 2 and content["findings_findinglogentry"][0] == 3

        # Unknown slices and actions are refused before anything happens.
        for args in (("park", "assets"), ("park",), ("drop", "findings"), ()):
            refused = instance.exec_script(PARK, *args)
            assert refused.returncode != 0, args
        with instance.connect("postgres") as superuser:
            assert {row[0] for row in _parked_tables(superuser)} == {"public"}

        parked = instance.exec_script(PARK, "park", "findings")
        assert parked.returncode == 0, parked.stderr
        assert "parked: findings_finding (2 rows)" in parked.stderr
        again = instance.exec_script(PARK, "park", "findings")
        assert again.returncode == 0 and "already parked" in again.stderr
        with instance.connect("postgres") as superuser:
            assert _parked_tables(superuser) == [
                ("trilha_parked", "findings_finding", OWNER),
                ("trilha_parked", "findings_findinglogentry", OWNER),
            ]
            assert _content(superuser, "trilha_parked") == content
            assert _structure(superuser) == structure  # constraints, indexes, trigger moved too
            public_grants = (
                superuser.execute(
                    "SELECT count(*) FROM pg_namespace n, aclexplode(n.nspacl) a"
                    " WHERE n.nspname = 'trilha_parked' AND a.grantee <> n.nspowner"
                ).fetchone()[0]
                + superuser.execute(
                    "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace,"
                    " aclexplode(c.relacl) a WHERE n.nspname = 'trilha_parked'"
                    " AND a.grantee <> c.relowner"
                ).fetchone()[0]
            )
            assert public_grants == 0  # neither the runtime role nor PUBLIC
        with instance.connect(APP) as app:
            assert app.execute(
                "SELECT has_schema_privilege('trilha_parked', 'USAGE')"
            ).fetchone() == (False,)
            for table in PARKED:
                with pytest.raises(errors.InsufficientPrivilege):
                    app.execute(
                        sql.SQL("SELECT 1 FROM trilha_parked.{}").format(sql.Identifier(table))
                    )

        # The previous release's db_migrate passes and grants nothing on the parked tables; this
        # release's would refuse until they are back.
        with instance.connect(OWNER) as owner:
            cursor = owner.cursor()
            assert db_privileges.refusal_reasons(cursor, APP, PREVIOUS_POLICY) == []
            with owner.transaction():
                db_privileges.apply(cursor, APP, PREVIOUS_POLICY)
            assert db_privileges.drift(cursor, APP, PREVIOUS_POLICY) == []
            assert (
                "classified tables that do not exist: findings_finding, findings_findinglogentry"
                in db_privileges.refusal_reasons(cursor, APP)
            )
        with instance.connect(APP) as app, pytest.raises(errors.InsufficientPrivilege):
            app.execute("SELECT 1 FROM trilha_parked.findings_findinglogentry")

        # Partial states and foreign objects are refused with nothing changed.
        with instance.connect("postgres") as superuser:
            superuser.execute("ALTER TABLE trilha_parked.findings_finding SET SCHEMA public")
            for action in ("park", "unpark"):
                partial = instance.exec_script(PARK, action, "findings")
                assert partial.returncode != 0 and "partial or unknown state" in partial.stderr
            superuser.execute("ALTER TABLE public.findings_finding SET SCHEMA trilha_parked")
            superuser.execute("CREATE TABLE trilha_parked.stray (id int)")
            stray = instance.exec_script(PARK, "unpark", "findings")
            assert stray.returncode != 0 and "other object" in stray.stderr
            superuser.execute("DROP TABLE trilha_parked.stray")
            assert {row[0] for row in _parked_tables(superuser)} == {"trilha_parked"}

        # Backups taken while parked list, count and verify the parked tables (AC-B5).
        backups = tmp_path_factory.mktemp("park-backups")
        result = backup(instance, backups)
        assert result.returncode == 0, result.stderr
        manifest = next(backups.glob("*.manifest")).read_text()
        assert f"trilha_parked.findings_finding|{OWNER}|" in manifest
        assert any(
            line.startswith("trilha_parked.findings_findinglogentry|") and line.endswith("|3")
            for line in manifest.splitlines()
        )
        verified = restore_verify(next(backups.glob("*.dump")))
        assert verified.returncode == 0, verified.stdout + verified.stderr
        assert "PASS  parked_tables_private" in verified.stdout
        assert "PASS  manifest" in verified.stdout

        # Roll forward: unpark, then this release's db_migrate re-applies the classes, no drift.
        unparked = instance.exec_script(PARK, "unpark", "findings")
        assert unparked.returncode == 0, unparked.stderr
        assert "unparked: findings_findinglogentry (3 rows)" in unparked.stderr
        again = instance.exec_script(PARK, "unpark", "findings")
        assert again.returncode == 0 and "already in public" in again.stderr
        assert "db_grants_applied" in instance.manage("db_migrate").stdout
        with instance.connect("postgres") as superuser:
            assert {row[0] for row in _parked_tables(superuser)} == {"public"}
            assert superuser.execute(
                "SELECT count(*) FROM pg_namespace WHERE nspname = 'trilha_parked'"
            ).fetchone() == (0,)
            assert _content(superuser, "public") == content
            assert _structure(superuser) == structure
        with instance.connect(OWNER) as owner:
            assert db_privileges.drift(owner.cursor(), APP) == []
        _finding_rows(instance, django_db_blocker)  # the runtime role works with them again
    finally:
        instance.remove()
