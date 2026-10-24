"""Runtime database privileges (SPEC-0013, ADR-0010).

The runtime role (Django and Celery) owns nothing. Every table of the application schema is named
below with the exact privileges the runtime holds on it; `manage.py db_migrate`, run by the schema
owner, re-applies them after every migration. There is no default class: an unclassified table, or
an entry whose table no longer exists, stops the deployment with every grant unchanged (fail
closed). A new table is classified in the same commit as the migration that creates it."""

import re

from psycopg import sql

SCHEMA = "public"
STANDARD = ("SELECT", "INSERT", "UPDATE", "DELETE")
UPDATABLE = ("SELECT", "INSERT", "UPDATE")  # SPEC-0007: records that change but are never removed
APPEND_ONLY = ("SELECT", "INSERT")
NO_ACCESS = ()

TABLE_PRIVILEGES = {
    "accounts_user": STANDARD,
    "accounts_user_groups": STANDARD,
    "accounts_user_user_permissions": STANDARD,
    "assets_asset": STANDARD,
    "audit_auditevent": APPEND_ONLY,  # SPEC-0002: recorded events are never changed or removed
    "auth_group": STANDARD,
    "auth_group_permissions": STANDARD,
    "auth_permission": STANDARD,
    "django_content_type": STANDARD,
    "django_migrations": NO_ACCESS,  # migration state belongs to the schema owner
    "django_session": STANDARD,
    "findings_finding": UPDATABLE,  # SPEC-0007: findings are business records, never deleted
    # SPEC-0007: the logbook is append-only; trigger findings_logentry_append_only also binds owners
    "findings_findinglogentry": APPEND_ONLY,
    "rbac_platformaccess": STANDARD,
    "rbac_role": STANDARD,
    "rbac_role_permissions": STANDARD,
    "rbac_roleassignment": STANDARD,
    "teams_membership": STANDARD,
    "teams_team": STANDARD,
}

# Every table privilege of PostgreSQL 18: anything outside a table's class must be absent.
TABLE_PRIVILEGE_NAMES = (
    "SELECT",
    "INSERT",
    "UPDATE",
    "DELETE",
    "TRUNCATE",
    "REFERENCES",
    "TRIGGER",
    "MAINTAIN",
)
SEQUENCE_PRIVILEGE_NAMES = ("USAGE", "SELECT", "UPDATE")
ROLE_NAME = re.compile(r"[a-z_][a-z0-9_]{0,62}")

_NOT_OWNED = """
    SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = %(schema)s AND pg_get_userbyid(c.relowner) <> current_user
    UNION ALL
    SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = %(schema)s AND pg_get_userbyid(p.proowner) <> current_user
    ORDER BY 1
"""
_TABLES = """
    SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = %(schema)s AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
"""
_TABLE_GRANTS = """
    SELECT c.relname, p.name FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    CROSS JOIN unnest(%(names)s::text[]) AS p(name)
    WHERE n.nspname = %(schema)s AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
      AND has_table_privilege(%(role)s, c.oid, p.name)
"""
_SEQUENCE_GRANTS = """
    SELECT c.relname, p.name FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    CROSS JOIN unnest(%(names)s::text[]) AS p(name)
    WHERE n.nspname = %(schema)s AND c.relkind = 'S'
      AND has_sequence_privilege(%(role)s, c.oid, p.name)
"""
_ROLE_FLAGS = """
    SELECT r.rolsuper, r.rolcreaterole, r.rolcreatedb, r.rolreplication, r.rolbypassrls,
        EXISTS (SELECT FROM pg_auth_members m WHERE m.member = r.oid),
        EXISTS (SELECT FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = %(schema)s AND c.relowner = r.oid),
        EXISTS (SELECT FROM pg_database d
                WHERE d.datname = current_database() AND d.datdba = r.oid),
        has_schema_privilege(r.oid, %(schema)s, 'CREATE'),
        has_database_privilege(r.oid, current_database(), 'TEMPORARY')
    FROM pg_roles r WHERE r.rolname = current_user
"""
_ROLE_FLAG_NAMES = (
    "superuser",
    "createrole",
    "createdb",
    "replication",
    "bypassrls",
    "role_member",
    "owns_objects",
    "owns_database",
    "schema_create",
    "temporary",
)
_WRITABLE_APPEND_ONLY = """
    SELECT t FROM unnest(%(tables)s::text[]) AS t
    WHERE has_table_privilege(current_user, to_regclass(format('%%I.%%I', %(schema)s, t)),
                              'UPDATE, DELETE, TRUNCATE')
"""


def _grants(cursor, query, role, names):
    cursor.execute(query, {"schema": SCHEMA, "role": role, "names": list(names)})
    granted = {}
    for relation, privilege in cursor.fetchall():
        granted.setdefault(relation, set()).add(privilege)
    return granted


def refusal_reasons(cursor, runtime, policy=TABLE_PRIVILEGES):
    """Why grants must not be applied: unsafe principals, ownership drift or an incomplete policy.
    Object names only, never values."""
    if not ROLE_NAME.fullmatch(runtime):
        return ["invalid runtime role name"]
    cursor.execute(
        "SELECT r.rolsuper, current_user = %(runtime)s, EXISTS ("
        " SELECT FROM pg_roles x WHERE x.rolname = %(runtime)s AND NOT x.rolsuper)"
        " FROM pg_roles r WHERE r.rolname = current_user",
        {"runtime": runtime},
    )
    superuser, same, runtime_ok = cursor.fetchone()
    reasons = []
    if superuser:
        reasons.append("the migrating role is a superuser")
    if same:
        reasons.append("the runtime role is the migrating role")
    if not runtime_ok:
        reasons.append("the runtime role is missing or a superuser")
    cursor.execute(_NOT_OWNED, {"schema": SCHEMA})
    if foreign := [row[0] for row in cursor.fetchall()]:
        reasons.append("not owned by the migrating role: " + ", ".join(foreign))
    cursor.execute(_TABLES, {"schema": SCHEMA})
    tables = {row[0] for row in cursor.fetchall()}
    if unclassified := sorted(tables - policy.keys()):
        reasons.append("unclassified tables: " + ", ".join(unclassified))
    if stale := sorted(policy.keys() - tables):
        reasons.append("classified tables that do not exist: " + ", ".join(stale))
    return reasons


def drift(cursor, runtime, policy=TABLE_PRIVILEGES):
    """Differences between effective privileges and the policy, for the runtime role and PUBLIC."""
    differences = []
    tables = _grants(cursor, _TABLE_GRANTS, runtime, TABLE_PRIVILEGE_NAMES)
    cursor.execute(_TABLES, {"schema": SCHEMA})
    for table in sorted(row[0] for row in cursor.fetchall()):
        granted, wanted = tables.get(table, set()), set(policy.get(table, ()))
        if granted != wanted:
            differences.append(f"{table}: runtime {sorted(granted)}, policy {sorted(wanted)}")
    for table, granted in sorted(
        _grants(cursor, _TABLE_GRANTS, "public", TABLE_PRIVILEGE_NAMES).items()
    ):
        differences.append(f"{table}: PUBLIC {sorted(granted)}")
    for role in (runtime, "public"):
        for sequence, granted in sorted(
            _grants(cursor, _SEQUENCE_GRANTS, role, SEQUENCE_PRIVILEGE_NAMES).items()
        ):
            differences.append(f"{sequence}: {role} {sorted(granted)}")
    return differences


def apply(cursor, runtime, policy=TABLE_PRIVILEGES):
    """Revoke everything from the runtime role and PUBLIC, then grant each class. The caller holds
    one transaction, so readers see the old or the new privileges, never none."""
    role, schema = sql.Identifier(runtime), sql.Identifier(SCHEMA)
    for kind in ("TABLES", "SEQUENCES"):
        cursor.execute(
            sql.SQL("REVOKE ALL ON ALL {} IN SCHEMA {} FROM {}, PUBLIC").format(
                sql.SQL(kind), schema, role
            )
        )
    by_class = {}
    for table, privileges in policy.items():
        if privileges:
            by_class.setdefault(privileges, []).append(table)
    for privileges, tables in by_class.items():
        cursor.execute(
            sql.SQL("GRANT {} ON TABLE {} TO {}").format(
                sql.SQL(", ").join(sql.SQL(privilege) for privilege in privileges),
                sql.SQL(", ").join(sql.Identifier(SCHEMA, table) for table in sorted(tables)),
                role,
            )
        )


def runtime_role_failures(cursor):
    """Names of the checks the connected role fails as a restricted runtime role (SEC-11)."""
    cursor.execute(_ROLE_FLAGS, {"schema": SCHEMA})
    row = cursor.fetchone()
    if row is None:
        return ["unknown_role"]
    failures = [name for name, failed in zip(_ROLE_FLAG_NAMES, row, strict=True) if failed]
    append_only = sorted(
        t for t, privileges in TABLE_PRIVILEGES.items() if privileges == APPEND_ONLY
    )
    cursor.execute(_WRITABLE_APPEND_ONLY, {"schema": SCHEMA, "tables": append_only})
    failures += [f"append_only_writable:{row[0]}" for row in cursor.fetchall()]
    return failures
