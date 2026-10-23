#!/bin/sh
# PostgreSQL provisioning for Trilha (SPEC-0013, ADR-0010). Idempotent and never destructive.
#   First start:      the image runs it from /docker-entrypoint-initdb.d.
#   Existing volume:  compose exec -T db sh /docker-entrypoint-initdb.d/01-provision.sh
# Creates or enforces the schema-owner and runtime roles, the application database and the
# database/schema privileges. It never changes an owner, drops anything or touches table data; table
# grants belong to `manage.py db_migrate`, which knows the per-table policy. Passwords are read inside
# psql with \getenv, so they never appear in a command line, and the session suppresses statement
# logging before any PASSWORD clause (CWE-532).
set -eu

psql -X -q -v ON_ERROR_STOP=1 -v VERBOSITY=terse -v SHOW_CONTEXT=never \
    --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
    -v app_db="$APP_DB_NAME" -v owner="$APP_DB_OWNER" -v runtime="$APP_DB_RUNTIME" <<'SQL'
SET log_statement = 'none';
SET log_min_error_statement = 'panic';
SET log_min_duration_statement = -1;
\getenv owner_password APP_DB_OWNER_PASSWORD
\getenv runtime_password APP_DB_RUNTIME_PASSWORD

SELECT (:'owner' ~ '^[a-z_][a-z0-9_]{0,62}$' AND :'runtime' ~ '^[a-z_][a-z0-9_]{0,62}$'
        AND :'app_db' ~ '^[a-z_][a-z0-9_]{0,62}$' AND :'owner' <> :'runtime'
        AND 'postgres' NOT IN (:'owner', :'runtime', :'app_db')
        AND :'owner' !~ '^pg_' AND :'runtime' !~ '^pg_'
        AND :'owner_password' <> '' AND :'runtime_password' <> ''
        AND :'owner_password' <> :'runtime_password')::int AS settings_ok \gset
\if :settings_ok
\else
    DO $$ BEGIN RAISE EXCEPTION 'provisioning refused: invalid names, or empty or identical passwords'; END $$;
\endif

-- An existing database must already belong to the owner: refuse before changing anything.
SELECT coalesce((SELECT (pg_get_userbyid(datdba) = :'owner')::int FROM pg_database
                 WHERE datname = :'app_db'), 1) AS owner_ok \gset
\if :owner_ok
\else
    DO $$ BEGIN RAISE EXCEPTION 'provisioning refused: the application database belongs to another role, and owners are never changed'; END $$;
\endif

SELECT format('CREATE ROLE %I', :'owner')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = :'owner') \gexec
SELECT format('CREATE ROLE %I', :'runtime')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = :'runtime') \gexec
ALTER ROLE :"owner" WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
    PASSWORD :'owner_password';
ALTER ROLE :"runtime" WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
    NOINHERIT PASSWORD :'runtime_password';
-- Neither role may hold another role's authority, whoever granted it.
SELECT format('REVOKE %I FROM %I GRANTED BY %I', granted.rolname, member.rolname, grantor.rolname)
FROM pg_auth_members m
JOIN pg_roles granted ON granted.oid = m.roleid
JOIN pg_roles member ON member.oid = m.member
JOIN pg_roles grantor ON grantor.oid = m.grantor
WHERE member.rolname IN (:'owner', :'runtime') \gexec

SELECT format('CREATE DATABASE %I OWNER %I', :'app_db', :'owner')
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = :'app_db') \gexec
REVOKE ALL ON DATABASE :"app_db" FROM PUBLIC;
REVOKE ALL ON DATABASE :"app_db" FROM :"runtime";
GRANT CONNECT ON DATABASE :"app_db" TO :"runtime";
REVOKE CONNECT, TEMPORARY ON DATABASE postgres, template1 FROM PUBLIC;

\connect :"app_db"
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM :"runtime";
GRANT USAGE ON SCHEMA public TO :"runtime";
SQL
