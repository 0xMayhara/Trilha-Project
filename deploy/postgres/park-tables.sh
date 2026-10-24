#!/bin/sh
# Code rollback below a release that created tables (SPEC-0007 Migration / Rollback, SEC-52;
# ADR-0008 §6). An older release's db_migrate refuses tables its privilege policy does not classify,
# so before it starts, this script moves the fixed tables of one slice from `public` into the
# owner-only schema `trilha_parked`; before rolling forward again it moves them back, and the newer
# db_migrate re-applies their privilege classes. Stop backend and worker first. Piped in, because a
# script in the mounted initdb directory would run on every first start:
#   compose exec -T db sh -s park findings   < deploy/postgres/park-tables.sh
#   compose exec -T db sh -s unpark findings < deploy/postgres/park-tables.sh
# One transaction, as the image superuser over the container's local socket. Rows, owners,
# constraints, indexes, foreign keys and triggers move unchanged; no row is read or rewritten. While
# parked, the runtime role and PUBLIC hold no privilege on the schema or the tables. Unknown slices,
# partial states and a schema holding anything else are refused with nothing changed; repeating a
# completed action changes nothing. Prints table names and row counts, never row data.
set -eu

usage="usage: sh -s park|unpark <slice> < park-tables.sh (slices: findings)"
case "${2:-}" in
    findings) tables="findings_finding findings_findinglogentry" ;;
    *) echo "error: unknown slice; $usage" >&2; exit 2 ;;
esac
case "${1:-}" in
    park | unpark) action=$1 ;;
    *) echo "error: $usage" >&2; exit 2 ;;
esac
owner=${APP_DB_OWNER:-${APP_DB_USER:-}}
runtime=${APP_DB_RUNTIME:-}
if [ -z "$owner" ] || [ -z "$runtime" ] || [ -z "${APP_DB_NAME:-}" ]; then
    echo "error: APP_DB_NAME, APP_DB_OWNER and APP_DB_RUNTIME must be set in the db container" >&2
    exit 2
fi

psql -X -q -v ON_ERROR_STOP=1 -v VERBOSITY=terse -v SHOW_CONTEXT=never \
    --username "$POSTGRES_USER" --dbname "$APP_DB_NAME" \
    -v action="$action" -v tables="$tables" -v owner="$owner" -v runtime="$runtime" <<'SQL'
BEGIN;
SET LOCAL trilha.park_action = :'action';
SET LOCAL trilha.park_tables = :'tables';
SET LOCAL trilha.park_owner = :'owner';
SET LOCAL trilha.park_runtime = :'runtime';
SET LOCAL lock_timeout = '5s';
DO $$
DECLARE
    action text := current_setting('trilha.park_action');
    wanted text[] := string_to_array(current_setting('trilha.park_tables'), ' ');
    owner_role text := current_setting('trilha.park_owner');
    runtime_role text := current_setting('trilha.park_runtime');
    in_public int;
    in_parked int;
    foreign_objects int;
    rows bigint;
    t text;
BEGIN
    IF (SELECT count(*) FROM pg_roles WHERE rolname IN (owner_role, runtime_role)) <> 2 THEN
        RAISE EXCEPTION 'refused: the owner or runtime role does not exist';
    END IF;
    SELECT count(*) INTO in_public FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relname = ANY (wanted);
    SELECT count(*) INTO in_parked FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'trilha_parked' AND c.relkind = 'r' AND c.relname = ANY (wanted);
    -- Anything in the schema other than these tables and the indexes that moved with them.
    SELECT count(*) INTO foreign_objects FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'trilha_parked'
      AND NOT (c.relkind = 'r' AND c.relname = ANY (wanted))
      AND NOT (c.relkind = 'i' AND EXISTS (
          SELECT FROM pg_index i JOIN pg_class r ON r.oid = i.indrelid
          WHERE i.indexrelid = c.oid AND r.relnamespace = n.oid AND r.relname = ANY (wanted)));
    foreign_objects := foreign_objects + (SELECT count(*) FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'trilha_parked');
    IF foreign_objects > 0 THEN
        RAISE EXCEPTION 'refused: trilha_parked holds % other object(s)', foreign_objects;
    END IF;

    IF action = 'park' THEN
        IF in_parked = cardinality(wanted) AND in_public = 0 THEN
            RAISE NOTICE 'already parked: %', array_to_string(wanted, ' ');
            RETURN;
        END IF;
        IF in_public <> cardinality(wanted) OR in_parked <> 0 THEN
            RAISE EXCEPTION 'refused: partial or unknown state (% of % tables in public, % parked)',
                in_public, cardinality(wanted), in_parked;
        END IF;
        EXECUTE format('CREATE SCHEMA IF NOT EXISTS trilha_parked AUTHORIZATION %I', owner_role);
        EXECUTE format('REVOKE ALL ON SCHEMA trilha_parked FROM PUBLIC, %I', runtime_role);
        FOREACH t IN ARRAY wanted LOOP
            EXECUTE format('ALTER TABLE public.%I SET SCHEMA trilha_parked', t);
            EXECUTE format('REVOKE ALL ON TABLE trilha_parked.%I FROM PUBLIC, %I', t, runtime_role);
            EXECUTE format('SELECT count(*) FROM trilha_parked.%I', t) INTO rows;
            RAISE NOTICE 'parked: % (% rows)', t, rows;
        END LOOP;
    ELSE
        IF in_public = cardinality(wanted) AND in_parked = 0 THEN
            DROP SCHEMA IF EXISTS trilha_parked;
            RAISE NOTICE 'already in public: %', array_to_string(wanted, ' ');
            RETURN;
        END IF;
        IF in_parked <> cardinality(wanted) OR in_public <> 0 THEN
            RAISE EXCEPTION 'refused: partial or unknown state (% of % tables parked, % in public)',
                in_parked, cardinality(wanted), in_public;
        END IF;
        FOREACH t IN ARRAY wanted LOOP
            EXECUTE format('ALTER TABLE trilha_parked.%I SET SCHEMA public', t);
            EXECUTE format('SELECT count(*) FROM public.%I', t) INTO rows;
            RAISE NOTICE 'unparked: % (% rows); run db_migrate to re-apply its grants', t, rows;
        END LOOP;
        DROP SCHEMA trilha_parked;  -- RESTRICT: refuses unless empty
    END IF;
END
$$;
COMMIT;
SQL
