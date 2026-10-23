#!/bin/sh
# Optional privilege rollback for SPEC-0013: removes the runtime role and every privilege it holds.
# Never touches data or owners. Point backend and worker back at the owner credentials (the previous
# release) first, then run it as the image's superuser. It is piped in because a script in the
# mounted initdb directory would run on every first start:
#   compose exec -T db sh -s < deploy/postgres/rollback-runtime-role.sh
set -eu

psql -X -q -v ON_ERROR_STOP=1 -v VERBOSITY=terse --username "$POSTGRES_USER" --dbname "$APP_DB_NAME" \
    -v app_db="$APP_DB_NAME" -v runtime="${APP_DB_RUNTIME:?APP_DB_RUNTIME is not set}" <<'SQL'
SELECT EXISTS (SELECT FROM pg_roles WHERE rolname = :'runtime')::int AS present \gset
\if :present
    REVOKE ALL ON ALL TABLES IN SCHEMA public FROM :"runtime";
    REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM :"runtime";
    REVOKE ALL ON SCHEMA public FROM :"runtime";
    REVOKE ALL ON DATABASE :"app_db" FROM :"runtime";
    DROP ROLE :"runtime";
\endif
SQL
