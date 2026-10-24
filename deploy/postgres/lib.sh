# Shared by backup.sh and restore-verify.sh (SPEC-0013). Sourced, never executed.

fail() {
    echo "error: $*" >&2
    exit 1
}

# CONTAINER_RUNTIME overrides; otherwise podman, then docker.
container_runtime() {
    if [ -n "${CONTAINER_RUNTIME:-}" ]; then
        echo "$CONTAINER_RUNTIME"
        return
    fi
    for candidate in podman docker; do
        if command -v "$candidate" >/dev/null 2>&1; then
            echo "$candidate"
            return
        fi
    done
    fail "no container runtime (podman or docker) found"
}

# The db container of exactly one Compose project. Nothing is inferred from the working directory:
# the project is explicit, the container is found by its Compose labels, and it must mount
# <project>_db-data (SPEC-0013 D-11). Prints the container ID; reports the target on stderr.
db_container() {
    printf '%s' "$1" | grep -Eq '^[a-z0-9][a-z0-9_-]*$' || fail "invalid Compose project name"
    ids=$($RUNTIME ps --filter "label=com.docker.compose.project=$1" \
        --filter "label=com.docker.compose.service=db" --format '{{.ID}}')
    [ -n "$ids" ] || fail "no running db container in Compose project $1"
    [ "$(printf '%s\n' "$ids" | wc -l)" -eq 1 ] || fail "more than one db container in project $1"
    volume=$($RUNTIME inspect --format \
        '{{range .Mounts}}{{if eq .Destination "/var/lib/postgresql"}}{{.Name}}{{end}}{{end}}' "$ids")
    [ "$volume" = "$1_db-data" ] || fail "db container of $1 mounts '$volume', expected $1_db-data"
    echo "target: project=$1 container=$($RUNTIME inspect --format '{{.Name}}' "$ids") volume=$volume" >&2
    echo "$ids"
}

# One line per application table: table|owner|acl|rows. A NULL ACL is written as the owner-only
# default it means, because pg_dump does not reproduce an explicit ACL equal to that default.
# Sessions are excluded from backups, so their count is recorded as "excluded" (restored empty).
# Tables parked for a rollback (park-tables.sh, SPEC-0007) are listed as trilha_parked.<table>.
MANIFEST_SQL="SELECT CASE WHEN n.nspname = 'public' THEN c.relname ELSE n.nspname || '.' || c.relname END,
    pg_get_userbyid(c.relowner), coalesce(c.relacl, acldefault('r', c.relowner))::text,
    CASE WHEN c.relname = 'django_session' THEN 'excluded' ELSE
    (xpath('/row/n/text()', query_to_xml(format('SELECT count(*) AS n FROM %I.%I',
        n.nspname, c.relname), false, true, '')))[1]::text END
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname IN ('public', 'trilha_parked') AND c.relkind IN ('r', 'p') ORDER BY 1;"
