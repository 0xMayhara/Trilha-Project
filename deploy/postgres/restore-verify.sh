#!/bin/sh
# Restore verification (SPEC-0013 FR-05): restores a backup into a disposable PostgreSQL container
# (same image digest as compose.yaml, no network, no volume, random throwaway passwords passed in an
# env file), checks it, prints PASS/FAIL per check and removes the container. Never touches a Compose
# project or its volumes.
#   deploy/postgres/restore-verify.sh <dir>/trilha-<UTC>.dump
set -eu
umask 077
here=$(cd "$(dirname "$0")" && pwd)
. "$here/lib.sh"

[ $# -eq 1 ] || fail "usage: $0 <dir>/trilha-<UTC>.dump"
dir=$(cd "$(dirname "$1")" && pwd)
base=$(basename "$1" .dump)
for part in dump manifest sha256; do
    [ -f "$dir/$base.$part" ] || fail "missing $dir/$base.$part"
done
RUNTIME=$(container_runtime)
status=0
check() {
    if [ "$2" = ok ]; then echo "PASS  $1"; else echo "FAIL  $1${3:+: $3}"; status=1; fi
}

# 1. Integrity first: nothing is restored from a file that does not match its checksum.
if [ "$(wc -l < "$dir/$base.sha256")" -eq 2 ] \
    && grep -q "  $base.dump\$" "$dir/$base.sha256" && grep -q "  $base.manifest\$" "$dir/$base.sha256" \
    && (cd "$dir" && sha256sum --check --status "$base.sha256"); then
    check checksum ok
else
    check checksum fail "dump or manifest does not match $base.sha256"
    echo "RESULT: FAIL"
    exit 1
fi

header=$(head -n 1 "$dir/$base.manifest")
database=$(printf '%s' "$header" | sed -n 's/^# database=\([a-z0-9_]*\) .*/\1/p')
owner=$(printf '%s' "$header" | sed -n 's/.* owner=\([a-z0-9_]*\) .*/\1/p')
runtime=$(printf '%s' "$header" | sed -n 's/.* runtime=\([a-z0-9_]*\)$/\1/p')
[ -n "$database" ] && [ -n "$owner" ] || fail "manifest header is malformed"
image=$(sed -n 's/^ *image: \(docker\.io\/library\/postgres:[^ ]*@sha256:[0-9a-f]\{64\}\)$/\1/p' \
    "$here/../../compose.yaml")
[ "$(printf '%s\n' "$image" | grep -c .)" -eq 1 ] || fail "cannot read the PostgreSQL image from compose.yaml"

random() { od -An -N 24 -tx1 /dev/urandom | tr -d ' \n'; }
work=$(mktemp -d)
name="trilha-restore-verify-$$"
trap '$RUNTIME rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$work"' EXIT
cat > "$work/env" <<ENV
POSTGRES_PASSWORD=$(random)
APP_DB_NAME=$database
APP_DB_OWNER=$owner
APP_DB_OWNER_PASSWORD=$(random)
APP_DB_RUNTIME=${runtime:-restore_runtime}
APP_DB_RUNTIME_PASSWORD=$(random)
ENV
$RUNTIME run -d --rm --name "$name" --network none --user postgres --env-file "$work/env" \
    -v "$here/init:/docker-entrypoint-initdb.d:ro,z" "$image" > /dev/null
rm -f "$work/env"
tries=0
until $RUNTIME logs "$name" 2>&1 | grep -q 'init process complete' \
    && $RUNTIME exec "$name" pg_isready -q -U postgres 2>/dev/null; do
    tries=$((tries + 1))
    [ "$tries" -lt 120 ] || fail "disposable PostgreSQL did not start"
    sleep 1
done
sql() { $RUNTIME exec -i "$name" psql -X -q -At -F '|' -v ON_ERROR_STOP=1 -U "${2:-postgres}" -d "$database" -c "$1"; }

# 2. Restore, stopping at the first error.
if $RUNTIME exec -i "$name" pg_restore -U postgres -d "$database" --exit-on-error < "$dir/$base.dump" \
    > "$work/restore.log" 2>&1; then
    check restore ok
else
    check restore fail "$(grep -m 1 -i 'error' "$work/restore.log" || echo 'pg_restore failed')"
    echo "RESULT: FAIL"
    exit 1
fi

# 3. Migration state: every recorded application migration exists in the checked-out code.
missing=""
for entry in $(sql "SELECT app || '/' || name FROM django_migrations
                    WHERE app IN ('accounts', 'assets', 'audit', 'rbac', 'teams')"); do
    # Names come from the (untrusted) dump: only app/0001_name shapes ever become a path.
    if ! printf '%s' "$entry" | grep -Eq '^[a-z]+/[0-9]{4}_[a-z0-9_]+$' \
        || [ ! -f "$here/../../backend/apps/${entry%%/*}/migrations/${entry#*/}.py" ]; then
        missing="$missing $entry"
    fi
done
if [ -z "$missing" ]; then check migrations ok; else check migrations fail "newer than this code:$missing"; fi

# 4. Owners, ACLs and row counts against the manifest ("-" = unknown, "excluded" = restored empty).
printf '%s\n' "$MANIFEST_SQL" | $RUNTIME exec -i "$name" \
    psql -X -q -At -F '|' -v ON_ERROR_STOP=1 -U postgres -d "$database" > "$work/restored"
differences=$(tail -n +2 "$dir/$base.manifest" | awk -F '|' 'NR == FNR { got[$1] = $0; next }
    { line = got[$1]; split(line, r, "|")
      if (line == "") { print $1 " missing"; next }
      if (r[2] != $2 || r[3] != $3) print $1 " owner/acl"
      if ($4 == "excluded" && r[4] != "excluded") print $1 " rows"
      if ($4 != "-" && $4 != "excluded" && r[4] != $4) print $1 " rows" }' "$work/restored" -)
if [ -z "$differences" ]; then check manifest ok; else check manifest fail "$(echo $differences)"; fi
excluded=$(sql "SELECT count(*) FROM django_session")
if [ "$excluded" = 0 ]; then check sessions_excluded ok; else check sessions_excluded fail "$excluded"; fi

# 5. Ownership and grants.
foreign=$(sql "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
               WHERE n.nspname = 'public' AND pg_get_userbyid(c.relowner) <> '$owner'")
if [ "$foreign" = 0 ]; then check owners ok; else check owners fail "$foreign objects"; fi
public=$(sql "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace,
               aclexplode(c.relacl) a WHERE n.nspname = 'public' AND a.grantee = 0")
if [ "$public" = 0 ]; then check no_public_grants ok; else check no_public_grants fail "$public"; fi

# 6. Audit protection: the trigger is present and rejects an update, even for the superuser.
trigger=$(sql "SELECT count(*) FROM pg_trigger WHERE tgrelid = 'audit_auditevent'::regclass
               AND tgname = 'audit_auditevent_append_only' AND tgenabled = 'O'")
if [ "$trigger" = 1 ]; then check audit_trigger ok; else check audit_trigger fail "missing or disabled"; fi
if sql "BEGIN;
        INSERT INTO audit_auditevent (event_id, occurred_at, actor_type, actor_label, action, outcome,
            resource_type, resource_id, source, changes, metadata)
        VALUES (gen_random_uuid(), now(), 'system', 'restore-verify', 'restore.verify_probe',
            'success', '', '', 'command', '{}', '{}');
        UPDATE audit_auditevent SET actor_label = 'x' WHERE action = 'restore.verify_probe';
        ROLLBACK;" > "$work/probe.log" 2>&1; then
    check audit_rejects_update fail "an audit row was updated"
elif grep -q 'append-only' "$work/probe.log"; then
    check audit_rejects_update ok
else
    check audit_rejects_update fail "probe did not run: $(tail -n 1 "$work/probe.log")"
fi

# 7. Logged in as the runtime role itself, audit rows cannot be changed or truncated.
if [ -n "$runtime" ]; then
    who=$(sql "SELECT session_user" "$runtime")
    if [ "$who" = "$runtime" ] \
        && ! sql "UPDATE audit_auditevent SET actor_label = actor_label" "$runtime" > /dev/null 2>&1 \
        && ! sql "TRUNCATE audit_auditevent" "$runtime" > /dev/null 2>&1; then
        check runtime_cannot_modify_audit ok
    else
        check runtime_cannot_modify_audit fail "as $who"
    fi
fi

if [ "$status" = 0 ]; then echo "RESULT: PASS"; else echo "RESULT: FAIL"; fi
exit "$status"
