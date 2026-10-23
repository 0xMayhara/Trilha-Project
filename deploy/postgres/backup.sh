#!/bin/sh
# Logical backup of the Trilha database (SPEC-0013 FR-05).
#   deploy/postgres/backup.sh --project <compose-project> <output-dir>
# Writes trilha-<UTC>.dump (pg_dump custom format, session data excluded), .manifest (owner, ACL and
# row count per table) and .sha256, all mode 0600, outside any git work tree. Runs pg_dump as the
# image's superuser over the container's local socket: no password is stored, passed or printed.
# The checksum detects corruption, not deliberate tampering: keep a copy of it elsewhere or sign it.
set -eu
umask 077
. "$(dirname "$0")/lib.sh"

[ $# -eq 3 ] && [ "$1" = "--project" ] || fail "usage: $0 --project <compose-project> <output-dir>"
out=$3
[ -d "$out" ] || fail "output directory does not exist"
# Walk up to the root rather than ask git, which may be missing: a missing tool must not let a dump
# land in a checkout.
dir=$(cd "$out" && pwd -P)
while :; do
    [ ! -e "$dir/.git" ] || fail "refusing to write a backup inside a git work tree"
    [ "$dir" != / ] || break
    dir=$(dirname "$dir")
done
RUNTIME=$(container_runtime)
db=$(db_container "$2")
name="trilha-$(date -u +%Y%m%dT%H%M%SZ)"
[ ! -e "$out/$name.dump" ] || fail "$name.dump already exists; wait a second and retry"
tmp="$out/.$name.partial"
trap 'rm -f "$tmp".*' EXIT

# Inside the container only constant commands run; names come from its environment, which carries
# the pre-SPEC-0013 variables (APP_DB_USER) or the current ones (APP_DB_OWNER, APP_DB_RUNTIME).
in_db() { $RUNTIME exec -i "$db" sh -c "$1"; }
manifest() {
    printf '%s\n' "$MANIFEST_SQL" | in_db \
        'psql -X -q -At -F "|" -v ON_ERROR_STOP=1 --username postgres --dbname "$APP_DB_NAME"'
}

in_db 'echo "# database=$APP_DB_NAME owner=${APP_DB_OWNER:-$APP_DB_USER} runtime=${APP_DB_RUNTIME:-}"' \
    > "$tmp.header"
manifest > "$tmp.before"
in_db 'pg_dump --username postgres --dbname "$APP_DB_NAME" --format custom \
    --exclude-table-data django_session' > "$tmp.dump"
manifest > "$tmp.after"
in_db 'pg_restore --list' < "$tmp.dump" > /dev/null || fail "pg_dump produced an unreadable archive"

# A count that changed while the database was in use is recorded as unknown ("-").
{
    cat "$tmp.header"
    awk -F '|' -v OFS='|' 'NR == FNR { after[$1] = $0; next }
        { if (after[$1] != $0) $4 = "-"; print }' "$tmp.after" "$tmp.before"
} > "$tmp.manifest"
for part in dump manifest; do
    printf '%s  %s\n' "$(sha256sum < "$tmp.$part" | cut -d ' ' -f 1)" "$name.$part"
done > "$tmp.sha256"
mv "$tmp.dump" "$out/$name.dump"
mv "$tmp.manifest" "$out/$name.manifest"
mv "$tmp.sha256" "$out/$name.sha256"

echo "backup: $out/$name.dump ($(wc -c < "$out/$name.dump") bytes)"
echo "sha256: $(cut -d ' ' -f 1 "$out/$name.sha256" | head -n 1)"
if grep -q '|-$' "$out/$name.manifest"; then
    echo "note: rows changed during the dump; restore-verify compares those counts loosely"
fi
