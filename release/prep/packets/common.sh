# shellcheck shell=sh
# Shared by the F1 and F3 server readings (release-packets). Sourced after the
# tool's exported inputs. Read-only: nothing here writes outside a private
# temporary directory, starts or stops a service, or changes the database.
set -u
R=${OW_ROOT:-}
SECRETS="$R/etc/openwatch/secrets.env"
WORK=$(mktemp -d) || exit 1
trap 'rm -rf -- "$WORK"' EXIT
trap 'rm -rf -- "$WORK"; exit 129' HUP
trap 'rm -rf -- "$WORK"; exit 130' INT
trap 'rm -rf -- "$WORK"; exit 143' TERM
failed=""
# Every section runs and is required; the script exits 1 naming each failure.
section() {
    title=$1
    shift
    echo "== $title"
    "$@"
    rc=$?
    echo "== exit $rc"
    [ "$rc" -eq 0 ] || failed="$failed
  $title (exit $rc)"
}
finish() {
    if [ -n "$failed" ]; then
        echo "$1: required sections failed:$failed" >&2
        exit 1
    fi
}
# The running service's own identity (VersionResponse). The tool checks its
# openwatch and commit fields, and openwatch --version's, against the candidate.
version_endpoint() {
    code=$(curl -sk --connect-timeout 3 --max-time 10 -o "$WORK/version.json" \
        -w '%{http_code}' "$OW_URL/api/v1/version") || return 1
    cat -- "$WORK/version.json"
    echo
    echo "http $code"
    [ "$code" = 200 ]
}
# psql as the service account, in a read-only transaction, stopping at the
# first error. SQL comes on standard input; -v NAME=VALUE pairs are bound as
# psql variables and quoted with :'NAME', never pasted into the SQL.
read_sql() {
    sudo -n -u openwatch sh -c 'set -a; . "$1"; set +a; shift
        exec psql "$OPENWATCH_DATABASE_DSN" -X -q -A -F " | " -P footer=off \
            -v ON_ERROR_STOP=1 -c "SET default_transaction_read_only = on" "$@"' \
        sh "$SECRETS" "$@"
}
