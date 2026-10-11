# shellcheck shell=sh
# Shared by the upgrade phase scripts (release-upgrade-steps). Sourced, not run.
# Each step prints its command's raw output and an "== exit N" line. step()
# stops the phase at the first failure, so nothing after a failed step runs.
# There are no pipes: POSIX sh has no pipefail, and a pipe would hide a
# required command's status.
#
# OW_ROOT prefixes the file paths read here. It is empty on a real host and is
# set only by the tests, which supply a fake root.
set -u
R=${OW_ROOT:-}
SECRETS="$R/etc/openwatch/secrets.env"

step() {
    title=$1
    shift
    echo "== $title"
    "$@"
    rc=$?
    echo "== exit $rc"
    if [ "$rc" -ne 0 ]; then
        echo "STOPPED at: $title (exit $rc)" >&2
        stopped "$title"
        exit 1
    fi
}

# Overridden by a phase that has something specific to say when it stops.
stopped() { :; }

# The first step of every phase that changes the host: this connection reaches
# the machine the verified preflight examined. The expected values come from
# that preflight capture, not from the command line.
identity_check() {
    if [ -z "${OW_EXPECT_MACHINE_ID:-}" ] || [ -z "${OW_EXPECT_HOSTNAME:-}" ]; then
        echo "no expected identity was given" >&2
        return 1
    fi
    mid=$(cat -- "$R/etc/machine-id") || return 1
    hn=$(hostname) || return 1
    echo "machine-id $mid (expected $OW_EXPECT_MACHINE_ID)"
    echo "hostname $hn (expected $OW_EXPECT_HOSTNAME)"
    if [ "$mid" != "$OW_EXPECT_MACHINE_ID" ] || [ "$hn" != "$OW_EXPECT_HOSTNAME" ]; then
        echo "This is not the host the preflight examined. Nothing was changed." >&2
        return 1
    fi
}

# Run a command as the openwatch user with the service's environment.
as_openwatch() {
    sudo -n -u openwatch sh -c 'set -a; . "$1"; set +a; shift; exec "$@"' sh "$SECRETS" "$@"
}

# Run a command as root with the database DSN from the service's environment.
with_dsn() {
    ( set -a; . "$SECRETS"; set +a; "$@" )
}

# The JSON endpoints, read by their schemas in api/openapi.yaml. The caller
# sets JSON to a private file. fetch_json prints the body and HTTP status and
# succeeds only on 200; a 503 carries an ErrorEnvelope, not a HealthResponse.
fetch_json() {
    code=$(curl -sk --connect-timeout 3 --max-time 10 -o "$JSON" -w '%{http_code}' "$OW_URL/api/v1/$1") || return 1
    cat -- "$JSON"
    echo
    echo "http $code"
    [ "$code" = 200 ]
}
# check_json ENDPOINT: the body's required fields, and the release it reports.
#   health   HealthResponse: status "healthy", db_connected true, version
#   version  VersionResponse: openwatch (there is no "version" field)
check_json() {
    python3 - "$1" "$JSON" "$OW_VERSION" <<'PY'
import json, sys
endpoint, path, want = sys.argv[1:]
try:
    with open(path) as f:
        d = json.load(f)
except ValueError as e:
    sys.exit("%s: the body is not JSON: %s" % (endpoint, e))
if not isinstance(d, dict):
    sys.exit("%s: the body is not a JSON object" % endpoint)
if endpoint == "health":
    need = {"status": "healthy", "db_connected": True, "version": want}
else:
    need = {"openwatch": want}
    for k in ("kensa", "go", "commit", "build_time"):
        print("%s=%r" % (k, d.get(k)))
bad = []
for k, v in sorted(need.items()):
    print("%s=%r (want %r)" % (k, d.get(k), v))
    # type() as well: a JSON 1 must not pass for true.
    if type(d.get(k)) is not type(v) or d.get(k) != v:
        bad.append(k)
if bad:
    sys.exit("%s: wrong or missing %s" % (endpoint, ", ".join(bad)))
PY
}
health_ok() { fetch_json health && check_json health; }
version_ok() { fetch_json version && check_json version; }
