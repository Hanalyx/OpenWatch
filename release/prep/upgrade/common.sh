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

# Run a command as the openwatch user with the service's environment.
as_openwatch() {
    sudo -n -u openwatch sh -c 'set -a; . "$1"; set +a; shift; exec "$@"' sh "$SECRETS" "$@"
}

# Run a command as root with the database DSN from the service's environment.
with_dsn() {
    ( set -a; . "$SECRETS"; set +a; "$@" )
}
