#!/usr/bin/env bash
# Runs INSIDE a systemd container. Proves that `openwatch setup` takes a host
# with nothing on it to a service answering /health with db_connected, and that
# running it a second time is safe.
#
# This is the gate evidence for release/gates.toml I1 (clean install) and I2
# (idempotence). It deliberately asserts more than "exit 0": an installer that
# reports success while the API is not serving is the specific failure the
# setup spec's C-12 exists to prevent.
#
# Expects, from the driver:
#   PKG_DIR    directory holding the packages to install
#   PKG_KIND   deb | rpm
#   ADMIN_PW   the admin password to create and then log in with
#   EXTRA_ARGS extra setup flags (e.g. --allow-untested)
set -euo pipefail

PKG_DIR="${PKG_DIR:-/pkgs}"
PKG_KIND="${PKG_KIND:?PKG_KIND must be deb or rpm}"
ADMIN_PW="${ADMIN_PW:?ADMIN_PW must be set}"
EXTRA_ARGS="${EXTRA_ARGS:-}"

fail() { echo "FAIL: $*" >&2; exit 1; }

# See OW-019. Provisioning reaches the distribution mirrors, which fail
# transiently, and a silenced package manager reports its own cleanup rather
# than what it could not reach. Retry, and keep the output for the failure.
retry_fetch() {
    local what="$1"; shift
    local attempt
    for attempt in 1 2 3; do
        if "$@" > /tmp/provision.log 2>&1; then
            return 0
        fi
        echo "   $what failed, attempt $attempt of 3" >&2
        sleep $(( attempt * 10 ))
    done
    echo "--- output of the last attempt ---" >&2
    cat /tmp/provision.log >&2
    fail "$what failed after 3 attempts"
}

echo ">> waiting for systemd to finish booting"
for _ in $(seq 1 60); do
    state="$(systemctl is-system-running 2>/dev/null || true)"
    case "$state" in
        running|degraded) break ;;
    esac
    sleep 1
done
# degraded is acceptable in a container: units irrelevant here (and often
# unmaskable, like systemd-logind's dependencies) fail without affecting
# PostgreSQL or openwatch. What matters is that systemctl works at all.
systemctl is-system-running >/dev/null 2>&1 || \
    [ "$(systemctl is-system-running || true)" = degraded ] || \
    fail "systemd never came up; setup drives systemctl and cannot work here"

echo ">> installing packages"
if [ "$PKG_KIND" = deb ]; then
    export DEBIAN_FRONTEND=noninteractive
    retry_fetch "apt-get update" apt-get update
    retry_fetch "curl install" apt-get install -y curl ca-certificates
    apt-get install -y "$PKG_DIR"/openwatch_*.deb "$PKG_DIR"/kensa-rules_*.deb
else
    dnf install -y -q "$PKG_DIR"/openwatch-*.rpm "$PKG_DIR"/kensa-rules-*.rpm
fi
command -v openwatch >/dev/null || fail "openwatch is not on PATH after install"
openwatch --version

# The state that makes this a CLEAN install test rather than a re-run test.
# If a base image ever starts shipping a cluster, this catches it rather than
# quietly weakening the claim.
[ ! -e /etc/openwatch/secrets.env ] || fail "secrets.env exists before setup ran"
[ ! -e /var/lib/openwatch/setup-receipt.json ] || fail "a receipt exists before setup ran"

# system-setup C-14 / AC-14: a run that cannot prompt is refused in preflight,
# naming the flag, rather than dying later at secret resolution.
echo ">> --yes without a credential source must be refused"
if openwatch setup --yes $EXTRA_ARGS >/tmp/refused.log 2>&1; then
    fail "--yes with no credential source succeeded; it cannot obtain an admin password"
fi
grep -q "admin password source" /tmp/refused.log || \
    fail "the refusal is not a preflight check; PKG-7 has regressed"
[ ! -e /etc/openwatch/secrets.env ] || fail "the refused run still changed the host"

umask 077
printf %s "$ADMIN_PW" > /root/admin-pw

# No --manage-pg-hba. Setup provisions the cluster in this run, so it manages
# pg_hba.conf itself (AC-15); passing the flag would hide a regression in that.
run_setup() {
    openwatch setup --yes $EXTRA_ARGS \
        --admin-password-from file:/root/admin-pw \
        --admin-email admin@example.com
}

assert_healthy() {
    local body
    body="$(curl -sk --max-time 20 https://127.0.0.1:8443/api/v1/health)" || \
        fail "the API did not answer: $1"
    echo "   health: $body"
    case "$body" in
        *'"db_connected":true'*) ;;
        *) fail "db_connected is not true: $1" ;;
    esac
}

echo ">> clean install (gate I1)"
run_setup
assert_healthy "after the first run"

echo ">> logging in as the admin setup created"
token="$(curl -sk --max-time 20 -X POST https://127.0.0.1:8443/api/v1/auth/login \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PW\"}" \
    | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')"
[ -n "$token" ] || fail "login failed; the admin account setup created is unusable"
curl -sk --max-time 20 https://127.0.0.1:8443/api/v1/auth/me \
    -H "Authorization: Bearer $token" | grep -q '"role":"admin"' || \
    fail "the created account is not an admin"

echo ">> file modes (system-setup AC-13)"
[ "$(stat -c '%a' /var/lib/openwatch/setup-receipt.json)" = 600 ] || \
    fail "the receipt is not 0600"
[ "$(stat -c '%a' /etc/openwatch/secrets.env)" = 640 ] || \
    fail "secrets.env is not 0640"
grep -q "$ADMIN_PW" /var/lib/openwatch/setup-receipt.json && \
    fail "the receipt contains the admin password"

echo ">> second run (gate I2, idempotence)"
run_setup
assert_healthy "after the second run"
systemctl is-active --quiet openwatch || fail "the service is not active after a re-run"

echo ">> OK: clean install and re-run both reached a serving instance"
