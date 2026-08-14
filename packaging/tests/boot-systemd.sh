#!/usr/bin/env bash
# Runs as PID 1 in a test container: makes sure systemd is installed, then
# execs it in place so the container has a real init.
#
# Usage, from a driver's `docker run`:
#
#   docker run -d ... -v .../boot-systemd.sh:/boot.sh:ro <image> bash /boot.sh deb|rpm
#
# Why this is a file and not the `bash -c` one-liner it replaces. That string
# installed systemd like this:
#
#   dnf install -y -q systemd >/dev/null 2>&1 || true; exec /sbin/init
#
# so a failed install produced no output and no failure. The container carried
# on without systemd, and the symptom arrived minutes later from a different
# script:
#
#   FAIL: systemd never came up; setup drives systemctl and cannot work here
#
# That message names systemd and points at the in-container test, when the real
# failure was a package install in the boot string. It cost a debugging session
# on PR #825, where every other gate was green and a plain rerun passed. See CP
# bugs/OW-019.
#
# The deb form had the same silence with a different ending: `apt-get install
# ... >/dev/null && exec /sbin/init` skipped the exec on failure, so the
# container exited and the next `docker exec` reported something unrelated.
#
# No `set -e`. The retry loop below tests exit status itself, and -e would end
# the script on the first failed attempt.
set -uo pipefail

KIND="${1:?usage: boot-systemd.sh deb|rpm}"

fail() {
    echo "boot-systemd: $*" >&2
    exit 1
}

install_systemd() {
    if [ "$KIND" = deb ]; then
        export DEBIAN_FRONTEND=noninteractive
        # systemd-sysv is what provides /sbin/init on Debian and Ubuntu. The
        # RHEL family gets it from the systemd package itself.
        apt-get update && apt-get install -y systemd systemd-sysv
    else
        dnf install -y systemd
    fi
}

# Measured, not assumed: neither rockylinux:9 nor ubuntu:24.04 ships /sbin/init,
# so this install runs on every image the matrix uses and every boot reaches a
# package mirror. The retry below is therefore on the hot path, not a corner
# case, which is the opposite of what the old `|| true` implied.
#
# The guard stays anyway. It costs nothing, it keeps the script idempotent, and
# an image that does ship systemd should not be made to reinstall it.
if [ ! -x /sbin/init ]; then
    echo "boot-systemd: /sbin/init is absent, installing systemd for $KIND" >&2
    installed=0
    for attempt in 1 2 3; do
        if install_systemd; then
            installed=1
            break
        fi
        echo "boot-systemd: install failed, attempt $attempt of 3" >&2
        sleep $(( attempt * 5 ))
    done
    [ "$installed" = 1 ] || fail "could not install systemd after 3 attempts; the package manager output is above"
fi

[ -x /sbin/init ] || fail "/sbin/init is still missing after installing systemd; this image cannot run it as PID 1"

exec /sbin/init
