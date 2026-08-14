#!/usr/bin/env bash
# Host-side driver for the `openwatch setup` install test. Starts a systemd
# container for the requested image, feeds it the built packages, and runs
# packaging/tests/setup-container-test.sh inside it.
#
#   bash packaging/tests/run-setup-container-test.sh ubuntu:24.04 deb
#   bash packaging/tests/run-setup-container-test.sh debian:12    deb
#   bash packaging/tests/run-setup-container-test.sh rockylinux:9 rpm
#
# Why a systemd container rather than the plain `container:` job the smoke
# matrix uses: setup drives systemctl for both PostgreSQL and its own unit, so
# a container without a real init cannot exercise it at all. The base images do
# not ship systemd as PID 1, so the entrypoint installs it and execs into it,
# which makes systemd PID 1 without needing a purpose-built image.
#
# --privileged and the cgroup mount are what systemd needs to run in a
# container. This is a throwaway test container on a CI runner, which is the
# one place that trade is reasonable.
#
# Deliberately NOT --network host, unlike the upgrade driver. Sharing the
# host's network namespace makes Debian's postgresql-common allocate the next
# free port instead of 5432 (it sees the host's clusters), while setup's DSN
# still says 5432 -- so the install reaches the HOST's PostgreSQL and fails
# with "password authentication failed for user openwatch". The test then
# reads as a product bug when it is a harness bug, which cost an hour once.
# Bridge networking reaches the package mirrors perfectly well.
set -euo pipefail

IMAGE="${1:?usage: run-setup-container-test.sh <image> <deb|rpm> [extra setup args]}"
KIND="${2:?usage: run-setup-container-test.sh <image> <deb|rpm> [extra setup args]}"
shift 2
EXTRA_ARGS="${*:-}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$APP_DIR"

command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }

case "$(uname -m)" in
    x86_64)        RPM_ARCH=x86_64; DEB_ARCH=amd64 ;;
    aarch64|arm64) RPM_ARCH=aarch64; DEB_ARCH=arm64 ;;
    *) echo "unsupported host arch $(uname -m)" >&2; exit 1 ;;
esac

# Stage exactly the packages for this arch and kind. dist/ can hold
# cross-built artifacts of the other arch, and installing two arches of the
# same package collides on /usr/bin/openwatch.
PKGS="$(mktemp -d)"
CONTAINER=""
cleanup() {
    [ -n "$CONTAINER" ] && docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    rm -rf "$PKGS"
}
trap cleanup EXIT

# Wait for the boot script to hand off to systemd, or report why it could not.
#
# Without this, a container that died during boot is discovered by whatever
# runs next: either a `docker exec` failing for a reason that reads as a docker
# problem, or the in-container test timing out on systemd. Both name the wrong
# thing. The boot script's own output is in `docker logs`, and nothing was
# printing it. See CP bugs/OW-019.
wait_for_systemd() {
    local container="$1" state
    for _ in $(seq 1 90); do
        state="$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null || echo false)"
        if [ "$state" != true ]; then
            echo ">> the container exited while booting. Its own log follows." >&2
            docker logs "$container" 2>&1 | sed 's/^/   | /' >&2
            exit 1
        fi
        # /run/systemd/system exists only once systemd is actually running.
        if docker exec "$container" test -d /run/systemd/system 2>/dev/null; then
            return 0
        fi
        sleep 1
    done
    echo ">> systemd did not come up within 90s. The container's log follows." >&2
    docker logs "$container" 2>&1 | sed 's/^/   | /' >&2
    exit 1
}

# Pin the VERSION as well as the arch. A CI runner's dist/ holds only the
# current build, but a developer's accumulates every historical one, and a
# glob that matches thirteen packages installs whichever the package manager
# happens to prefer.
VERSION="$(. packaging/version.env && echo "$VERSION")"
KENSA_DEB="$(ls -1 dist/kensa-rules_*_all.deb | sort -V | tail -1)"
KENSA_RPM="$(ls -1 dist/kensa-rules-*.noarch.rpm | sort -V | tail -1)"
if [ "$KIND" = deb ]; then
    cp "dist/openwatch_${VERSION}_${DEB_ARCH}.deb" "$KENSA_DEB" "$PKGS/"
else
    cp "dist/openwatch-${VERSION}-1.${RPM_ARCH}.rpm" "$KENSA_RPM" "$PKGS/"
fi
echo ">> staged $(ls "$PKGS" | tr '\n' ' ')"

# Installing systemd then exec'ing it makes it PID 1 in place. boot-systemd.sh
# does that; it is a mounted file rather than a `bash -c` string because the
# string silenced its own package install and reported the failure minutes
# later as a systemd timeout. See CP bugs/OW-019.
case "$KIND" in
    deb|rpm) ;;
    *) echo "kind must be deb or rpm" >&2; exit 1 ;;
esac

echo ">> booting $IMAGE with systemd as PID 1"
CONTAINER="$(docker run -d --privileged --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    -v "$PKGS:/pkgs:ro" \
    -v "$APP_DIR/packaging/tests/boot-systemd.sh:/boot.sh:ro" \
    -v "$APP_DIR/packaging/tests/setup-container-test.sh:/test.sh:ro" \
    "$IMAGE" bash /boot.sh "$KIND")"

wait_for_systemd "$CONTAINER"

echo ">> running the setup test in $CONTAINER"
docker exec \
    -e PKG_DIR=/pkgs \
    -e PKG_KIND="$KIND" \
    -e ADMIN_PW='Container-Verify!Ow2026' \
    -e EXTRA_ARGS="$EXTRA_ARGS" \
    "$CONTAINER" bash /test.sh
