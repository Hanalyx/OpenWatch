#!/usr/bin/env bash
# Host-side driver for the previous-GA upgrade test (gate U2). Downloads the
# previous GA's published packages, stages the candidate's from dist/, boots a
# systemd container and runs packaging/tests/upgrade-from-ga-container-test.sh
# inside it.
#
#   bash packaging/tests/run-upgrade-from-ga-test.sh ubuntu:24.04 deb v0.6.0
#   bash packaging/tests/run-upgrade-from-ga-test.sh rockylinux:9 rpm v0.6.0
#
# The previous GA is downloaded rather than rebuilt, deliberately. Rebuilding
# the old version from a tag proves the upgrade works from something that was
# never shipped; operators upgrade from the artifact on the releases page, and
# that is the only artifact whose scriptlets and file ownership are the ones
# actually in the field.
#
# Not --network host: see run-setup-container-test.sh for why that quietly
# breaks the Debian family.
set -euo pipefail

IMAGE="${1:?usage: run-upgrade-from-ga-test.sh <image> <deb|rpm> <prev-tag>}"
KIND="${2:?usage: run-upgrade-from-ga-test.sh <image> <deb|rpm> <prev-tag>}"
PREV_TAG="${3:?usage: run-upgrade-from-ga-test.sh <image> <deb|rpm> <prev-tag>}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$APP_DIR"

command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }
command -v gh >/dev/null || { echo "gh is required to download the previous GA" >&2; exit 1; }

case "$(uname -m)" in
    x86_64)        RPM_ARCH=x86_64; DEB_ARCH=amd64 ;;
    aarch64|arm64) RPM_ARCH=aarch64; DEB_ARCH=arm64 ;;
    *) echo "unsupported host arch $(uname -m)" >&2; exit 1 ;;
esac

OLD="$(mktemp -d)"; NEW="$(mktemp -d)"
CONTAINER=""
cleanup() {
    [ -n "$CONTAINER" ] && docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    rm -rf "$OLD" "$NEW"
}
trap cleanup EXIT

OLD_VER="${PREV_TAG#v}"
NEW_VER="$(. packaging/version.env && echo "$VERSION")"
[ "$OLD_VER" != "$NEW_VER" ] || { echo "previous GA and candidate are both $NEW_VER" >&2; exit 1; }

echo ">> downloading the previous GA ($PREV_TAG) packages"
if [ "$KIND" = deb ]; then
    gh release download "$PREV_TAG" -D "$OLD" \
        -p "openwatch_*_${DEB_ARCH}.deb" -p 'kensa-rules_*_all.deb'
    cp "dist/openwatch_${NEW_VER}_${DEB_ARCH}.deb" \
       "$(ls -1 dist/kensa-rules_*_all.deb | sort -V | tail -1)" "$NEW/"
else
    gh release download "$PREV_TAG" -D "$OLD" \
        -p "openwatch-*.${RPM_ARCH}.rpm" -p 'kensa-rules-*.noarch.rpm'
    cp "dist/openwatch-${NEW_VER}-1.${RPM_ARCH}.rpm" \
       "$(ls -1 dist/kensa-rules-*.noarch.rpm | sort -V | tail -1)" "$NEW/"
fi
echo "   old: $(ls "$OLD" | tr '\n' ' ')"
echo "   new: $(ls "$NEW" | tr '\n' ' ')"

case "$KIND" in
    deb) BOOT='export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq systemd systemd-sysv >/dev/null && exec /sbin/init' ;;
    rpm) BOOT='dnf install -y -q systemd >/dev/null 2>&1 || true; exec /sbin/init' ;;
    *)   echo "kind must be deb or rpm" >&2; exit 1 ;;
esac

echo ">> booting $IMAGE with systemd as PID 1"
CONTAINER="$(docker run -d --privileged --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    -v "$OLD:/old:ro" -v "$NEW:/new:ro" \
    -v "$APP_DIR/packaging/tests/upgrade-from-ga-container-test.sh:/test.sh:ro" \
    "$IMAGE" bash -c "$BOOT")"

echo ">> upgrading $OLD_VER to $NEW_VER in $CONTAINER"
docker exec \
    -e OLD_DIR=/old -e NEW_DIR=/new -e PKG_KIND="$KIND" \
    -e OLD_VER="$OLD_VER" -e NEW_VER="$NEW_VER" \
    "$CONTAINER" bash /test.sh
