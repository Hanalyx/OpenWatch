#!/usr/bin/env bash
# Build the OpenWatch DEB.
#
# Usage:   bash packaging/deb/build-deb.sh            # host arch (amd64)
#          ARCH=arm64 bash packaging/deb/build-deb.sh # cross-compile arm64
# Output:  dist/openwatch_<version>_<arch>.deb
#
# Spec: specs/release/package-build.spec.yaml AC-02, AC-06, AC-13.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$APP_DIR"

# Version source: Go-rebuild's own packaging/version.env (preferred),
# then repo-root VERSION (legacy fallback), then a hardcoded floor.
if [ -z "${VERSION:-}" ]; then
    if [ -f "$APP_DIR/packaging/version.env" ]; then
        # shellcheck source=/dev/null
        . "$APP_DIR/packaging/version.env"
    elif [ -f "$APP_DIR/../VERSION" ]; then
        VERSION="$(cat "$APP_DIR/../VERSION")"
    else
        VERSION="0.1.0"
    fi
fi
# Pre-release ordering: DEB (like RPM) needs '~' to sort a pre-release BELOW
# the final release (0.2.0~rc.8 < 0.2.0). A plain hyphen revision (0.2.0-rc.8)
# sorts ABOVE 0.2.0, so GA would never supersede an RC. Epoch 1 steps over the
# rc.3..rc.8 .debs already published with the hyphen form. The control file
# carries the epoch; the .deb filename omits it (Debian convention). The binary
# keeps the true semver ($VERSION, e.g. 0.2.0-rc.8).
DEB_EPOCH="${DEB_EPOCH:-1}"
DEB_UPSTREAM="${VERSION/-/\~}"                 # 0.2.0-rc.8 -> 0.2.0~rc.8 (GA unchanged)
DEB_VERSION="${DEB_EPOCH}:${DEB_UPSTREAM}"     # control Version field (e.g. 1:0.2.0~rc.8)
# Target architecture (Debian names, which match GOARCH for our targets).
ARCH="${ARCH:-amd64}"
case "$ARCH" in
    amd64 | arm64) ;;
    *) echo "build-deb.sh: unsupported ARCH=$ARCH (use amd64 | arm64)" >&2; exit 1 ;;
esac
DIST_DIR="${APP_DIR}/dist"

mkdir -p "$DIST_DIR"

# Step 1: build the Go binary for the target arch. CGO is disabled so the
# binary is portable and cross-compiles without a C toolchain (the embedded
# frontend SPA is arch-independent).
echo ">> building openwatch binary (version=${VERSION}, arch=${ARCH})"
GOOS=linux GOARCH="$ARCH" CGO_ENABLED=0 make build VERSION="$VERSION" >/dev/null

# Step 2: stage the package tree.
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

mkdir -p "$STAGE/DEBIAN"
mkdir -p "$STAGE/usr/bin"
mkdir -p "$STAGE/usr/lib/openwatch"
mkdir -p "$STAGE/etc/openwatch/tls"
# Identity-key directory ships empty (0750); postinst generates the
# per-install keys into it. The key files are not part of the payload.
mkdir -p "$STAGE/etc/openwatch/keys"
chmod 0750 "$STAGE/etc/openwatch/keys"
mkdir -p "$STAGE/etc/systemd/system"
mkdir -p "$STAGE/var/lib/openwatch"
# Pre-upgrade DB dumps land here (written by the upgrade scriptlet).
mkdir -p "$STAGE/var/lib/openwatch/backups"
chmod 0750 "$STAGE/var/lib/openwatch/backups"
mkdir -p "$STAGE/var/log/openwatch"

# Binary + config + unit.
install -m 0755 "$DIST_DIR/openwatch"                       "$STAGE/usr/bin/openwatch"
install -m 0640 "$APP_DIR/packaging/common/openwatch.toml"  "$STAGE/etc/openwatch/openwatch.toml"
install -m 0640 "$APP_DIR/packaging/common/upgrade.conf"    "$STAGE/etc/openwatch/upgrade.conf"
install -m 0644 "$APP_DIR/packaging/common/openwatch.service" "$STAGE/etc/systemd/system/openwatch.service"
install -m 0644 "$APP_DIR/packaging/common/openwatch-backup-cleanup.service" "$STAGE/etc/systemd/system/openwatch-backup-cleanup.service"
install -m 0644 "$APP_DIR/packaging/common/openwatch-backup-cleanup.timer"   "$STAGE/etc/systemd/system/openwatch-backup-cleanup.timer"
install -m 0755 "$APP_DIR/packaging/common/provision-identity-keys.sh" "$STAGE/usr/lib/openwatch/provision-identity-keys.sh"
install -m 0755 "$APP_DIR/packaging/common/openwatch-upgrade.sh"       "$STAGE/usr/lib/openwatch/openwatch-upgrade.sh"
install -m 0755 "$APP_DIR/packaging/common/cleanup-backups.sh"         "$STAGE/usr/lib/openwatch/cleanup-backups.sh"

# Demo TLS cert (chmod inside the script).
bash "$APP_DIR/packaging/common/gen-demo-cert.sh" "$STAGE/etc/openwatch/tls" >/dev/null

# Step 3: control + maintainer scripts.
# Render control with the actual version and target arch inserted.
sed -e "s/^Version: .*/Version: ${DEB_VERSION}/" \
    -e "s/^Architecture: .*/Architecture: ${ARCH}/" \
    "$APP_DIR/packaging/deb/control" > "$STAGE/DEBIAN/control"

install -m 0644 "$APP_DIR/packaging/deb/conffiles" "$STAGE/DEBIAN/conffiles"
install -m 0755 "$APP_DIR/packaging/deb/preinst"   "$STAGE/DEBIAN/preinst"
install -m 0755 "$APP_DIR/packaging/deb/postinst"  "$STAGE/DEBIAN/postinst"
install -m 0755 "$APP_DIR/packaging/deb/prerm"     "$STAGE/DEBIAN/prerm"
install -m 0755 "$APP_DIR/packaging/deb/postrm"    "$STAGE/DEBIAN/postrm"

# Step 4: dpkg-deb.
echo ">> running dpkg-deb"
OUT="$DIST_DIR/openwatch_${DEB_UPSTREAM}_${ARCH}.deb"
dpkg-deb --root-owner-group --build "$STAGE" "$OUT" >/dev/null
echo ">> wrote $(basename "$OUT") to $DIST_DIR/"
