#!/usr/bin/env bash
# Build the OpenWatch DEB.
#
# Usage:   bash packaging/deb/build-deb.sh
# Output:  app/dist/openwatch_<version>_<arch>.deb
#
# Spec: app/specs/release/package-build.spec.yaml AC-02, AC-06, AC-13.

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
# DEB allows hyphens; reuse upstream version as-is.
DEB_VERSION="$VERSION"
ARCH="${ARCH:-amd64}"
DIST_DIR="${APP_DIR}/dist"

mkdir -p "$DIST_DIR"

# Step 1: build the Go binary.
echo ">> building openwatch binary (version=${DEB_VERSION})"
make build VERSION="$DEB_VERSION" >/dev/null

# Step 2: stage the package tree.
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

mkdir -p "$STAGE/DEBIAN"
mkdir -p "$STAGE/usr/bin"
mkdir -p "$STAGE/etc/openwatch/tls"
mkdir -p "$STAGE/etc/systemd/system"
mkdir -p "$STAGE/var/lib/openwatch"
mkdir -p "$STAGE/var/log/openwatch"

# Binary + config + unit.
install -m 0755 "$DIST_DIR/openwatch"                       "$STAGE/usr/bin/openwatch"
install -m 0640 "$APP_DIR/packaging/common/openwatch.toml"  "$STAGE/etc/openwatch/openwatch.toml"
install -m 0644 "$APP_DIR/packaging/common/openwatch.service" "$STAGE/etc/systemd/system/openwatch.service"

# Demo TLS cert (chmod inside the script).
bash "$APP_DIR/packaging/common/gen-demo-cert.sh" "$STAGE/etc/openwatch/tls" >/dev/null

# Step 3: control + maintainer scripts.
# Render control with the actual version inserted.
sed "s/^Version: .*/Version: ${DEB_VERSION}/" \
    "$APP_DIR/packaging/deb/control" > "$STAGE/DEBIAN/control"

install -m 0644 "$APP_DIR/packaging/deb/conffiles" "$STAGE/DEBIAN/conffiles"
install -m 0755 "$APP_DIR/packaging/deb/preinst"   "$STAGE/DEBIAN/preinst"
install -m 0755 "$APP_DIR/packaging/deb/postinst"  "$STAGE/DEBIAN/postinst"
install -m 0755 "$APP_DIR/packaging/deb/prerm"     "$STAGE/DEBIAN/prerm"
install -m 0755 "$APP_DIR/packaging/deb/postrm"    "$STAGE/DEBIAN/postrm"

# Step 4: dpkg-deb.
echo ">> running dpkg-deb"
OUT="$DIST_DIR/openwatch_${DEB_VERSION}_${ARCH}.deb"
dpkg-deb --root-owner-group --build "$STAGE" "$OUT" >/dev/null
echo ">> wrote $(basename "$OUT") to $DIST_DIR/"
