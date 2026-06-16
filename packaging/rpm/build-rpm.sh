#!/usr/bin/env bash
# Build the OpenWatch RPM.
#
# Usage:   bash packaging/rpm/build-rpm.sh            # host arch (x86_64)
#          ARCH=arm64 bash packaging/rpm/build-rpm.sh # cross-compile aarch64
# Output:  dist/openwatch-<version>-<release>.<arch>.rpm
#
# Spec: specs/release/package-build.spec.yaml AC-01, AC-04, AC-13.

set -euo pipefail

# Resolve repo root (app/) regardless of where the script is invoked from.
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
# Strip any -dev / -alpha / -rc suffixes — RPM version field doesn't allow them.
RPM_VERSION="${VERSION%%-*}"
RPM_RELEASE="${RPM_RELEASE:-1}"
DIST_DIR="${APP_DIR}/dist"

# Target architecture: GOARCH name in, RPM arch name out.
ARCH="${ARCH:-amd64}"
case "$ARCH" in
    amd64) GOARCH=amd64; RPM_ARCH=x86_64 ;;
    arm64) GOARCH=arm64; RPM_ARCH=aarch64 ;;
    *) echo "build-rpm.sh: unsupported ARCH=$ARCH (use amd64 | arm64)" >&2; exit 1 ;;
esac

mkdir -p "$DIST_DIR"

# Step 1: build the Go binary (release flags) for the target arch. Done
# outside rpmbuild's %build so the chroot needs no Go toolchain. CGO is
# disabled for a portable binary that cross-compiles without a C toolchain
# (the embedded frontend SPA is arch-independent).
echo ">> building openwatch binary (version=${RPM_VERSION}, arch=${RPM_ARCH})"
GOOS=linux GOARCH="$GOARCH" CGO_ENABLED=0 make build VERSION="$RPM_VERSION" >/dev/null

# Step 2: stage the rpmbuild tree.
RPMTOP="$(mktemp -d)"
trap 'rm -rf "$RPMTOP"' EXIT
mkdir -p "$RPMTOP"/{BUILD,RPMS,SOURCES,SPECS,SRPMS,BUILDROOT}

# Step 3: assemble the source tarball.
STAGE_DIR="$(mktemp -d)"
SRC_DIR="$STAGE_DIR/openwatch-${RPM_VERSION}"
mkdir -p "$SRC_DIR"

cp "$DIST_DIR/openwatch"                      "$SRC_DIR/openwatch"
cp "$APP_DIR/packaging/common/openwatch.toml" "$SRC_DIR/openwatch.toml"
cp "$APP_DIR/packaging/common/openwatch.service" "$SRC_DIR/openwatch.service"
cp "$APP_DIR/packaging/common/provision-identity-keys.sh" "$SRC_DIR/provision-identity-keys.sh"
# Upgrade automation: migrate-on-upgrade helper, backup cleanup, systemd
# timer + units, and the operator-tunable upgrade.conf.
cp "$APP_DIR/packaging/common/openwatch-upgrade.sh"             "$SRC_DIR/openwatch-upgrade.sh"
cp "$APP_DIR/packaging/common/cleanup-backups.sh"              "$SRC_DIR/cleanup-backups.sh"
cp "$APP_DIR/packaging/common/upgrade.conf"                    "$SRC_DIR/upgrade.conf"
cp "$APP_DIR/packaging/common/openwatch-backup-cleanup.service" "$SRC_DIR/openwatch-backup-cleanup.service"
cp "$APP_DIR/packaging/common/openwatch-backup-cleanup.timer"   "$SRC_DIR/openwatch-backup-cleanup.timer"

# Demo TLS cert.
bash "$APP_DIR/packaging/common/gen-demo-cert.sh" "$SRC_DIR" >/dev/null

(cd "$STAGE_DIR" && tar czf "$RPMTOP/SOURCES/openwatch-${RPM_VERSION}.tar.gz" "openwatch-${RPM_VERSION}")
rm -rf "$STAGE_DIR"

# Step 4: rpmbuild.
echo ">> running rpmbuild"
rpmbuild \
    --define "_topdir $RPMTOP" \
    --define "ow_version ${RPM_VERSION}" \
    --define "ow_release ${RPM_RELEASE}" \
    --target "${RPM_ARCH}" \
    -bb "$APP_DIR/packaging/rpm/openwatch.spec" >/dev/null

# Step 5: copy the artifact into app/dist/.
RPM_OUT="$(find "$RPMTOP/RPMS" -name '*.rpm' -type f | head -n1)"
if [[ -z "$RPM_OUT" ]]; then
    echo "build-rpm.sh: no .rpm produced" >&2
    exit 1
fi
cp "$RPM_OUT" "$DIST_DIR/"
echo ">> wrote $(basename "$RPM_OUT") to $DIST_DIR/"
