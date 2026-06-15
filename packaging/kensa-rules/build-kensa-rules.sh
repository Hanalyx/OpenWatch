#!/usr/bin/env bash
# Build the standalone Kensa rule-corpus packages (RPM + DEB).
#
# Usage:   bash packaging/kensa-rules/build-kensa-rules.sh
# Output:  dist/kensa-rules-<kver>-<rel>.noarch.rpm
#          dist/kensa-rules_<kver>_all.deb
#
# Both are arch-independent (the corpus is plain YAML), so unlike the
# openwatch binary there is no amd64/arm64 split — one artifact each
# serves every target. The version tracks the vendored kensa module
# (e.g. 0.4.3), not the OpenWatch platform version.
#
# Spec: specs/release/package-build.spec.yaml AC-15, AC-16, AC-17.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$APP_DIR"

DIST_DIR="${APP_DIR}/dist"
KR_RELEASE="${KR_RELEASE:-1}"
mkdir -p "$DIST_DIR"

# Step 1: stage the corpus from the vendored kensa module. The stager
# prints the kensa version on its last stdout line.
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
RULES_DIR="$STAGE/rules"
KVER="$(bash "$APP_DIR/packaging/common/stage-kensa-rules.sh" "$RULES_DIR")"
echo ">> staging kensa-rules version=${KVER}"

# ---- Step 2: build the noarch RPM. ----
RPMTOP="$(mktemp -d)"
mkdir -p "$RPMTOP"/{BUILD,RPMS,SOURCES,SPECS,SRPMS,BUILDROOT}
SRCDIR="$STAGE/kensa-rules-${KVER}"
mkdir -p "$SRCDIR"
cp -R "$RULES_DIR" "$SRCDIR/rules"
(cd "$STAGE" && tar czf "$RPMTOP/SOURCES/kensa-rules-${KVER}.tar.gz" "kensa-rules-${KVER}")

echo ">> running rpmbuild (kensa-rules, noarch)"
rpmbuild \
    --define "_topdir $RPMTOP" \
    --define "kr_version ${KVER}" \
    --define "kr_release ${KR_RELEASE}" \
    --target noarch \
    -bb "$APP_DIR/packaging/kensa-rules/kensa-rules.spec" >/dev/null
cp "$RPMTOP"/RPMS/noarch/kensa-rules-*.rpm "$DIST_DIR/"
rm -rf "$RPMTOP"
echo ">> wrote kensa-rules-${KVER}-${KR_RELEASE}.noarch.rpm to dist/"

# ---- Step 3: build the arch:all DEB. ----
DEBROOT="$(mktemp -d)"
mkdir -p "$DEBROOT/DEBIAN" "$DEBROOT/usr/share/kensa/rules"
cp -R "$RULES_DIR/." "$DEBROOT/usr/share/kensa/rules/"
find "$DEBROOT/usr/share/kensa" -type d -exec chmod 0755 {} +
find "$DEBROOT/usr/share/kensa" -type f -exec chmod 0644 {} +

cat > "$DEBROOT/DEBIAN/control" <<CONTROL
Package: kensa-rules
Version: ${KVER}
Section: admin
Priority: optional
Architecture: all
Maintainer: OpenWatch Build <build@hanalyx.com>
Homepage: https://github.com/Hanalyx/kensa
Description: Kensa compliance rule corpus (native YAML rules)
 Native YAML compliance rules consumed by the Kensa scan engine embedded
 in OpenWatch. Installs to /usr/share/kensa/rules, the engine's default
 rule-load path. Versioned on the Kensa content line, independent of the
 OpenWatch platform version, so rule updates ship without a platform
 re-release.
CONTROL

echo ">> running dpkg-deb (kensa-rules, all)"
OUT="$DIST_DIR/kensa-rules_${KVER}_all.deb"
dpkg-deb --root-owner-group --build "$DEBROOT" "$OUT" >/dev/null
rm -rf "$DEBROOT"
echo ">> wrote $(basename "$OUT") to dist/"
