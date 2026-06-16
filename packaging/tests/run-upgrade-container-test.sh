#!/usr/bin/env bash
# Host-side driver for the full package-upgrade test. Builds an OLD
# (release 1) and NEW (release 2) openwatch RPM from the current tree, then
# runs packaging/tests/upgrade-container-test.sh inside a rockylinux:9
# container to prove that `rpm -U` (the real package upgrade) migrates the
# DB to head, takes a pre-upgrade backup, and stop/starts the service.
#
# Requires docker plus the host build toolchain (go, make, rpmbuild).
#
# Network: uses --network host so dnf inside the container can reach the
# Rocky mirrors; the container's throwaway Postgres binds the unused port
# 55432 to avoid colliding with any Postgres already on the host.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$APP_DIR"

command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }

RPMS="$(mktemp -d)"
trap 'rm -rf "$RPMS"' EXIT
mkdir -p "$RPMS/old" "$RPMS/new"

echo ">> building OLD (release 1) and NEW (release 2) RPMs"
make rpm >/dev/null
cp dist/openwatch-*-1.*.rpm "$RPMS/old/"
RPM_RELEASE=2 bash packaging/rpm/build-rpm.sh >/dev/null
cp dist/openwatch-*-2.*.rpm "$RPMS/new/"

echo ">> running the upgrade in a rockylinux:9 container"
exec docker run --rm --network host \
    -v "$RPMS:/rpms:ro" \
    -v "$APP_DIR/packaging/tests/upgrade-container-test.sh:/test.sh:ro" \
    rockylinux:9 bash /test.sh
