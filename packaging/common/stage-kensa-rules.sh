#!/usr/bin/env bash
# Stage the Kensa rule corpus from the vendored kensa Go module into a
# destination directory, normalizing permissions for packaging.
#
# The kensa binary carries NO embedded corpus by design — rules ship as
# a separate package installed to /usr/share/kensa/rules (kensa's
# loader default path). OpenWatch vendors github.com/Hanalyx/kensa, so
# the authoritative corpus already lives in the module cache at build
# time; this script copies it out rather than fetching from the network
# (air-gapped builds must work).
#
# Usage:   bash packaging/common/stage-kensa-rules.sh <dest-dir>
# Output:  copies <module>/rules/** into <dest-dir>/, prints the kensa
#          module version (e.g. 0.4.3) to stdout on the LAST line.
#
# Spec: specs/release/package-build.spec.yaml AC-15, AC-16.

set -euo pipefail

DEST="${1:?usage: stage-kensa-rules.sh <dest-dir>}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$APP_DIR"

KMOD="github.com/Hanalyx/kensa"

# Ensure the module is present in the cache (no-op once downloaded; the
# binary build already pulls it, but staging may run standalone).
go mod download "$KMOD"

KDIR="$(go list -m -f '{{.Dir}}' "$KMOD")"
KVER="$(go list -m -f '{{.Version}}' "$KMOD")"
KVER="${KVER#v}" # strip leading v: v0.4.3 -> 0.4.3

SRC="$KDIR/rules"
if [ ! -d "$SRC" ]; then
    echo "stage-kensa-rules: corpus dir not found at $SRC" >&2
    exit 1
fi

# Copy the corpus, preserving the category subdirectory layout the
# loader walks. Module-cache files are mode 0444 and the tree is
# read-only, so normalize perms after copying (dirs 0755, files 0644).
mkdir -p "$DEST"
cp -R "$SRC/." "$DEST/"
chmod -R u+w "$DEST"
find "$DEST" -type d -exec chmod 0755 {} +
find "$DEST" -type f -exec chmod 0644 {} +

# Sanity floor: the v0.4.x corpus is ~539 rules. A copy that lost the
# tree (e.g. a layout change upstream) must fail the build, not ship an
# empty "compliance" package.
COUNT="$(find "$DEST" -name '*.yml' | wc -l)"
if [ "$COUNT" -lt 500 ]; then
    echo "stage-kensa-rules: only $COUNT rule files staged (expected >=500) — corpus layout may have changed" >&2
    exit 1
fi

echo "stage-kensa-rules: staged $COUNT rules from ${KMOD}@v${KVER}" >&2
# Last stdout line is the version, for callers to capture via $(...).
echo "$KVER"
