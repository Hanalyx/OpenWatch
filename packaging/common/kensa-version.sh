#!/usr/bin/env bash
# kensa-version.sh: print the version of the Kensa Go module this tree links,
# without the leading "v" (v0.10.0 -> 0.10.0).
#
# One derivation, used by every package build. The openwatch packages
# declare it as `openwatch-kensa-engine`, the engine they link, and the
# kensa-rules package requires an engine at least as new as its own
# corpus. An engine older than the corpus cannot load it (Kensa v0.9.0 fails
# the whole v0.10.0 load on the first variable it does not know), so the
# two values must come from the same place or the guard means nothing.
#
# Usage: bash packaging/common/kensa-version.sh
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/../.."
KVER="$(go list -m -f '{{.Version}}' github.com/Hanalyx/kensa)"
KVER="${KVER#v}"
if ! [[ "$KVER" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "kensa-version: unexpected module version '$KVER'" >&2
    exit 1
fi
echo "$KVER"
