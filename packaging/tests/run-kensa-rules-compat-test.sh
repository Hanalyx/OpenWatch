#!/usr/bin/env bash
# run-kensa-rules-compat-test.sh: host-side runner for
# kensa-rules-compat-container-test.sh (spec release-upgrade AC-09).
#
# Usage: run-kensa-rules-compat-test.sh <image> <rpm|deb> <old-dir> <new-dir>
#   e.g. run-kensa-rules-compat-test.sh rockylinux:9 rpm /tmp/old dist
# old-dir holds a release that predates the engine provide (the published
# v0.8.0-rc.5 openwatch and kensa-rules assets); new-dir holds the packages
# built from this tree. Needs docker.
set -euo pipefail
IMAGE="${1:?usage: $0 <image> <rpm|deb> <old-dir> <new-dir>}"
KIND="${2:?kind}"
OLD="$(cd "${3:?old-dir}" && pwd)"
NEW="$(cd "${4:?new-dir}" && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }

docker run --rm \
    -v "$OLD":/pk/old:ro \
    -v "$NEW":/pk/new:ro \
    -v "$SCRIPT_DIR/kensa-rules-compat-container-test.sh":/t.sh:ro \
    "$IMAGE" bash /t.sh "$KIND" /pk/old /pk/new
