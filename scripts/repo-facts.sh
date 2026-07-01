#!/usr/bin/env bash
# repo-facts.sh — print live, computed facts about the repo.
#
# Why this exists: hand-maintained counts in prose docs rot (the version, the
# spec count, the package count all drifted at various points). This script is
# the single place to ask "what is true right now" so docs can point here instead
# of hardcoding a number that goes stale the next commit. Cheap, read-only.
#
# Usage: scripts/repo-facts.sh
set -euo pipefail
cd "$(dirname "$0")/.."

echo "OpenWatch repo facts ($(git rev-parse --short HEAD 2>/dev/null || echo 'no-git'))"
echo

# Product version (single source of truth is packaging/version.env).
if [ -f packaging/version.env ]; then
  # shellcheck disable=SC1091
  VERSION="$(grep -E '^VERSION=' packaging/version.env | cut -d'"' -f2)"
  CODENAME="$(grep -E '^CODENAME=' packaging/version.env | cut -d'"' -f2)"
  echo "version:        ${VERSION} (${CODENAME})   [packaging/version.env]"
fi

# Go packages under internal/ (leaf packages with non-test .go files).
PKG_COUNT="$(find internal -name '*.go' -not -name '*_test.go' -print0 2>/dev/null \
  | xargs -0 -n1 dirname 2>/dev/null | sort -u | wc -l | tr -d ' ')"
echo "internal pkgs:  ${PKG_COUNT}   [see docs/engineering/ARCHITECTURE.md]"

# Behavioral specs: files on disk vs ids registered in specter.yaml. These
# should match; a gap means a spec is unregistered (and therefore ungated).
SPEC_FILES="$(find specs -name '*.spec.yaml' 2>/dev/null | wc -l | tr -d ' ')"
if [ -f specter.yaml ]; then
  SPEC_REG="$(grep -oE '(system|api|frontend|release|services)-[a-z0-9-]+' specter.yaml 2>/dev/null | sort -u | wc -l | tr -d ' ')"
  echo "specs:          ${SPEC_FILES} files on disk, ${SPEC_REG} registered in specter.yaml"
  if [ "${SPEC_FILES}" != "${SPEC_REG}" ]; then
    echo "                (note: file count != registered count — reconcile specter.yaml)"
  fi
fi

# Kensa engine version (from go.mod).
KENSA="$(grep -E 'Hanalyx/kensa ' go.mod 2>/dev/null | awk '{print $2}')"
[ -n "${KENSA:-}" ] && echo "kensa engine:   ${KENSA}   [go.mod]"

echo
echo "For architecture, see docs/engineering/ARCHITECTURE.md"
echo "For the spec registry, see specter.yaml"
