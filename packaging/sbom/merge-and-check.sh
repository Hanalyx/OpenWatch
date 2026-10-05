#!/usr/bin/env bash
# merge-and-check.sh: add the frontend's npm components to each openwatch SBOM
# in dist/, check it, then schema-validate every SBOM in dist/.
#
# Run by release.yml on the real release artifacts, and by package-smoke on a
# pull request's build, so the same code runs before and at release. Expects
# dist/<artifact>.cdx.json from `syft scan ... -o cyclonedx-json@1.5`, the
# embedded SPA in internal/server/spa and frontend/node_modules from `make
# packages`, Go for `go version -m`, rpm2cpio, cpio and dpkg-deb.
#
# For a package, the binary inside it is extracted and scanned, so the package
# SBOM gains the Go modules of the binary it actually ships.
#
# The frontend inventory is complete against the runtime lockfile. It does not
# prove which JavaScript ships; see scripts/sbom-merge.py.
# Spec system-supply-chain C-09.
#
# Usage: merge-and-check.sh <python-with-fastjsonschema>
set -euo pipefail

PY="${1:?usage: merge-and-check.sh <python-with-fastjsonschema>}"
root="$(pwd)"
shopt -s nullglob
merged=0
for art in dist/openwatch dist/openwatch-*.rpm dist/openwatch_*.deb; do
  sbom="dist/$(basename "$art").cdx.json"
  [ -e "$sbom" ] || { echo "merge-and-check: $art has no SBOM at $sbom" >&2; exit 1; }
  work="$(mktemp -d)"
  extra=()
  case "$art" in
    *.rpm) (cd "$work" && rpm2cpio "$root/$art" | cpio -idm --quiet ./usr/bin/openwatch) ;;
    *.deb) dpkg-deb --fsys-tarfile "$art" | tar -x -C "$work" ./usr/bin/openwatch ;;
  esac
  if [ -e "$work/usr/bin/openwatch" ]; then
    bin="$work/usr/bin/openwatch"
    syft scan "file:$bin" -q -o "cyclonedx-json@1.5=$work/binary.cdx.json"
    extra=(--binary-sbom "$work/binary.cdx.json")
  else
    bin="$art"
  fi
  "$PY" scripts/sbom-merge.py merge --sbom "$sbom" --binary "$bin" "${extra[@]}" --out "$work/merged.json"
  "$PY" scripts/sbom-merge.py check --sbom "$work/merged.json" --binary "$bin" --artifact "$art"
  mv "$work/merged.json" "$sbom"
  rm -rf "$work"
  merged=$((merged + 1))
done
[ "$merged" -gt 0 ] || { echo "merge-and-check: no openwatch artifacts in dist/" >&2; exit 1; }
for sbom in dist/*.cdx.json; do
  "$PY" scripts/sbom-merge.py validate --sbom "$sbom"
done
