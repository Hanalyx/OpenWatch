#!/usr/bin/env bash
# Write a detached, ASCII-armored GPG signature beside each file, as
# <file>.asc, with one pinned key, then verify each one.
#
#   fpr="$(bash packaging/release-signing-key.sh security/KEYS)"
#   GPG_PASSPHRASE=... bash packaging/sign-detached.sh "$fpr" dist/*.deb
#   GPG_PASSPHRASE=... bash packaging/sign-detached.sh "$fpr" dist/SHA256SUMS
#
# release.yml signs the DEBs with this after the RPMs and before the SBOMs
# and SHA256SUMS, and signs SHA256SUMS with it after the checksums are
# written. FPR is the release key's 40-hex primary fingerprint, from
# packaging/release-signing-key.sh. Signing with it (never `FPR!`) lets gpg
# pick the key's signing subkey, as rpmsign does with the same fingerprint;
# the real primary is certify-only.
#
# Operators verify with:
#   gpg --import KEYS
#   gpg --verify openwatch_X.Y.Z_amd64.deb.asc openwatch_X.Y.Z_amd64.deb
#
# Fails closed. Before signing anything it removes each file's old .asc, and
# it exits non-zero when FPR is not a full fingerprint, GPG_PASSPHRASE is not
# set (it may be empty for a key without a passphrase), no file is named, or
# a named file does not exist. A signing failure, or a signature that does not
# verify as a good one whose primary key is FPR, removes every .asc this run
# wrote and exits non-zero. GNUPGHOME is honored, which is how the tests use
# a throwaway key.
#
# Spec: release-package-build C-18, C-19.

set -euo pipefail

fpr="${1:-}"
fail() {
  echo "sign-detached: $*" >&2
  exit 1
}
[ "$#" -gt 0 ] && shift

# A signature left from an earlier run is never trusted, whatever else is
# wrong with this one.
for f in "$@"; do
  rm -f -- "$f.asc"
done
[[ "$fpr" =~ ^[0-9A-F]{40}$ ]] || fail "usage: sign-detached.sh FPR FILE...; FPR must be a 40-hex fingerprint, got '${fpr}'"
[ "$#" -gt 0 ] || fail "no file to sign"
if [ "${GPG_PASSPHRASE+set}" != "set" ]; then
  fail "GPG_PASSPHRASE is not set (set it empty for a key without a passphrase)"
fi
for f in "$@"; do
  [ -f "$f" ] || fail "$f does not exist"
done

written=()
cleanup() {
  for asc in "${written[@]}"; do
    rm -f -- "$asc"
  done
}
trap 'cleanup' ERR

for f in "$@"; do
  asc="$f.asc"
  written+=("$asc")
  printf '%s' "$GPG_PASSPHRASE" | gpg --batch --yes --pinentry-mode loopback \
    --passphrase-fd 0 --no-secmem-warning --digest-algo sha256 \
    --local-user "$fpr" --armor --detach-sign --output "$asc" -- "$f"

  # A signature counts only if gpg exits 0 and reports a VALIDSIG whose
  # primary key is FPR.
  status="$(gpg --batch --status-fd 1 --verify -- "$asc" "$f" 2>/dev/null)" ||
    { cleanup; fail "the signature on $f does not verify"; }
  primary="$(awk '$2 == "VALIDSIG" {print $NF; exit}' <<<"$status")"
  if [ "$primary" != "$fpr" ]; then
    cleanup
    fail "$f was not signed by $fpr (got '${primary:-nothing}')"
  fi
  echo "signed $(basename -- "$f") -> $(basename -- "$asc") by $fpr"
done
