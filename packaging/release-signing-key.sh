#!/usr/bin/env bash
# Print the fingerprint of the one release key this keyring may sign with.
#
#   fpr="$(bash packaging/release-signing-key.sh security/KEYS)"
#
# Every signing step in release.yml calls this after GPG_PRIVATE_KEY is
# imported, and signs with the fingerprint it prints: the RPMs, the DEBs and
# SHA256SUMS. It prints the 40-hex primary fingerprint of the imported key on
# stdout, and exits non-zero, printing nothing there, when:
#
#   - the keyring holds no secret primary, or more than one (a stubbed
#     primary, `sec#`, from --export-secret-subkeys still counts);
#   - that primary is not a primary key in KEYS, the file operators import;
#   - it has no usable signing key: a primary or subkey that can sign, whose
#     secret part is present, and that is not expired, revoked or disabled.
#
# KEYS may hold several primaries, as it does during a key rotation, as long
# as the imported key is one of them. Reading KEYS changes no keyring
# (--import-options show-only). GNUPGHOME is honored, which is how the tests
# use throwaway keys.
#
# Spec: release-package-build C-19.

set -euo pipefail

keys="${1:?usage: release-signing-key.sh KEYS}"
fail() {
  echo "release-signing-key: $*" >&2
  exit 1
}
[ -r "$keys" ] || fail "cannot read $keys"

secret="$(gpg --batch --with-colons --list-secret-keys)" || fail "gpg could not list the secret keys"
count="$(awk -F: '$1 == "sec"' <<<"$secret" | wc -l)"
if [ "$count" -ne 1 ]; then
  fail "the keyring holds $count secret primary keys; exactly one, the release key, is allowed"
fi
fpr="$(awk -F: '$1 == "sec" {want = 1; next} want && $1 == "fpr" {print $10; exit}' <<<"$secret")"
[[ "$fpr" =~ ^[0-9A-F]{40}$ ]] || fail "could not read the secret key's fingerprint"

listed="$(gpg --batch --with-colons --import-options show-only --import "$keys" 2>/dev/null)" ||
  fail "gpg could not read $keys"
primaries="$(awk -F: '$1 == "pub" {want = 1; next} want && $1 == "fpr" {print $10; want = 0} $1 == "sub" {want = 0}' <<<"$listed")"
grep -qx -- "$fpr" <<<"$primaries" || fail "the imported key $fpr is not a primary key in $keys"

# A record that can sign: its own capabilities (field 12, lowercase) include
# s, its secret part is present (field 15 is not the stub mark #), and its
# validity (field 2) is not expired, revoked, disabled or invalid.
usable="$(awk -F: '($1 == "sec" || $1 == "ssb") && $12 ~ /s/ && $15 != "#" && $2 !~ /[erdi]/ {print $5}' <<<"$secret")"
[ -n "$usable" ] || fail "the imported key $fpr has no usable signing key or subkey"

echo "$fpr"
