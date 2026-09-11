#!/usr/bin/env bash
# Verify an OpenWatch report snapshot.
#
# These are the exact commands in docs/guides/REPORT_VERIFICATION.md. The guide
# explains them; this file is what the test suite runs, so the two cannot drift.
#
# Usage:
#   verify.sh <report.json> <report.meta.json> <signing-key.json> [trusted]
#
# The optional fourth argument is a TRUST ANCHOR you obtained WITHOUT asking the
# server that served the report: either the complete base64 public key, or the
# lowercase hex SHA-256 of the decoded 32-byte key. Without it this script can
# only show the three files agree with each other. With it, a replacement signed
# by a different key is rejected.
#
# Do NOT pass the short key_id here. It is 64 bits and exists to correlate a
# report with a key, not to anchor trust.
#
# Dependencies: Python 3, OpenSSL 3.x, coreutils. No network.
#
# Exit codes, kept distinct so a caller can tell the failures apart:
#   0  every check passed
#   2  the canonical JSON does not hash to the declared content_sha256
#   3  the signature does not verify against the supplied key
#   4  the artifact carries no signature
#   5  the key is not declared ed25519
#   6  the decoded public key is not 32 bytes
#   7  the key's key_id does not match the report's signing_key_id
#   8  the key does not match the trusted anchor supplied
set -euo pipefail

if [ "$#" -lt 3 ] || [ "$#" -gt 4 ]; then
  echo "usage: $0 <report.json> <report.meta.json> <signing-key.json> [trusted]" >&2
  exit 64
fi
report=$1
meta=$2
keyfile=$3
trusted=${4:-}

# -I -S: isolated, no site packages, no user site directory, no PYTHON* env.
# The snippets below are standard library only and should not be able to pick
# up anything from the machine running them.
py() { python3 -I -S "$@"; }
field() { py -c 'import json,sys; v=json.load(open(sys.argv[1])).get(sys.argv[2]); print("" if v is None else v)' "$1" "$2"; }

declared=$(field "$meta" content_sha256)
signature=$(field "$meta" signature)
reported_key=$(field "$meta" signing_key_id)
key_id=$(field "$keyfile" key_id)
algorithm=$(field "$keyfile" algorithm)

# Step 0: the key must be the kind of key this procedure knows how to check.
# Checking the algorithm before using the key keeps a future key type from
# being verified with the wrong routine and reported as fine.
if [ "$algorithm" != "ed25519" ]; then
  echo "ALGORITHM MISMATCH: key declares '$algorithm', expected 'ed25519'" >&2
  exit 5
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

field "$keyfile" public_key | base64 -d > "$work/pub.raw" 2>/dev/null || true
keylen=$(wc -c < "$work/pub.raw" | tr -d ' ')
if [ "$keylen" != "32" ]; then
  echo "MALFORMED KEY: decoded public key is $keylen bytes, expected 32" >&2
  exit 6
fi

# Step 1: the canonical JSON must hash to the content address the snapshot
# declares. This ties the bytes you are reading to the thing that was signed;
# the signature alone says nothing about the report body.
computed=$(sha256sum "$report" | cut -d' ' -f1)
if [ "$computed" != "$declared" ]; then
  echo "CONTENT MISMATCH" >&2
  echo "  computed sha256: $computed" >&2
  echo "  declared content_sha256: $declared" >&2
  exit 2
fi
echo "content hash OK: $computed"

if [ -z "$signature" ]; then
  echo "NO SIGNATURE: this snapshot was generated with no signing key wired." >&2
  echo "The content hash above still shows the bytes are internally consistent," >&2
  echo "but nothing attests to who produced them." >&2
  exit 4
fi

# Step 2: the key on offer must be the key the report names. This is a
# CORRELATION check, not a trust check: it catches the wrong key being handed
# over, and nothing more.
if [ -n "$reported_key" ] && [ "$key_id" != "$reported_key" ]; then
  echo "KEY ID MISMATCH: report names '$reported_key', key file offers '$key_id'" >&2
  exit 7
fi

# Step 3: rebuild the exact payload that was signed. It is the domain tag
# followed by the hex content address, NOT the report bytes themselves.
printf 'openwatch/report-snapshot/v1\n%s' "$declared" > "$work/payload.bin"

# Step 4: wrap the raw 32-byte key in the SPKI header openssl expects. The API
# serves the bare key; the 12-byte prefix is the fixed DER preamble for
# id-Ed25519.
printf '\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00' > "$work/pub.der"
cat "$work/pub.raw" >> "$work/pub.der"
openssl pkey -pubin -inform DER -in "$work/pub.der" -out "$work/pub.pem" 2>/dev/null

printf '%s' "$signature" | base64 -d > "$work/sig.bin"
if ! openssl pkeyutl -verify -pubin -inkey "$work/pub.pem" -rawin \
      -in "$work/payload.bin" -sigfile "$work/sig.bin" >/dev/null 2>&1; then
  echo "SIGNATURE INVALID for key $key_id" >&2
  exit 3
fi
echo "signature OK: key $key_id"

if [ "$(field "$keyfile" ephemeral)" = "True" ] || [ "$(field "$keyfile" ephemeral)" = "true" ]; then
  echo "WARNING: this key is EPHEMERAL. The server generated it at boot and will" >&2
  echo "generate a different one at the next restart, so this result cannot be" >&2
  echo "reproduced later. Treat it as a development artifact." >&2
fi

# Step 5: the anchor. Everything above compares the three files with each
# other. Only this compares them with something the server did not supply.
if [ -z "$trusted" ]; then
  echo
  echo "CONSISTENCY ONLY. These three files agree with each other."
  echo "AUTHENTICITY NOT ESTABLISHED: no trusted anchor was supplied, so nothing"
  echo "here rules out a replacement report served with its own matching"
  echo "signature and key. Re-run with the complete public key, or its SHA-256,"
  echo "obtained independently of the server that served this report."
  exit 0
fi

actual_b64=$(field "$keyfile" public_key)
actual_sha=$(sha256sum "$work/pub.raw" | cut -d' ' -f1)
if [ "$trusted" = "$actual_b64" ] || [ "$trusted" = "$actual_sha" ]; then
  echo
  echo "AUTHENTICITY ESTABLISHED against the anchor supplied."
  echo "  public key sha256: $actual_sha"
  exit 0
fi

echo "TRUSTED KEY MISMATCH" >&2
echo "  anchor supplied:   $trusted" >&2
echo "  key in this bundle: $actual_b64" >&2
echo "  its sha256:         $actual_sha" >&2
echo "This bundle is internally consistent but was signed by a DIFFERENT key" >&2
echo "than the one you trust. That is exactly what a replacement looks like." >&2
exit 8
