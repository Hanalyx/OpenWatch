#!/usr/bin/env bash
# Verify an OpenWatch report snapshot: content hash, then Ed25519 signature.
#
# These are the exact commands in docs/guides/REPORT_VERIFICATION.md. The guide
# explains them; this file is what the test suite runs, so the two cannot drift.
#
# Usage:
#   verify.sh <report.json> <report.meta.json> <signing-key.json>
#
# Needs openssl 3.x and coreutils. Nothing else, and no network: verification is
# arithmetic over files you already hold.
#
# Exit codes, kept distinct so a caller can tell the failures apart:
#   0  content hash matched AND signature verified
#   2  the canonical JSON does not hash to the declared content_sha256
#   3  the signature does not verify against the supplied key
#   4  the artifact carries no signature
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <report.json> <report.meta.json> <signing-key.json>" >&2
  exit 64
fi
report=$1
meta=$2
keyfile=$3

field() { python3 -c 'import json,sys; v=json.load(open(sys.argv[1])).get(sys.argv[2]); print("" if v is None else v)' "$1" "$2"; }

declared=$(field "$meta" content_sha256)
signature=$(field "$meta" signature)

# Step 1: the canonical JSON must hash to the content address the snapshot
# declares. This is what ties the bytes you are reading to the thing that
# was signed; the signature alone says nothing about the report body.
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

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Step 2: rebuild the exact payload that was signed. It is the domain tag
# followed by the hex content address, NOT the report bytes themselves.
# Signing the hash is what makes verification cheap; the domain tag is what
# stops this signature being replayed as a signature over anything else.
printf 'openwatch/report-snapshot/v1\n%s' "$declared" > "$work/payload.bin"

# Step 3: wrap the raw 32-byte Ed25519 key in the SPKI header openssl expects.
# The API serves the bare key; the 12-byte prefix is the fixed DER preamble
# for id-Ed25519.
field "$keyfile" public_key | base64 -d > "$work/pub.raw"
printf '\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00' > "$work/pub.der"
cat "$work/pub.raw" >> "$work/pub.der"
openssl pkey -pubin -inform DER -in "$work/pub.der" -out "$work/pub.pem" 2>/dev/null

# Step 4: verify.
printf '%s' "$signature" | base64 -d > "$work/sig.bin"
if ! openssl pkeyutl -verify -pubin -inkey "$work/pub.pem" -rawin \
      -in "$work/payload.bin" -sigfile "$work/sig.bin" >/dev/null 2>&1; then
  echo "SIGNATURE INVALID for key $(field "$keyfile" key_id)" >&2
  exit 3
fi

echo "signature OK: key $(field "$keyfile" key_id)"
if [ "$(field "$keyfile" ephemeral)" = "True" ] || [ "$(field "$keyfile" ephemeral)" = "true" ]; then
  echo "WARNING: this key is EPHEMERAL. The server generated it at boot and will" >&2
  echo "generate a different one at the next restart, so this result cannot be" >&2
  echo "reproduced later. Treat it as a development artifact." >&2
fi
echo
echo "Verified that this key signed this content."
echo "NOT established: that the key is OpenWatch's. If you fetched it from the"
echo "same server that served the report, you have checked consistency only."
