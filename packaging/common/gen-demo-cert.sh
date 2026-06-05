#!/usr/bin/env bash
# Generate a self-signed demo TLS cert + key pair. Shipped with the
# package so the service boots out of the box; operators are expected
# to replace before production.
#
# Usage: gen-demo-cert.sh <out-dir>

set -euo pipefail

OUT="${1:?usage: $0 <out-dir>}"
mkdir -p "$OUT"

openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -subj "/CN=openwatch-demo/O=Hanalyx/OU=Stage 0 demo cert" \
    -keyout "$OUT/key.pem" \
    -out    "$OUT/cert.pem" \
    >/dev/null 2>&1

chmod 0644 "$OUT/cert.pem"
chmod 0600 "$OUT/key.pem"
echo "wrote $OUT/cert.pem (0644) and $OUT/key.pem (0600)"
