# Verifying a report

**Audience:** operators and auditors who hold an OpenWatch report and need to
check that it is intact and that OpenWatch produced it.

Verification answers two separate questions. Keep them apart, because they have
different answers and different costs:

1. **Integrity.** Do these bytes match the content address the snapshot
   declares? This is a hash comparison and needs nothing but the file.
2. **Provenance.** Did an OpenWatch signing key sign that content address? This
   needs the signature and a public key you trust.

A third question, **authenticity**, is not answered by either step on its own.
See [What this does not prove](#what-this-does-not-prove).

You need `openssl` 3.x and standard command line tools. Verification runs
offline. Nothing here calls back to the server.

---

## What you need

| Item | Where it comes from |
|---|---|
| The canonical JSON face | `GET /api/v1/reports/{id}/export?face=json` |
| `content_sha256`, `signature`, `signing_key_id` | `GET /api/v1/reports/{id}` |
| The public key | `GET /api/v1/reports/signing-key`, or a channel you trust more |

All three endpoints need the `host:read` permission. The complete response
shape is in [the OpenAPI contract](../../api/openapi.yaml); this guide names
only the fields verification uses.

**Use the JSON face, not the PDF or the CSV.** The content address covers the
canonical JSON. The other faces are renderings of the same snapshot and hash to
different bytes.

```bash
curl -sS -H "Authorization: Bearer $TOKEN" \
  "https://openwatch.example.com/api/v1/reports/$ID/export?face=json" \
  -o report.json

curl -sS -H "Authorization: Bearer $TOKEN" \
  "https://openwatch.example.com/api/v1/reports/$ID" \
  -o report.meta.json

curl -sS -H "Authorization: Bearer $TOKEN" \
  "https://openwatch.example.com/api/v1/reports/signing-key" \
  -o signing-key.json
```

The signing-key endpoint returns `404` on older builds and `503` when the
server has no signer wired. The plural `/api/signing/public-keys` path does not
exist; do not use it.

---

## Step 1: check the content hash

```bash
sha256sum report.json
```

Compare the result with `content_sha256` in `report.meta.json`. They must be
identical.

A match means the JSON you hold is the exact content the snapshot names. A
mismatch means the bytes changed after generation, or you fetched a different
face. Stop and investigate; the signature check below cannot repair this.

---

## Step 2: rebuild the signed payload

OpenWatch does not sign the report bytes. It signs the **content address**,
under a domain tag:

```
openwatch/report-snapshot/v1\n<content_sha256>
```

The tag ends with a newline, and the hash follows as its 64 lowercase hex
characters. There is no trailing newline after the hash.

```bash
SHA=$(python3 -c 'import json;print(json.load(open("report.meta.json"))["content_sha256"])')
printf 'openwatch/report-snapshot/v1\n%s' "$SHA" > payload.bin
```

Signing the hash rather than the document keeps verification cheap for a large
report. The domain tag is what stops the same signature being presented as a
signature over some other OpenWatch payload.

**Do not verify the signature against `report.json` itself.** That check fails
on a perfectly valid report, because those are not the bytes that were signed.

---

## Step 3: prepare the public key

The API serves the raw 32-byte Ed25519 key, base64 encoded. `openssl` wants it
inside an SPKI header, which for Ed25519 is a fixed 12-byte prefix:

```bash
python3 -c 'import json;print(json.load(open("signing-key.json"))["public_key"])' \
  | base64 -d > pub.raw
printf '\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00' > pub.der
cat pub.raw >> pub.der
openssl pkey -pubin -inform DER -in pub.der -out pub.pem
```

Check that `key_id` in `signing-key.json` matches `signing_key_id` on the
report. If they differ, the report was signed by a key the server no longer
serves, and you need the original key to verify it.

---

## Step 4: verify the signature

```bash
python3 -c 'import json,base64,sys;sys.stdout.buffer.write(base64.b64decode(json.load(open("report.meta.json"))["signature"]))' > sig.bin

openssl pkeyutl -verify -pubin -inkey pub.pem -rawin -in payload.bin -sigfile sig.bin
```

`Signature Verified Successfully` means the key you supplied signed that
content address.

`-rawin` is required. Ed25519 signs the message itself rather than a digest of
it, and without that flag `openssl` will hash first and the check will fail.

---

## The whole thing as a script

[`examples/report-verification/verify.sh`](examples/report-verification/verify.sh)
runs all four steps. The example files beside it are a real signed report,
produced by the same code path that serves the API.

```bash
cd docs/guides/examples/report-verification
./verify.sh report.json report.meta.json signing-key.json
```

It exits `0` when both checks pass, `2` when the content hash does not match,
`3` when the signature does not verify, and `4` when the artifact carries no
signature.

---

## What this does not prove

**A key fetched from the same server proves consistency, not authenticity.**

If a server can serve you a replaced report, it can serve the matching
signature and the matching public key beside it. Everything checks out, and the
check has told you only that those three files agree with each other.

To get authenticity you need the key, or its `key_id` fingerprint, from an
independently trusted channel: one that does not depend on that server. Record the fingerprint when the
key is first installed. Store it where the OpenWatch host cannot change it, and
compare against that record every time.

The `key_id` is a short public fingerprint of the public key, so comparing
fingerprints is enough. You do not need to move the key itself.

---

## Ephemeral keys

When no signing key is configured, the service generates a fresh key at every
boot and `ephemeral` is `true` on the signing-key response.

Reports still get signed. The signatures still verify, right up until the next
restart, after which the server serves a different key and every earlier
signature stops verifying against it. Nothing about the report changes; the
person checking it finds out, and you do not.

Treat an ephemeral signature as a development artifact and nothing more. Set a
durable key before issuing any report that someone will keep. See
[Production deployment](PRODUCTION_DEPLOYMENT.md#set-the-report-signing-key-before-issuing-evidence).

---

## Unsigned reports

A snapshot generated while no signer was wired carries `signature` and
`signing_key_id` as `null`. This is not a failure and not tampering. It means
nothing attested to the content at the time it was made.

Step 1 still works and is still worth running: it shows the bytes are the ones
the snapshot names. Step 2 onward does not apply. An unsigned artifact cannot
be made signed after the fact, because the signature covers the content address
as it stood at generation.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| Hash mismatch on an untouched file | You exported the PDF or CSV face. Only the JSON face is content addressed. |
| `Signature Verification Failure` on a good report | The payload was built wrong. It is the domain tag plus the hex hash, not the report bytes. |
| Same failure, correct payload | `-rawin` is missing, or `key_id` does not match `signing_key_id`. |
| `503` from the signing-key endpoint | The server has no signer wired, so it has no key to publish. |
| Verified yesterday, fails today | An ephemeral key, and the service restarted. |

---

## Related

- [Production deployment](PRODUCTION_DEPLOYMENT.md) sets the durable signing key.
- [Environment reference](ENVIRONMENT_REFERENCE.md) documents
  `OPENWATCH_REPORTS_SIGNING_KEY_FILE`.
- [Scanning and compliance](SCANNING_AND_COMPLIANCE.md) explains the scores a
  report carries.
- [API guide](API_GUIDE.md) covers the report endpoints.
