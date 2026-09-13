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

## Dependencies

| Tool | Why |
|---|---|
| Python 3 | Reads fields out of the JSON responses. Standard library only. |
| OpenSSL 3.x | Ed25519 verification, which needs `pkeyutl -rawin`. |
| coreutils | `sha256sum`, `base64`, `cat`, `printf`. |

Run the Python snippets with `python3 -I -S`. That is isolated mode with no
site packages, so nothing installed on the machine can change what they read.

Verification runs offline. Nothing here calls back to the server.

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

**An unsigned report needs only the first two.** `signature` and
`signing_key_id` are an all-or-nothing pair: both are present or both are
`null`. When they are absent there is no key to fetch, and the procedure runs
without one. One present without the other is malformed metadata, not a signed
report and not an unsigned one, and it is rejected as such.

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
SHA=$(python3 -I -S -c 'import json;print(json.load(open("report.meta.json"))["content_sha256"])')
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

Check three things about the key before you use it:

| Check | Why |
|---|---|
| `algorithm` is exactly `ed25519` | A different algorithm needs a different routine. Verifying it with this one would report success it did not earn. |
| The decoded key is exactly 32 bytes | Anything else is not an Ed25519 key, however well formed the base64 looks. |
| Both identifiers equal the one you DERIVE from the key | See below. Comparing them only with each other proves the two documents agree, which whoever wrote them controls. |

The identifier is `ed25519-` followed by the first 16 hex characters of the
SHA-256 of the decoded key:

```bash
echo "ed25519-$(sha256sum pub.raw | cut -c1-16)"
```

That value must equal `key_id` in the key response **and** `signing_key_id` on
the report. Deriving it is what ties the identifier to real key material. Two
documents can carry the same invented identifier and agree with each other
perfectly.

```bash
python3 -I -S -c 'import json;print(json.load(open("signing-key.json"))["public_key"])' \
  | base64 -d > pub.raw
wc -c < pub.raw    # must be 32
printf '\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00' > pub.der
cat pub.raw >> pub.der
openssl pkey -pubin -inform DER -in pub.der -out pub.pem
```

---

## Step 4: verify the signature

```bash
python3 -I -S -c 'import json,base64,sys;sys.stdout.buffer.write(base64.b64decode(json.load(open("report.meta.json"))["signature"]))' > sig.bin

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
cd docs/runbooks/examples/report-verification

# Consistency only.
./verify.sh report.json report.meta.json signing-key.json

# With a trust anchor you hold independently.
./verify.sh report.json report.meta.json signing-key.json "$(cat trusted-key.sha256)"

# An unsigned artifact, with no key file.
./verify.sh unsigned/report.json unsigned/report.meta.json
```

Usage is `verify.sh <report.json> <report.meta.json> [signing-key.json]
[trusted]`. The key file is required for a signed artifact and unused for an
unsigned one.

| Exit | Meaning |
|---|---|
| 0 | Every check passed. Read the last lines: with no anchor this is consistency only. |
| 2 | The canonical JSON does not hash to the declared `content_sha256`. |
| 3 | The signature does not verify against the supplied key. |
| 4 | The artifact is unsigned. |
| 5 | The key is not declared `ed25519`. |
| 6 | The decoded public key is not 32 bytes. |
| 7 | A key identifier is missing, or is not the one derived from the key. |
| 8 | The key does not match the trust anchor you supplied. |
| 9 | Malformed metadata: `signature` and `signing_key_id` are not both present or both absent. |

---

## What this does not prove

**A key fetched from the same server proves consistency, not authenticity.**

If a server can serve you a replaced report, it can serve the matching
signature and the matching public key beside it. Everything checks out, and the
check has told you only that those three files agree with each other.

### The trust anchor

To get authenticity you need a copy of the key from an independently trusted
channel: one that does not depend on that server. The anchor is the **complete
key**, in one of two forms:

| Anchor | What it is |
|---|---|
| The full `public_key` | The complete base64 string from the signing-key response. |
| Its SHA-256 | The lowercase hex SHA-256 of the **decoded 32 bytes**, not of the base64 text. |

```bash
python3 -I -S -c 'import json;print(json.load(open("signing-key.json"))["public_key"])' \
  | base64 -d | sha256sum
```

Record one of those when the key is first installed. Store it where the
OpenWatch host cannot change it, and compare against that record every time.

### Do not anchor on `key_id`

**`key_id` and `signing_key_id` are correlation identifiers, not anchors.**
Both are the first 8 bytes of the SHA-256 of the public key: 64 bits. They are
there to match a report to a key and to name a key in your records.

Sixty-four bits is not enough to anchor trust. Someone able to generate keys
can search for a different key carrying the same `key_id`, and the work needed
is far below what a signature is supposed to withstand. Comparing `key_id`
values would feel like checking a fingerprint and would not be one. Compare the
whole key, or its full SHA-256.

---

## Proving it to yourself

The example directory carries a `counterexample/`: a second report with its own
signature and its own public key, all three internally consistent, signed by a
different key.

```bash
# Passes. Nothing here is inconsistent.
./verify.sh counterexample/report.json counterexample/report.meta.json \
  counterexample/signing-key.json

# Rejected, because the key is not the one you trust.
./verify.sh counterexample/report.json counterexample/report.meta.json \
  counterexample/signing-key.json "$(cat trusted-key.sha256)"
```

The first command exits `0` and says authenticity was not established. The
second exits `8`. That gap is the whole argument for holding an anchor: a
replacement bundle is not detectably wrong until you compare it with something
the server did not give you.

## About the committed example key

**The key in this directory is public, test-only, and its private half is
derivable by anyone.** The seed is written in the clear in
`internal/report/fixture_gen_test.go`, so the example can be regenerated. That
is deliberate: the fixture teaches the procedure, it is not evidence about any
system.

Never reuse it, never treat it as secret, and never treat a report it signed as
attested. A production key is 32 bytes from a random source, readable only by
the service; see
[Production deployment](../guides/PRODUCTION_DEPLOYMENT.md#set-the-report-signing-key-before-issuing-evidence).

## Ephemeral keys

When no signing key is configured, the service generates a fresh key at every
boot and `ephemeral` is `true` on the signing-key response.

Reports still get signed. The signatures still verify, right up until the next
restart, after which the server serves a different key and every earlier
signature stops verifying against it. Nothing about the report changes; the
person checking it finds out, and you do not.

Treat an ephemeral signature as a development artifact and nothing more. Set a
durable key before issuing any report that someone will keep. See
[Production deployment](../guides/PRODUCTION_DEPLOYMENT.md#set-the-report-signing-key-before-issuing-evidence).

---

## Unsigned reports

A snapshot generated while no signer was wired carries `signature` and
`signing_key_id` as `null`. This is not a failure and not tampering. It means
nothing attested to the content at the time it was made.

Check it with two files and no key:

```bash
./verify.sh unsigned/report.json unsigned/report.meta.json
```

Step 1 still works and is still worth running: it shows the bytes are the ones
the snapshot names. The script reports exit `4` after that check, not before,
so you learn both things. Nothing beyond step 1 applies, and no signing key is
fetched or opened.

An unsigned artifact cannot be made signed after the fact, because the
signature covers the content address as it stood at generation.

**One field without the other is neither state.** A `signature` with no
`signing_key_id`, or the reverse, is metadata that describes nothing real. The
script exits `9` rather than guessing, because guessing in either direction
hides something: reading it as unsigned would excuse a missing identifier, and
reading it as signed would excuse a missing signature.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| Hash mismatch on an untouched file | You exported the PDF or CSV face. Only the JSON face is content addressed. |
| `Signature Verification Failure` on a good report | The payload was built wrong. It is the domain tag plus the hex hash, not the report bytes. |
| Same failure, correct payload | `-rawin` is missing. |
| Exit 7, key identity | The key on offer is not the one the report names, or its `key_id` is not the identifier of the key material it ships. |
| Exit 9, malformed metadata | `signature` and `signing_key_id` disagree about whether the snapshot is signed. |
| Exit 8, trusted key mismatch | The bundle is self-consistent but signed by a key you do not trust. Treat it as a replacement until proven otherwise. |
| `503` from the signing-key endpoint | The server has no signer wired, so it has no key to publish. |
| Verified yesterday, fails today | An ephemeral key, and the service restarted. |

---

## Related

- [Production deployment](../guides/PRODUCTION_DEPLOYMENT.md) sets the durable signing key.
- [Environment reference](../guides/ENVIRONMENT_REFERENCE.md) documents
  `OPENWATCH_REPORTS_SIGNING_KEY_FILE`.
- [Scanning and compliance](../guides/SCANNING_AND_COMPLIANCE.md) explains the scores a
  report carries.
- [API guide](../guides/API_GUIDE.md) covers the report endpoints.
