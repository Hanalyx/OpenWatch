# Evidence Signing Security Review

**Date**: 2026-04-14
**Last updated**: 2026-04-14 (scope narrow per Kensa↔OpenWatch coordination)
**Scope**: `backend/app/services/signing/`, `backend/app/routes/signing/`, signing integration in `backend/app/services/compliance/audit_export.py`, schema migration `051_add_signing_keys.py`
**Reviewer**: Automated (Bandit 1.9.4, Semgrep 239 rules) + manual code review
**Spec**: `specs/services/signing/evidence-signing.spec.yaml` (9 ACs, active, **v2.0**)
**Phase**: Phase 4 mandatory security review per `docs/OPENWATCH_Q1_Q3_PLAN.md` §"Security review gates"

---

## Scope narrow (2026-04-14)

Per the Kensa↔OpenWatch coordination (`docs/KENSA_OPENWATCH_COORDINATION_2026-04-14.md` §3.2; Kensa team response §2.2), this review covered two trust layers that must not be conflated. The signing scope has been narrowed accordingly.

### Trust-layer boundary

| Layer | Who signs | What it attests | Storage |
|---|---|---|---|
| **Per-transaction evidence envelope** | **Kensa** (not OpenWatch) | "This execution happened on this host at this time" | Kensa SQLite store at capture time; envelope travels with the transaction log record |
| **Aggregate audit export / quarterly posture report / State-of-Production release** | OpenWatch | "OpenWatch aggregated this data from N hosts and produced this artifact" | OpenWatch PostgreSQL; signed at export time by `SigningService` |

### What was removed from OpenWatch

- `POST /api/transactions/{id}/sign` endpoint — that surface belongs to Kensa per `KENSA_GO_DAY1_PLAN.md` §8.2
- Any future per-transaction signing code path — OpenWatch does not attempt to co-sign what Kensa already signed

### What remains in OpenWatch (covered by this review)

- `SigningService.sign_envelope()` used **only** by `audit_export._generate_json()` and future aggregate-report services
- `GET /api/signing/public-keys` — public key list so auditors can verify OpenWatch-signed aggregate bundles
- `POST /api/signing/verify` — verification endpoint for OpenWatch-signed aggregate bundles
- All five findings below remain valid for the narrowed scope

### OpenWatch audit-UI verification of Kensa-signed envelopes

At Kensa Week 22, OpenWatch audit UIs verify per-transaction envelopes via `kensa.api.Kensa.VerifyEnvelope()` (see `KENSA_GO_DAY1_PLAN.md` §3.5.4). OpenWatch does **not** maintain its own Kensa-envelope verification code path — Kensa owns that verification logic.

## Summary

Manual review found one HIGH (insecure private-key fallback to plain base64), two MEDIUM (race condition on key generation, silent signing failure on export), and two LOW (verify endpoint DoS surface, no key revocation flag). Automated scans clean. **HIGH and both MEDIUMs fixed in this PR**; LOWs filed as follow-up issues.

## Findings

### Resolved in this PR

#### SEC-SIGN-01: Private key fallback to plain base64 — HIGH

**Details:** `signing_service.py:91-94`:

```python
if self._enc:
    priv_encrypted = base64.b64encode(self._enc.encrypt(priv_bytes)).decode()
else:
    priv_encrypted = base64.b64encode(priv_bytes).decode()
```

When `EncryptionService` is not provided, the Ed25519 private key is stored **base64-encoded only — no encryption**. The docstring at line 57 calls this "dev only" but nothing enforces that. A production misconfiguration (e.g., `app.state.encryption_service` not initialized at startup) silently produces a deployment whose audit-facing claim ("private keys encrypted at rest via EncryptionService") is false.

This violates the spec's AC-8 ("Private keys MUST be encrypted at rest using AES-256-GCM via EncryptionService").

**Risk:** Anyone with database read access (operator with PostgreSQL credentials, backup restorer, breach attacker who lifts a backup) can decode the private key with one base64 round-trip and forge signed evidence bundles indistinguishable from legitimate ones. The signing trust chain collapses.

**Fix:** Hard-fail in `generate_key()` and `sign_envelope()` if `_enc is None` unless an explicit `OPENWATCH_SIGNING_DEV_MODE=true` env var is set (test/dev only). Production deploys that rely on the silent fallback will surface the misconfiguration loudly instead of quietly accepting it.

#### SEC-SIGN-02: Race condition on key generation — MEDIUM

**Details:** `generate_key()` at lines 96-111 executes:
```
UPDATE deployment_signing_keys SET active = false WHERE active = true
INSERT INTO deployment_signing_keys (..., active) VALUES (..., true)
COMMIT
```
Two separate `db.execute()` calls with no transaction wrapping. Concurrent invocations (admin script + API user, or two simultaneous rotations) can interleave such that two rows end up with `active = true`. The `sign_envelope()` query uses `LIMIT 1` so it picks one — non-deterministically.

**Risk:** Sign operations under load could pick either of the two active keys. Verification still works (looks up by `key_id`), so this doesn't break trust, but it does break the "one active key at any time" invariant the codebase assumes.

**Fix:** Wrap UPDATE + INSERT in a single transaction with `SELECT ... FOR UPDATE` on the active row (PostgreSQL row-level lock).

#### SEC-SIGN-03: Silent signing failure on export — MEDIUM

**Details:** `audit_export.py:447-458` wraps the signing call in `try / except Exception`, logs a warning, and proceeds with an unsigned export. The export file is generated and downloadable with no indication to the auditor that signing failed.

**Risk:** The compliance use case for these exports requires non-repudiation. An auditor downloads what they believe is a signed export and gets an unsigned one — and the only signal is a backend log line they don't have access to. The export's value as audit evidence is undermined.

**Fix:** When signing fails, write `"signed_bundle": null` to the export with a `"signing_error"` field naming the cause. The export is still produced (so operators can see partial data), but the fact that it is unsigned is now machine-detectable from the export itself.

### Deferred (follow-up issues filed)

#### SEC-SIGN-04: Verify endpoint is unauthenticated and CPU-bound — LOW

**Details:** `POST /api/signing/verify` is unauthenticated by design (auditors verify externally). Each request does base64 decode + canonical JSON serialization + Ed25519 verification. Large or deeply-nested envelopes amplify the cost of the JSON canonicalization step. Combined with the global rate limit (100 req/min per IP) the practical risk is bounded, but a coordinated source could still consume meaningful CPU.

**Recommendation:** Add a per-endpoint request-size limit (e.g., 64KB envelope max) and a stricter rate limit (e.g., 20 req/min per IP) on this specific endpoint. Tracked as follow-up issue.

#### SEC-SIGN-05: No key revocation flag — LOW

**Details:** Current model: `active` (true/false) + `rotated_at` timestamp. There's no way to mark a key as "compromised — bundles signed with this key should NOT be trusted." `verify()` happily verifies any bundle whose `key_id` matches a row in `deployment_signing_keys`, regardless of whether the key was leaked.

**Recommendation:** Add `revoked` boolean + `revoked_at` timestamp + `revocation_reason` text. `verify()` returns false (with reason in response) for bundles signed with a revoked key. Add `POST /api/signing/keys/{id}/revoke` admin endpoint. Tracked as follow-up issue.

### Informational (no action)

#### INFO-SIGN-01: Public public-keys endpoint exposes retired keys

By design — auditors need retired keys to verify older bundles. Not a finding.

#### INFO-SIGN-02: Canonical JSON for deterministic signing

`sign_envelope()` uses `json.dumps(envelope, sort_keys=True, separators=(",", ":"))` — correct deterministic serialization. Same canonicalization in `verify()`. Confirmed correct.

#### INFO-SIGN-03: alg=none N/A

Ed25519 has no algorithm-confusion vector (single algorithm by definition). The OIDC `alg=none` defense applied to JWTs is not relevant here.

## Positive observations

| Area | Finding | Location |
|------|---------|----------|
| Algorithm choice | Ed25519 (modern, no parameter choices, fixed output size, fast) | `signing_service.py:23, 74` |
| Key generation | `cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.generate()` (CSPRNG-backed) | line 74 |
| Canonical signing | `json.dumps(..., sort_keys=True, separators=(",", ":"))` — deterministic byte representation | lines 162, 201 |
| Verify failure mode | `except Exception: return False` — never leaks why verify failed | lines 204-208 |
| RBAC on sign | `@require_role([SECURITY_ADMIN, SUPER_ADMIN])` — only privileged users sign | `routes.py:123` |
| Public verify | Unauthenticated by design — auditors don't need OpenWatch credentials | `routes.py:95` |
| Schema | UUID PK, `active` flag, `rotated_at` for retirement | migration 051 |
| Rotation support | Old keys remain in DB for verification of historical bundles | `signing_service.py:96-100` |
| Encrypted at rest | `EncryptionService.encrypt()` AES-256-GCM applied to private key | `signing_service.py:91-92` (when configured) |

## Tool results

### Bandit 1.9.4 (high+medium severity)

```
Code scanned: 416 lines
Total issues: 0
```

### Semgrep (p/security-audit + p/owasp-top-ten + p/python + p/secrets)

```
239 rules run, 4 files scanned, 0 findings
```

## Governance

This automated + manual review does **not** substitute for:

1. **Key management operational runbook** — operators are responsible for the lifecycle of `OPENWATCH_MASTER_KEY` (the EncryptionService root key); compromise of that key compromises all signing keys
2. **External auditor verification flow** — the public verification endpoint and `verify-bundle.py` companion script (if any) need a human-readable runbook published alongside signed exports
3. **Cryptoperiod policy** — NIST SP 800-57 §5.3.6 recommends Ed25519 cryptoperiods ≤2 years; OpenWatch should establish a rotation schedule (suggest annual)

## References

- NIST SP 800-57 Pt. 1 Rev. 5 §5.3.6 (asymmetric key cryptoperiods): https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final
- RFC 8032 (Ed25519): https://datatracker.ietf.org/doc/html/rfc8032
- Spec: `specs/services/signing/evidence-signing.spec.yaml` (8 ACs, active)
- Implementing PR: #351 (squashed `3b95ef7a feat: Q2 implementation`)

---

**Review status:** Phase 4 signing review complete per Q1-Q3 plan §"Security review gates". HIGH (SEC-SIGN-01) and both MEDIUMs fixed in this PR; LOWs (SEC-SIGN-04, SEC-SIGN-05) filed as follow-up issues.
