# SSO Federation Security Review

**Date**: 2026-04-14
**Scope**: `backend/app/services/auth/sso/`, `backend/app/routes/auth/sso.py`, SSO dependencies
**Reviewer**: Automated (Bandit 1.9.4, Semgrep 205 rules, pip-audit 2.10.0) + manual code review
**Spec**: `specs/services/auth/sso-federation.spec.yaml` (16 ACs, active)

## Summary

Automated scans found one real transitive CVE chain (pyOpenSSL 22.0.0, pulled in by pysaml2) which is fixed in this PR. Manual code review found two defense-in-depth items filed as follow-up issues. No P0/P1 findings. The SSO code follows OIDC best practices for the critical validation paths (signature, `alg=none` rejection, single-use state token, PKCE S256).

## Findings

### Resolved in this PR

#### SEC-SSO-01: Transitive pyOpenSSL CVEs (MEDIUM)

**Details:**
- `pyOpenSSL 22.0.0` pulled transitively by `pysaml2 7.5.4`
- CVE-2026-27448 and CVE-2026-27459 — fix version 26.0.0
- Not exploitable via OpenWatch application code (we don't call pyOpenSSL directly), but any pysaml2 code path that reaches into pyOpenSSL inherits the risk

**Fix:** Pinned `pyOpenSSL==26.0.0` in `backend/requirements.txt` under the Authentication & Security block.

**Verification:**
```
$ pip-audit -r requirements.txt | grep pyopenssl
(no output — clean)
```

### Deferred (follow-up issues filed)

#### SEC-SSO-02: OIDC nonce not implemented — LOW

**Details:** The OIDC authorization URL in `oidc.py:23-46` does not include a `nonce` parameter, and `handle_callback()` at line 48 does not validate a `nonce` claim on the id_token. OpenID Connect Core 1.0 §15.5.2 strongly recommends nonce for Authorization Code Flow as defense-in-depth against id_token replay.

**Risk:** Low — current defenses are already strong:
- 256-bit cryptographically random state, single-use, validated on callback (`provider.py:102-111`, `sso.py:274-281`)
- PKCE S256 enforced (`oidc.py:39`)
- id_token signature verified against JWKS, `alg=none` explicitly rejected (`oidc.py:89-90`)
- `iss`, `aud`, `exp`, `nbf` validated (`oidc.py:93`)

A successful replay would require simultaneously compromising both the state token (server-side session) AND the token endpoint response — the state alone already binds the session.

**Recommendation:** Add nonce as defense-in-depth, tracked as [follow-up issue](https://github.com/Hanalyx/OpenWatch/issues/___).

#### SEC-SSO-03: JWKS fetched on every callback with no cache — LOW

**Details:** `_get_jwks()` in `oidc.py:103-113` does a synchronous `httpx.get()` to the IdP's JWKS endpoint on every SSO login. No caching.

**Risks:**
- Latency: adds a round-trip to every SSO login
- Availability coupling: if the IdP's JWKS endpoint is slow or down, all SSO logins stall
- Rate-limiting: frequent JWKS fetches may be rate-limited by some IdPs

**Industry practice:** IdPs publish JWKS with Cache-Control / ETag headers; clients cache for minutes to hours. Google, Auth0, Okta all advise clients cache JWKS.

**Recommendation:** In-process TTL cache (5-15 min), with refresh-on-miss if the id_token's `kid` isn't in the cached set. Tracked as [follow-up issue](https://github.com/Hanalyx/OpenWatch/issues/___).

### Informational (no action)

#### INFO-SSO-01: Bandit B105 false positive

`routes/auth/sso.py:177` — `"token_type": "bearer"` flagged as hardcoded password. This is the OAuth2 token_type standard string; not a credential. Suppressing adds noise; leaving unsuppressed since the scan already runs at LOW severity and this is a known pattern.

## Positive observations (confirmed by review)

| Area | Finding | Location |
|------|---------|----------|
| State parameter | 256-bit `secrets.token_urlsafe(32)`, single-use, PostgreSQL-backed | `provider.py:102-111`, `sso_state.py` |
| PKCE | S256 enforced | `oidc.py:39` |
| id_token signature | Verified against JWKS, alg=none rejected | `oidc.py:84-90` |
| Standard claims | `iss`, `aud`, `exp`, `nbf` validated by authlib | `oidc.py:93` |
| SAML assertion signature | `want_assertions_signed: True` | `saml.py:123` |
| SAML AuthnRequest signature | `authn_requests_signed: True` | `saml.py` config |
| Audit logging | All SSO login outcomes logged via `log_login_event` | `sso.py` |
| Client IP | Uses trusted proxy validation (not raw XFF header) | `sso.py:38-42` |
| Encryption at rest | Provider configs stored encrypted via `EncryptionService` | `sso.py:50-56` |

## Tool results

### Bandit (backend-only, SSO scope)
```
Test results:
    Total lines of code: 650
    Total issues (by severity):
        High: 0
        Medium: 0
        Low: 1  (B105 false positive on "bearer")
```

### Semgrep (p/security-audit + p/owasp-top-ten + p/jwt + p/python)
```
205 rules run, 0 findings, 5 files scanned.
```

### pip-audit (SSO-relevant dependencies)
Before this PR:
```
authlib 1.6.10     (clean after group update)
pysaml2 7.5.4      (clean)
pyOpenSSL 22.0.0   (2 CVEs)       <-- FIXED in this PR
cryptography 46.0.5 (2 CVEs)      <-- fixed by Dependabot PR #376
```

After this PR + #376 merged: zero known CVEs in SSO-relevant dependency subgraph.

## Governance

This automated + manual review does **not** substitute for a human security sign-off on the following, which remain explicit operational requirements:

1. **IdP metadata trust**: operator is responsible for validating the IdP's metadata URL / certificate fingerprint before adding a provider to OpenWatch
2. **Role mapping review**: group-to-role mappings (`claim_mappings`) must be reviewed per-IdP to prevent unintended privilege grants
3. **Session timeout**: absolute session timeout (12h) applies equally to SSO and local auth; no SSO-specific override

## References

- OpenID Connect Core 1.0 §15.5.2 (nonce recommendation): https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes
- RFC 7636 (PKCE): https://tools.ietf.org/html/rfc7636
- Authlib security advisories: https://github.com/lepture/authlib/security/advisories
- pysaml2 security: https://github.com/IdentityPython/pysaml2/security

---

**Review status:** complete for automated tooling. Manual review items SEC-SSO-02 and SEC-SSO-03 are defense-in-depth improvements, not correctness or exploitability fixes.
