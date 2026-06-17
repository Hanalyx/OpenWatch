# OpenWatch — Pre-Release Security Review (2026-06-16)

**Scope:** the full Go backend (`internal/`, `cmd/`), the React/TypeScript
frontend (`frontend/`), and packaging/CI. Conducted as six parallel,
read-only dimension audits; every High/Critical finding was then
re-verified by hand against the source.

**Method:** auth/session · authZ/RBAC · cryptography/secrets ·
injection/SSH/SSRF · web/HTTP/audit · supply-chain/packaging.

---

## Verdict

**Release-ready (pending CI + the medium/low backlog).** The cryptographic and data-handling core is
strong — correct AES-256-GCM at rest, sound Argon2id, no SQL injection /
command injection / path traversal / unsafe deserialization, secrets never
on argv or in logs, strong SSRF defense. The problems were **missing
perimeter controls** and **two access-control defects**. Five of those have
been fixed under SDD discipline (PR #584); three larger items remain and are
the gate for an internet-facing release.

| State | Count |
|-------|-------|
| **Fixed** (PR #584, specced + tested) | 8 |
| **Open — release blockers** | 0 |
| Open — medium | ~7 |
| Open — low / informational | ~12 |
| Verified strong (no action) | many |

---

## Fixed in PR #584 (spec → test → code)

| # | Sev | Finding | Fix | Spec |
|---|-----|---------|-----|------|
| 1 | **High** | `GET /api/v1/audit/events` had **zero authorization** — anonymous full audit-trail disclosure (actor ids, IPs, resource ids). | Require `audit:read`; anonymous → 403, no events. | `api-audit-events-query` C-06/AC-11 |
| 2 | **High** | API-token **privilege escalation**: a `token:write` holder (e.g. `security_admin`) could `POST /tokens` with `role_id:"admin"` and obtain a full-admin bearer token. | New `auth.RoleGrantsWithin`: requested role's permissions must be ⊆ caller's; else 403. | `api-tokens` C-03/AC-05 |
| 3 | Med-High | `roles:assign` had no subset/self guard (escalation primitive; only admin holds `role:assign` today, so defense-in-depth). | Same `RoleGrantsWithin` check on assignment. | `api-users` C-05/AC-13 |
| 4 | **High** | **No security headers** on an origin serving SPA + API (clickjacking, SSL-strip, MIME-sniff, no XSS defense-in-depth). | `securityHeaders` middleware: HSTS, CSP (`frame-ancestors 'none'`, `default-src 'self'`), nosniff, `X-Frame-Options: DENY`, Referrer-Policy. | `system-http-server` C-12/AC-17 |
| 5 | **High** | **Breach-password check dead in production** — every `users.NewService` passed a `nil` corpus, so compromised passwords were accepted. | Always-on embedded baseline (`DefaultBreachCorpus`, 129 common passwords, airgap-safe) wired at all 3 prod sites; operator HIBP override via `OPENWATCH_BREACH_CORPUS_FILE`. | `system-auth-identity` C-15/AC-27 |
| 6 | **High** | **No CSRF enforcement** — frontend double-submit was theater; only `SameSite=Lax` protected mutations. | `csrfProtect` middleware (constant-time double-submit) + `XSRF-TOKEN` cookie at login/refresh; gated on the session cookie; Bearer/`/auth/*` exempt. | `system-http-server` C-14/AC-19 |
| 7 | **High** | **No login rate-limiting / lockout** — unlimited online guessing. | Dependency-free per-IP sliding-window limiter on `/auth/login` + `/auth/mfa:verify`; 429 + Retry-After. | `system-http-server` C-13/AC-18 |
| 8 | Med-High | **SSH host-key in-memory per-process TOFU** — MITM on first scan after every restart. | PostgreSQL-backed `KnownHostsStore` (migration 0036) wired at all 4 dial sites → durable TOFU across restarts. | `system-ssh-connectivity` C-13/AC-22 |

> #1, #2, #4, #5 are mutually reinforcing: weak-password acceptance + no
> CSRF (below) + clickjacking + anonymous data access formed a realistic
> account-takeover / data-exposure chain. #1 (anonymous) was the most
> severe and is fixed.

---

## ~~Open — release blockers~~ → ALL FIXED in PR #584

The three blockers below are **now closed** (see fixed rows 6-8 above). The
original analysis is retained for the record.

### B-1 (High) — CSRF is not enforced server-side  ✅ FIXED
State-changing endpoints authenticate via the `openwatch_session` cookie.
The frontend advertises a double-submit scheme (`client.ts`), but **no
server code sets an `XSRF-TOKEN` cookie or validates `X-CSRF-Token`** — the
protection reduces to `SameSite=Lax`. The client-side half is theater.
**Fix:** issue a random non-HttpOnly `XSRF-TOKEN` cookie at login/refresh +
middleware requiring `X-CSRF-Token == XSRF-TOKEN` on unsafe methods for
cookie-authenticated requests (matches what the frontend already sends).
*Evidence:* `internal/server/server.go` chain; `frontend/src/api/client.ts`.

### B-2 (High) — No login rate-limiting or account lockout  ✅ FIXED
`PostAuthLogin` / `PostAuthMFAVerify` have no throttle, no failed-attempt
counter, no lockout (confirmed: no rate-limiter anywhere in the HTTP chain).
Direct online password / OTP guessing + credential-stuffing. Flagged
independently by both the auth and web audits.
**Fix:** per-IP + per-account limiter (e.g. `httprate` or a DB-backed
counter) with stricter buckets on `/auth/*`, plus progressive backoff/lockout.
Derive client IP from a trusted-proxy config (see L-7).
*Evidence:* `internal/server/auth_handlers.go:27`.

### B-3 (Med-High) — SSH host-key trust is in-memory, per-process TOFU  ✅ FIXED
Every production dial uses `ModeTOFU` + `NewMemoryStore()` (no persistent
store, no `ModeStrict`). A network attacker can MITM the **first** scan after
every daemon restart and harvest the credentials presented to each host. The
~5-minute liveness probe is worse: `InsecureIgnoreHostKey()`.
**Fix:** a Postgres-backed `KnownHostsStore` (persist `hostname → key`),
wire it in place of `NewMemoryStore()`, default `ModeStrict` once keys are
provisioned (TOFU only for an explicit enrollment window), surface
host-key-mismatch as an operator alert, and share the store with the
liveness probe (drop `InsecureIgnoreHostKey`).
*Evidence:* `cmd/openwatch/worker.go:181-182`, `main.go:385/409/525-526`;
`internal/sshprivilege/privilege.go:311`.

---

## Open — medium

- **Access JWTs (30 min) are not revocable; password change revokes nothing.** `jti` is stamped but never checked; logout/reuse-cascade don't cover the bearer path. `internal/identity/jwt.go`, `internal/users/users.go UpdatePassword`. *Fix:* `jti`/token-version denylist in `VerifyJWT`; revoke sessions on password change.
- **Shared demo TLS key** baked into every package at the prod cert path, not `%config(noreplace)`/conffile → silently reverts an operator's cert on upgrade. *(2 audits)* `packaging/common/gen-demo-cert.sh`, `packaging/rpm/openwatch.spec`. *Fix:* generate per-install in `%post`; mark cert/key as config; warn/refuse on the `openwatch-demo` subject.
- **No request body-size limits** (`http.MaxBytesReader` absent) → cheap memory-exhaustion DoS on any JSON endpoint.
- **API-token create/revoke emit no audit event**; **security-failure audit events omit source IP / user-agent** (forensics gaps on a compliance product). `tokens_handlers.go`, `auth_handlers.go emitAudit`.
- **Raw `err.Error()` leaked on 500 paths** (`users_handlers.go:69,205`).
- **Release job pipes unpinned `curl | sh` syft** in the same job that holds the signing keys; **untrusted PR title interpolated into a shell `run:`** (`claude-code-alerts.yml`).

## Open — low / informational

JWT verify lacks an explicit `WithValidMethods` pin (safe today, weaker than
the OIDC/license verifiers) · TLS 1.2 default cipher set, and the "OpenSSL
FIPS provider" claim should be reconciled with the actual `crypto/tls` stack
· JWT signing key shipped `0640` group-readable (DEK is `0600`) ·
Swagger/OpenAPI served unauthenticated (full API-surface recon) ·
`X-Forwarded-Host/-Proto` trusted unconditionally (latent host-header
injection; becomes load-bearing once IP-based rate-limiting lands) · no
per-user SSE connection cap · default DSN ships `sslmode=disable` ·
`cosign.pub` not published (breaks the documented offline cosign verify) ·
`govulncheck` doesn't gate the *release* workflow (only `go-ci`) ·
custom-role creation can request permissions you don't hold (latent — inert
because custom roles currently resolve to zero permissions) · alert
ack/resolve gate on the wrong permission (fail-closed correctness bug) ·
login username-enumeration via Argon2id timing.

---

## Verified strong (no action)

Credential AES-256-GCM with per-encrypt nonces + enforced `0600` DEK ·
Argon2id (64 MiB / t=3) with constant-time compare · session/refresh tokens
256-bit CSPRNG, SHA-256 at rest, no fixation, reuse-detection cascade-revoke,
idle + absolute expiry correctly clamped · MFA 160-bit secret, encrypted,
replay-prevented · **no SQLi / command injection / path traversal / unsafe
deserialization** · sudo password delivered via stdin only, never argv ·
strong SSRF (post-DNS dial-IP re-check closes the rebind hole) · audit
redaction recursively scrubs secrets; parameterized audit SQL · RBAC and
license gating fail-closed · exception separation-of-duties enforced in the
service layer (not just the handler) · API tokens hashed, role re-evaluated
per request · hardened non-root systemd unit · per-install identity secrets ·
signed artifacts + CycloneDX SBOMs · slowloris-resistant server timeouts ·
open-redirect handled (`safeReturnTo`).

---

## Recommendation

1. **Merge PR #584** (all 8 fixes — the 5 quick wins + B-1/B-2/B-3).
2. **Smoke-test the CSP against the running SPA + /docs** before release (it
   is a single tunable const).
3. Work the medium list as a fast-follow; the lows can be batched post-GA.
4. Add a CI guard that fails the release if the binary contains a font-CDN
   or other external-host string (airgap regression backstop).

*This review reflects the codebase at commit on `feat/security-hardening`.
Re-run on the release tag (including a live `make vuln`) before sign-off.*
