# OpenWatch — Project Status

**Last Updated:** 2026-06-25
**Latest release:** `v0.2.0-rc.14` (Eyrie) — signed RPM/DEB (amd64 + arm64) + SBOMs, GitHub pre-release
**Stack:** single Go binary (`openwatch`, go 1.26), PostgreSQL-only, Kensa v0.6.0 (538 rules), React 19 + TanStack frontend (embedded)

> One-page snapshot of where the project is. For the work queue see
> [BACKLOG.md](BACKLOG.md); for history see [CHANGELOG.md](CHANGELOG.md) and
> [SESSION_LOG.md](SESSION_LOG.md); for the deployment roadmap see
> [docs/engineering/openwatch_roadmap.md](docs/engineering/openwatch_roadmap.md).

---

## Shipped (on `main` / in the last release)

- **Compliance scanning** end to end: Kensa SSH-based scans, OS-aware lens
  views, adaptive scheduler (4h–48h bands), durable per-scan evidence + OSCAL
  export, Kensa rule-library browser.
- **Fleet management**: hosts list/detail, multilayer liveness (ping/SSH/
  privilege), server-intelligence collection, groups, posture trends.
- **Remediation** (free-core, single-rule): apply + rollback from the host tab,
  serialized per host, live status over SSE.
- **Exception governance**: request/approve/revoke/expire with separation of
  duties.
- **Reports**: scoped, coverage-honest, signed snapshots with multiple faces
  (OSCAL SAR, CSV, PDF, JSON), scheduled + emailed.
- **Settings** activated: Audit, License status, Users (invite/add + manage),
  Notifications channels (Slack/webhook/email), Security (auth policy, SSO/OIDC,
  API tokens).
- **Security controls**: CSRF double-submit, per-IP auth rate-limit, security
  headers, durable TOFU known-hosts, breach-corpus password screening, Argon2id,
  RS256 JWT, AES-256-GCM credential encryption.
- **Packaging**: native RPM (CentOS Stream 9) + DEB (Ubuntu 24.04), tag-driven
  signed release pipeline, FIPS via OpenSSL 3.x provider.

## In flight (open PRs, not yet merged — 2026-06-25)

| PR | Area | Status |
|----|------|--------|
| #673 | **PKG-3**: remediation store path under hardened unit | green; **production-breaking fix**, land first |
| #675 | **AUTH-1 slice 1**: client idle-session timeout | green; land before #678 |
| #678 | **AUTH-1 b+c**: absolute-timeout ceiling + slide-on-activity | green; (c) client side inert until #675 ships |
| #679 | **Notifications Slice 1**: durable change-driven bell | green |
| #676 | **Avg-compliance parity** (/hosts ↔ /dashboard) | green |
| #677 | Notifications design doc | docs |
| #674 | Backlog (PKG-3 + AUTH-1) | docs |

Recommended merge order: **#673 → #675 → #678**, then #676 / #679 / docs.

## Next

- Cut **`v0.2.0-rc.15`** once #673 (and the auth fixes) land — remediation is
  broken on hardened installs until then.
- **Notifications Slice 2**: transaction-log rule-regression projector (critical
  `pass→fail`, grouped per host/scan) + per-host RBAC recipient scoping.
- **License enforcement coverage**: the tier/key/402 machinery exists but only
  the demo endpoint is gated; wire `x-required-feature` to actually gate
  declared paid routes.
- GA gates: Stage 3 fleet-verification per `docs/runbooks/RELEASING.md`.

## Known issues / caveats

- Remediation is **non-functional on hardened packaged installs** until #673
  lands (operator workaround: set `OPENWATCH_KENSA_STORE_PATH`).
- Landing/login animation can appear frozen under OS **reduced-motion** (by
  design — the radar/pulse honor `prefers-reduced-motion`).
- License **enforcement coverage** is partial (machinery present, most paid
  routes not yet gated).
