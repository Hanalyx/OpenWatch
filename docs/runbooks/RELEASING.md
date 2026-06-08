# Releasing OpenWatch

The gated process for cutting an OpenWatch release. Nothing reaches a GA tag
until the docs are frozen, every automated gate is green, the packages install
and run on each target distro, a functional pass is done against a real fleet,
and a human signs off.

---

## Versioning

- Semantic versioning. The single source of truth is
  [`packaging/version.env`](../../packaging/version.env) (`VERSION`, `CODENAME`).
  The Go binary reads it via the Makefile `ldflags`, and the RPM/DEB build
  scripts source it for the package version.
- Release candidates use a `-rc.N` suffix (e.g. `0.2.0-rc.4`). The RPM version
  field strips the suffix; the DEB and the binary keep it.
- Tags are `v<version>` (e.g. `v0.2.0-rc.4`, `v0.2.0`).

## The pipeline at a glance

| Tag | Workflow | Produces |
|-----|----------|----------|
| `v*` | [`release.yml`](../../.github/workflows/release.yml) | RPM+DEB (amd64+arm64), CycloneDX SBOMs, `SHA256SUMS`(`.asc`) → GitHub Release |
| `v*` / packaging PRs | [`package-smoke.yml`](../../.github/workflows/package-smoke.yml) | per-distro install + binary smoke |
| every PR | [`go-ci.yml`](../../.github/workflows/go-ci.yml) | vet/lint/vuln/test-race + specter 100% AC coverage |

---

## Stage 1 — Docs freeze (before any tag)

1. Bump `packaging/version.env` (`VERSION`, `CODENAME`).
2. Update `CHANGELOG.md` for the version (GitHub auto-notes supplement this).
3. Refresh user-facing docs that changed this cycle:
   - `README.md` (version/badges, install flow)
   - `docs/guides/INSTALLATION.md` (supported-distro matrix, commands)
   - DB-migration notes for any new migrations
   - API docs if `api/openapi.yaml` changed
4. Confirm `specter check` and `specter coverage` are clean locally.

## Stage 2 — Cut the release candidate

```bash
git tag v<version>-rc.N
git push origin v<version>-rc.N
```

This triggers `release.yml` (builds + SBOMs + publishes a pre-release) and
`package-smoke.yml` (per-distro install matrix).

## Stage 3 — Verification gate (must all pass before GA)

**Automated (CI):**
- `go-ci` green on `main` at the RC commit — includes `specter sync` at **100% AC
  coverage** (the `release-admin-signoff` C-01 requirement) and the composition
  E2E (`internal/server/api_admin_*signoff*_test.go`, real session cookies).
- `package-smoke` green — RPM installs on Rocky/Alma/Fedora/Oracle, DEB installs
  on Ubuntu/Debian; binary runs (`--version`, `check-config`); system user + files
  land. (amd64; arm64 install is covered by cross-build correctness until arm64
  runners are wired in.)

**Manual (on the RC, against a real fleet — CI cannot reach workstation hosts):**
1. Install the RC package on a clean VM of at least one RHEL-family and one
   Debian-family distro: `sudo dnf install ./openwatch-<v>.x86_64.rpm` /
   `sudo apt install ./openwatch_<v>_amd64.deb`.
2. `sudo openwatch migrate` && `sudo openwatch create-admin …` &&
   `sudo systemctl enable --now openwatch`; confirm
   `curl -k https://localhost:8443/api/v1/health` is healthy and the UI loads at
   `https://<host>:8443/`.
3. **Upgrade path:** install the previous GA, then upgrade to the RC; confirm the
   service comes back and data survives.
4. **Functional walkthrough** against the test fleet (`~/Documents/openwatch/test_hosts.csv`):
   log in → add host → run a Kensa scan → view posture → drift → exceptions →
   export → role-based access. Record results in the sign-off checklist.

**Sign-off:** complete the `release-admin-signoff` Definition-of-Done. A release
captain records pass/fail per DoD step and signs.

> If any gate fails, fix on `main`, cut the next `-rc.N`, and repeat. Never
> promote an RC that skipped a gate.

## Stage 4 — Promote to GA

```bash
git tag v<version>          # no -rc suffix
git push origin v<version>
```

`release.yml` builds the final signed artifacts + SBOMs and publishes the GA
GitHub Release.

## Stage 5 — Post-release smoke

On a clean box, install the **published** artifact and confirm it starts:

```bash
# download openwatch-<v>.x86_64.rpm from the release, then:
sudo dnf install ./openwatch-<v>.x86_64.rpm
sudo openwatch migrate && sudo systemctl enable --now openwatch
curl -k https://localhost:8443/api/v1/health
```

Then bump `packaging/version.env` to the next `-dev`/`-rc` and announce.

---

## Release signing key (GPG)

`release.yml` signs `SHA256SUMS` with a detached GPG signature **only when** the
signing key is configured; without it, releases publish with checksums but no
signature. To enable:

1. Generate a dedicated release key (offline, RSA 4096, no expiry or a long one):
   ```bash
   gpg --batch --gen-key <<EOF
   %no-protection
   Key-Type: RSA
   Key-Length: 4096
   Name-Real: OpenWatch Release Signing
   Name-Email: release@hanalyx.com
   Expire-Date: 2y
   %commit
   EOF
   gpg --armor --export-secret-keys release@hanalyx.com   # → GPG_PRIVATE_KEY
   gpg --armor --export release@hanalyx.com               # → publish this public key
   ```
2. Add repo secrets **`GPG_PRIVATE_KEY`** (the armored private key) and
   **`GPG_PASSPHRASE`** (empty if `%no-protection`).
3. Publish the **public** key (in the repo / release notes) so operators can
   `gpg --verify SHA256SUMS.asc SHA256SUMS`.

Per-package signing (`rpm --addsign`, `debsign`) and a hosted GPG-signed dnf/apt
repo are a follow-up for when distribution moves beyond GitHub Releases.
