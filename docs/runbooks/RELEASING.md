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
| `v*` | [`release.yml`](../../.github/workflows/release.yml) | RPM+DEB (amd64+arm64, GPG-signed per-package), CycloneDX SBOMs, `SHA256SUMS` (GPG `.asc` + cosign `.sig`), `KEYS` → GitHub Release |
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

## Signing model

When the signing keys are configured, `release.yml` signs at three layers (and
skips each layer gracefully if its key is absent — releases still publish,
unsigned):

| Layer | How | Operator verifies |
|---|---|---|
| **Each RPM** | `rpmsign --addsign` (GPG, in the RPM header) | `rpm --import KEYS` then `rpm -K openwatch-*.rpm` → "signatures OK"; or dnf `gpgcheck=1` |
| **Each DEB** | `dpkg-sig --sign builder` (GPG) | `dpkg-sig --verify openwatch_*.deb` (standalone-`.deb` verification is niche; the signed checksums below are the primary DEB authenticity path until a signed apt repo exists) |
| **`SHA256SUMS`** | detached GPG (`.asc`) **and** cosign (`.cosign.sig`) | `gpg --verify SHA256SUMS.asc SHA256SUMS`; `cosign verify-blob --key cosign.pub --signature SHA256SUMS.cosign.sig SHA256SUMS` |

The Hanalyx GPG public key ships in the repo as [`KEYS`](../../KEYS) and is
attached to every release.

## Configuring the signing keys

OpenWatch reuses the **Hanalyx release-signing key** (the same one Kensa uses;
see the offline vault at `~/vault/hanalyx`, generated 2026-05-28). Add these as
**`Hanalyx/OpenWatch`** repo secrets:

| Secret | Source (from the vault) |
|---|---|
| `GPG_PRIVATE_KEY` | armored export of `hanalyx-key-backup/MASTER-secret.asc` (full keyset) |
| `GPG_PASSPHRASE` | the master passphrase |
| `COSIGN_PRIVATE_KEY` | the cosign private key |
| `COSIGN_PASSWORD` | the cosign keypair password |

```bash
gh secret set GPG_PRIVATE_KEY  --repo Hanalyx/OpenWatch < ~/vault/hanalyx/hanalyx-key-backup/MASTER-secret.asc
gh secret set GPG_PASSPHRASE   --repo Hanalyx/OpenWatch   # paste the master passphrase
gh secret set COSIGN_PRIVATE_KEY --repo Hanalyx/OpenWatch < <cosign.key>
gh secret set COSIGN_PASSWORD    --repo Hanalyx/OpenWatch # paste the cosign password
```

Notes:
- The repo `KEYS` file is the **corrected** public key (primary UID
  `Hanalyx LLC (release signing)`). If you sign with the vault's
  `MASTER-secret.asc` before running its UID-sync procedure, signatures still
  verify against `KEYS` (the key material is identical; only UID metadata
  differs) — but run the sync first if you want clean UID metadata.
- A hosted, GPG-signed dnf/apt **repository** (so operators can
  `dnf install openwatch` without `./`) is the next distribution milestone; the
  per-package signatures above are what such a repo requires.
