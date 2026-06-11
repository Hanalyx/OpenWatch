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
- Release candidates use a `-rc.N` suffix (e.g. `0.2.0-rc.5`). The RPM version
  field strips the suffix; the DEB and the binary keep it.
- Tags are `v<version>` (e.g. `v0.2.0-rc.5`, `v0.2.0`).

## The pipeline at a glance

| Tag | Workflow | Produces |
|-----|----------|----------|
| `v*` | [`release.yml`](../../.github/workflows/release.yml) | RPM+DEB (amd64+arm64; RPMs GPG-signed per-package), CycloneDX SBOMs, `SHA256SUMS` (GPG `.asc` + cosign `.sig`), `KEYS` → GitHub Release |
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

When the signing keys are configured, `release.yml` signs at these layers (and
skips each layer gracefully if its key is absent — releases still publish,
unsigned):

| Layer | How | Operator verifies |
|---|---|---|
| **Each RPM** | `rpmsign --addsign` (GPG, in the RPM header) | `rpm --import KEYS` then `rpm -K openwatch-*.rpm` → "signatures OK"; or dnf `gpgcheck=1` |
| **Each DEB** | *not* signed per-package — see note | covered by the signed `SHA256SUMS` below |
| **`SHA256SUMS`** | detached GPG (`.asc`) **and** cosign (`.cosign.sig`) | `gpg --verify SHA256SUMS.asc SHA256SUMS`; `cosign verify-blob --key cosign.pub --signature SHA256SUMS.cosign.sig SHA256SUMS` |

> **Why DEBs aren't signed per-package:** `apt`/`dpkg` never verify a
> standalone `.deb`'s embedded signature, and the tool that produced them
> (`dpkg-sig`) was removed from Ubuntu. Each `.deb`'s authenticity instead
> comes from its SHA256 entry in the GPG- (and cosign-) signed `SHA256SUMS`.
> A signed apt **repository** is the proper path if per-DEB trust is ever
> required.

The Hanalyx GPG public key ships in the repo as [`KEYS`](../../KEYS) and is
attached to every release.

## Configuring the signing keys

OpenWatch reuses the **Hanalyx release-signing key** (the same one Kensa uses;
see the offline vault at `~/vault/hanalyx`, generated 2026-05-28).

> **NEVER push `MASTER-secret.asc` to a GitHub secret.** It is the
> certify-capable **master** private key — your root of trust. Only the
> **signing subkey** belongs in CI. The vault's `scripts/setup-signing-keys.sh`
> enforces this: it exports `--export-secret-subkeys` and hard-aborts unless the
> master private has been replaced with a `gnu-dummy` stub. Follow the same rule
> here.

| Secret | Source | Required? |
|---|---|---|
| `GPG_PRIVATE_KEY` | the **signing subkey only**, exported from the master with the master stubbed (see below) | yes |
| `GPG_PASSPHRASE` | the subkey passphrase (same as master by default) | yes |
| `COSIGN_PRIVATE_KEY` | the cosign private key (NOT in this vault — retrieve from wherever Kensa's `COSIGN_PRIVATE_KEY` was generated, e.g. 1Password) | optional |
| `COSIGN_PASSWORD` | the cosign keypair password | optional |

cosign is **optional**: `release.yml` gates it independently, so with only the
two GPG secrets set, releases still get per-package GPG signatures **and** a
GPG-signed `SHA256SUMS` — just no cosign `.sig`. Set the GPG pair first; add
cosign once you have its private key.

**Export the signing subkey (never the master) and set the GPG secrets:**

```bash
# 1. Import the existing Hanalyx master into your keyring (one-time).
gpg --import ~/vault/hanalyx/hanalyx-key-backup/MASTER-secret.asc

# 2. Find the SIGNING SUBKEY fingerprint (the 2nd fpr line; the 1st is the master).
gpg --list-secret-keys --with-colons ops@hanalyx.com \
  | awk -F: '/^fpr:/{print $10}' | sed -n '2p'

# 3. Export ONLY that subkey (note the trailing '!'). This stubs the master.
SUBKEY_FPR=<paste from step 2>
gpg --armor --export-secret-subkeys "${SUBKEY_FPR}!" > /tmp/ow-subkey.asc

# 4. SAFETY GATE — must print a match, else STOP and shred the file.
gpg --list-packets /tmp/ow-subkey.asc | grep -q gnu-dummy \
  && echo "OK: master is stubbed" || echo "ABORT: master private present"

# 5. Push the subkey + passphrase (passphrase via silent prompt — never on the CLI).
gh secret set GPG_PRIVATE_KEY --repo Hanalyx/OpenWatch < /tmp/ow-subkey.asc
gh secret set GPG_PASSPHRASE  --repo Hanalyx/OpenWatch   # paste at the prompt

# 6. Shred the exported subkey.
shred -u /tmp/ow-subkey.asc

# 7. (optional) cosign, once you have its private key file:
gh secret set COSIGN_PRIVATE_KEY --repo Hanalyx/OpenWatch < <cosign.key>
gh secret set COSIGN_PASSWORD    --repo Hanalyx/OpenWatch  # paste at the prompt
```

Notes:
- The repo `KEYS` file is the **corrected** public key (primary UID
  `Hanalyx LLC (release signing)`). Subkey signatures verify against it because
  `KEYS` carries the same master that certifies the subkey.
- A hosted, GPG-signed dnf/apt **repository** (so operators can
  `dnf install openwatch` without `./`) is the next distribution milestone; the
  per-package signatures above are what such a repo requires.
