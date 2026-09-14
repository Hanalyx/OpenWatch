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
- Release candidates use a `-rc.N` suffix (e.g. `0.2.0-rc.5`). Both packages
  encode it with a tilde (`0.2.0~rc.5`), which sorts below the final release;
  the binary reports the true semver. The suffix is never stripped
  (`release-package-build` C-12).
- Tags are `v<version>` (e.g. `v0.2.0-rc.5`, `v0.2.0`), and `release.yml`
  refuses any tag whose version is not exactly `VERSION` in `version.env`
  (`packaging/check-tag-version.sh`, C-14). Every candidate and the GA are
  therefore distinct commits, each carrying its own version.

## The pipeline at a glance

| Tag | Workflow | Produces |
|-----|----------|----------|
| `v*` | [`release.yml`](../../.github/workflows/release.yml) | RPM+DEB (amd64+arm64; RPMs GPG-signed per-package), CycloneDX SBOMs, `SHA256SUMS` (GPG `.asc` + cosign `.sig`), `KEYS` → GitHub Release |
| `v*` / packaging PRs | [`package-smoke.yml`](../../.github/workflows/package-smoke.yml) | per-distro install + binary smoke |
| every PR | [`go-ci.yml`](../../.github/workflows/go-ci.yml) | vet/lint/vuln/test-race + specter 100% AC coverage |

---

## Stage 1: Docs freeze (before any tag)

1. Set the candidate version, suffix included, in the three places that must
   agree: `VERSION="<version>-rc.N"` in `packaging/version.env`, the README
   version phrase, and the newest `CHANGELOG.md` heading
   (`## [<version>-rc.N] <codename> (<date>)`). `CODENAME` stays as decided.
   `go test ./packaging/tests/ -run TestRepoHygiene` fails while they disagree.
2. Update `CHANGELOG.md` for the version (GitHub auto-notes supplement this).
3. Refresh user-facing docs that changed this cycle:
   - `README.md` (version/badges, install flow)
   - `docs/guides/INSTALLATION.md` (supported-distro matrix, commands)
   - DB-migration notes for any new migrations
   - API docs if `api/openapi.yaml` changed
4. Confirm `specter check` and `specter coverage` are clean locally.

## Stage 2: Cut the release candidate

The tag is read from `packaging/version.env`, never typed. The Stage 1 commit
must be merged first, so the tag names a commit on `main` whose `version.env`
carries the candidate version. `v0.8.0-rc.1` was tagged by hand against
`VERSION="0.8.0"` and refused by the hosted check after it had been signed and
pushed (CP `bugs/OW-037`). The local check below catches that before the tag
exists.

```bash
git switch main
git pull --ff-only origin main
test -z "$(git status --porcelain)"   # tag a merged commit, not a working tree
. packaging/version.env
RC="v$VERSION"                        # derived from the file, never typed
RELEASE_REF="$RC" bash packaging/check-tag-version.sh
git tag -s "$RC" -m "$RC"
git push origin "$RC"
```

Pushing the tag triggers `release.yml` (builds + SBOMs + publishes a
pre-release) and `package-smoke.yml` (per-distro install matrix). A refused
candidate is a failed candidate: leave its tag in place as a record, file the
cause, and cut the next number. Never move a tag.

## Stage 3: Verification gate (must all pass before GA)

**Automated (CI):**
- `go-ci` green on `main` at the RC commit: includes `specter sync` at **100% AC
  coverage** (the `release-admin-signoff` C-01 requirement) and the composition
  E2E (`internal/server/api_admin_*signoff*_test.go`, real session cookies).
- `package-smoke` green. It is now four job groups, not one. `smoke` installs
  the packages on almalinux 9 and 10, rockylinux 9, oraclelinux 9, fedora 41,
  debian 12 and ubuntu 24.04, and checks the binary runs and the system user and
  files land. `setup-install` runs `openwatch setup` end to end under systemd on
  the four tested platforms. `upgrade-from-ga` installs the previous GA and
  upgrades to the candidate in one transaction. `upgrade` covers the
  `rpm -U` auto-migrate path. (amd64; arm64 install is covered by cross-build
  correctness until arm64 runners are wired in.)

**Manual (on the RC, against a real fleet: CI cannot reach workstation hosts):**
1. Install the RC packages on a clean VM of at least one RHEL-family and one
   Debian-family distro: both the platform and the rule corpus, in one
   transaction (openwatch hard-depends on kensa-rules):
   `sudo dnf install ./openwatch-<v>.x86_64.rpm ./kensa-rules-<kv>.noarch.rpm` /
   `sudo apt install ./openwatch_<v>_amd64.deb ./kensa-rules_<kv>_all.deb`.
   Confirm a scan finds the corpus: `test -d /usr/share/kensa/rules`.
2. `sudo openwatch setup`. This is the documented install path as of v0.7.0 and
   replaces the old `migrate` plus `create-admin` plus `systemctl enable`
   sequence. It provisions the PostgreSQL role and database, generates the
   credential and report signing keys, issues a TLS certificate, opens the
   listener port, creates the first admin, and starts the service. Confirm
   `curl -k https://localhost:8443/api/v1/health` is healthy and the UI loads at
   the URL setup prints.

   **Set a durable report signing key before generating any report.** With
   `OPENWATCH_REPORTS_SIGNING_KEY_FILE` unset, the signer makes a fresh key on
   every boot and reports still sign, so nothing looks wrong until a restart
   invalidates every signature already issued. Record the key id in the sign-off.
3. **Upgrade path:** install the previous GA, then upgrade to the RC; confirm the
   service comes back and data survives.
4. **Functional walkthrough** against the release captain's test fleet:
   log in → add host → run a Kensa scan → view posture → drift → exceptions →
   export → role-based access. Record results in the sign-off checklist.

**Before asking anyone to sign, run the gate.** `release/gates.toml` declares
every gate and `scripts/release-status.py` evaluates them against real evidence,
printing GO or NO-GO with a per-gate reason. It exists so release readiness is
answered by evidence rather than by asking. Two properties to preserve:
attestations are scoped to the artifact hash, so a rebuild invalidates prior
evidence as STALE; and a run still in progress reports PENDING rather than FAIL,
because an unfinished build is not a failed one.

Some gates are human-only by construction: the fleet walkthrough and the release
captain's signature. Those must never become auto-satisfiable.

**Sign-off:** complete the `release-admin-signoff` Definition-of-Done. A release
captain records pass/fail per DoD step and signs.

> If any gate fails, fix on `main`, cut the next `-rc.N`, and repeat. Never
> promote an RC that skipped a gate.

## Stage 3b: Documentation review (gate D1)

Gate D1 is blocking. A named human reads every tracked Markdown document at the
candidate commit and records a verdict for each. Scope is every tracked blob
whose path ends in `.md`, with no directory exclusions, so `.github`, `.claude`
and `scripts/README.md` are reviewed like any other document.

The evidence is bound to the candidate, not to a date. Reviewing recently
proves nothing; reviewing these bytes does.

1. **Cut the RC first and wait for its assets.** The attestation names an
   artifact and its digest, and both come from the published `SHA256SUMS`. There
   is nothing to attest until `release.yml` has finished.

2. **Resolve and record the exact RC commit.** Do not work from a branch name
   or from whatever `HEAD` happens to be.

   ```bash
   RC=v<version>-rc.N
   RC_COMMIT=$(git rev-list -n 1 "$RC")
   echo "$RC_COMMIT"
   ```

3. **Generate the skeleton for that commit.**

   ```bash
   python3 -S scripts/doc-review-skeleton.py --commit "$RC_COMMIT" --tag "$RC" \
     > /tmp/doc-review-$RC.toml
   ```

   It writes one entry per document with `verdict = "pending"`, and leaves the
   human identity blank. It cannot fill either in for you.

4. **Read the files as they are at that commit**, not as they are in your
   working tree. `git show "$RC_COMMIT:path/to/doc.md"` is the safe way; a
   checkout that has moved on is a different document.

5. **Fill in every field.** Each verdict becomes `accurate` only for a document
   you read and found accurate. `performed_by` is your own name, never an agent.
   `performed_at` is an ISO date that is not in the future. `artifact` and
   `artifact_sha256` are the matching pair from the candidate's `SHA256SUMS`.
   Then recompute `docs_sha256` over the finished entries. A verdict of anything
   other than `accurate` is a NO-GO: there is no waiver.

6. **Run the checker with the completed attestation present.**

   ```bash
   cp /tmp/doc-review-$RC.toml release/attestations/
   python3 -S scripts/release-status.py --tag "$RC"
   ```

   **Leave that file untracked while the decision is open.** It is a working
   document until D1 passes; committing it earlier records a review that has not
   been accepted yet.

7. **Do not commit anything between the verified RC and the GA tag.** The
   evidence describes one commit. Any change after it, including a documentation
   fix found during the review, means cutting a new RC and reviewing again.

8. **Tag GA explicitly from the verified commit.**

   ```bash
   git tag v<version> "$RC_COMMIT"
   ```

   Never `git tag v<version>` on its own. That takes the current `HEAD`, which
   is only the reviewed commit by luck, and the gate cannot tell the difference
   afterward.

9. **Commit the attestation after promotion**, not before. By then the released
   commit is fixed, so the audit commit that records the evidence cannot change
   what was released.

The attestation's `tag` stays the **RC tag**. It records which candidate's
evidence authorized the promotion, and the GA tag points at the same commit. An
attestation relabeled with the GA tag would claim a review that never happened
against that tag.

## Stage 4: Promote to GA

> **This stage cannot succeed as written, and the sequence that replaces it is
> awaiting approval (CP `bugs/OW-037`).** A commit whose `version.env` carries
> `<version>-rc.N` cannot satisfy a `v<version>` tag: the C-14 check refuses
> it. GA must be a new commit, and a new commit invalidates the D1 evidence
> bound to the RC's documentation bytes and the fleet evidence bound to the
> RC's artifact digests. Do not promote until this stage is rewritten.

Tag the reviewed commit by name. `$RC_COMMIT` is the value resolved in Stage 3b,
and it must equal the commit you are promoting.

```bash
git tag v<version> "$RC_COMMIT"   # no -rc suffix, explicit commit
git push origin v<version>
```

`release.yml` builds the final signed artifacts + SBOMs and publishes the GA
GitHub Release.

## Stage 5: Post-release smoke

On a clean box, install the **published** artifact and confirm it starts:

```bash
# download openwatch-<v>.x86_64.rpm AND kensa-rules-<kv>.noarch.rpm, then:
sudo dnf install ./openwatch-<v>.x86_64.rpm ./kensa-rules-<kv>.noarch.rpm
sudo openwatch setup
curl -k https://localhost:8443/api/v1/health
```

Then bump `packaging/version.env` to the next `-dev`/`-rc` and announce.

---

## Signing model

### Git tags

**Tags are GPG-signed from v0.7.0 onward.** None of the six tags before it were,
which was `bugs/OW-006`. The key is `4AA0538FE239E50C`, "Hanalyx LLC (release
signing) <ops@hanalyx.com>", valid to 2028. `user.signingkey` and
`tag.gpgsign=true` are set in the repository config, so a GA tag cannot go out
unsigned by forgetting a flag.

> **Signing cannot be done from an automation shell, and should not be worked
> around.** The symptom is `error: unable to sign the tag` with
> `gpg: signing failed: Operation cancelled`, which reads like a bad key and is
> not: pinentry has no TTY to prompt on. `gpg-agent` is configured with
> `no-allow-loopback-pinentry`, which is correct for a release key. The working
> pattern is that a human unlocks the key once in their own terminal, `gpg-agent`
> caches it, and subsequent signing succeeds from any shell without the
> passphrase ever being handled by automation. Test with
> `echo test | gpg --local-user <keyid> --armor --detach-sign` before assuming a
> prompt is needed.

### Packages

On a **tag-push release, GPG signing is required**: `release.yml` fails closed and
refuses to publish if `GPG_PRIVATE_KEY` is absent, so operators never receive
unverifiable packages. The cosign layer is optional and skips gracefully if its key
is absent. An unsigned build is only possible via a manual `workflow_dispatch` trial
run (never a tag push). When the keys are configured, `release.yml` signs at these
layers:

| Layer | How | Operator verifies |
|---|---|---|
| **Each RPM** | `rpmsign --addsign` (GPG, in the RPM header) | `rpm --import KEYS` then `rpm -K openwatch-*.rpm` → "signatures OK"; or dnf `gpgcheck=1` |
| **Each DEB** | *not* signed per-package. See note | covered by the signed `SHA256SUMS` below |
| **`SHA256SUMS`** | detached GPG (`.asc`) **and** cosign (`.cosign.sig`) | `gpg --verify SHA256SUMS.asc SHA256SUMS`; `cosign verify-blob --key cosign.pub --signature SHA256SUMS.cosign.sig SHA256SUMS` |

> **Why DEBs aren't signed per-package:** `apt`/`dpkg` never verify a
> standalone `.deb`'s embedded signature, and the tool that produced them
> (`dpkg-sig`) was removed from Ubuntu. Each `.deb`'s authenticity instead
> comes from its SHA256 entry in the GPG- (and cosign-) signed `SHA256SUMS`.
> A signed apt **repository** is the proper path if per-DEB trust is ever
> required.

The Hanalyx GPG public key ships in the repo as [`KEYS`](../../security/KEYS) and is
attached to every release.

## Configuring the signing keys

OpenWatch reuses the **Hanalyx release-signing key**, the same one Kensa uses,
held in the offline vault (generated 2026-05-28). `$VAULT` below is the vault
path on the release captain's own machine. **Do not write the real path into
this file**: it is a public repository, and the vault holds the certify-capable
master private key.

> **NEVER push `MASTER-secret.asc` to a GitHub secret.** It is the
> certify-capable **master** private key. Your root of trust. Only the
> **signing subkey** belongs in CI. The vault's own `setup-signing-keys.sh`
> (in the vault repository, not this one) enforces this: it exports with
> `--export-secret-subkeys` and hard-aborts unless the master private has been
> replaced with a `gnu-dummy` stub. Follow the same rule here.

| Secret | Source | Required? |
|---|---|---|
| `GPG_PRIVATE_KEY` | the **signing subkey only**, exported from the master with the master stubbed (see below) | yes |
| `GPG_PASSPHRASE` | the subkey passphrase (same as master by default) | yes |
| `COSIGN_PRIVATE_KEY` | the cosign private key (NOT in this vault: retrieve from wherever Kensa's `COSIGN_PRIVATE_KEY` was generated, e.g. 1Password) | optional |
| `COSIGN_PASSWORD` | the cosign keypair password | optional |

cosign is **optional**: `release.yml` gates it independently, so with only the
two GPG secrets set, releases still get per-package GPG signatures **and** a
GPG-signed `SHA256SUMS`: just no cosign `.sig`. Set the GPG pair first; add
cosign once you have its private key.

**Export the signing subkey (never the master) and set the GPG secrets:**

```bash
# 1. Import the existing Hanalyx master into your keyring (one-time).
gpg --import "$VAULT"/hanalyx-key-backup/MASTER-secret.asc

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
