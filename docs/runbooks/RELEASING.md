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
| `v*` | [`release.yml`](../../.github/workflows/release.yml) | RPM+DEB (amd64+arm64; RPMs GPG-signed per-package), CycloneDX SBOMs, `SHA256SUMS` (GPG `.asc` + cosign `.sig`), `KEYS`. A `-rc.N` tag publishes a pre-release; a bare tag lands in a DRAFT release, published later by `scripts/release-publish.py`. A tag that already has assets is refused, never rebuilt |
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
(
  set -euo pipefail                     # a failed line stops the cut here
  git switch main
  git pull --ff-only origin main
  test -z "$(git status --porcelain)"   # tag a merged commit, not a working tree
  . packaging/version.env
  TAG="v$VERSION"                       # derived from the file, never typed
  RELEASE_REF="$TAG" bash packaging/check-tag-version.sh
  git tag -s "$TAG" -m "$TAG"
  git push origin "$TAG"
)
```

The block is a subshell with `set -e`, so a failed pull, a dirty tree or a
refused check leaves no tag, and a failed signature leaves nothing to push.
Pasted into an interactive shell it stops the block, not the shell. The same
block cuts the GA tag in Stage 4; only `version.env` differs.

Pushing the tag triggers `release.yml` (builds + SBOMs + publishes a
pre-release for a `-rc.N` tag) and `package-smoke.yml` (per-distro install
matrix). A refused candidate is a failed candidate: leave its tag in place as
a record, file the cause, and take the next number. That holds for a GA tag
too; see "When a GA candidate fails" under Stage 4. Recovery names ONE version
in all four places: `VERSION` in `version.env`, the README phrase, the newest
CHANGELOG heading, and the tag the block derives from them. After `v0.8.0-rc.1`
was refused, the next candidate was `0.8.0-rc.2` in all four, never
`0.8.0-rc.1` in the files with `rc.2` on the tag.

## Stage 3: Verification gate (every candidate, GA included)

Stages 3 and 3b run against EVERY candidate: each `-rc.N`, and the GA candidate
itself. Nothing carries over. A GA candidate is a new commit and a new build,
so a review or a fleet result recorded against an RC describes bytes that are
not the ones being published, and the checker reports it as STALE.

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

**Manual (on the candidate, against a real fleet: CI cannot reach workstation
hosts). Founder-performed. For the GA candidate the packages come from the draft
release, downloaded with `gh release download <tag>` or from the asset ids
`scripts/release-status.py` lists:**
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

> If any gate fails on an RC, fix on `main`, cut the next `-rc.N`, and repeat.
> If any gate fails on the GA candidate, replace the candidate (Stage 4). Never
> publish a candidate that skipped a gate.

## Stage 3b: Documentation review (gate D1)

Gate D1 is blocking. A named human reads every tracked Markdown document at the
candidate commit and records a verdict for each. Scope is every tracked blob
whose path ends in `.md`, with no directory exclusions, so `.github`, `.claude`
and `scripts/README.md` are reviewed like any other document.

The evidence is bound to the candidate, not to a date. Reviewing recently
proves nothing; reviewing these bytes does. The GA candidate gets its own full
review: a verdict recorded against an RC describes a different commit.

1. **Cut the candidate first and wait for its assets.** The attestation names
   an artifact and its digest, and both come from the candidate's `SHA256SUMS`
   (on the pre-release for an RC, on the draft for GA). There is nothing to
   attest until `release.yml` has finished.

2. **Resolve and record the exact candidate commit.** Do not work from a
   branch name or from whatever `HEAD` happens to be.

   ```bash
   TAG=v<version>            # v0.8.0-rc.2 for a candidate, v0.8.0 for GA
   COMMIT=$(git rev-list -n 1 "$TAG")
   echo "$COMMIT"
   ```

3. **Generate the skeleton for that commit.**

   ```bash
   python3 -S scripts/doc-review-skeleton.py --commit "$COMMIT" --tag "$TAG" \
     > /tmp/doc-review-$TAG.toml
   ```

   It writes one entry per document with `verdict = "pending"`, and leaves the
   human identity blank. It cannot fill either in for you.

4. **Read the files as they are at that commit**, not as they are in your
   working tree. `git show "$COMMIT:path/to/doc.md"` is the safe way; a
   checkout that has moved on is a different document.

5. **Fill in every field.** Each verdict becomes `accurate` only for a document
   you read and found accurate. `performed_by` is your own name, never an agent.
   `performed_at` is an ISO date that is not in the future. `artifact` and
   `artifact_sha256` are the matching pair from the candidate's `SHA256SUMS`.
   Then recompute `docs_sha256` over the finished entries. A verdict of anything
   other than `accurate` is a NO-GO: there is no waiver.

6. **Run the checker with the completed attestation present.**

   ```bash
   cp /tmp/doc-review-$TAG.toml release/attestations/
   python3 -S scripts/release-status.py --tag "$TAG"
   ```

   **Leave that file untracked while the decision is open.** It is a working
   document until D1 passes; committing it earlier records a review that has not
   been accepted yet.

7. **Do not commit anything to the candidate between the review and
   publication.** The evidence describes one commit. Any change after it,
   including a documentation fix found during the review, means a new
   candidate and a new review.

8. **Commit the attestation after publication**, not before. By then the
   released commit is fixed, so the audit commit that records the evidence
   cannot change what was released.

The attestation's `tag` is the tag it was performed against. A GA review says
`v0.8.0`; an RC review says `v0.8.0-rc.N`. Relabeling one as the other would
claim a review that never happened against that tag, and the checker's commit
and digest binding would report it STALE anyway.

## Stage 4: The GA candidate, its draft, and publication

Decided by the founder on 2026-09-14 (CP `bugs/OW-037`, option C): the GA
release is a distinct final-version commit, built once into a draft, verified
in full against that exact build, and published by flipping the draft. Nothing
is inherited from any RC. `release-ci-gates` C-14 is the contract.

1. **Prepare the final-version commit through review.** A pull request that
   sets the three bound places to the bare version: `VERSION="X.Y.Z"` in
   `packaging/version.env`, the README phrase, and the newest CHANGELOG heading
   `## [X.Y.Z] <codename> (<date>)`. **The date is the intended publication
   date**, not the date of the commit. Nothing else changes in that pull
   request. Merge it.

2. **Cut the tag with the Stage 2 block, unchanged.** It reads `version.env`
   on the merged commit and derives `vX.Y.Z`. Because the tag carries no
   hyphen, `release.yml` builds the assets into a **draft** release. It refuses
   to run for a tag that already has assets, so the build cannot be repeated.

3. **Run Stage 3 and Stage 3b against the GA candidate.** Automated gates on
   the GA commit; fresh F1, F2, F3 and H1 by the founder against the draft's
   packages; a full D1 against the GA commit's documentation. The checker
   downloads every asset from the draft, hashes it against `SHA256SUMS`, and
   verifies `SHA256SUMS.asc` against `security/KEYS` (gates A1 and A2), then
   reports the release state with the verdict:

   ```bash
   python3 -S scripts/release-status.py --tag "$TAG"
   ```

   Until this says `VERDICT: GO`, there is nothing to publish.

4. **Publish the verified draft, on GO and on separate founder authorization.**

   ```bash
   python3 -S scripts/release-publish.py --tag "$TAG"          # dry run
   python3 -S scripts/release-publish.py --tag "$TAG" --yes    # publish
   ```

   The script re-evaluates, records every asset id, name and size, the
   manifest bytes and the commit the tag names on `origin`, re-reads all of
   that, refuses if anything changed, flips the single `draft` flag, and
   re-reads again. It never uploads, deletes, renames, rebuilds or tags.
   `--yes` is the founder's authorization; GO is a precondition of it, not a
   substitute for it. A `PUBLISHED BUT CHANGED` outcome means what is public
   is not what was verified: treat every attestation for the tag as stale and
   investigate before announcing.

5. **Commit the attestations** (D1 and the fleet files) after publication.

### When a GA candidate fails

Any change to the candidate commit or to any asset invalidates the evidence
that names the old commit or the old digests; the checker reports it STALE. A
changed intended publication date is such a change, and so is a defect found
during Stage 3 or 3b.

**Tags are immutable.** Founder-approved policy, 2026-09-14 (CP
`bugs/OW-037`; `release-ci-gates` C-14). Once pushed, an RC or GA tag is never
moved or deleted, and nothing is rebuilt under it. A candidate that must
change is recorded as failed, and the path is the same one an RC takes, one
level up:

1. Leave the tag and its draft where they are. The tag and version remain
   reserved as the record of the failed candidate; the draft stays unpublished
   (`release-publish.py` refuses anything that is not GO) and its assets are
   never re-cut.
2. Record the failure: the cause in the appropriate CP `bugs/` record, and a
   line in the next version's changelog saying that number was not released
   and why.
3. Prepare the next version through review as a new final-version commit
   (step 1 above), with its own intended publication date: a failed `0.8.0`
   advances to `0.8.1`.
4. Cut it with the Stage 2 block and run Stages 3 and 3b in full against it.
   Nothing carries over from the failed candidate.

Diagnostic tests may run against a failed candidate's draft (installing its
packages on a scratch VM to characterize the defect, for example) provided
they do not alter the tag, the release draft or the candidate assets.

Version numbers are cheap; a tag that means one thing forever is not.

A published release is never rebuilt. A defect found after publication is a
new version.

## Stage 5: Post-release smoke

On a clean box, install the **published** artifact and confirm it starts:

```bash
# download openwatch-<v>.x86_64.rpm AND kensa-rules-<kv>.noarch.rpm, then:
sudo dnf install ./openwatch-<v>.x86_64.rpm ./kensa-rules-<kv>.noarch.rpm
sudo openwatch setup
curl -k https://localhost:8443/api/v1/health
```

Then bump `packaging/version.env` to the next `-dev`/`-rc` (and the README
phrase and a fresh `[Unreleased]` heading with it) and announce.

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

**Export the signing subkey (never the master) and set the GPG secrets.**
The block is one subshell with `set -e`: the safety gate at step 4 ends the
block before any upload when the export carries the master's private key,
and the export is shredded on every exit path. An earlier version printed
`ABORT` and carried on to `gh secret set`; a test in `packaging/tests` now
runs this block with `gpg` and `gh` stubbed and asserts that a failed gate
records no upload.

```bash
(
  set -euo pipefail
  export GNUPGHOME="${GNUPGHOME:-$HOME/.gnupg}"
  EXPORT="$(mktemp -t ow-subkey.XXXXXX)"
  trap 'shred -u "$EXPORT" 2>/dev/null || rm -f "$EXPORT"' EXIT

  # 1. Import the existing Hanalyx master into your keyring (one-time).
  gpg --import "$VAULT"/hanalyx-key-backup/MASTER-secret.asc

  # 2. The SIGNING SUBKEY fingerprint: the 2nd fpr line (the 1st is the master).
  SUBKEY_FPR="$(gpg --list-secret-keys --with-colons ops@hanalyx.com \
    | awk -F: '/^fpr:/{print $10}' | sed -n '2p')"
  test -n "$SUBKEY_FPR"

  # 3. Export ONLY that subkey (the trailing '!'). This stubs the master.
  gpg --armor --export-secret-subkeys "${SUBKEY_FPR}!" > "$EXPORT"

  # 4. SAFETY GATE. A stubbed master shows as a gnu-dummy packet; a real one
  #    does not. Anything but a match ends the block here, before any upload.
  if ! gpg --list-packets "$EXPORT" | grep -q gnu-dummy; then
    echo "ABORT: master private key present in the export; nothing uploaded" >&2
    exit 1
  fi
  echo "OK: master is stubbed"

  # 5. Push the subkey + passphrase (passphrase via silent prompt; never on the CLI).
  gh secret set GPG_PRIVATE_KEY --repo Hanalyx/OpenWatch < "$EXPORT"
  gh secret set GPG_PASSPHRASE  --repo Hanalyx/OpenWatch   # paste at the prompt

  # 6. The trap shreds the export on exit.

  # 7. (optional) cosign, once you have its private key file:
  # gh secret set COSIGN_PRIVATE_KEY --repo Hanalyx/OpenWatch < <cosign.key>
  # gh secret set COSIGN_PASSWORD    --repo Hanalyx/OpenWatch  # paste at the prompt
)
```

Notes:
- The repo `KEYS` file is the **corrected** public key (primary UID
  `Hanalyx LLC (release signing)`). Subkey signatures verify against it because
  `KEYS` carries the same master that certifies the subkey.
- A hosted, GPG-signed dnf/apt **repository** (so operators can
  `dnf install openwatch` without `./`) is the next distribution milestone; the
  per-package signatures above are what such a repo requires.
