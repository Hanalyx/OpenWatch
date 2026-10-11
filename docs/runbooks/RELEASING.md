# Releasing OpenWatch

The gated process for cutting an OpenWatch release. A GA tag builds a draft
that nobody can download. Nothing is published until the docs are frozen,
every automated gate is green, the packages install and run on each target
distro, a functional pass is done against a real fleet, and a human signs off.

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
| every PR, `main`, `v*` | [`go-ci.yml`](../../.github/workflows/go-ci.yml) | vet/lint/vuln/test-race + specter 100% AC coverage. A `v*` tag always runs the full pipeline on the tagged commit, and its `Full test evidence` job is what gates Q1 and S1 to S7 read |

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

`scripts/release_prep_pr.py` drafts steps 1 and 2's mechanical edits from a clean
clone and, once they are committed, a pull request body from recorded evidence. It
does not write the release notes, and it leaves every confirmation blank.

## Stage 2: Cut the release candidate

> **Before you start**
> - **You need:** the Stage 1 commit merged on `main`, its full SHA recorded as the candidate, and the signing key `4AA0538FE239E50C` unlocked in your own terminal.
> - **Run as:** the release captain, from an interactive shell (signing cannot run from automation).
> - **What changes:** one signed tag on `origin`; pushing it starts `release.yml` and `package-smoke.yml`.
> - **Verify with:** the tag appears on `origin` and `release.yml` runs against it; `scripts/release-status.py --tag` reports PENDING then PASS per gate.
> - **Recover by:** nothing that moves or deletes the tag. A refused or failed candidate keeps its tag; take the next number (see below).

The candidate is a commit, named by its full SHA, typed once from the release
record and never derived from a branch. The tag name is read from
`packaging/version.env` at that commit, never typed. Two failures shaped this:

- `v0.8.0-rc.1` was tagged by hand against `VERSION="0.8.0"` and refused by the
  hosted check after it had been signed and pushed (CP `bugs/OW-037`).
- The previous block tagged whatever `main` was at. While v0.8.4 was being cut,
  `main` advanced past the chosen candidate with the same `VERSION`. That block
  would have tagged the later commit under the candidate's name, and no check
  would have failed (CP `bugs/OW-118`).

`scripts/release_tag.py` runs every check before anything is signed:

- the commit exists and is an ancestor of `origin/main` after a fetch;
- `version.env`, the README phrase and the newest CHANGELOG heading agree at the
  commit, and the commit's own `packaging/check-tag-version.sh` accepts the
  derived tag;
- the tag does not exist locally, on `origin`, or on any release, drafts
  included;
- the key, named by its full fingerprint, is a primary key in `security/KEYS` at
  the commit, and its secret key is available.

It signs with that key explicitly (`git tag -s -u`), not with the repository's
`user.signingkey`. It then verifies the tag object, its target and a
`VALIDSIG` from the release key. It pushes `refs/tags/<tag>` only, and checks
the tag object and the peeled commit on `origin`.

```bash
CANDIDATE=<the candidate's full 40-character commit SHA, from the release record>
KEY=4CB70E1C09426E43CBBAD2804AA0538FE239E50C   # 4AA0538FE239E50C, from security/KEYS
python3 -S scripts/release_tag.py --commit "$CANDIDATE" --key "$KEY"          # dry run
python3 -S scripts/release_tag.py --commit "$CANDIDATE" --key "$KEY" --sign   # sign, verify
python3 -S scripts/release_tag.py --commit "$CANDIDATE" --key "$KEY" --push   # push, verify
```

Run the three lines one at a time and read each result before the next:

1. **The dry run** changes nothing. Capture it as evidence with
   `scripts/evidence_capture.py run --timeout 300 -- python3 -S scripts/release_tag.py ...`.
2. **`--sign`** needs the key unlocked in your own terminal (see "Signing
   model"), so run it directly, not through a capture. It never pushes.
3. **`--push`** re-runs every check and re-verifies the local tag before
   pushing.

A failure after signing leaves the local tag in place, unpushed. Nothing moves
or deletes it; decide what to do with it before anything else. The same three
lines cut the GA tag in Stage 4; only the candidate commit differs.

Pushing the tag triggers `release.yml` (builds + SBOMs + publishes a
pre-release for a `-rc.N` tag) and `package-smoke.yml` (per-distro install
matrix). A refused candidate is a failed candidate: leave its tag in place as
a record, file the cause, and take the next number. That holds for a GA tag
too; see "When a GA candidate fails" under Stage 4. Recovery names ONE version
in all four places: `VERSION` in `version.env`, the README phrase, the newest
CHANGELOG heading, and the tag `scripts/release_tag.py` derives from them. After `v0.8.0-rc.1`
was refused, the next candidate was `0.8.0-rc.2` in all four, never
`0.8.0-rc.1` in the files with `rc.2` on the tag.

## Stage 3: Verification gate (every candidate, GA included)

Stages 3 and 3b run against EVERY candidate: each `-rc.N`, and the GA candidate
itself. Nothing carries over. A GA candidate is a new commit and a new build,
so a review or a fleet result recorded against an RC describes bytes that are
not the ones being published, and the checker reports it as STALE.

**Automated (CI):**
- **`Full test evidence` succeeded on the candidate's own commit.** This is a
  job in `go-ci.yml`, and gates Q1 and S1 to S7 read it. It succeeds only when
  the full pipeline ran on that commit and every part of it passed:
  - the race tests;
  - `specter sync` at **100% AC coverage** (the `release-admin-signoff` C-01
    requirement);
  - the composition E2E (`internal/server/api_admin_*signoff*_test.go`, real
    session cookies).

  A green "Quality + security gates" check is not enough: it also passes on the
  documentation path, where the full suite is skipped. Pushing the tag runs the
  full pipeline on the tagged commit, so wait for that run before running the
  checker.

  How the checker reads several runs of one commit:
  - Within one run, only the latest attempt counts. A re-run replaces the
    attempts before it, so a failure re-run to success passes and a success
    re-run to failure fails.
  - Across separate runs of `go-ci.yml` on the commit, such as the push to
    `main` and the tag's run: any run still in progress makes the gate
    PENDING, and any run whose evidence failed, was canceled or did not
    succeed makes it FAIL, even beside a success. A skipped job means that
    run took the documentation path; it is not evidence and does not count
    against a success.

**Historical releases keep their recorded decision.** This requirement applies
to candidates whose own commit carries it, from `release-ci-gates` 1.23.0 on.
A release is judged by the checker and `release/gates.toml` at the commit
where its decision was recorded. v0.8.3's GO was recorded by
`scripts/release-status.py` and `release/gates.toml` at `79f18f78`, and that
record stands. Running a newer checker against an older tag reports these gates
MISSING, because its commit predates the evidence job; that does not revise
the decision, and the checker prints a note when the gate definitions differ.
An older tag cannot gain the evidence either: re-running its workflow runs the
workflow file at that tag, which has no evidence job and, before this change,
did not run on tags at all.
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
   service comes back and data survives. Then run the upgrade procedure's
   Step 8 (restart, then compare the served rules with the installed rules)
   and record its `MATCH` before any scan in the next step.
   `scripts/release_upgrade.py` runs the standard upgrade's Steps 1 to 8 in
   gated phases, with every step's raw output captured (see the release-prep
   skill). It changes the host only with `--execute`, and using it on a fleet
   host needs the release captain's authorization for that host.
4. **Functional walkthrough** against the release captain's test fleet:
   log in → add host → run a Kensa scan → view posture → drift → exceptions →
   export → role-based access. Record results in the sign-off checklist.
5. **F2 evidence: capture the staged state before rolling back.** Run
   `scripts/release_prep.py f2` against one host whose `auditctl -s` reports
   `enabled 2`, in order:
   1. `preflight`, before the remediation;
   2. `staged`, while the remediation shows as staged;
   3. `after`, after the rollback.

   Each phase captures a read-only host snapshot through
   `scripts/evidence_capture.py`, then fetches and verifies it. **Roll back only
   after `staged` prints its rollback prompt.** The prompt appears only once the
   staged capture has verified; on v0.8.4 the staged state was lost because the
   rollback came first. `f2 packet` collects the three captures and leaves the
   observation fields for the captain. The skill
   `.claude/skills/release-prep/SKILL.md` has the full commands.
6. **F1 and F3 packets: read the server after the captain's check.** After the
   captain runs the F1 scan from the UI, `scripts/release_packets.py f1 --scan-id`
   reads that scan's records on the server, read-only: the run, its results, its
   skip reasons and its audit trail, bound to the scan by id. `f3` reads the
   scan variables the server resolves. Each writes a packet and an attestation
   skeleton bound to the artifact's digest from the verified `SHA256SUMS`. The
   tool never starts a scan or changes a setting, and it leaves every captain
   field blank.

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
proves nothing; reviewing these bytes does. A verdict recorded against an RC
describes a different commit, so nothing is ever carried over from an RC.

**Inheriting from the last published release** (`release-ci-gates` C-21). A
document whose path and blob are unchanged since the last published release
may keep the verdict recorded in that release's review instead of being read
again. Every other document gets a fresh read: changed, new and renamed
documents, and any unchanged document whose subject changed, such as a page
that describes a workflow that was edited. Matching bytes do not prove the
behavior a document describes is unchanged. Only the documentation review can
inherit; tests, assets, fleet checks and the captain's signature are always
fresh.

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

   `scripts/release_packets.py d1` runs the same generator from a clean checkout,
   through the capture library, and adds a packet naming the checker commit. It
   refuses a checkout with tracked changes and any output that carries a verdict.

   To inherit from the last published release, pass its archived review:

   ```bash
   python3 -S scripts/doc-review-skeleton.py --commit "$COMMIT" --tag "$TAG" \
     --inherit-from <archive>/doc-review-<previous tag>.toml > /tmp/doc-review-$TAG.toml
   ```

   Unchanged documents go under `[[inherited]]`; everything else under
   `[[reviewed]]`. An unchanged document that names a changed file is put under
   `[[reviewed]]` with a comment saying why. The skeleton lists every
   non-document file changed since that release: check each for effects on the
   inherited documents, and move any affected document to `[[reviewed]]`.

4. **Read the files as they are at that commit**, not as they are in your
   working tree. `git show "$COMMIT:path/to/doc.md"` is the safe way; a
   checkout that has moved on is a different document.

5. **Fill in every field.** Each verdict becomes `accurate` only for a document
   you read and found accurate. `performed_by` is your own name, never an agent.
   `performed_at` is an ISO date that is not in the future. `artifact` and
   `artifact_sha256` are the matching pair from the candidate's `SHA256SUMS`.
   Then recompute `docs_sha256` over the finished entries. A verdict of anything
   other than `accurate` is a NO-GO. There is no general waiver.

   **The one exception: C-22, for two v0.8.4 documents.** `release-ci-gates`
   C-22 lets the D1 review of v0.8.4 record `.github/BRANCH_MANAGEMENT.md` and
   `.github/workflows/README.md` as `accepted-defect`, never `accurate`. Their
   inaccuracies are registered in `release/doc-review-exceptions.toml`, which
   holds the technical scope only: candidate, paths, exact blobs, defect
   descriptions and the fixing pull requests (#930, #931). The release
   captain's acceptance is internal: add one `[[defect_acceptance]]` entry per
   document to the attestation, naming the record's id, with `accepted_by`,
   `accepted_at` and the acceptance wording. On each of those two entries write
   `verdict = "accepted-defect"`, `exception = "<the record's id>"` and
   `otherwise_accurate = true`, the last only if nothing else in the document
   is wrong. Never write `accurate` for them. The checker refuses the entry
   unless the registered scope and the internal acceptance both match. C-22
   covers nothing else: no other candidate, document or defect.

   For an inheriting review, `performed_by` and `performed_at` describe your
   fresh reviews only; inherited entries carry no verdict and no date. After
   checking the listed changes, set `inherits.changes_reviewed` to exactly
   `<previous commit>..<candidate commit>`. `docs_sha256` covers both lists, an
   inherited entry hashing with the verdict `inherited`.

6. **Run the checker with the completed attestation present.**

   ```bash
   cp /tmp/doc-review-$TAG.toml release/attestations/
   python3 -S scripts/release-status.py --tag "$TAG"
   ```

   An inheriting review also needs the previous release's review present, as
   archived: the checker finds it by its sha256, checks that its release is the
   last published one before this candidate, and re-checks that review with the
   checker from that release's own tag, over its own documents and `SHA256SUMS`.
   The split the generator writes is provisional: naming a changed file is a
   flag, not a dependency analysis, so decide for every inherited document
   whether a behavior change makes it inaccurate. Copy it into `release/attestations/`
   for the run; it stays untracked like the new one.

   **Leave that file untracked while the decision is open.** It is a working
   document until D1 passes; committing it earlier records a review that has not
   been accepted yet.

7. **Do not commit anything to the candidate between the review and
   publication.** The evidence describes one commit. Any change after it,
   including a documentation fix found during the review, means a new
   candidate and a new review.

8. **Archive the attestation internally after publication. Never commit it
   and never upload it.** Attestations are internal evidence. Copy each one
   to the internal release evidence store, outside the repository, then
   write a checksum manifest beside them and verify it:

   ```bash
   sha256sum -- *.toml > SHA256SUMS
   sha256sum -c SHA256SUMS
   ```

   Record the store's location and the manifest's checksum in the internal
   release ledger. The file in `release/attestations/` stays untracked, so
   nothing about the evidence can change what was released.

The attestation's `tag` is the tag it was performed against. A GA review says
`v0.8.0`; an RC review says `v0.8.0-rc.N`. Relabeling one as the other would
claim a review that never happened against that tag, and the checker's commit
and digest binding would report it STALE anyway.

## Stage 4: The GA candidate, its draft, and publication

> **Before you start**
> - **You need:** every gate GO on the final-version commit: fresh F1 to F3, H1 and D1 against the draft's own assets.
> - **Run as:** the release captain, with a separate founder authorization for the publish step.
> - **What changes:** the draft release's single `draft` flag; nothing is uploaded, rebuilt, renamed or tagged.
> - **Verify with:** `scripts/release-publish.py --tag` in dry run reports GO and the same asset set it will flip; after `--yes`, the release is public with unchanged digests.
> - **Recover by:** not un-publishing. A defect found after publication is a new version.

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

2. **Cut the tag with the Stage 2 commands, unchanged.** Record the merged
   final-version commit's full SHA as the candidate; `scripts/release_tag.py`
   reads `version.env` at that commit and derives `vX.Y.Z`. Because the tag carries no
   hyphen, `release.yml` builds the assets into a **draft** release. It refuses
   to run for a tag that already has assets, so the build cannot be repeated.

3. **Run Stage 3 and Stage 3b against the GA candidate.** Automated gates on
   the GA commit; fresh F1, F2, F3 and H1 by the founder against the draft's
   packages; a D1 against the GA commit's documentation, fresh for every
   document C-21 does not let it inherit. The checker
   downloads every asset from the draft, hashes it against `SHA256SUMS`, and
   verifies `SHA256SUMS.asc` against `security/KEYS` (gates A1 and A2), then
   reports the release state with the verdict:

   ```bash
   python3 -S scripts/release-status.py --tag "$TAG"
   ```

   Until this says `VERDICT: GO`, there is nothing to publish.

   **Before the fleet checks, verify the draft's assets in full.**
   `scripts/release_assets.py` reads every expectation from the candidate
   commit and checks what gates A1 and A2 do not:
   - the Go toolchain, revision, version and modules in each binary;
   - `govulncheck` on each binary;
   - the RPM signatures;
   - the shipped notices;
   - the SBOMs.

   It changes nothing, captures every command's raw output, and writes a
   `REPORT.md`. It is preparation evidence, not a gate, and it records no
   decision.

   ```bash
   python3 -S scripts/release_assets.py --tag "$TAG" --commit "$CANDIDATE" \
     --key "$KEY" --evidence ~/Documents/openwatch/release-evidence/"$TAG"/assets-verification
   ```

   **Then run the engine and corpus pairing test on those packages.**
   `scripts/release_compat.py` runs the candidate commit's own pairing test in
   local, disposable containers, three modes (Rocky 9 RPM, Ubuntu 24.04 DEB,
   Rocky 9 RPM without scriptlets). The new pair is the draft's packages; the
   old pair is the previous GA's. It verifies both releases' signed
   `SHA256SUMS` first, and a skipped or incomplete mode is a failure. Like the
   asset check, it is preparation evidence, not a gate.

   ```bash
   python3 -S scripts/release_compat.py --tag "$TAG" --commit "$CANDIDATE" \
     --key "$KEY" --old-tag "$PREVIOUS_GA" \
     --evidence ~/Documents/openwatch/release-evidence/"$TAG"/compat
   ```

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

5. **Archive the attestations internally** (D1, the fleet files and H1) after
   publication, as Stage 3b step 8 describes. Never commit or upload them.

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
4. Cut it with the Stage 2 commands, naming its full SHA as the candidate, and run Stages 3 and 3b in full against it.
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
