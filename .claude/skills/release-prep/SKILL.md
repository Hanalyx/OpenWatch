---
name: release-prep
description: >
  Prepare evidence for an OpenWatch release candidate with the maintained, tested scripts:
  capture fleet-host evidence raw, bound and verified, and run the F2 staged-remediation
  check in its three phases. Use when preparing a release's verification gates (Stage 3 of
  docs/runbooks/RELEASING.md), collecting fleet evidence for the release captain, or
  building an F2 packet. Not for verdicts, sign-offs, tagging, merging or publishing.
---

# release-prep

This skill prepares evidence. The release captain decides. The procedure itself is
`docs/runbooks/RELEASING.md`; this skill covers how the agent gathers evidence for it.

## Rules

1. **Evidence goes through `scripts/evidence_capture.py`, never through a pipe.** Raw stdout,
   raw stderr and the exit status are written before anything is displayed. A filtered or
   summarized view is derived from those files and never replaces them. On v0.8.4 a
   banner-stripping `grep -v` deleted a real line from two host snapshots and produced a false
   finding.
2. **Every capture has an explicit timeout.** The library's command line refuses `run` and
   `fetch` without `--timeout`. In Python, pass `timeout=`; a capture without one waits for as
   long as any descendant holds its streams.
3. **Fleet evidence is fetched and verified, not copied.** Use `release_prep.py`, or
   `evidence_capture.py fetch`. The capture's checksums, candidate and machine id are checked
   before it is named. Anything that fails is isolated in `NAME.transfer-failed`.
4. **Secrets go in environment variables named with `--secret-env`, never in arguments.**
   The check protects the supplied values only. It does not find a credential a command
   prints by itself.
5. **Leave every human field blank.** Confirmations, observations, attestation verdicts, H1
   and D1 are the captain's. Do not fill one because it is the last blocker, and do not infer
   one from evidence.
6. **No outward action without explicit authorization for that action.** That covers tags,
   merges, release publication, release-body edits, advisories, server changes and Context
   Plane writes outside `projects/openwatch/`, `features/` and `bugs/`. Authorization to
   prepare is not authorization to publish.
7. **Timestamps come from the evidence.** Use a capture's `started_at`, a file's mtime or a
   command's output. Never type a time.
8. **Hand-offs are written down the same turn.** A finding for another agent goes to the
   Context Plane `bugs/` or `features/`, not only to a message. After any Context Plane move,
   read both paths back.

## F2: staged remediation

F2 runs on one host whose `auditctl -s` reports `enabled 2`, in three phases. Each phase
captures the same read-only snapshot (`release/prep/f2-host-snapshot.sh`) on the host, then
fetches and verifies it.

```bash
H="--host owas-rhn02 --ssh-target admin@HOST --ssh-key KEY --tag vX.Y.Z --commit SHA \
   --evidence ~/Documents/openwatch/release-evidence/vX.Y.Z"
python3 -S scripts/release_prep.py f2 preflight $H   # checks enabled 2
#   captain: remediate the audit_rule_set rule in the UI; wait for "staged"
python3 -S scripts/release_prep.py f2 staged $H      # captures the staged state
#   only now does the tool say to roll back; captain records the UI, then rolls back
python3 -S scripts/release_prep.py f2 after $H
python3 -S scripts/release_prep.py f2 packet $H      # F2-PACKET.md, confirmations blank
python3 -S scripts/release_prep.py f2 status $H      # what is verified, what is next
```

- **Never tell the captain to roll back before `f2 staged` has printed its rollback prompt.**
  That prompt appears only after the staged capture verifies. If `staged` fails, the staged
  state has not been captured: fix the cause and capture again before any rollback. A
  rollback first destroys the evidence F2 needs, which is what happened on v0.8.4.
- `f2 after` and `f2 packet` re-verify every earlier capture from disk and refuse if any is
  missing, altered, from another candidate or from another machine.
- Every snapshot section is required. A section that fails (for example `auditctl -l`, or one
  unreadable rules file) fails the capture, and so does any `== exit N` other than 0 in its
  output. Its raw output is kept, but it never counts as staged evidence.
- Never hold command output in a shell variable when writing a capture script: `$(...)` strips
  trailing newlines. Write to a private temporary file and emit its exact bytes.
- A phase is never captured twice under the same name. To retry, move the failed capture
  aside and say so in the hand-off.
- The tool sends the capture library to the host over SSH standard input. The host needs
  `python3` (set `--remote-python` otherwise) and passwordless `sudo -n`.
- `--ssh-key` is required. The SSH command sets `StrictHostKeyChecking=yes` and
  `IdentitiesOnly=yes` on the command line, which overrides any `ssh_config`, so an unknown
  or changed host key, or an agent's other key, cannot be used.
- Verified on a real host: preflight only (owas-rhn02, 2026-10-10). The staged capture and
  the rollback sequencing are tested in simulation only. Do not describe the whole F2
  workflow as fleet-verified.

## Tagging (OW-118)

`scripts/release_tag.py` cuts a release tag on an explicit candidate commit. The procedure is
RELEASING.md Stage 2:

- The candidate is the full SHA from the release record, typed once. Never pass a branch,
  `HEAD` or a short SHA.
- The dry run (no `--sign`) changes nothing. Capture it through
  `evidence_capture.py run --timeout`.
- `--sign` and `--push` are the release captain's actions, run in their own terminal. Never
  run either without explicit authorization for that tag, and never move or delete a tag.

## Draft-asset verification

`scripts/release_assets.py` verifies a draft's (or a published release's) assets against the
candidate commit, read-only. Run it before asking for fleet checks:

```bash
python3 -S scripts/release_assets.py --tag "$TAG" --commit "$CANDIDATE" --key "$KEY" \
  --evidence ~/Documents/openwatch/release-evidence/"$TAG"/assets-verification
```

- Read `REPORT.md` and every FAIL. The raw captures under `captures/` are the evidence; the
  report is derived from them.
- A `govulncheck` finding only in required modules or imported packages is listed, not failed.
  Report it to the release captain; do not decide it away.
- Completeness comes from `release/assets.toml` at the candidate commit, not from whatever was
  downloaded. A candidate older than that file needs `--inventory-from-tree`, and the report
  then says the inventory is not the candidate's. Say so in the hand-off.
- A check that could not run is a FAIL, never a pass. Never report PASS from a run with
  missing input, a failed download or unusable `govulncheck` output.
- It records no decision and changes nothing. Gates A1 and A2 stay in `release-status.py`.
- Validated so far against the published v0.8.4 release, read-only. Draft verification is still
  pending. `--inventory-from-tree` is only an explicit, recorded fallback for a candidate older
  than `release/assets.toml`.

## Local compatibility runs

`scripts/release_compat.py` runs the candidate commit's own pairing test in local, disposable
containers. The new pair is the release's packages and the old pair an older release's (for
v0.8.4, v0.7.1):

```bash
python3 -S scripts/release_compat.py --tag "$TAG" --commit "$CANDIDATE" --key "$KEY" \
  --old-tag vA.B.C --evidence ~/Documents/openwatch/release-evidence/"$TAG"/compat
```

- Both releases' signatures and every package's hash are checked before anything runs.
- A skipped, incomplete or failing mode is a FAIL. Never report the pairing as verified from a
  run that skipped.
- These are local containers only. Upgrading a real host is separate and needs explicit
  authorization; so does any real remediation.
- Validated so far against the published v0.8.4 with v0.7.1 as the old pair: 39, 35 and 39
  checks. Not yet run against a draft candidate.

## Upgrade Steps 1 to 8

`scripts/release_upgrade.py` runs the standard upgrade on one OpenWatch server in five
phases: `plan` (read-only), `backup`, `install`, `verify` and `rules` (Step 8). Each phase
needs the previous ones verified from the same machine.

- **Using it on a fleet host needs the release captain's authorization for that host and
  that upgrade.** Implementation, tests and a passing dry run are not that authorization.
- Without `--execute`, a changing phase prints exactly what it would run and contacts
  nothing. Show that to the captain first.
- The tool never starts the service by hand, rolls back or reboots. If `install` or `verify`
  stops, read its output and follow the procedure's Rollback section with the captain. Do
  not improvise.
- Step 8 needs a root-only token file on the host (`--token-file`). The token never leaves
  the host. Do not scan until `rules` prints `STEP 8 DONE: MATCH`.
- Validated so far against a simulated server only. Not yet run on a fleet host.

## Not covered yet

These steps are still done by hand from `RELEASING.md` and `UPGRADE_PROCEDURE.md`. When doing
them, capture every command through `evidence_capture.py run --timeout`:

- the release-prep PR content;
- F1, F3 and D1 packets.
