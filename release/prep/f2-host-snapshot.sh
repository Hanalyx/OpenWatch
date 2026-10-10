#!/bin/sh
# F2 host snapshot (release-preparation C-03). Read-only. It runs as root under
# scripts/evidence_capture.py on the fleet host, once before the remediation,
# once while it is staged and once after the rollback, so the three captures
# compare like with like. Nothing here filters output: every section prints
# what its command printed, followed by that command's exit status.
#
# Every section is required. The script exits non-zero when any section
# failed, so a failure cannot be reported and then forgotten. There are no
# pipelines (POSIX sh has no pipefail, so a pipe would hide its first
# command's status), and a loop fails if any iteration failed, not only the
# last one.
#
# F2_SNAPSHOT_ROOT prefixes the file paths read below. It is empty on a fleet
# host and is set only by the tests, which supply a fake root.
set -u

R=${F2_SNAPSHOT_ROOT:-}
failed=""

section() {
    title=$1
    shift
    echo "== $title"
    "$@"
    rc=$?
    echo "== exit $rc"
    if [ "$rc" -ne 0 ]; then
        failed="$failed
  $title (exit $rc)"
    fi
}

# Print each rules.d file; fail if any of them could not be read.
rules_contents() {
    rc=0
    found=0
    for f in "$R"/etc/audit/rules.d/*; do
        [ -e "$f" ] || [ -L "$f" ] || continue
        found=1
        echo "--- $f"
        cat -- "$f" || rc=$?
    done
    [ "$found" -eq 1 ] || { echo "no files in $R/etc/audit/rules.d" >&2; rc=1; }
    return "$rc"
}

# Digest each rules.d file; fail if any digest failed.
rules_digests() {
    rc=0
    found=0
    for f in "$R"/etc/audit/rules.d/*; do
        [ -e "$f" ] || [ -L "$f" ] || continue
        found=1
        sha256sum -- "$f" || rc=$?
    done
    [ "$found" -eq 1 ] || { echo "no files in $R/etc/audit/rules.d" >&2; rc=1; }
    return "$rc"
}

# The loaded rules and their digest, from one auditctl run. auditctl's status
# is the section's status; the digest is of the output exactly as printed.
loaded_rules() {
    out=$(auditctl -l) || { rc=$?; printf '%s\n' "$out"; return "$rc"; }
    printf '%s\n' "$out"
    echo "--- digest of the output above"
    printf '%s\n' "$out" | sha256sum
}

boot() {
    uptime -s || return $?
    cat -- "$R"/proc/sys/kernel/random/boot_id
}

section "captured_at" date -u +%Y-%m-%dT%H:%M:%SZ
section "auditctl -s" auditctl -s
section "rules.d listing" ls -la --time-style=full-iso "$R"/etc/audit/rules.d
section "rules.d digests" rules_digests
section "rules.d contents" rules_contents
section "audit.rules digest" sha256sum -- "$R"/etc/audit/audit.rules
section "loaded rules" loaded_rules
section "boot" boot

if [ -n "$failed" ]; then
    echo "f2-host-snapshot: required sections failed:$failed" >&2
    exit 1
fi
exit 0
