#!/bin/sh
# F2 host snapshot (release-preparation C-03). Read-only: it changes nothing on
# the host and writes only one private temporary file, removed on exit and on
# interruption. It runs as root under
# scripts/evidence_capture.py on the fleet host, once before the remediation,
# once while it is staged and once after the rollback, so the three captures
# compare like with like. Nothing here filters output: every section prints
# what its command printed, followed by that command's exit status.
#
# Every section is required. The script exits non-zero when any section
# failed, so a failure cannot be reported and then forgotten. There are no
# pipelines (POSIX sh has no pipefail, so a pipe would hide its first
# command's status), and a loop fails if any iteration failed, not only the
# last one. Output is never held in a shell variable, because command
# substitution strips trailing newlines and the bytes would no longer be raw.
#
# F2_SNAPSHOT_ROOT prefixes the file paths read below. It is empty on a fleet
# host and is set only by the tests, which supply a fake root.
set -u

R=${F2_SNAPSHOT_ROOT:-}
failed=""
tmp=""

# Remove the temporary file however the script ends. A signal exits with the
# conventional 128+N status, which runs the EXIT trap.
trap 'if [ -n "$tmp" ]; then rm -f -- "$tmp"; fi' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

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

# The loaded rules, from one auditctl run written to a private temporary file:
# its exact bytes, then a trailer line giving their count and sha256, both
# computed from the file. The trailer starts on a new line of its own, so the
# raw output is the BYTES bytes before "\n--- auditctl -l output above".
# auditctl's status is the section's status; the trailer is printed for a
# failed run too, describing the partial output.
loaded_rules() {
    tmp=$(mktemp "${TMPDIR:-/tmp}/f2-auditctl.XXXXXXXX") || return 1
    auditctl -l > "$tmp"
    rc=$?
    cat -- "$tmp" || rc=1
    bytes=$(wc -c < "$tmp") || rc=1
    digest=$(sha256sum < "$tmp") || rc=1
    set -- ${bytes:-unknown} ${digest:-unknown}
    printf '\n--- auditctl -l output above: %s bytes, sha256 %s\n' "$1" "$2"
    rm -f -- "$tmp"
    tmp=""
    return "$rc"
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
