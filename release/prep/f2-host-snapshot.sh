#!/bin/sh
# F2 host snapshot (release-preparation C-03). Read-only. It runs as root under
# scripts/evidence_capture.py on the fleet host, once before the remediation,
# once while it is staged and once after the rollback, so the three captures
# compare like with like. Nothing here filters output: every section prints
# what its command printed, followed by that command's exit status.
set -u

section() {
    title=$1
    shift
    echo "== $title"
    "$@"
    echo "== exit $?"
}

section "captured_at" date -u +%Y-%m-%dT%H:%M:%SZ
section "auditctl -s" auditctl -s
section "rules.d listing" ls -la --time-style=full-iso /etc/audit/rules.d
section "rules.d digests" sh -c 'cd /etc/audit/rules.d && sha256sum -- *'
section "rules.d contents" sh -c 'for f in /etc/audit/rules.d/*; do echo "--- $f"; cat -- "$f"; done'
section "audit.rules digest" sha256sum /etc/audit/audit.rules
section "loaded rules" auditctl -l
section "loaded rule digest" sh -c 'auditctl -l | sha256sum'
section "boot" sh -c 'uptime -s; cat /proc/sys/kernel/random/boot_id'
