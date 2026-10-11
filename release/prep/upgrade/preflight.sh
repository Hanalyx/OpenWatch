# shellcheck shell=sh
# Upgrade preflight (release-upgrade-steps). Read-only: "Before you upgrade"
# in UPGRADE_PROCEDURE.md. Every section runs; the phase fails if any did.
# Inputs: OW_URL.
failed=""
section() {
    title=$1
    shift
    echo "== $title"
    "$@"
    rc=$?
    echo "== exit $rc"
    [ "$rc" -eq 0 ] || failed="$failed
  $title (exit $rc)"
}
section "hostname" hostname
section "machine-id" cat -- "$R/etc/machine-id"
section "boot_id" cat -- "$R/proc/sys/kernel/random/boot_id"
section "openwatch --version" openwatch --version
section "packages" sh -c 'rpm -q openwatch kensa-rules 2>/dev/null || dpkg-query -W openwatch kensa-rules'
section "service" systemctl is-active openwatch
section "health" curl -sk --max-time 10 "$OW_URL/api/v1/health"
section "version" curl -sk --max-time 10 "$OW_URL/api/v1/version"
section "migrate --status" as_openwatch openwatch migrate --status
section "disk" df -h "$R/var/lib/openwatch" "$R/var"
section "config digests" find "$R/etc/openwatch" -type f -exec sha256sum {} +
section "backups" ls -la "$R/var/lib/openwatch/backups"
if [ -n "$failed" ]; then
    echo "upgrade preflight: required sections failed:$failed" >&2
    exit 1
fi
