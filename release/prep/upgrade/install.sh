# shellcheck shell=sh
# Steps 2 and 3 (release-upgrade-steps): stop, record, install.
# Inputs: OW_KIND (rpm|deb), OW_PKGS (staged package paths, space-separated),
# OW_SUMS (the matching "sha256  path" lines, one per package).
# Never starts the service: the package scriptlet does, or leaves it stopped.
stopped() {
    case "$1" in
        "Step 3: install"*) echo "The package install failed. Do not start the service by hand; read the output above and go to Rollback." >&2 ;;
    esac
}
check_sums() {
    printf '%s\n' "$OW_SUMS" > "$TMP"
    sha256sum -c -- "$TMP"
}
TMP=$(mktemp) || exit 1
trap 'rm -f -- "$TMP"' EXIT
step "staged packages match their digests" check_sums
step "Step 2: stop the service" systemctl stop openwatch
step "Step 2: migrate --status (roll-back point)" as_openwatch openwatch migrate --status
step "Step 2: service state" sh -c 'systemctl is-active openwatch; test "$?" -ne 0'
case "$OW_KIND" in
    rpm) step "Step 3: install (dnf upgrade)" dnf upgrade -y $OW_PKGS ;;
    deb) step "Step 3: install (apt-get install)" apt-get install -y $OW_PKGS ;;
    *) step "Step 3: install" sh -c 'echo "OW_KIND must be rpm or deb" >&2; exit 2' ;;
esac
step "Step 3: openwatch --version" openwatch --version
step "Step 3: migrate --status" as_openwatch openwatch migrate --status
# Step 3 records the state; Step 6 (verify) decides. A stopped service here
# means the scriptlet left it stopped, and it must not be started by hand.
record_state() { systemctl is-active openwatch; echo "is-active exit $?"; }
step "Step 3: service state (recorded; Step 6 decides)" record_state
step "Step 3: backups (newest first)" ls -lt "$R/var/lib/openwatch/backups"
echo "INSTALL DONE"
