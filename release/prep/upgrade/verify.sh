# shellcheck shell=sh
# Steps 4 to 7 (release-upgrade-steps). Inputs: OW_URL, OW_VERSION (expected).
stopped() {
    case "$1" in
        "Step 6"*) echo "The service is not active after the install. Do not start it by hand; go to Rollback." >&2 ;;
        "Step 5"*) echo "migrate did not report a finished schema; the scriptlet did not complete. Read journalctl -u openwatch before going on." >&2 ;;
    esac
}
OUT=$(mktemp) || exit 1
trap 'rm -f -- "$OUT"' EXIT
migrate_finished() {
    as_openwatch openwatch --config "$R/etc/openwatch/openwatch.toml" migrate > "$OUT" 2>&1
    rc=$?
    cat -- "$OUT"
    [ "$rc" -eq 0 ] && grep -q "no migrations to run" "$OUT"
}
reports_version() {
    curl -sk --max-time 10 "$OW_URL/api/v1/$1" > "$OUT"
    rc=$?
    cat -- "$OUT"
    echo
    [ "$rc" -eq 0 ] && grep -q "\"version\":\"$OW_VERSION\"" "$OUT"
}
step "Step 4: check-config" as_openwatch openwatch --config "$R/etc/openwatch/openwatch.toml" check-config
step "Step 5: migrate (expects no migrations to run)" migrate_finished
step "Step 6: service active" systemctl is-active openwatch
step "Step 6: service status" systemctl status openwatch --no-pager
step "Step 7: health reports $OW_VERSION" reports_version health
step "Step 7: version reports $OW_VERSION" reports_version version
step "Step 7: journal" journalctl -u openwatch -n 100 --no-pager
step "Step 7: database reachable" as_openwatch sh -c 'exec psql "$OPENWATCH_DATABASE_DSN" -c "SELECT 1;"'
echo "VERIFY DONE: Step 8 is next, before any scan"
