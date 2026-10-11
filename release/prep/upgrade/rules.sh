# shellcheck shell=sh
# Step 8 (release-upgrade-steps): restart, prove the rule library loaded, then
# compare the served rules with the installed rules by ID.
# Inputs: OW_URL, OW_KIND (rpm|deb), OW_TOKEN_FILE (a root-only file on this
# host holding an owk_ token with scan:read). The token is read here, sent to
# curl through a private file, and never printed.
stopped() { echo "Step 8 did not reach MATCH. Do not scan. Run Step 8 again; if it still fails, stop and contact support." >&2; }
step "identity matches the verified preflight" identity_check
WORK=$(mktemp -d) || exit 1
trap 'rm -rf -- "$WORK"' EXIT
# shellcheck disable=SC2034 # read by fetch_json in common.sh
JSON=$WORK/endpoint.json
token_file_is_private() {
    test -f "$OW_TOKEN_FILE" || return 1
    set -- $(stat -c '%U %a' -- "$OW_TOKEN_FILE")
    echo "owner $1, mode $2"
    [ "$1" = root ] && { [ "$2" = 600 ] || [ "$2" = 400 ]; }
}
load_token() {
    OWK=$(cat -- "$OW_TOKEN_FILE") || return 1
    case "$OWK" in owk_*) ;; *) echo "the token file does not hold an owk_ token" >&2; return 1 ;; esac
    umask 077
    printf 'header = "Authorization: Bearer %s"\n' "$OWK" > "$WORK/curl.conf"
    echo "token loaded (not shown)"
}
restart() {
    SINCE=$(date '+%Y-%m-%d %H:%M:%S')
    echo "since $SINCE"
    systemctl restart openwatch
}
healthy_within_60s() {
    n=0
    # 30 tries 2 s apart: the procedure's 60 s. OW_HEALTH_TRIES is for tests.
    while [ "$n" -lt "${OW_HEALTH_TRIES:-30}" ]; do
        if health_ok > "$WORK/health.log" 2>&1; then
            cat -- "$WORK/health.log"
            echo "healthy after $((n * 2))s"; return 0
        fi
        n=$((n + 1)); sleep 2
    done
    cat -- "$WORK/health.log"
    echo "not healthy within 60s" >&2; return 1
}
journal_has_no_rule_load_failure() {
    journalctl -u openwatch --since "$SINCE" --no-pager -o cat > "$WORK/journal" || return 1
    cat -- "$WORK/journal"
    ! grep -q -e "kensa scan wiring unavailable" -e "kensa rule library unavailable" "$WORK/journal"
}
served_rules() {
    curl -skf --connect-timeout 3 --max-time 30 -K "$WORK/curl.conf" -o "$WORK/served.json" "$OW_URL/api/v1/rules" || return 1
    echo "served rules: $(wc -c < "$WORK/served.json") bytes"
}
package_files_unchanged() {
    case "$OW_KIND" in
        rpm) rpm -V kensa-rules > "$WORK/verify"; rc=$? ;;
        deb) dpkg --verify kensa-rules > "$WORK/verify"; rc=$? ;;
        *) echo "OW_KIND must be rpm or deb" >&2; return 2 ;;
    esac
    cat -- "$WORK/verify"
    # No output means clean.
    [ "$rc" -eq 0 ] && [ ! -s "$WORK/verify" ]
}
compare() {
    python3 - "$WORK/served.json" "$R/usr/share/kensa/rules" <<'PY'
import glob, json, sys
try:
    import yaml
except ImportError:
    print("python3 has no yaml module (python3-pyyaml or python3-yaml)", file=sys.stderr)
    sys.exit(2)
served = {r["id"] for r in json.load(open(sys.argv[1]))["rules"]}
installed = set()
for path in glob.glob(sys.argv[2] + "/**/*.yml", recursive=True):
    doc = yaml.safe_load(open(path))
    if isinstance(doc, dict) and "id" in doc:
        installed.add(doc["id"])
print("served:", len(served), "installed:", len(installed))
print("served but not installed:", sorted(served - installed))
print("installed but not served:", sorted(installed - served))
print("MATCH" if served == installed and served else "MISMATCH")
sys.exit(0 if served == installed and served else 1)
PY
}
step "token file is root-only" token_file_is_private
step "token" load_token
step "Step 8.1: restart" restart
step "Step 8.1: healthy" healthy_within_60s
step "Step 8.1: no rule-load failure in the journal" journal_has_no_rule_load_failure
step "Step 8.1: rules endpoint" served_rules
step "Step 8.2: package files unchanged" package_files_unchanged
step "Step 8.3: served rules match installed rules" compare
echo "STEP 8 DONE: MATCH"
