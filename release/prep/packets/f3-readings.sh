# shellcheck shell=sh
# F3 server readings (release-packets): the scan variables the server
# resolves from its rule corpus, read-only. Inputs: OW_URL, OW_TOKEN_FILE (a
# root-only file on this host holding an owk_ token with system:read).
# Every section runs, so the token is read only after this check has passed in
# this same shell: a token file another user can read is never read or sent.
TOKEN_OK=no
token_file_is_private() {
    test -f "$OW_TOKEN_FILE" || return 1
    stat -c '%U %a' -- "$OW_TOKEN_FILE" > "$WORK/stat" || return 1
    cat -- "$WORK/stat"
    mode=$(cat -- "$WORK/stat")
    if [ "$mode" = "root 600" ] || [ "$mode" = "root 400" ]; then
        TOKEN_OK=yes
        return 0
    fi
    return 1
}
# The token is read here and written only to a private curl config; it is
# never printed and never leaves this host.
variables() {
    if [ "$TOKEN_OK" != yes ]; then
        echo "the token file is not root-only; it was not read" >&2
        return 1
    fi
    owk=$(cat -- "$OW_TOKEN_FILE") || return 1
    case "$owk" in
        owk_*) ;;
        *) echo "the token file does not hold an owk_ token" >&2; return 1 ;;
    esac
    printf 'header = "Authorization: Bearer %s"\n' "$owk" > "$WORK/curl.conf" || return 1
    code=$(curl -sk --connect-timeout 3 --max-time 30 -K "$WORK/curl.conf" \
        -o "$WORK/variables.json" -w '%{http_code}' "$OW_URL/api/v1/system/scan/variables") \
        || return 1
    rm -f -- "$WORK/curl.conf"
    cat -- "$WORK/variables.json"
    echo
    echo "http $code"
    [ "$code" = 200 ]
}
# ScanVariablesResponse (api/openapi.yaml). Exits 1 on a body that does not
# match the schema, and on an empty list: F3's blank panel.
summary() {
    python3 - "$WORK/variables.json" <<'PY'
import json, sys
REQUIRED = {"name": str, "default": str, "value": str, "overridden": bool,
            "affects_rules": int, "rule_ids": list, "configure_me": bool}
try:
    with open(sys.argv[1]) as f:
        d = json.load(f)
except (OSError, ValueError) as e:
    sys.exit("the body is not JSON: %s" % e)
vs = d.get("variables") if isinstance(d, dict) else None
if not isinstance(vs, list):
    sys.exit("no variables list")
for v in vs:
    for k, t in REQUIRED.items():
        if not isinstance(v, dict) or type(v.get(k)) is not t:
            sys.exit("a variable lacks %s as %s: %r" % (k, t.__name__, v))
print("variables %d" % len(vs))
print("configure_me %d" % sum(v["configure_me"] for v in vs))
print("overridden %d" % sum(v["overridden"] for v in vs))
for v in vs:
    print("name %s" % v["name"])
if not vs:
    sys.exit("the server lists no scan variables: the rule corpus did not resolve")
PY
}
section "hostname" hostname
section "machine-id" cat -- "$R/etc/machine-id"
section "openwatch --version" openwatch --version
section "version endpoint" version_endpoint
section "token file is root-only" token_file_is_private
section "scan variables" variables
section "summary" summary
finish "F3 readings"
