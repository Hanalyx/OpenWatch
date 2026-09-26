#!/usr/bin/env bash
# kensa-rules-compat-container-test.sh: runs INSIDE a disposable container.
#
# Proves the package manager enforces the engine/corpus pairing
# (spec release-upgrade C-06, AC-09). An engine older than its corpus cannot
# load it, and OpenWatch starts anyway with every scan failing, so:
#
#   1. a rules-only upgrade beside an older openwatch is REFUSED, and the
#      installed corpus is unchanged afterwards;
#   2. an openwatch-only upgrade over the older corpus succeeds (a newer
#      engine loads an older corpus);
#   3. the coordinated upgrade, both packages in one transaction, succeeds;
#   4. a fresh install of the new pair succeeds;
#   5. the new corpus refuses to stay beside a downgraded openwatch;
#   6. release-candidate versions order correctly: rc.5 < rc.6 < rc.10 < GA,
#      with the epoch both package formats carry.
#
# Usage: kensa-rules-compat-container-test.sh <rpm|deb> <old-dir> <new-dir>
#   old-dir: an openwatch release that predates the engine provide, and its
#            kensa-rules (the published v0.8.0-rc.5 assets).
#   new-dir: openwatch and kensa-rules built from this tree.
#
# RPM transactions run with tsflags=noscripts: scriptlets are covered by the
# setup and upgrade harnesses, and this test is about dependency resolution,
# which noscripts leaves untouched. The DEB scriptlets tolerate a container
# without systemd, so apt runs them.
set -uo pipefail

KIND="${1:?usage: $0 <rpm|deb> <old-dir> <new-dir>}"
OLD="${2:?old-dir}"
NEW="${3:?new-dir}"

FAILURES=0
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; FAILURES=$((FAILURES + 1)); }

# Installed version of a package, or "absent".
installed() {
    if [ "$KIND" = deb ]; then
        dpkg-query -W -f='${Status} ${Version}\n' "$1" 2>/dev/null |
            awk '$1=="install" && $3=="installed" {print $4; f=1} END {if (!f) print "absent"}'
    elif rpm -q "$1" >/dev/null 2>&1; then
        # Checked first: `rpm -q` reports a missing package on stdout, and a
        # pipe would hide its exit status.
        rpm -q --qf '%{EPOCH}:%{VERSION}\n' "$1" | sed 's/^(none)://'
    else
        echo absent
    fi
}

# Run a package transaction; its output goes to a log, its status is returned.
txn() {
    local log="/tmp/txn.$RANDOM.log"
    if [ "$KIND" = deb ]; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades "$@" >"$log" 2>&1
    else
        dnf install -y --setopt=tsflags=noscripts "$@" >"$log" 2>&1
    fi
    local rc=$?
    LAST_LOG="$log"
    return $rc
}

# The files of one package kind in a directory.
pkg() { # pkg <dir> <openwatch|kensa-rules>
    if [ "$KIND" = deb ]; then
        ls "$1"/"$2"_*.deb
    else
        ls "$1"/"$2"-*.rpm
    fi
}

OLD_OW="$(pkg "$OLD" openwatch)"
OLD_KR="$(pkg "$OLD" kensa-rules)"
NEW_OW="$(pkg "$NEW" openwatch)"
NEW_KR="$(pkg "$NEW" kensa-rules)"

if [ "$KIND" = deb ]; then
    apt-get update -qq >/dev/null 2>&1 || { echo "apt-get update failed" >&2; exit 2; }
fi

reset_to_old() {
    if [ "$KIND" = deb ]; then
        dpkg --purge kensa-rules openwatch >/dev/null 2>&1
    else
        rpm -e --nodeps --noscripts kensa-rules openwatch >/dev/null 2>&1
    fi
    txn "$OLD_OW" "$OLD_KR" || { echo "could not install the old pair; log follows" >&2; cat "$LAST_LOG" >&2; exit 2; }
}

echo "### 1. rules-only upgrade beside the older openwatch is refused"
reset_to_old
before_kr="$(installed kensa-rules)"
if txn "$NEW_KR"; then
    fail "the package manager installed $(basename "$NEW_KR") beside openwatch $(installed openwatch)"
else
    pass "refused: $(grep -m1 -iE 'openwatch-kensa-engine' "$LAST_LOG" | sed 's/^ *//')"
fi
[ "$(installed kensa-rules)" = "$before_kr" ] &&
    pass "the installed corpus is unchanged ($before_kr)" ||
    fail "the installed corpus changed from $before_kr to $(installed kensa-rules)"
if [ "$KIND" = rpm ]; then
    # The plain rpm path checks dependencies too; --nodeps is the only bypass.
    if rpm -U --noscripts "$NEW_KR" >/tmp/rpmU.log 2>&1; then
        fail "rpm -U installed the new corpus beside the older openwatch"
        rpm -U --oldpackage --nodeps --noscripts "$OLD_KR" >/dev/null 2>&1
    else
        pass "rpm -U refused: $(grep -m1 openwatch-kensa-engine /tmp/rpmU.log | sed 's/^[[:space:]]*//')"
    fi
fi

echo "### 2. openwatch-only upgrade over the older corpus succeeds"
reset_to_old
if txn "$NEW_OW"; then
    pass "openwatch $(installed openwatch) installed beside kensa-rules $(installed kensa-rules)"
else
    fail "openwatch-only upgrade failed; log follows"; cat "$LAST_LOG"
fi

echo "### 3. coordinated upgrade succeeds"
reset_to_old
if txn "$NEW_OW" "$NEW_KR"; then
    pass "upgraded to openwatch $(installed openwatch) and kensa-rules $(installed kensa-rules)"
else
    fail "coordinated upgrade failed; log follows"; cat "$LAST_LOG"
fi

echo "### 5. the new corpus refuses a downgraded openwatch"
if txn "$OLD_OW"; then
    fail "openwatch downgraded to $(installed openwatch) beside kensa-rules $(installed kensa-rules)"
else
    pass "refused while kensa-rules $(installed kensa-rules) is installed"
fi

echo "### 4. fresh install of the new pair succeeds"
if [ "$KIND" = deb ]; then
    dpkg --purge kensa-rules openwatch >/dev/null 2>&1
else
    rpm -e --nodeps --noscripts kensa-rules openwatch >/dev/null 2>&1
fi
[ "$(installed openwatch)" = absent ] || fail "cleanup left openwatch installed"
if txn "$NEW_OW" "$NEW_KR"; then
    pass "fresh install: openwatch $(installed openwatch), kensa-rules $(installed kensa-rules)"
else
    fail "fresh install failed; log follows"; cat "$LAST_LOG"
fi

echo "### 6. release-candidate ordering"
older_than() { # older_than A B: true when A sorts strictly before B
    if [ "$KIND" = deb ]; then
        dpkg --compare-versions "$1" lt "$2"
    else
        [ "$(rpm --eval "%{lua: print(rpm.vercmp('$1', '$2'))}")" = "-1" ]
    fi
}
for pair in "1:0.8.0~rc.5 1:0.8.0~rc.6" "1:0.8.0~rc.6 1:0.8.0~rc.10" "1:0.8.0~rc.10 1:0.8.0" \
            "1:0.7.1 1:0.8.0~rc.5" "0.9.0 0.10.0"; do
    set -- $pair
    older_than "$1" "$2" && pass "$1 < $2" || fail "$1 does not sort before $2"
done

echo
if [ "$FAILURES" -eq 0 ]; then
    echo "kensa-rules compat ($KIND): all checks passed"
    exit 0
fi
echo "kensa-rules compat ($KIND): $FAILURES check(s) failed"
exit 1
