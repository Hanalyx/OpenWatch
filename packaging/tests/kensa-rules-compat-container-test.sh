#!/usr/bin/env bash
# kensa-rules-compat-container-test.sh: runs INSIDE a disposable container.
#
# Proves the package manager enforces the engine/corpus pairing on real
# installs (spec release-upgrade C-06; the criteria run in Go CI, this runs
# the same scenarios for real in package-smoke). An engine older than its
# corpus cannot load it, and OpenWatch starts anyway with every scan
# failing, so:
#
#   1. a rules-only upgrade beside an older openwatch is REFUSED, and the
#      installed corpus is unchanged afterwards;
#   2. an openwatch-only upgrade over the older corpus succeeds (a newer
#      engine loads an older corpus);
#   3. the coordinated upgrade, both packages in one transaction, succeeds:
#      through the package manager, and on RPM also through `dnf upgrade`
#      and a joint `rpm -Uvh`;
#   4. a fresh install of the new pair succeeds;
#   5. the new corpus refuses a downgraded openwatch, and rolling both
#      packages back together succeeds;
#   6. release-candidate versions order correctly: rc.5 < rc.6 < rc.10 < GA,
#      with the epoch both package formats carry;
#   7. DEB only: a bare `dpkg -i` of the corpus is refused before it replaces
#      any file (the preinst guard), `dpkg -i` of both succeeds with openwatch
#      listed first, and with the corpus listed first it is refused leaving a
#      compatible pair;
#   8. single-package upgrades in both orders: openwatch then kensa-rules
#      succeeds step by step, and kensa-rules first is refused, after which
#      openwatch then kensa-rules succeeds.
#
# After every step the test checks two things separately, because either can
# be wrong while the other looks right:
#
#   - package-manager state: each package's recorded version, that it is
#     fully installed (dpkg `ii` and an empty `dpkg --audit`; `rpm -V` of the
#     corpus package), and nothing half-installed;
#   - corpus contents: a digest of every file under /usr/share/kensa/rules,
#     compared with the digest of the payload of the kensa-rules package that
#     should be installed. A failed `dpkg -i` can leave the recorded version
#     looking unchanged while the files are already replaced.
#
# Usage: kensa-rules-compat-container-test.sh <rpm|deb> <old-dir> <new-dir>
#   old-dir: an openwatch release that predates the engine provide, and its
#            kensa-rules (package-smoke passes the previous GA).
#   new-dir: openwatch and kensa-rules built from this tree.
#
# Scriptlets run on both formats. The openwatch scriptlets tolerate a
# container without systemd or a database: the upgrade scriptlet skips its
# migration when `openwatch migrate --status` cannot connect.

set -uo pipefail

KIND="${1:?usage: $0 <rpm|deb> <old-dir> <new-dir>}"
OLD="${2:?old-dir}"
NEW="${3:?new-dir}"

FAILURES=0
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; FAILURES=$((FAILURES + 1)); }

# Installed version of a package, or "absent". Only a fully installed
# package counts; check_state reports any other state separately.
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

# Version a package file carries, in the form installed() prints.
file_version() {
    if [ "$KIND" = deb ]; then
        dpkg-deb -f "$1" Version
    else
        rpm -qp --qf '%{EPOCH}:%{VERSION}\n' "$1" 2>/dev/null | sed 's/^(none)://'
    fi
}

# Run a package transaction; its output goes to a log, its status is returned.
txn() {
    local log="/tmp/txn.$RANDOM.log"
    if [ "$KIND" = deb ]; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades "$@" >"$log" 2>&1
    else
        dnf install -y "$@" >"$log" 2>&1
    fi
    local rc=$?
    LAST_LOG="$log"
    return $rc
}

# Digest of every file under a rules directory, by path relative to it, so a
# live corpus and an extracted payload compare directly.
tree_digest() {
    [ -d "$1" ] || { echo none; return; }
    (cd "$1" && find . -type f -print0 | sort -z | xargs -0 sha256sum) | sha256sum | cut -c1-16
}
corpus_digest() { tree_digest /usr/share/kensa/rules; }

# Digest of the corpus a kensa-rules package file would install.
payload_digest() {
    local dir
    dir="$(mktemp -d)"
    if [ "$KIND" = deb ]; then
        dpkg-deb -x "$1" "$dir"
    else
        (cd "$dir" && rpm2cpio "$1" | cpio -idm --quiet)
    fi
    tree_digest "$dir/usr/share/kensa/rules"
    rm -rf "$dir"
}

# The files of one package kind in a directory.
pkg() { # pkg <dir> <openwatch|kensa-rules>
    if [ "$KIND" = deb ]; then
        ls "$1"/"$2"_*.deb
    else
        ls "$1"/"$2"-*.rpm
    fi
}

if [ "$KIND" = deb ]; then
    apt-get update -qq >/dev/null 2>&1 || { echo "apt-get update failed" >&2; exit 2; }
else
    # rpm2cpio ships with rpm; cpio does not in every image.
    dnf install -y cpio >/dev/null 2>&1 || { echo "could not install cpio" >&2; exit 2; }
fi

OLD_OW="$(pkg "$OLD" openwatch)"
OLD_KR="$(pkg "$OLD" kensa-rules)"
NEW_OW="$(pkg "$NEW" openwatch)"
NEW_KR="$(pkg "$NEW" kensa-rules)"
V_OLD_OW="$(file_version "$OLD_OW")"
V_OLD_KR="$(file_version "$OLD_KR")"
V_NEW_OW="$(file_version "$NEW_OW")"
V_NEW_KR="$(file_version "$NEW_KR")"
D_OLD="$(payload_digest "$OLD_KR")"
D_NEW="$(payload_digest "$NEW_KR")"
echo "old pair: openwatch $V_OLD_OW, kensa-rules $V_OLD_KR (corpus $D_OLD)"
echo "new pair: openwatch $V_NEW_OW, kensa-rules $V_NEW_KR (corpus $D_NEW)"
[ "$D_OLD" != "$D_NEW" ] || { echo "old and new corpora are identical; the test would prove nothing" >&2; exit 2; }

# check_state <label> <openwatch version> <kensa-rules version> <old|new>
# Checks package-manager state and corpus contents as separate facts.
check_state() {
    local label="$1" want_ow="$2" want_kr="$3" want_corpus="$4" ok=1
    local got_ow got_kr expect_digest got_digest
    got_ow="$(installed openwatch)"
    got_kr="$(installed kensa-rules)"
    if [ "$got_ow" = "$want_ow" ] && [ "$got_kr" = "$want_kr" ]; then
        :
    else
        fail "$label: package manager records openwatch $got_ow and kensa-rules $got_kr, want $want_ow and $want_kr"
        ok=0
    fi
    if [ "$KIND" = deb ]; then
        local audit
        audit="$(dpkg --audit 2>&1)"
        if [ -n "$audit" ]; then
            fail "$label: dpkg --audit reports a package not fully installed: $audit"
            ok=0
        fi
    elif [ "$got_kr" != absent ] && ! rpm -V kensa-rules >/tmp/rpmV.log 2>&1; then
        fail "$label: rpm -V kensa-rules reports files that differ from the rpm database: $(head -3 /tmp/rpmV.log)"
        ok=0
    fi
    [ "$want_corpus" = new ] && expect_digest="$D_NEW" || expect_digest="$D_OLD"
    got_digest="$(corpus_digest)"
    if [ "$got_digest" != "$expect_digest" ]; then
        fail "$label: corpus files on disk are $got_digest, want the $want_corpus payload $expect_digest"
        ok=0
    fi
    [ "$ok" = 1 ] && pass "$label: package manager openwatch $got_ow, kensa-rules $got_kr, fully installed; corpus files match the $want_corpus payload"
}

reset_to_old() {
    if [ "$KIND" = deb ]; then
        dpkg --purge kensa-rules openwatch >/dev/null 2>&1
    else
        rpm -e --nodeps --noscripts kensa-rules openwatch >/dev/null 2>&1
    fi
    rm -rf /usr/share/kensa/rules
    txn "$OLD_OW" "$OLD_KR" || { echo "could not install the old pair; log follows" >&2; cat "$LAST_LOG" >&2; exit 2; }
}

echo "### 1. rules-only upgrade beside the older openwatch is refused"
reset_to_old
check_state "old pair installed" "$V_OLD_OW" "$V_OLD_KR" old
if txn "$NEW_KR"; then
    fail "the package manager installed $(basename "$NEW_KR") beside openwatch $(installed openwatch)"
else
    pass "refused: $(grep -m1 -iE 'openwatch-kensa-engine|needs openwatch' "$LAST_LOG" | sed 's/^ *//')"
fi
check_state "after the refused rules-only upgrade" "$V_OLD_OW" "$V_OLD_KR" old
if [ "$KIND" = rpm ]; then
    # The plain rpm path checks dependencies too; --nodeps is the only bypass.
    if rpm -U "$NEW_KR" >/tmp/rpmU.log 2>&1; then
        fail "rpm -U installed the new corpus beside the older openwatch"
    else
        pass "rpm -U refused: $(grep -m1 openwatch-kensa-engine /tmp/rpmU.log | sed 's/^[[:space:]]*//')"
    fi
    check_state "after the refused rpm -U" "$V_OLD_OW" "$V_OLD_KR" old
fi

echo "### 2. openwatch-only upgrade over the older corpus succeeds"
reset_to_old
if txn "$NEW_OW"; then
    pass "openwatch-only upgrade accepted"
else
    fail "openwatch-only upgrade failed; log follows"; cat "$LAST_LOG"
fi
check_state "after the openwatch-only upgrade" "$V_NEW_OW" "$V_OLD_KR" old

echo "### 3. coordinated upgrade succeeds"
reset_to_old
if txn "$NEW_OW" "$NEW_KR"; then
    pass "coordinated upgrade accepted"
else
    fail "coordinated upgrade failed; log follows"; cat "$LAST_LOG"
fi
check_state "after the coordinated upgrade" "$V_NEW_OW" "$V_NEW_KR" new
# Scriptlets ran: the openwatch pre-install creates the service user, and the
# post-install provisions the identity keys.
if getent passwd openwatch >/dev/null && [ -n "$(ls -A /etc/openwatch/keys 2>/dev/null)" ]; then
    pass "scriptlets ran: the openwatch user exists and identity keys are provisioned"
else
    fail "scriptlets did not run: no openwatch user or no identity keys"
fi

if [ "$KIND" = rpm ]; then
    echo "### 3b. dnf upgrade of both packages succeeds"
    reset_to_old
    if dnf upgrade -y "$NEW_OW" "$NEW_KR" >/tmp/dnfup.log 2>&1; then
        pass "dnf upgrade accepted"
    else
        fail "dnf upgrade failed; log follows"; cat /tmp/dnfup.log
    fi
    check_state "after dnf upgrade" "$V_NEW_OW" "$V_NEW_KR" new

    echo "### 3c. a joint rpm -Uvh of both packages succeeds"
    reset_to_old
    if rpm -Uvh "$NEW_OW" "$NEW_KR" >/tmp/rpmUvh.log 2>&1; then
        pass "joint rpm -Uvh accepted"
    else
        fail "joint rpm -Uvh failed; log follows"; cat /tmp/rpmUvh.log
    fi
    check_state "after the joint rpm -Uvh" "$V_NEW_OW" "$V_NEW_KR" new
fi

echo "### 5. the new corpus refuses a downgraded openwatch; both roll back together"
if txn "$OLD_OW"; then
    fail "openwatch downgraded to $(installed openwatch) beside kensa-rules $(installed kensa-rules)"
else
    pass "downgrade of openwatch alone refused"
fi
check_state "after the refused downgrade" "$V_NEW_OW" "$V_NEW_KR" new
if txn "$OLD_OW" "$OLD_KR"; then
    pass "joint rollback accepted"
else
    fail "rolling both packages back failed; log follows"; cat "$LAST_LOG"
fi
check_state "after the joint rollback" "$V_OLD_OW" "$V_OLD_KR" old

echo "### 8. single-package upgrades in both orders"
reset_to_old
if txn "$NEW_OW"; then pass "openwatch first: accepted"; else fail "openwatch first failed"; cat "$LAST_LOG"; fi
check_state "openwatch first, before kensa-rules" "$V_NEW_OW" "$V_OLD_KR" old
if txn "$NEW_KR"; then pass "then kensa-rules: accepted"; else fail "then kensa-rules failed"; cat "$LAST_LOG"; fi
check_state "openwatch first, then kensa-rules" "$V_NEW_OW" "$V_NEW_KR" new

reset_to_old
if txn "$NEW_KR"; then fail "kensa-rules first was accepted beside the older openwatch"; else pass "kensa-rules first: refused"; fi
check_state "kensa-rules first, refused" "$V_OLD_OW" "$V_OLD_KR" old
if txn "$NEW_OW"; then pass "then openwatch: accepted"; else fail "then openwatch failed"; cat "$LAST_LOG"; fi
check_state "kensa-rules refused, then openwatch" "$V_NEW_OW" "$V_OLD_KR" old
if txn "$NEW_KR"; then pass "then kensa-rules again: accepted"; else fail "then kensa-rules again failed"; cat "$LAST_LOG"; fi
check_state "kensa-rules refused, then openwatch, then kensa-rules" "$V_NEW_OW" "$V_NEW_KR" new

if [ "$KIND" = rpm ]; then
    reset_to_old
    if rpm -U "$NEW_OW" >/tmp/rpmU1.log 2>&1; then pass "rpm -U openwatch first: accepted"; else fail "rpm -U openwatch first failed"; cat /tmp/rpmU1.log; fi
    check_state "rpm -U openwatch first" "$V_NEW_OW" "$V_OLD_KR" old
    if rpm -U "$NEW_KR" >/tmp/rpmU2.log 2>&1; then pass "then rpm -U kensa-rules: accepted"; else fail "then rpm -U kensa-rules failed"; cat /tmp/rpmU2.log; fi
    check_state "rpm -U openwatch, then kensa-rules" "$V_NEW_OW" "$V_NEW_KR" new
fi

echo "### 4. fresh install of the new pair succeeds"
if [ "$KIND" = deb ]; then
    dpkg --purge kensa-rules openwatch >/dev/null 2>&1
else
    rpm -e --nodeps --noscripts kensa-rules openwatch >/dev/null 2>&1
fi
rm -rf /usr/share/kensa/rules
[ "$(installed openwatch)" = absent ] || fail "cleanup left openwatch installed"
if txn "$NEW_OW" "$NEW_KR"; then
    pass "fresh install accepted"
else
    fail "fresh install failed; log follows"; cat "$LAST_LOG"
fi
check_state "after the fresh install" "$V_NEW_OW" "$V_NEW_KR" new

if [ "$KIND" = deb ]; then
    echo "### 7. dpkg -i: the corpus is never replaced beside an older engine"
    reset_to_old
    if dpkg -i "$NEW_KR" >/tmp/dpkg.log 2>&1; then
        fail "dpkg -i installed the corpus beside openwatch $(installed openwatch)"
    else
        pass "dpkg -i refused: $(grep -m1 'needs openwatch' /tmp/dpkg.log)"
    fi
    check_state "after the refused dpkg -i of the corpus" "$V_OLD_OW" "$V_OLD_KR" old

    reset_to_old
    if dpkg -i "$NEW_OW" "$NEW_KR" >/tmp/dpkg.log 2>&1; then
        pass "dpkg -i with openwatch first: accepted"
    else
        fail "dpkg -i with openwatch first failed"; cat /tmp/dpkg.log
    fi
    check_state "after dpkg -i with openwatch first" "$V_NEW_OW" "$V_NEW_KR" new

    reset_to_old
    if dpkg -i "$NEW_KR" "$NEW_OW" >/tmp/dpkg.log 2>&1; then
        pass "dpkg -i with the corpus first: accepted"
        check_state "after dpkg -i with the corpus first" "$V_NEW_OW" "$V_NEW_KR" new
    else
        # Refused before unpack; openwatch still upgrades, so the pair left
        # behind is the compatible one (new engine, old corpus).
        pass "dpkg -i with the corpus first: corpus refused"
        check_state "after dpkg -i with the corpus first" "$V_NEW_OW" "$V_OLD_KR" old
    fi
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
