#!/bin/bash
# Package Build Infrastructure Test
# Spec: specs/release/package-build.spec.yaml
# Validates that RPM/DEB build scripts, specs, and CI workflow are correctly
# configured. No actual package builds are performed.
#
# Mirrors checks defined in specs/release/package-build.spec.yaml

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

PASS=0
FAIL=0

pass() {
    echo "  PASS: $1"
    PASS=$((PASS + 1))
}

fail() {
    echo "  FAIL: $1"
    FAIL=$((FAIL + 1))
}

echo "Package build infrastructure check"
echo "==================================="
echo ""

# -----------------------------------------------------------------------
# 1. Build script existence and executability
# -----------------------------------------------------------------------
echo "[1] Build scripts exist and are executable..."

for script in "$PROJECT_ROOT/packaging/rpm/build-rpm.sh" \
              "$PROJECT_ROOT/packaging/deb/build-deb.sh"; do
    name="$(basename "$script")"
    if [[ -f "$script" ]]; then
        if [[ -x "$script" ]]; then
            pass "$name exists and is executable"
        else
            fail "$name exists but is not executable"
        fi
    else
        fail "$name does not exist"
    fi
done

# -----------------------------------------------------------------------
# 2. Both build scripts source version.env
# -----------------------------------------------------------------------
echo ""
echo "[2] Build scripts source version.env..."

for script in "$PROJECT_ROOT/packaging/rpm/build-rpm.sh" \
              "$PROJECT_ROOT/packaging/deb/build-deb.sh"; do
    name="$(basename "$script")"
    if grep -q 'source.*version\.env' "$script"; then
        pass "$name sources version.env"
    else
        fail "$name does not source version.env"
    fi
done

# -----------------------------------------------------------------------
# 3. RPM spec files use ow_version / ow_release macros
# -----------------------------------------------------------------------
echo ""
echo "[3] RPM spec files use version/release macros..."

for spec in "$PROJECT_ROOT/packaging/rpm/openwatch.spec" \
            "$PROJECT_ROOT/packaging/rpm/openwatch-po.spec"; do
    name="$(basename "$spec")"

    if grep -qE '^Version:[[:space:]]+%\{ow_version\}' "$spec"; then
        pass "$name uses %{ow_version} macro"
    else
        fail "$name does not use %{ow_version} macro"
    fi

    if grep -qE '^Release:[[:space:]]+%\{ow_release\}' "$spec"; then
        pass "$name uses %{ow_release} macro"
    else
        fail "$name does not use %{ow_release} macro"
    fi
done

# -----------------------------------------------------------------------
# 4. DEB control has placeholder Version: 0.0.0
# -----------------------------------------------------------------------
echo ""
echo "[4] DEBIAN/control has placeholder version..."

control="$PROJECT_ROOT/packaging/deb/DEBIAN/control"
control_ver=$(grep '^Version:' "$control" | awk '{print $2}')
if [[ "$control_ver" == "0.0.0" ]]; then
    pass "DEBIAN/control Version=$control_ver (placeholder)"
else
    fail "DEBIAN/control Version=$control_ver expected 0.0.0"
fi

# -----------------------------------------------------------------------
# 5. DEB maintainer scripts exist and are executable
# -----------------------------------------------------------------------
echo ""
echo "[5] DEB maintainer scripts exist and are executable..."

for script_name in postinst prerm postrm; do
    script="$PROJECT_ROOT/packaging/deb/DEBIAN/$script_name"
    if [[ -f "$script" ]]; then
        if [[ -x "$script" ]]; then
            pass "$script_name exists and is executable"
        else
            fail "$script_name exists but is not executable"
        fi
    else
        fail "$script_name does not exist"
    fi
done

# -----------------------------------------------------------------------
# 6. release.yml contains build-rpm and build-deb jobs
# -----------------------------------------------------------------------
echo ""
echo "[6] release.yml contains package build jobs..."

workflow="$PROJECT_ROOT/.github/workflows/release.yml"
if [[ ! -f "$workflow" ]]; then
    fail "release.yml does not exist"
else
    if grep -q 'build-rpm:' "$workflow"; then
        pass "release.yml contains build-rpm job"
    else
        fail "release.yml missing build-rpm job"
    fi

    if grep -q 'build-deb:' "$workflow"; then
        pass "release.yml contains build-deb job"
    else
        fail "release.yml missing build-deb job"
    fi
fi

# -----------------------------------------------------------------------
# 7. version.env has correct format
# -----------------------------------------------------------------------
echo ""
echo "[7] version.env format..."

version_env="$PROJECT_ROOT/packaging/version.env"
if grep -qE '^VERSION="' "$version_env"; then
    pass "version.env has quoted VERSION="
else
    fail "version.env missing quoted VERSION="
fi

if grep -qE '^CODENAME="' "$version_env"; then
    pass "version.env has quoted CODENAME="
else
    fail "version.env missing quoted CODENAME="
fi

# -----------------------------------------------------------------------
# 8. Bash syntax check on build scripts
# -----------------------------------------------------------------------
echo ""
echo "[8] Bash syntax check..."

for script in "$PROJECT_ROOT/packaging/rpm/build-rpm.sh" \
              "$PROJECT_ROOT/packaging/deb/build-deb.sh"; do
    name="$(basename "$script")"
    if bash -n "$script" 2>/dev/null; then
        pass "$name passes bash -n"
    else
        fail "$name has syntax errors"
    fi
done

# -----------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------
echo ""
echo "==================================="
echo "Results: $PASS passed, $FAIL failed"

if [[ $FAIL -gt 0 ]]; then
    exit 1
fi
