#!/bin/bash
# Version Consistency Test
# Spec: specs/release/changelog.spec.yaml
# Verifies that all version-bearing files agree with packaging/version.env

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

# Source the single source of truth
source "$PROJECT_ROOT/packaging/version.env"

echo "Version consistency check"
echo "========================="
echo "Reference: VERSION=$VERSION  CODENAME=$CODENAME"
echo ""

# -----------------------------------------------------------------------
# 1. RPM spec: must use macro placeholders, not hardcoded version
# -----------------------------------------------------------------------
echo "[1] RPM spec files use macro-based version (no hardcoded value)..."

for spec in "$PROJECT_ROOT/packaging/rpm/openwatch.spec" \
            "$PROJECT_ROOT/packaging/rpm/openwatch-po.spec"; do
    name="$(basename "$spec")"

    if grep -qE '^Version:[[:space:]]+%\{ow_version\}' "$spec"; then
        pass "$name Version: uses %{ow_version} macro"
    else
        fail "$name Version: does not use %{ow_version} macro"
    fi

    if grep -qE '^Release:[[:space:]]+%\{ow_release\}' "$spec"; then
        pass "$name Release: uses %{ow_release} macro"
    else
        fail "$name Release: does not use %{ow_release} macro"
    fi

    if grep -q '%{!?ow_version:' "$spec"; then
        pass "$name defines ow_version default macro"
    else
        fail "$name missing ow_version default macro"
    fi
done

# -----------------------------------------------------------------------
# 2. pyproject.toml: PEP 440 form of VERSION
# -----------------------------------------------------------------------
echo ""
echo "[2] pyproject.toml version..."

# Normalise: "0.0.0-dev" -> "0.0.0.dev0"  (simple heuristic)
if [[ "$VERSION" == *"-"* ]]; then
    pre="${VERSION#*-}"
    base="${VERSION%-*}"
    pep440="${base}.${pre}0"
else
    pep440="$VERSION"
fi

actual_pyproject=$(grep -E '^version = ' "$PROJECT_ROOT/pyproject.toml" | sed 's/version = "\(.*\)"/\1/')
if [[ "$actual_pyproject" == "$pep440" ]]; then
    pass "pyproject.toml version=$actual_pyproject matches $pep440"
else
    fail "pyproject.toml version=$actual_pyproject expected $pep440"
fi

# -----------------------------------------------------------------------
# 3. frontend/package.json
# -----------------------------------------------------------------------
echo ""
echo "[3] frontend/package.json version..."

actual_npm=$(grep '"version"' "$PROJECT_ROOT/frontend/package.json" | head -1 | sed 's/.*"version": "\(.*\)".*/\1/')
if [[ "$actual_npm" == "$VERSION" ]]; then
    pass "package.json version=$actual_npm"
else
    fail "package.json version=$actual_npm expected $VERSION"
fi

# -----------------------------------------------------------------------
# 4. owadm root.go: Codename default is non-empty (ldflags override at build time)
# -----------------------------------------------------------------------
echo ""
echo "[4] internal/owadm/cmd/root.go Codename var..."

if grep -q 'Codename  = "' "$PROJECT_ROOT/internal/owadm/cmd/root.go"; then
    default_codename=$(grep 'Codename  = "' "$PROJECT_ROOT/internal/owadm/cmd/root.go" | sed 's/.*"\(.*\)".*/\1/')
    if [[ -n "$default_codename" ]]; then
        pass "root.go Codename default=\"$default_codename\" (non-empty)"
    else
        fail "root.go Codename default is empty"
    fi
else
    fail "root.go does not declare Codename variable"
fi

# -----------------------------------------------------------------------
# 5. owadm root.go: Version default is "dev" (set by ldflags at build time)
# -----------------------------------------------------------------------
echo ""
echo "[5] internal/owadm/cmd/root.go Version default is 'dev'..."

if grep -qE 'Version\s+= "dev"' "$PROJECT_ROOT/internal/owadm/cmd/root.go"; then
    pass "root.go Version default is \"dev\" (set by ldflags at build time)"
else
    fail "root.go Version default is not \"dev\""
fi

# -----------------------------------------------------------------------
# 6. DEB DEBIAN/control: placeholder version is 0.0.0 (injected at build time)
# -----------------------------------------------------------------------
echo ""
echo "[6] packaging/deb/DEBIAN/control has placeholder 0.0.0..."

control_ver=$(grep '^Version:' "$PROJECT_ROOT/packaging/deb/DEBIAN/control" | awk '{print $2}')
if [[ "$control_ver" == "0.0.0" ]]; then
    pass "DEBIAN/control Version=$control_ver (placeholder, injected at build time)"
else
    fail "DEBIAN/control Version=$control_ver expected 0.0.0 placeholder"
fi

# -----------------------------------------------------------------------
# 7. CHANGELOG.md: must exist, have [Unreleased], and have entry for VERSION
# -----------------------------------------------------------------------
echo ""
echo "[7] CHANGELOG.md changelog entries (per specs/release/changelog.spec.yaml)..."

changelog="$PROJECT_ROOT/CHANGELOG.md"

if [[ ! -f "$changelog" ]]; then
    fail "CHANGELOG.md does not exist"
elif [[ ! -s "$changelog" ]]; then
    fail "CHANGELOG.md is empty"
else
    pass "CHANGELOG.md exists and is non-empty"
fi

if grep -q "## \[Unreleased\]" "$changelog"; then
    pass "CHANGELOG.md contains [Unreleased] section"
else
    fail "CHANGELOG.md missing [Unreleased] section (required by changelog.spec.yaml)"
fi

if grep -q "## \[$VERSION\]" "$changelog"; then
    pass "CHANGELOG.md has entry for current version [$VERSION]"
else
    fail "CHANGELOG.md has no entry for [$VERSION] — update CHANGELOG.md when bumping version.env"
fi

# -----------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------
echo ""
echo "========================="
echo "Results: $PASS passed, $FAIL failed"

if [[ $FAIL -gt 0 ]]; then
    exit 1
fi
