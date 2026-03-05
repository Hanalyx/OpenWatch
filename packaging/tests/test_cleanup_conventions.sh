#!/bin/bash
# Test: Cleanup Operations Spec Validation
# Spec: specs/release/cleanup-operations.spec.yaml
#
# Validates that:
#   1. The cleanup spec exists and has required structure
#   2. Existing cleanup scripts follow the conventions
#   3. Tier classification, dry-run, and constraint sections are defined
#   4. Acceptance criteria are present

set -euo pipefail

PASS=0
FAIL=0
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

pass() { PASS=$((PASS + 1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL: $1"; }

echo "=== Cleanup Operations Spec Tests ==="
echo ""

# --- Structural checks ---

echo "--- Spec structure ---"

SPEC_FILE="$REPO_ROOT/specs/release/cleanup-operations.spec.yaml"

# 1. Spec file exists
if [ -f "$SPEC_FILE" ]; then
    pass "cleanup-operations.spec.yaml exists"
else
    fail "cleanup-operations.spec.yaml missing"
fi

# 2. Status is active
if grep -q "^status: active" "$SPEC_FILE"; then
    pass "spec status is active"
else
    fail "spec status is not active"
fi

# 3. Has classification section with all 4 tiers
for tier in "cosmetic" "removal" "structural" "destructive"; do
    if grep -q "name: $tier" "$SPEC_FILE"; then
        pass "tier '$tier' defined"
    else
        fail "tier '$tier' missing from classification"
    fi
done

# 4. Has dry-run section
if grep -q "^dry_run:" "$SPEC_FILE"; then
    pass "dry_run section exists"
else
    fail "dry_run section missing"
fi

# 5. Has constraints section
if grep -q "^constraints:" "$SPEC_FILE"; then
    pass "constraints section exists"
else
    fail "constraints section missing"
fi

# 6. Has staged cleanup process
if grep -q "^staged_cleanup:" "$SPEC_FILE"; then
    pass "staged_cleanup section exists"
else
    fail "staged_cleanup section missing"
fi

# 7. Has acceptance criteria
if grep -q "^acceptance_criteria:" "$SPEC_FILE"; then
    pass "acceptance_criteria section exists"
else
    fail "acceptance_criteria section missing"
fi

# 8. Has all 10 ACs
for n in $(seq 1 10); do
    if grep -q "id: AC-$n$" "$SPEC_FILE"; then
        pass "AC-$n defined"
    else
        fail "AC-$n missing"
    fi
done

echo ""
echo "--- Constraint categories ---"

# 9. Has constraint categories for all cleanup types
for category in "general" "code_removal" "dependency_removal" "database_cleanup" "documentation_cleanup" "deprecation"; do
    if grep -q "$category:" "$SPEC_FILE"; then
        pass "constraint category '$category' defined"
    else
        fail "constraint category '$category' missing"
    fi
done

echo ""
echo "--- Existing cleanup scripts follow conventions ---"

# 10. Existing cleanup scripts have dry-run support
if [ -f "$REPO_ROOT/scripts/cleanup-documentation.sh" ]; then
    if grep -q "dry.run\|dry_run\|DRY_RUN" "$REPO_ROOT/scripts/cleanup-documentation.sh"; then
        pass "cleanup-documentation.sh has dry-run support"
    else
        fail "cleanup-documentation.sh missing dry-run support"
    fi
else
    pass "cleanup-documentation.sh not present (skip)"
fi

if [ -f "$REPO_ROOT/packaging/rpm/scripts/cleanup-openwatch.sh" ]; then
    if grep -q "dry.run\|dry_run\|DRY_RUN" "$REPO_ROOT/packaging/rpm/scripts/cleanup-openwatch.sh"; then
        pass "cleanup-openwatch.sh has dry-run support"
    else
        fail "cleanup-openwatch.sh missing dry-run support"
    fi
else
    pass "cleanup-openwatch.sh not present (skip)"
fi

# 11. Registry lists this spec
if grep -q "cleanup-operations.spec.yaml" "$REPO_ROOT/specs/SPEC_REGISTRY.md"; then
    pass "cleanup spec listed in SPEC_REGISTRY.md"
else
    fail "cleanup spec missing from SPEC_REGISTRY.md"
fi

echo ""
echo "==========================="
echo "Results: $PASS passed, $FAIL failed"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
