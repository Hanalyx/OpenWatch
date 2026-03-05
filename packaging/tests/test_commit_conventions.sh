#!/bin/bash
# Test: Commit Conventions Validation
# Spec: specs/release/commit-conventions.spec.yaml
#
# Validates that:
#   1. The commit-msg-lint hook script exists and is valid bash
#   2. The check-commit-message.py script exists and works
#   3. Banned terms are correctly rejected
#   4. Valid messages are accepted
#   5. .commitlintrc.json has the expected type list

set -euo pipefail

PASS=0
FAIL=0
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

pass() { PASS=$((PASS + 1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL: $1"; }

echo "=== Commit Conventions Tests ==="
echo ""

# --- Structural checks ---

echo "--- Structural checks ---"

# 1. Spec file exists
if [ -f "$REPO_ROOT/specs/release/commit-conventions.spec.yaml" ]; then
    pass "commit-conventions.spec.yaml exists"
else
    fail "commit-conventions.spec.yaml missing"
fi

# 2. check-commit-message.py exists
if [ -f "$REPO_ROOT/scripts/check-commit-message.py" ]; then
    pass "check-commit-message.py exists"
else
    fail "check-commit-message.py missing"
fi

# 3. .commitlintrc.json exists and has expected types
if [ -f "$REPO_ROOT/.commitlintrc.json" ]; then
    pass ".commitlintrc.json exists"
else
    fail ".commitlintrc.json missing"
fi

EXPECTED_TYPES=("feat" "fix" "docs" "style" "refactor" "perf" "test" "build" "ci" "chore" "revert")
for t in "${EXPECTED_TYPES[@]}"; do
    if grep -q "\"$t\"" "$REPO_ROOT/.commitlintrc.json"; then
        pass "commitlint type '$t' configured"
    else
        fail "commitlint type '$t' missing from .commitlintrc.json"
    fi
done

echo ""
echo "--- Banned term rejection ---"

# 4. check-commit-message.py rejects banned terms
BANNED_MESSAGES=(
    "feat: SDD Phase 0 — governance and validation"
    "fix: step 3 of migration plan"
    "chore: sprint 4 cleanup"
    "feat: complete milestone 2 deliverables"
    "docs: backlog item B-7 documentation"
    "feat: epic 3 implementation"
    "chore: iteration 5 release prep"
    "fix: stage 2 bug fixes"
    "feat: add task tracking"
    "docs: story 42 acceptance criteria"
    "ci: ticket 123 pipeline fix"
)

for msg in "${BANNED_MESSAGES[@]}"; do
    if python3 "$REPO_ROOT/scripts/check-commit-message.py" -m "$msg" > /dev/null 2>&1; then
        fail "should reject: $msg"
    else
        pass "rejects: $msg"
    fi
done

echo ""
echo "--- Valid message acceptance ---"

# 5. check-commit-message.py accepts valid messages
VALID_MESSAGES=(
    "feat: add spec governance rules and JSON Schema validation"
    "fix: correct temporal query resolution for missing snapshots"
    "chore: remove deprecated MongoDB connection pooling"
    "feat(auth): add RBAC authorization matrix with role-route validation"
    "docs: add operator quickstart guide with SSH setup instructions"
    "refactor(scan): extract SSH executor into dedicated module"
    "test: add regression tests for drift classification"
    "build(packaging): update RPM spec to use version.env macros"
    "ci: add spec validation to CI pipeline"
    "perf(compliance): optimize posture query with materialized view"
)

for msg in "${VALID_MESSAGES[@]}"; do
    if python3 "$REPO_ROOT/scripts/check-commit-message.py" -m "$msg" > /dev/null 2>&1; then
        pass "accepts: $msg"
    else
        fail "should accept: $msg"
    fi
done

echo ""
echo "--- Format rejection ---"

# 6. check-commit-message.py rejects bad format
BAD_FORMAT_MESSAGES=(
    "Added new feature"
    "FEAT: uppercase type"
    "no type here"
    ""
)

for msg in "${BAD_FORMAT_MESSAGES[@]}"; do
    if python3 "$REPO_ROOT/scripts/check-commit-message.py" -m "$msg" > /dev/null 2>&1; then
        fail "should reject bad format: '$msg'"
    else
        pass "rejects bad format: '${msg:-<empty>}'"
    fi
done

echo ""
echo "==========================="
echo "Results: $PASS passed, $FAIL failed"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
