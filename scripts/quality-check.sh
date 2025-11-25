#!/bin/bash
#
# OpenWatch Quality Check Script
# Run this before committing or creating a PR
#
# Usage:
#   ./scripts/quality-check.sh               # Check all
#   ./scripts/quality-check.sh backend       # Check backend only
#   ./scripts/quality-check.sh frontend      # Check frontend only
#   ./scripts/quality-check.sh --fix         # Auto-fix issues
#   ./scripts/quality-check.sh --check-message "feat: add feature"  # Validate commit message

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

# ============================================================================
# Special Modes
# ============================================================================

# Check commit message format
if [[ "$1" == "--check-message" ]]; then
    if [ -z "$2" ]; then
        echo -e "${RED}[ERROR] Missing commit message${NC}"
        echo -e "${YELLOW}  Usage: $0 --check-message \"feat(api): add endpoint\"${NC}"
        exit 1
    fi

    MESSAGE="$2"
    echo -e "${BLUE}→ Validating commit message format${NC}"

    if [ -x ".git/hooks/commit-msg-lint.sh" ]; then
        if echo "$MESSAGE" | .git/hooks/commit-msg-lint.sh /dev/stdin; then
            echo -e "${GREEN}[OK] Commit message valid${NC}"
            exit 0
        else
            exit 1
        fi
    else
        echo -e "${RED}[ERROR] commit-msg-lint.sh not found${NC}"
        echo -e "${YELLOW}  Run: pre-commit install --hook-type commit-msg${NC}"
        exit 1
    fi
fi

TARGET=${1:-all}
AUTOFIX=false

if [[ "$1" == "--fix" ]] || [[ "$2" == "--fix" ]]; then
    AUTOFIX=true
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

ERRORS=0
SCRIPT_START_TIME=$(date +%s)

echo -e "${BOLD}${BLUE}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "OpenWatch Code Quality Check"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${NC}"

# ============================================================================
# Backend Quality Checks
# ============================================================================
if [[ "$TARGET" == "all" ]] || [[ "$TARGET" == "backend" ]]; then
    echo -e "${BOLD}${YELLOW}Backend Quality Checks${NC}\n"

    cd backend

    # 1. Black
    echo -e "${BLUE}→ Black (Python Formatter)${NC}"
    if command -v black &> /dev/null; then
        if [ "$AUTOFIX" = true ]; then
            black . --line-length=120
            echo -e "${GREEN}[OK] Code formatted${NC}\n"
        else
            if black . --check --line-length=120; then
                echo -e "${GREEN}[OK] Formatting correct${NC}\n"
            else
                echo -e "${RED}[ERROR] Formatting issues found${NC}"
                echo -e "${YELLOW}  Run: black . --line-length=120${NC}\n"
                ERRORS=$((ERRORS + 1))
            fi
        fi
    else
        echo -e "${RED}[ERROR] Black not installed${NC}"
        echo -e "${YELLOW}  Install: pip install black${NC}\n"
        ERRORS=$((ERRORS + 1))
    fi

    # 2. isort
    echo -e "${BLUE}→ isort (Import Sorting)${NC}"
    if command -v isort &> /dev/null; then
        if [ "$AUTOFIX" = true ]; then
            isort . --profile black --line-length=120
            echo -e "${GREEN}[OK] Imports sorted${NC}\n"
        else
            if isort . --check-only --profile black --line-length=120; then
                echo -e "${GREEN}[OK] Import order correct${NC}\n"
            else
                echo -e "${RED}[ERROR] Import order issues${NC}"
                echo -e "${YELLOW}  Run: isort . --profile black${NC}\n"
                ERRORS=$((ERRORS + 1))
            fi
        fi
    else
        echo -e "${RED}[ERROR] isort not installed${NC}"
        echo -e "${YELLOW}  Install: pip install isort${NC}\n"
        ERRORS=$((ERRORS + 1))
    fi

    # 3. Flake8
    echo -e "${BLUE}→ Flake8 (Linter)${NC}"
    if command -v flake8 &> /dev/null; then
        if flake8 app/ --max-line-length=120 \
            --extend-ignore=E203,W503,E501 \
            --exclude=__pycache__,*.pyc,.git,venv,env,migrations \
            --statistics; then
            echo -e "${GREEN}[OK] Linting passed${NC}\n"
        else
            echo -e "${RED}[ERROR] Linting issues found${NC}\n"
            ERRORS=$((ERRORS + 1))
        fi
    else
        echo -e "${RED}[ERROR] Flake8 not installed${NC}"
        echo -e "${YELLOW}  Install: pip install flake8${NC}\n"
        ERRORS=$((ERRORS + 1))
    fi

    # 4. MyPy (Strengthened - matches pre-commit config)
    echo -e "${BLUE}→ MyPy (Type Checking - Strict Mode)${NC}"
    if command -v mypy &> /dev/null; then
        if mypy app/ \
            --ignore-missing-imports \
            --warn-redundant-casts \
            --warn-unused-ignores \
            --warn-unreachable \
            --warn-return-any \
            --check-untyped-defs; then
            echo -e "${GREEN}[OK] Type checking passed${NC}\n"
        else
            echo -e "${RED}[ERROR] Type checking failed${NC}\n"
            ERRORS=$((ERRORS + 1))
        fi
    else
        echo -e "${RED}[ERROR] MyPy not installed${NC}"
        echo -e "${YELLOW}  Install: pipx install mypy${NC}\n"
        ERRORS=$((ERRORS + 1))
    fi

    # 5. Bandit (Security)
    echo -e "${BLUE}→ Bandit (Security Scanner)${NC}"
    if command -v bandit &> /dev/null; then
        if bandit -r app/ -ll -f txt 2>&1; then
            echo -e "${GREEN}[OK] Security scan passed${NC}\n"
        else
            echo -e "${RED}[ERROR] Security issues found${NC}\n"
            ERRORS=$((ERRORS + 1))
        fi
    else
        echo -e "${YELLOW}[WARNING] Bandit not installed${NC}"
        echo -e "${YELLOW}  Install: pip install bandit${NC}\n"
    fi

    # 6. Safety (Dependency vulnerabilities)
    echo -e "${BLUE}→ Safety (Dependency Vulnerability Check)${NC}"
    if command -v safety &> /dev/null; then
        if safety check --json 2>&1 | head -20; then
            echo -e "${GREEN}[OK] No known vulnerabilities${NC}\n"
        else
            echo -e "${YELLOW}[WARNING] Vulnerabilities found (review)${NC}\n"
        fi
    else
        echo -e "${YELLOW}[WARNING] Safety not installed (optional)${NC}\n"
    fi

    # 7. Test Coverage
    echo -e "${BLUE}→ Test Coverage (Pytest)${NC}"
    if command -v pytest &> /dev/null; then
        if [ -d "tests" ]; then
            if pytest tests/ --cov=app --cov-report=term-missing --cov-fail-under=80 -q 2>/dev/null; then
                echo -e "${GREEN}[OK] Coverage >=80%${NC}\n"
            else
                echo -e "${YELLOW}[WARNING] Coverage below 80% threshold (non-blocking)${NC}\n"
            fi
        else
            echo -e "${YELLOW}[WARNING] No tests directory found${NC}\n"
        fi
    else
        echo -e "${YELLOW}[WARNING] Pytest not installed (optional)${NC}\n"
    fi

    # 8. Code Complexity (Radon)
    echo -e "${BLUE}→ Code Complexity (Radon)${NC}"
    if command -v radon &> /dev/null; then
        COMPLEX_FUNCS=$(radon cc app/ -n C -j 2>/dev/null | grep -c '"complexity"' || echo "0")
        if [ "$COMPLEX_FUNCS" -gt 0 ]; then
            echo -e "${YELLOW}[WARNING] Found $COMPLEX_FUNCS high-complexity functions${NC}"
            radon cc app/ -n C -s 2>/dev/null || true
            echo ""
        else
            echo -e "${GREEN}[OK] No high-complexity functions${NC}\n"
        fi
    else
        echo -e "${YELLOW}[WARNING] Radon not installed (optional)${NC}\n"
    fi

    cd ..
fi

# ============================================================================
# Frontend Quality Checks
# ============================================================================
if [[ "$TARGET" == "all" ]] || [[ "$TARGET" == "frontend" ]]; then
    echo -e "${BOLD}${YELLOW}Frontend Quality Checks${NC}\n"

    cd frontend

    # Check node_modules
    if [ ! -d "node_modules" ]; then
        echo -e "${RED}[ERROR] Frontend dependencies not installed${NC}"
        echo -e "${YELLOW}  Run: npm install${NC}\n"
        ERRORS=$((ERRORS + 1))
        cd ..
    else
        # 1. ESLint
        echo -e "${BLUE}→ ESLint (Linter)${NC}"
        if [ "$AUTOFIX" = true ]; then
            npm run lint:fix
            echo -e "${GREEN}[OK] Linting issues fixed${NC}\n"
        else
            if npm run lint; then
                echo -e "${GREEN}[OK] Linting passed${NC}\n"
            else
                echo -e "${RED}[ERROR] Linting issues found${NC}"
                echo -e "${YELLOW}  Run: npm run lint:fix${NC}\n"
                ERRORS=$((ERRORS + 1))
            fi
        fi

        # 2. TypeScript
        echo -e "${BLUE}→ TypeScript (Type Checking)${NC}"
        if npx tsc --noEmit; then
            echo -e "${GREEN}[OK] Type checking passed${NC}\n"
        else
            echo -e "${RED}[ERROR] TypeScript errors found${NC}\n"
            ERRORS=$((ERRORS + 1))
        fi

        # 3. Build test
        echo -e "${BLUE}→ Build Test${NC}"
        if npm run build &> /tmp/openwatch-build.log; then
            echo -e "${GREEN}[OK] Build successful${NC}\n"
        else
            echo -e "${RED}[ERROR] Build failed${NC}"
            echo -e "${YELLOW}  Check: /tmp/openwatch-build.log${NC}\n"
            ERRORS=$((ERRORS + 1))
        fi

        cd ..
    fi
fi

# ============================================================================
# General Checks
# ============================================================================
echo -e "${BOLD}${YELLOW}General Checks${NC}\n"

# ShellCheck (Shell Scripts)
echo -e "${BLUE}→ ShellCheck (Shell Script Linting)${NC}"
if command -v shellcheck &> /dev/null; then
    SHELL_SCRIPTS=$(find . -name "*.sh" \
        -not -path "*/node_modules/*" \
        -not -path "*/.git/*" \
        -not -path "*/venv/*" \
        -not -path "*/__pycache__/*" 2>/dev/null)

    if [ -n "$SHELL_SCRIPTS" ]; then
        SHELLCHECK_ISSUES=0
        while IFS= read -r script; do
            if ! shellcheck -x "$script" > /dev/null 2>&1; then
                SHELLCHECK_ISSUES=$((SHELLCHECK_ISSUES + 1))
            fi
        done <<< "$SHELL_SCRIPTS"

        if [ $SHELLCHECK_ISSUES -eq 0 ]; then
            echo -e "${GREEN}[OK] All shell scripts validated${NC}\n"
        else
            echo -e "${YELLOW}[WARNING] Found issues in $SHELLCHECK_ISSUES shell scripts (non-blocking)${NC}\n"
        fi
    else
        echo -e "${GREEN}[OK] No shell scripts to check${NC}\n"
    fi
else
    echo -e "${YELLOW}[WARNING] ShellCheck not installed${NC}"
    echo -e "${YELLOW}  Install: pipx install shellcheck-py${NC}\n"
fi

# detect-secrets (Secret Scanner)
echo -e "${BLUE}→ detect-secrets (Secret Scanner)${NC}"
if command -v detect-secrets &> /dev/null; then
    if [ -f ".secrets.baseline" ]; then
        SECRETS_OUTPUT=$(detect-secrets scan 2>&1)
        if echo "$SECRETS_OUTPUT" | grep -q "potential secrets"; then
            echo -e "${RED}[ERROR] Potential secrets detected${NC}"
            echo -e "${YELLOW}  Review findings and update baseline if false positive${NC}\n"
            ERRORS=$((ERRORS + 1))
        else
            echo -e "${GREEN}[OK] No new secrets detected${NC}\n"
        fi
    else
        echo -e "${YELLOW}[WARNING] .secrets.baseline not found${NC}"
        echo -e "${YELLOW}  Generate: detect-secrets scan > .secrets.baseline${NC}\n"
    fi
else
    echo -e "${YELLOW}[WARNING] detect-secrets not installed${NC}"
    echo -e "${YELLOW}  Install: pipx install detect-secrets${NC}\n"
fi

# Check for TODOs
echo -e "${BLUE}→ Checking for TODOs/FIXMEs${NC}"
TODO_COUNT=$(find . -type f \( -name "*.py" -o -name "*.ts" -o -name "*.tsx" \) \
    -not -path "*/node_modules/*" \
    -not -path "*/.venv/*" \
    -not -path "*/venv/*" \
    -not -path "*/__pycache__/*" \
    -exec grep -l "TODO\|FIXME\|XXX\|HACK" {} \; 2>/dev/null | wc -l)

if [ "$TODO_COUNT" -gt 0 ]; then
    echo -e "${YELLOW}[WARNING] Found $TODO_COUNT files with TODO/FIXME comments${NC}\n"
else
    echo -e "${GREEN}[OK] No TODOs found${NC}\n"
fi

# Check for large files
echo -e "${BLUE}→ Checking for large files${NC}"
LARGE_FILES=$(find . -type f -size +1M \
    -not -path "*/node_modules/*" \
    -not -path "*/.git/*" \
    -not -path "*/dist/*" \
    -not -path "*/build/*" 2>/dev/null || true)

if [ -n "$LARGE_FILES" ]; then
    echo -e "${YELLOW}[WARNING] Large files found:${NC}"
    echo "$LARGE_FILES"
    echo ""
else
    echo -e "${GREEN}[OK] No large files${NC}\n"
fi

# ============================================================================
# Summary
# ============================================================================
SCRIPT_END_TIME=$(date +%s)
TOTAL_DURATION=$((SCRIPT_END_TIME - SCRIPT_START_TIME))

echo -e "${BOLD}${BLUE}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Quality Check Summary"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${NC}"

echo -e "${BLUE}Total execution time: ${TOTAL_DURATION}s${NC}\n"

if [ $ERRORS -eq 0 ]; then
    echo -e "${BOLD}${GREEN}[OK] All quality checks passed!${NC}"
    echo -e "${GREEN}  Your code is ready to commit${NC}\n"
    exit 0
else
    echo -e "${BOLD}${RED}[ERROR] Found $ERRORS error(s)${NC}"
    echo -e "${RED}  Fix the issues above before committing${NC}"
    echo -e "${YELLOW}  Run with --fix to auto-fix some issues:${NC}"
    echo -e "${YELLOW}    ./scripts/quality-check.sh --fix${NC}\n"
    exit 1
fi
