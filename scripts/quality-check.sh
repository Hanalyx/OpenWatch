#!/bin/bash
#
# OpenWatch Quality Check Script
# Run this before committing or creating a PR
#
# Usage:
#   ./scripts/quality-check.sh          # Check all
#   ./scripts/quality-check.sh backend  # Check backend only
#   ./scripts/quality-check.sh frontend # Check frontend only
#   ./scripts/quality-check.sh --fix    # Auto-fix issues

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

TARGET=${1:-all}
AUTOFIX=false

if [[ "$1" == "--fix" ]] || [[ "$2" == "--fix" ]]; then
    AUTOFIX=true
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

ERRORS=0

echo -e "${BOLD}${BLUE}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔍 OpenWatch Code Quality Check"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${NC}"

# ============================================================================
# Backend Quality Checks
# ============================================================================
if [[ "$TARGET" == "all" ]] || [[ "$TARGET" == "backend" ]]; then
    echo -e "${BOLD}${YELLOW}📦 Backend Quality Checks${NC}\n"

    cd backend

    # 1. Black
    echo -e "${BLUE}→ Black (Python Formatter)${NC}"
    if command -v black &> /dev/null; then
        if [ "$AUTOFIX" = true ]; then
            black . --line-length=120
            echo -e "${GREEN}✓ Code formatted${NC}\n"
        else
            if black . --check --line-length=120; then
                echo -e "${GREEN}✓ Formatting correct${NC}\n"
            else
                echo -e "${RED}✗ Formatting issues found${NC}"
                echo -e "${YELLOW}  Run: black . --line-length=120${NC}\n"
                ERRORS=$((ERRORS + 1))
            fi
        fi
    else
        echo -e "${RED}✗ Black not installed${NC}"
        echo -e "${YELLOW}  Install: pip install black${NC}\n"
        ERRORS=$((ERRORS + 1))
    fi

    # 2. isort
    echo -e "${BLUE}→ isort (Import Sorting)${NC}"
    if command -v isort &> /dev/null; then
        if [ "$AUTOFIX" = true ]; then
            isort . --profile black --line-length=120
            echo -e "${GREEN}✓ Imports sorted${NC}\n"
        else
            if isort . --check-only --profile black --line-length=120; then
                echo -e "${GREEN}✓ Import order correct${NC}\n"
            else
                echo -e "${RED}✗ Import order issues${NC}"
                echo -e "${YELLOW}  Run: isort . --profile black${NC}\n"
                ERRORS=$((ERRORS + 1))
            fi
        fi
    else
        echo -e "${RED}✗ isort not installed${NC}"
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
            echo -e "${GREEN}✓ Linting passed${NC}\n"
        else
            echo -e "${RED}✗ Linting issues found${NC}\n"
            ERRORS=$((ERRORS + 1))
        fi
    else
        echo -e "${RED}✗ Flake8 not installed${NC}"
        echo -e "${YELLOW}  Install: pip install flake8${NC}\n"
        ERRORS=$((ERRORS + 1))
    fi

    # 4. MyPy
    echo -e "${BLUE}→ MyPy (Type Checking)${NC}"
    if command -v mypy &> /dev/null; then
        if mypy app/ --ignore-missing-imports --no-strict-optional; then
            echo -e "${GREEN}✓ Type checking passed${NC}\n"
        else
            echo -e "${YELLOW}⚠️  Type checking warnings (non-blocking)${NC}\n"
        fi
    else
        echo -e "${YELLOW}⚠️  MyPy not installed (optional)${NC}\n"
    fi

    # 5. Bandit (Security)
    echo -e "${BLUE}→ Bandit (Security Scanner)${NC}"
    if command -v bandit &> /dev/null; then
        if bandit -r app/ -ll -f txt 2>&1; then
            echo -e "${GREEN}✓ Security scan passed${NC}\n"
        else
            echo -e "${RED}✗ Security issues found${NC}\n"
            ERRORS=$((ERRORS + 1))
        fi
    else
        echo -e "${YELLOW}⚠️  Bandit not installed${NC}"
        echo -e "${YELLOW}  Install: pip install bandit${NC}\n"
    fi

    # 6. Safety (Dependency vulnerabilities)
    echo -e "${BLUE}→ Safety (Dependency Vulnerability Check)${NC}"
    if command -v safety &> /dev/null; then
        if safety check --json 2>&1 | head -20; then
            echo -e "${GREEN}✓ No known vulnerabilities${NC}\n"
        else
            echo -e "${YELLOW}⚠️  Vulnerabilities found (review)${NC}\n"
        fi
    else
        echo -e "${YELLOW}⚠️  Safety not installed (optional)${NC}\n"
    fi

    cd ..
fi

# ============================================================================
# Frontend Quality Checks
# ============================================================================
if [[ "$TARGET" == "all" ]] || [[ "$TARGET" == "frontend" ]]; then
    echo -e "${BOLD}${YELLOW}📦 Frontend Quality Checks${NC}\n"

    cd frontend

    # Check node_modules
    if [ ! -d "node_modules" ]; then
        echo -e "${RED}✗ Frontend dependencies not installed${NC}"
        echo -e "${YELLOW}  Run: npm install${NC}\n"
        ERRORS=$((ERRORS + 1))
        cd ..
    else
        # 1. ESLint
        echo -e "${BLUE}→ ESLint (Linter)${NC}"
        if [ "$AUTOFIX" = true ]; then
            npm run lint:fix
            echo -e "${GREEN}✓ Linting issues fixed${NC}\n"
        else
            if npm run lint; then
                echo -e "${GREEN}✓ Linting passed${NC}\n"
            else
                echo -e "${RED}✗ Linting issues found${NC}"
                echo -e "${YELLOW}  Run: npm run lint:fix${NC}\n"
                ERRORS=$((ERRORS + 1))
            fi
        fi

        # 2. TypeScript
        echo -e "${BLUE}→ TypeScript (Type Checking)${NC}"
        if npx tsc --noEmit; then
            echo -e "${GREEN}✓ Type checking passed${NC}\n"
        else
            echo -e "${RED}✗ TypeScript errors found${NC}\n"
            ERRORS=$((ERRORS + 1))
        fi

        # 3. Build test
        echo -e "${BLUE}→ Build Test${NC}"
        if npm run build &> /tmp/openwatch-build.log; then
            echo -e "${GREEN}✓ Build successful${NC}\n"
        else
            echo -e "${RED}✗ Build failed${NC}"
            echo -e "${YELLOW}  Check: /tmp/openwatch-build.log${NC}\n"
            ERRORS=$((ERRORS + 1))
        fi

        cd ..
    fi
fi

# ============================================================================
# General Checks
# ============================================================================
echo -e "${BOLD}${YELLOW}📦 General Checks${NC}\n"

# Check for TODOs
echo -e "${BLUE}→ Checking for TODOs/FIXMEs${NC}"
TODO_COUNT=$(find . -type f \( -name "*.py" -o -name "*.ts" -o -name "*.tsx" \) \
    -not -path "*/node_modules/*" \
    -not -path "*/.venv/*" \
    -not -path "*/venv/*" \
    -not -path "*/__pycache__/*" \
    -exec grep -l "TODO\|FIXME\|XXX\|HACK" {} \; 2>/dev/null | wc -l)

if [ "$TODO_COUNT" -gt 0 ]; then
    echo -e "${YELLOW}⚠️  Found $TODO_COUNT files with TODO/FIXME comments${NC}\n"
else
    echo -e "${GREEN}✓ No TODOs found${NC}\n"
fi

# Check for large files
echo -e "${BLUE}→ Checking for large files${NC}"
LARGE_FILES=$(find . -type f -size +1M \
    -not -path "*/node_modules/*" \
    -not -path "*/.git/*" \
    -not -path "*/dist/*" \
    -not -path "*/build/*" 2>/dev/null || true)

if [ -n "$LARGE_FILES" ]; then
    echo -e "${YELLOW}⚠️  Large files found:${NC}"
    echo "$LARGE_FILES"
    echo ""
else
    echo -e "${GREEN}✓ No large files${NC}\n"
fi

# ============================================================================
# Summary
# ============================================================================
echo -e "${BOLD}${BLUE}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📊 Quality Check Summary"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${NC}"

if [ $ERRORS -eq 0 ]; then
    echo -e "${BOLD}${GREEN}✓ All quality checks passed!${NC}"
    echo -e "${GREEN}  Your code is ready to commit${NC}\n"
    exit 0
else
    echo -e "${BOLD}${RED}✗ Found $ERRORS error(s)${NC}"
    echo -e "${RED}  Fix the issues above before committing${NC}"
    echo -e "${YELLOW}  Run with --fix to auto-fix some issues:${NC}"
    echo -e "${YELLOW}    ./scripts/quality-check.sh --fix${NC}\n"
    exit 1
fi
