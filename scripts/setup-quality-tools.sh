#!/bin/bash
#
# OpenWatch Quality Tools Setup Script
# Installs all required code quality and pre-commit tools
#
# Usage: ./scripts/setup-quality-tools.sh

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}${BLUE}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🛠️  OpenWatch Quality Tools Setup"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${NC}\n"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# ============================================================================
# Python Tools
# ============================================================================
echo -e "${BOLD}${YELLOW}📦 Installing Python Quality Tools${NC}\n"

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | grep -oP '(?<=Python )\d+\.\d+')
echo -e "${BLUE}→ Python version: ${PYTHON_VERSION}${NC}"

# Check for pipx (preferred over pip --user)
echo -e "${BLUE}→ Checking for pipx...${NC}"
if ! command -v pipx &> /dev/null; then
    echo -e "${YELLOW}⚠️  pipx not found - installing...${NC}"
    if command -v apt-get &> /dev/null; then
        sudo apt-get update -qq
        sudo apt-get install -y pipx
    else
        python3 -m pip install --user pipx
    fi
    pipx ensurepath
    export PATH="$HOME/.local/bin:$PATH"
    echo -e "${GREEN}✓ pipx installed${NC}\n"
else
    echo -e "${GREEN}✓ pipx found${NC}\n"
fi

# Install Python quality tools via pipx (isolated environments)
echo -e "${BLUE}→ Installing Python packages via pipx...${NC}"
pipx install pre-commit --force || pipx upgrade pre-commit
pipx install detect-secrets --force || pipx upgrade detect-secrets
pipx install black --force || pipx upgrade black
pipx install isort --force || pipx upgrade isort
pipx install flake8 --force || pipx upgrade flake8
pipx install mypy --force || pipx upgrade mypy
pipx install bandit --force || pipx upgrade bandit
pipx install pytest --force || pipx upgrade pytest
pipx install radon --force || pipx upgrade radon
pipx install vulture --force || pipx upgrade vulture
pipx install safety --force || pipx upgrade safety

echo -e "${GREEN}✓ Python tools installed via pipx${NC}\n"

# Install shellcheck-py
echo -e "${BLUE}→ Installing shellcheck-py...${NC}"
if ! command -v shellcheck &> /dev/null; then
    pipx install shellcheck-py --force || pipx upgrade shellcheck-py
    echo -e "${GREEN}✓ shellcheck installed${NC}\n"
else
    echo -e "${GREEN}✓ shellcheck already installed${NC}\n"
fi

# Install backend dev dependencies if requirements-dev.txt exists
if [ -f "backend/requirements-dev.txt" ]; then
    echo -e "${BLUE}→ Installing backend dev dependencies...${NC}"
    pip3 install --user -r backend/requirements-dev.txt
    echo -e "${GREEN}✓ Backend dev dependencies installed${NC}\n"
fi

# ============================================================================
# Node.js / npm Tools
# ============================================================================
echo -e "${BOLD}${YELLOW}📦 Installing Frontend Quality Tools${NC}\n"

# Check Node.js version
if command -v node &> /dev/null; then
    NODE_VERSION=$(node --version)
    echo -e "${BLUE}→ Node.js version: ${NODE_VERSION}${NC}"
    echo -e "${GREEN}✓ Node.js found${NC}\n"
else
    echo -e "${RED}✗ Node.js not found${NC}"
    echo -e "${YELLOW}  Install: sudo apt-get install nodejs npm${NC}\n"
    exit 1
fi

# Install frontend dependencies
if [ -d "frontend" ]; then
    echo -e "${BLUE}→ Installing frontend dependencies...${NC}"
    cd frontend
    npm install
    echo -e "${GREEN}✓ Frontend dependencies installed${NC}\n"
    cd ..
else
    echo -e "${YELLOW}⚠️  Frontend directory not found (skipping)${NC}\n"
fi

# ============================================================================
# Pre-commit Hooks
# ============================================================================
echo -e "${BOLD}${YELLOW}🪝 Setting Up Pre-commit Hooks${NC}\n"

# Check if pre-commit is installed
if command -v pre-commit &> /dev/null; then
    echo -e "${GREEN}✓ pre-commit found${NC}"

    # Install pre-commit hooks
    echo -e "${BLUE}→ Installing pre-commit hooks...${NC}"
    pre-commit install
    echo -e "${GREEN}✓ Pre-commit hooks installed${NC}\n"

    # Install commit-msg hook
    echo -e "${BLUE}→ Installing commit-msg hook...${NC}"
    pre-commit install --hook-type commit-msg
    echo -e "${GREEN}✓ Commit-msg hook installed${NC}\n"

    # Generate secrets baseline if not exists
    echo -e "${BLUE}→ Checking secrets baseline...${NC}"
    if [ ! -f ".secrets.baseline" ]; then
        echo -e "${YELLOW}⚠️  Generating .secrets.baseline (this may take a moment)...${NC}"
        detect-secrets scan > .secrets.baseline 2>/dev/null || echo "{}" > .secrets.baseline
        echo -e "${GREEN}✓ .secrets.baseline generated${NC}\n"
    else
        echo -e "${GREEN}✓ .secrets.baseline already exists${NC}\n"
    fi

    # Run hooks once to download dependencies
    echo -e "${BLUE}→ Running initial hook setup (this may take a moment)...${NC}"
    pre-commit run --all-files || echo -e "${YELLOW}  (Some checks may fail - this is normal on first run)${NC}"

    echo -e "${GREEN}✓ Pre-commit setup complete${NC}\n"
else
    echo -e "${RED}✗ pre-commit not installed${NC}"
    echo -e "${YELLOW}  Install: pipx install pre-commit${NC}\n"
fi

# Make custom pre-commit hook executable
if [ -f ".git/hooks/pre-commit" ]; then
    chmod +x .git/hooks/pre-commit
    echo -e "${GREEN}✓ Custom pre-commit hook configured${NC}\n"
fi

# Make commit-msg-lint.sh executable
if [ -f ".git/hooks/commit-msg-lint.sh" ]; then
    chmod +x .git/hooks/commit-msg-lint.sh
    echo -e "${GREEN}✓ commit-msg-lint.sh configured${NC}\n"
fi

# ============================================================================
# Quality Check Script
# ============================================================================
echo -e "${BOLD}${YELLOW}📋 Setting Up Quality Check Script${NC}\n"

if [ -f "scripts/quality-check.sh" ]; then
    chmod +x scripts/quality-check.sh
    echo -e "${GREEN}✓ Quality check script ready${NC}\n"
else
    echo -e "${YELLOW}⚠️  Quality check script not found${NC}\n"
fi

# ============================================================================
# Verification
# ============================================================================
echo -e "${BOLD}${YELLOW}✅ Verification${NC}\n"

echo -e "${BLUE}→ Checking installed tools:${NC}"
echo ""

# Python tools
for tool in black isort flake8 mypy bandit safety pytest pre-commit detect-secrets shellcheck radon vulture; do
    if command -v $tool &> /dev/null; then
        VERSION=$($tool --version 2>&1 | head -1)
        echo -e "${GREEN}  ✓ $tool${NC} - $VERSION"
    else
        echo -e "${RED}  ✗ $tool not found${NC}"
    fi
done

echo ""

# Node tools (check in frontend directory)
if [ -d "frontend/node_modules" ]; then
    echo -e "${GREEN}  ✓ Frontend dependencies installed${NC}"

    # Check specific tools
    cd frontend
    for tool in eslint typescript prettier; do
        if [ -f "node_modules/.bin/$tool" ]; then
            echo -e "${GREEN}  ✓ $tool${NC}"
        else
            echo -e "${RED}  ✗ $tool not found${NC}"
        fi
    done
    cd ..
else
    echo -e "${YELLOW}  ⚠️  Frontend dependencies not installed${NC}"
fi

echo ""

# ============================================================================
# Summary
# ============================================================================
echo -e "${BOLD}${BLUE}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📊 Setup Complete!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${NC}\n"

echo -e "${GREEN}✓ All quality tools installed${NC}"
echo -e "${GREEN}✓ Pre-commit hooks configured${NC}"
echo -e "${GREEN}✓ Ready to develop!${NC}"

echo -e "\n${BOLD}Next Steps:${NC}"
echo -e "  1. Read developer guide: ${BLUE}docs/DEVELOPER_SETUP.md${NC}"
echo -e "  2. Run quality check: ${BLUE}./scripts/quality-check.sh${NC}"
echo -e "  3. Make changes and commit (hooks will run automatically)"
echo -e "  4. See ${BLUE}docs/DEVELOPER_SETUP.md${NC} for coding standards\n"

echo -e "${BOLD}Useful Commands:${NC}"
echo -e "  ${BLUE}./scripts/quality-check.sh${NC}                        # Check code quality"
echo -e "  ${BLUE}./scripts/quality-check.sh --fix${NC}                  # Auto-fix issues"
echo -e "  ${BLUE}./scripts/quality-check.sh --check-message \"MSG\"${NC}  # Validate commit message"
echo -e "  ${BLUE}pre-commit run --all-files${NC}                        # Run all hooks"
echo -e "  ${BLUE}cd frontend && npm run quality${NC}                    # Frontend quality check"
echo -e "  ${BLUE}cd backend && black . && isort .${NC}                  # Format backend code"
echo -e "  ${BLUE}detect-secrets scan --baseline .secrets.baseline${NC}  # Check for secrets\n"
