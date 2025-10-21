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

if command -v pip3 &> /dev/null; then
    echo -e "${GREEN}✓ pip3 found${NC}\n"
else
    echo -e "${RED}✗ pip3 not found${NC}"
    echo -e "${YELLOW}  Install: sudo apt-get install python3-pip${NC}\n"
    exit 1
fi

# Install Python quality tools
echo -e "${BLUE}→ Installing Python packages...${NC}"
pip3 install --user --upgrade \
    black \
    isort \
    flake8 \
    mypy \
    bandit \
    safety \
    pre-commit \
    pytest \
    pytest-cov \
    pytest-asyncio

echo -e "${GREEN}✓ Python tools installed${NC}\n"

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

    # Install hooks
    echo -e "${BLUE}→ Installing pre-commit hooks...${NC}"
    pre-commit install

    echo -e "${GREEN}✓ Pre-commit hooks installed${NC}\n"

    # Run hooks once to download dependencies
    echo -e "${BLUE}→ Running initial hook setup (this may take a moment)...${NC}"
    pre-commit run --all-files || echo -e "${YELLOW}  (Some checks may fail - this is normal on first run)${NC}"

    echo -e "${GREEN}✓ Pre-commit setup complete${NC}\n"
else
    echo -e "${RED}✗ pre-commit not installed${NC}"
    echo -e "${YELLOW}  Install: pip3 install --user pre-commit${NC}\n"
fi

# Make custom pre-commit hook executable
if [ -f ".git/hooks/pre-commit" ]; then
    chmod +x .git/hooks/pre-commit
    echo -e "${GREEN}✓ Custom pre-commit hook configured${NC}\n"
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
for tool in black isort flake8 mypy bandit safety pytest pre-commit; do
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
echo -e "  ${BLUE}./scripts/quality-check.sh${NC}           # Check code quality"
echo -e "  ${BLUE}./scripts/quality-check.sh --fix${NC}     # Auto-fix issues"
echo -e "  ${BLUE}pre-commit run --all-files${NC}           # Run all hooks"
echo -e "  ${BLUE}cd frontend && npm run quality${NC}       # Frontend quality check"
echo -e "  ${BLUE}cd backend && black . && isort .${NC}     # Format backend code\n"
