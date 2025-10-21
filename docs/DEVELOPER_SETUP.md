# OpenWatch Developer Setup & Code Quality Guide

**Last Updated:** October 20, 2025

This guide ensures all developers follow consistent code quality standards before committing code.

---

## 🎯 Quick Start

```bash
# 1. Clone repository
git clone https://github.com/Hanalyx/OpenWatch.git
cd OpenWatch

# 2. Install quality tools
./scripts/setup-quality-tools.sh

# 3. Install pre-commit hooks
pre-commit install

# 4. Run quality check before committing
./scripts/quality-check.sh

# 5. Commit (hooks will run automatically)
git commit -m "Your commit message"
```

---

## 📋 Table of Contents

1. [Required Tools](#required-tools)
2. [Pre-Commit Hooks](#pre-commit-hooks)
3. [Quality Check Scripts](#quality-check-scripts)
4. [IDE Configuration](#ide-configuration)
5. [Code Standards](#code-standards)
6. [Troubleshooting](#troubleshooting)

---

## 🛠️ Required Tools

### Backend (Python)

```bash
# Install Python quality tools
pip install black isort flake8 mypy bandit safety pre-commit

# Or use requirements-dev.txt
pip install -r backend/requirements-dev.txt
```

**Tools:**
- **black** - Code formatter (enforces PEP 8)
- **isort** - Import sorter
- **flake8** - Linter (finds code smells)
- **mypy** - Type checker
- **bandit** - Security scanner
- **safety** - Dependency vulnerability scanner

### Frontend (TypeScript/React)

```bash
cd frontend

# Install dependencies (includes dev tools)
npm install

# Quality tools are included in devDependencies:
# - eslint: Linter
# - typescript: Type checker
# - prettier: Code formatter
```

### Git Hooks

```bash
# Install pre-commit framework
pip install pre-commit

# Install hooks
pre-commit install

# Test hooks
pre-commit run --all-files
```

---

## 🪝 Pre-Commit Hooks

Pre-commit hooks **automatically run** before every commit to catch issues early.

### What Gets Checked:

#### Automatically Fixed:
- ✅ Trailing whitespace
- ✅ End-of-file newlines
- ✅ Python code formatting (Black)
- ✅ Import sorting (isort)
- ✅ Line endings (LF on Linux/Mac)

#### Validation Only (You Must Fix):
- ❌ TypeScript type errors
- ❌ ESLint errors
- ❌ Python linting errors (Flake8)
- ❌ Security issues (Bandit)
- ❌ Large files (>1MB)
- ❌ Secrets/credentials in code

### Bypass Hooks (Emergency Only)

```bash
# NOT RECOMMENDED - only for emergencies
git commit --no-verify -m "Emergency fix"
```

**⚠️ WARNING:** Bypassing hooks may cause CI failures and code review rejections.

---

## ✅ Quality Check Scripts

### Full Quality Check

```bash
# Check everything
./scripts/quality-check.sh

# Check and auto-fix what's possible
./scripts/quality-check.sh --fix

# Check backend only
./scripts/quality-check.sh backend

# Check frontend only
./scripts/quality-check.sh frontend
```

### What Gets Checked:

**Backend:**
1. **Black** - Python formatting
2. **isort** - Import order
3. **Flake8** - Code linting
4. **MyPy** - Type checking
5. **Bandit** - Security scan
6. **Safety** - Dependency vulnerabilities

**Frontend:**
1. **ESLint** - Code linting
2. **TypeScript** - Type checking
3. **Prettier** - Code formatting
4. **Build Test** - Verify code builds

**General:**
1. Large file detection
2. TODO/FIXME detection
3. Debug code detection
4. Secret detection

---

## 💻 IDE Configuration

### VS Code (Recommended)

Create `.vscode/settings.json`:

```json
{
  "editor.formatOnSave": true,
  "editor.codeActionsOnSave": {
    "source.fixAll.eslint": true,
    "source.organizeImports": true
  },

  // Python
  "[python]": {
    "editor.defaultFormatter": "ms-python.black-formatter",
    "editor.formatOnSave": true,
    "editor.rulers": [120]
  },
  "python.linting.enabled": true,
  "python.linting.flake8Enabled": true,
  "python.linting.banditEnabled": true,
  "python.formatting.provider": "black",
  "isort.args": ["--profile", "black"],

  // TypeScript/React
  "[typescript]": {
    "editor.defaultFormatter": "esbenp.prettier-vscode"
  },
  "[typescriptreact]": {
    "editor.defaultFormatter": "esbenp.prettier-vscode"
  },
  "typescript.updateImportsOnFileMove.enabled": "always",

  // ESLint
  "eslint.validate": [
    "javascript",
    "javascriptreact",
    "typescript",
    "typescriptreact"
  ],

  // Prettier
  "prettier.singleQuote": true,
  "prettier.semi": true,
  "prettier.printWidth": 100
}
```

**Required Extensions:**
- **Python**: `ms-python.python`, `ms-python.black-formatter`
- **ESLint**: `dbaeumer.vscode-eslint`
- **Prettier**: `esbenp.prettier-vscode`
- **TypeScript**: Built-in

### PyCharm / IntelliJ IDEA

1. **Settings → Tools → Black**
   - Enable "Run Black on save"
   - Line length: 120

2. **Settings → Tools → External Tools**
   - Add Flake8
   - Add Bandit

3. **Settings → Editor → Code Style → Python**
   - Line length: 120
   - Import sorting: Use isort

---

## 📝 Code Standards

### Python Backend

```python
# Good ✅
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.app.models import Host
from backend.app.schemas import HostCreate, HostResponse


def create_host(host: HostCreate, db: Session) -> HostResponse:
    """
    Create a new host in the database.

    Args:
        host: Host creation data
        db: Database session

    Returns:
        Created host response
    """
    new_host = Host(**host.dict())
    db.add(new_host)
    db.commit()
    return HostResponse.from_orm(new_host)


# Bad ❌
import os, sys
from backend.app.models import *  # Don't use star imports

def create_host(host,db):  # Missing type hints
    new_host=Host(**host.dict())  # Bad spacing
    db.add(new_host);db.commit()  # Multiple statements on one line
    return new_host
```

**Standards:**
- ✅ Line length: 120 characters max
- ✅ Use type hints for all functions
- ✅ Docstrings for public functions
- ✅ Black formatting
- ✅ isort import ordering
- ✅ No star imports (`from x import *`)
- ✅ No hardcoded credentials
- ✅ No `print()` statements (use `logger`)

### TypeScript Frontend

```typescript
// Good ✅
import React, { useState, useEffect } from 'react';
import { Box, Typography } from '@mui/material';
import { Host } from '../types/host';
import { fetchHosts } from '../services/hostService';

interface HostListProps {
  onHostSelect: (host: Host) => void;
}

export const HostList: React.FC<HostListProps> = ({ onHostSelect }) => {
  const [hosts, setHosts] = useState<Host[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const loadHosts = async () => {
      try {
        const data = await fetchHosts();
        setHosts(data);
      } catch (error) {
        console.error('Failed to load hosts:', error);
      } finally {
        setLoading(false);
      }
    };

    loadHosts();
  }, []);

  return (
    <Box>
      {/* Component JSX */}
    </Box>
  );
};

// Bad ❌
import React from 'react'  // Missing semicolon
import {Box,Typography} from '@mui/material'  // Bad spacing

export const HostList = (props) => {  // Missing type annotations
  const [hosts, setHosts] = useState([])  // Missing type parameter

  // Missing error handling
  useEffect(() => {
    fetchHosts().then(data => setHosts(data))
  }, [])

  return <div>{/* ... */}</div>
}
```

**Standards:**
- ✅ Strict TypeScript mode
- ✅ Type annotations for props, state, functions
- ✅ Interface over type for object shapes
- ✅ Named exports for components
- ✅ Functional components with hooks
- ✅ Proper error handling
- ✅ No `any` types (use `unknown` or specific type)
- ✅ ESLint + Prettier formatting

---

## 🔄 Development Workflow

### Before Starting Work

```bash
# 1. Pull latest changes
git checkout main
git pull origin main

# 2. Create feature branch
git checkout -b feature/your-feature-name

# 3. Ensure quality tools are installed
pip install -r backend/requirements-dev.txt
cd frontend && npm install
```

### During Development

```bash
# Run quality check frequently
./scripts/quality-check.sh

# Auto-fix issues
./scripts/quality-check.sh --fix

# Check specific component
./scripts/quality-check.sh backend
./scripts/quality-check.sh frontend
```

### Before Committing

```bash
# 1. Run full quality check
./scripts/quality-check.sh

# 2. Review changes
git diff

# 3. Stage changes
git add .

# 4. Commit (hooks run automatically)
git commit -m "feat: Add host monitoring dashboard"

# 5. Push to GitHub
git push origin feature/your-feature-name
```

### Commit Message Format

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Code style changes (formatting, no logic change)
- `refactor`: Code refactoring
- `test`: Adding tests
- `chore`: Maintenance tasks

**Examples:**
```bash
git commit -m "feat(hosts): Add bulk scan functionality"
git commit -m "fix(api): Resolve authentication token expiry"
git commit -m "docs(readme): Update installation instructions"
git commit -m "refactor(scanner): Migrate to QueryBuilder pattern"
```

---

## 🚨 Common Issues & Solutions

### Issue: Pre-commit hook fails with "command not found"

```bash
# Solution: Install missing tools
pip install black isort flake8 mypy bandit
```

### Issue: TypeScript errors in commit

```bash
# Solution: Fix type errors
cd frontend
npm run type-check

# See specific errors and fix them
```

### Issue: Black formatting conflicts with existing code

```bash
# Solution: Format entire codebase once
cd backend
black .

# Commit formatting changes separately
git commit -m "style: Apply Black formatting to backend"
```

### Issue: ESLint errors

```bash
# Solution: Auto-fix what's possible
cd frontend
npm run lint:fix

# Manually fix remaining errors shown in output
```

### Issue: "Large file detected" error

```bash
# Solution: Use Git LFS for large files
git lfs install
git lfs track "*.bin"
git lfs track "*.zip"
git add .gitattributes
```

### Issue: Secrets detected in commit

```bash
# Solution: Remove secrets, use environment variables
# 1. Remove the secret from code
# 2. Add to .env file (NOT committed)
# 3. Reference via os.getenv() or process.env

# If already committed:
git reset HEAD~1
# Remove secret, commit again
```

---

## 📊 Quality Metrics

### Minimum Standards for Pull Requests

- ✅ All pre-commit hooks pass
- ✅ No TypeScript errors
- ✅ No ESLint errors
- ✅ No Flake8 errors (Python)
- ✅ No security issues (Bandit)
- ✅ Code coverage ≥ 80% for new code
- ✅ All CI checks pass
- ✅ Peer review approved

### Running Tests

```bash
# Backend tests
cd backend
pytest tests/ -v --cov=app --cov-report=html

# Frontend tests
cd frontend
npm run test:e2e
```

---

## 🔗 Additional Resources

- [Black Documentation](https://black.readthedocs.io/)
- [Flake8 Rules](https://flake8.pycqa.org/en/latest/user/error-codes.html)
- [TypeScript Handbook](https://www.typescriptlang.org/docs/handbook/intro.html)
- [ESLint Rules](https://eslint.org/docs/latest/rules/)
- [Conventional Commits](https://www.conventionalcommits.org/)
- [Pre-commit Framework](https://pre-commit.com/)

---

## 💬 Getting Help

- **Code quality questions**: Check [CLAUDE.md](../CLAUDE.md)
- **Bug reports**: [GitHub Issues](https://github.com/Hanalyx/OpenWatch/issues)
- **Feature requests**: [GitHub Discussions](https://github.com/Hanalyx/OpenWatch/discussions)

---

**Last Updated:** October 20, 2025
**Maintained By:** OpenWatch Development Team
