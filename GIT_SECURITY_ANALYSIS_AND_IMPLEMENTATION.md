# Git Security Analysis & 5-Layer Protection Implementation Plan

**Analysis Date:** October 15, 2025
**Current Branch:** refactor/scap-scanner-base-class
**Repository:** git@github.com:Hanalyx/OpenWatch.git

---

## Current State Analysis

### ✅ What's Already in Place

#### 1. Git Configuration
```
Repository: OpenWatch (GitHub)
User: Remylus Losius (remyluslosius@gonaibo.com)
Remote: git@github.com:Hanalyx/OpenWatch.git
Pull Strategy: Merge (not rebase)
```

#### 2. Existing GitHub Actions (Well-Established CI/CD)

**A. Code Quality Workflow** (.github/workflows/code-quality.yml)
- ✅ **Bandit security scanning** (line 62-64) - Already scans for security issues!
- ✅ Python linting (Black, Flake8, Pylint, MyPy)
- ✅ JavaScript/TypeScript quality checks
- ✅ SonarCloud integration
- ✅ Code coverage reporting

**B. Container Security Workflow** (.github/workflows/container-security.yml)
- ✅ **Trivy container scanning** - Vulnerability detection
- ✅ **Grype container scanning** - Secondary vulnerability scanner
- ✅ Daily scheduled scans (2 AM UTC)
- ✅ SARIF upload to GitHub Security tab

**C. Additional Workflows**
- ✅ CI/CD pipeline (ci.yml)
- ✅ CodeQL analysis (codeql.yml)
- ✅ Dependency management (dependency-management.yml)
- ✅ Container security scanning

#### 3. Git Hooks Status
**Current hooks:** All are sample files (*.sample)
- ❌ **No active pre-commit hooks** - Sample only
- ❌ **No active pre-push hooks** - Sample only
- ❌ **No active commit-msg hooks** - Sample only

**Opportunity:** Can safely install custom hooks without conflicts

#### 4. Secret Scanning Tools
**Installed:** NONE
- ❌ git-secrets: Not installed
- ❌ gitleaks: Not installed
- ❌ TruffleHog: Not installed

**Config Files:** NONE
- ❌ .gitleaks.toml: Not present
- ❌ .git-secrets config: Not present

#### 5. .gitignore Status
- ✅ **Just updated** with MongoDB cert patterns
- ✅ Comprehensive patterns for secrets
- ✅ Environment files protected
- ⚠️ **Issue:** mongodb.pem was committed BEFORE these patterns existed

---

## Gap Analysis

### ❌ Missing Protection Layers

| Layer | Status | Risk Level | Effort to Fix |
|-------|--------|------------|---------------|
| Pre-commit hooks | Missing | HIGH | 5 minutes |
| Secret scanning (local) | Missing | HIGH | 15 minutes |
| Secret scanning (CI/CD) | Missing | MEDIUM | 20 minutes |
| Gitleaks config | Missing | MEDIUM | 10 minutes |
| Developer training | Not documented | LOW | 30 minutes |

### ⚠️ Potential Conflicts

**NONE IDENTIFIED** - Safe to proceed with all 5 layers

---

## Implementation Plan (Conservative Approach)

### Phase 1: Immediate Protection (TODAY - 30 minutes)

#### Step 1.1: Install Pre-Commit Hook (5 min)
```bash
cd /home/rracine/hanalyx/openwatch

# Create pre-commit hook
cat > .git/hooks/pre-commit << 'EOFHOOK'
#!/bin/bash
# OpenWatch Secret Protection Hook
# Generated: 2025-10-15

RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "🔒 Running OpenWatch secret protection checks..."

# Block private keys
BLOCKED_FILES=$(git diff --cached --name-only | grep -E '\.(pem|key)$' | grep -v '\.example' | grep -v '\.template' || true)
if [ -n "$BLOCKED_FILES" ]; then
    echo -e "${RED}❌ ERROR: Attempting to commit private key files!${NC}"
    echo "$BLOCKED_FILES"
    echo ""
    echo "These files should be in .gitignore or use .example versions"
    exit 1
fi

# Block .env files
if git diff --cached --name-only | grep -E '^\.env$' > /dev/null; then
    echo -e "${RED}❌ ERROR: Attempting to commit .env file!${NC}"
    echo "Use .env.example for templates"
    exit 1
fi

# Warn on potential secrets
POTENTIAL_SECRETS=$(git diff --cached -U0 | grep -E '(password|secret|api_key|private_key|token).*=.*["\047][^"\047]{8,}' || true)
if [ -n "$POTENTIAL_SECRETS" ]; then
    echo -e "${YELLOW}⚠️  WARNING: Potential secrets detected:${NC}"
    echo "$POTENTIAL_SECRETS" | head -5
    echo ""
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Commit aborted by user"
        exit 1
    fi
fi

echo "✅ Secret protection checks passed"
exit 0
EOFHOOK

chmod +x .git/hooks/pre-commit
echo "✅ Pre-commit hook installed"
```

**Test it:**
```bash
# Should FAIL (blocked)
touch test_secret.pem
git add test_secret.pem
git commit -m "test"

# Clean up
git reset HEAD test_secret.pem
rm test_secret.pem
```

#### Step 1.2: Install Gitleaks (15 min)
```bash
# Download gitleaks
wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz
tar -xzf gitleaks_8.18.0_linux_x64.tar.gz
sudo mv gitleaks /usr/local/bin/
rm gitleaks_8.18.0_linux_x64.tar.gz

# Verify installation
gitleaks version

# Scan repository NOW
cd /home/rracine/hanalyx/openwatch
gitleaks detect --source . --verbose --report-path gitleaks-report.json

# Review findings
cat gitleaks-report.json | jq '.[] | {Description, File, StartLine}'
```

#### Step 1.3: Create Gitleaks Config (10 min)
```bash
cat > .gitleaks.toml << 'EOFCONFIG'
title = "OpenWatch Gitleaks Configuration"

# MongoDB Private Keys
[[rules]]
id = "mongodb-private-key"
description = "MongoDB Private Key"
path = '''security/certs/mongodb/.*\.(pem|key)'''
tags = ["mongodb", "certificate", "critical"]

# JWT Private Keys
[[rules]]
id = "jwt-private-key"
description = "JWT Private Key"
path = '''security/keys/.*private.*\.(pem|key)'''
tags = ["jwt", "private-key", "critical"]

# Generic Private Keys
[[rules]]
id = "private-key-pattern"
description = "Private Key Pattern"
regex = '''-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'''
tags = ["key", "private", "critical"]

# Environment Files
[[rules]]
id = "env-file"
description = "Environment File"
path = '''\.env$'''
tags = ["env", "config", "high"]

# Hardcoded Passwords
[[rules]]
id = "hardcoded-password"
description = "Hardcoded Password"
regex = '''(?i)(password|passwd|pwd)\s*=\s*["\047][^"\047]{8,}["\047]'''
tags = ["password", "hardcoded", "high"]

# API Keys
[[rules]]
id = "api-key"
description = "API Key"
regex = '''(?i)(api[_-]?key|apikey)\s*=\s*["\047][^"\047]{16,}["\047]'''
tags = ["api-key", "high"]

# Generic Secrets
[[rules]]
id = "generic-secret"
description = "Generic Secret"
regex = '''(?i)secret.*=.*["\047][a-zA-Z0-9]{16,}["\047]'''
tags = ["secret", "medium"]

# AWS Keys
[[rules]]
id = "aws-access-key"
description = "AWS Access Key"
regex = '''AKIA[0-9A-Z]{16}'''
tags = ["aws", "critical"]

# Allowlist (false positives)
[allowlist]
description = "Allowlist for known false positives"
paths = [
    '''\.env\.example$''',
    '''\.env\.template$''',
    '''\.sample$''',
    '''/test/''',
    '''/tests/''',
    '''/docs/examples/''',
    '''/PREVENT_SECRETS_IN_GIT\.md$''',
    '''/SECURITY.*\.md$'''
]
EOFCONFIG

echo "✅ Gitleaks config created"
```

### Phase 2: CI/CD Integration (TOMORROW - 20 minutes)

#### Step 2.1: Add Secret Scanning to GitHub Actions

Create `.github/workflows/secret-scan.yml`:

```yaml
name: Secret Scanning

on:
  push:
    branches: [ main, develop, 'feature/**', 'fix/**' ]
  pull_request:
    branches: [ main, develop ]

jobs:
  gitleaks:
    name: Gitleaks Secret Scan
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v5
        with:
          fetch-depth: 0  # Full history

      - name: Run Gitleaks
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITLEAKS_LICENSE: ${{ secrets.GITLEAKS_LICENSE }}

      - name: Upload SARIF report
        if: failure()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
          category: secret-scanning

  trufflehog:
    name: TruffleHog Secret Scan
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v5
        with:
          fetch-depth: 0

      - name: TruffleHog Scan
        uses: trufflesecurity/trufflehog@main
        with:
          path: ./
          base: ${{ github.event.repository.default_branch }}
          head: HEAD
          extra_args: --debug --only-verified

      - name: Fail on secrets found
        if: failure()
        run: |
          echo "::error::Secrets detected! Review TruffleHog output above"
          exit 1
```

**Placement:** This COMPLEMENTS existing workflows (no conflicts with Bandit, Trivy, Grype)

#### Step 2.2: Update Existing CI Workflow

Add to `.github/workflows/ci.yml` (near the end):

```yaml
  secret-scan-gate:
    name: Secret Scan Gate
    runs-on: ubuntu-latest
    needs: [build, test]  # Run after builds succeed
    
    steps:
      - name: Checkout
        uses: actions/checkout@v5

      - name: Quick Gitleaks Scan
        run: |
          wget -q https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz
          tar -xzf gitleaks_8.18.0_linux_x64.tar.gz
          ./gitleaks detect --source . --no-git --exit-code 1
```

### Phase 3: Developer Protection (NEXT WEEK - 1 hour)

#### Step 3.1: Install git-secrets (Optional but Recommended)

```bash
# Clone and install
git clone https://github.com/awslabs/git-secrets.git /tmp/git-secrets
cd /tmp/git-secrets
sudo make install

# Configure for OpenWatch
cd /home/rracine/hanalyx/openwatch
git secrets --install
git secrets --register-aws

# Add custom patterns
git secrets --add '-----BEGIN (RSA |EC )?PRIVATE KEY-----'
git secrets --add 'mongodb\.pem'
git secrets --add 'security/certs/mongodb/'
git secrets --add '(?i)password.*=.*["\047].{8,}["\047]'

# Test
git secrets --scan

echo "✅ git-secrets installed and configured"
```

#### Step 3.2: Create Developer Setup Script

Create `scripts/setup-developer-environment.sh`:

```bash
#!/bin/bash
# OpenWatch Developer Security Setup

echo "🔧 Setting up OpenWatch developer environment..."

# 1. Install pre-commit hook
if [ ! -f .git/hooks/pre-commit ] || [ -L .git/hooks/pre-commit ]; then
    echo "Installing pre-commit hook..."
    # (Copy the hook from Step 1.1)
    echo "✅ Pre-commit hook installed"
else
    echo "⚠️  Pre-commit hook already exists - skipping"
fi

# 2. Check gitleaks
if ! command -v gitleaks &> /dev/null; then
    echo "⚠️  Gitleaks not installed. Install with:"
    echo "    wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz"
    echo "    tar -xzf gitleaks_8.18.0_linux_x64.tar.gz && sudo mv gitleaks /usr/local/bin/"
else
    echo "✅ Gitleaks already installed"
fi

# 3. Run initial scan
echo ""
echo "Running initial security scan..."
gitleaks detect --source . --verbose || echo "⚠️  Secrets detected! Review output above"

echo ""
echo "✅ Developer environment setup complete!"
echo ""
echo "Next steps:"
echo "  1. Review any detected secrets"
echo "  2. Never commit .pem, .key, or .env files"
echo "  3. Use .env.example for configuration templates"
```

### Phase 4: Historical Cleanup (COORDINATE WITH TEAM)

#### Step 4.1: Document Compromised Certificate

Create `security/CERTIFICATE_ROTATION_LOG.md`:

```markdown
# Certificate Rotation Log

## 2025-10-15: MongoDB Certificate Compromise

**Issue:** MongoDB private key (mongodb.pem) was committed to git history

**Affected File:** security/certs/mongodb/mongodb.pem

**Git Commits:** 16 commits in repository history

**Action Taken:**
1. [ ] Generated new MongoDB certificates
2. [ ] Updated all MongoDB instances
3. [ ] Verified no production systems using old certificate
4. [ ] Removed from git history (see below)
5. [ ] Enhanced .gitignore
6. [ ] Installed pre-commit hooks

**Removal Method:**
- [ ] Option A: Remove from tracking (if not public)
- [ ] Option B: BFG Repo-Cleaner (if private repo)
- [ ] Option C: Accept and rotate (if public)

**Selected:** _____________

**Completed By:** _____________
**Date:** _____________
```

#### Step 4.2: Choose History Cleanup Method

**Option A: Minimal (Recommended for Now)**
```bash
# Just remove from tracking, keep history as lesson learned
git rm --cached security/certs/mongodb/mongodb.pem
git commit -m "chore: Remove MongoDB private key from tracking

SECURITY: This certificate was previously committed to git history
and has been rotated. New certificates generated on 2025-10-15.

See: security/CERTIFICATE_ROTATION_LOG.md"
```

**Option B: Full Cleanup (If Needed Later)**
```bash
# Use BFG Repo-Cleaner
java -jar bfg.jar --delete-files mongodb.pem
git reflog expire --expire=now --all
git gc --prune=now --aggressive

# Force push (requires team coordination!)
git push origin --force --all
```

### Phase 5: Monitoring & Maintenance (ONGOING)

#### Step 5.1: Regular Scans

Add to cron or GitHub Actions schedules:

```yaml
# In .github/workflows/secret-scan.yml
on:
  schedule:
    - cron: '0 0 * * 0'  # Weekly on Sunday
```

#### Step 5.2: Quarterly Reviews

Create `SECURITY_QUARTERLY_CHECKLIST.md`:

```markdown
# Quarterly Security Review Checklist

## Git Security

- [ ] Run full gitleaks scan: `gitleaks detect --source . --verbose`
- [ ] Verify .gitignore patterns are comprehensive
- [ ] Check all hooks are installed: `ls -la .git/hooks/`
- [ ] Review certificate expiration dates
- [ ] Audit git-secrets patterns
- [ ] Review GitHub Security tab for alerts

## Certificate Management

- [ ] Verify MongoDB certificates valid for >90 days
- [ ] Verify JWT keys rotated within policy
- [ ] Check TLS certificate expiration
- [ ] Review access logs for old certificates

## Training

- [ ] New developers onboarded with security setup
- [ ] Team reviewed recent security incidents
- [ ] Documentation updated with lessons learned
```

---

## Implementation Timeline

| Phase | Task | Duration | Depends On | Risk |
|-------|------|----------|------------|------|
| 1 | Install pre-commit hook | 5 min | None | None |
| 1 | Install gitleaks | 15 min | None | None |
| 1 | Create gitleaks config | 10 min | None | None |
| 1 | Run initial scan | 5 min | Gitleaks installed | None |
| 2 | Add secret-scan.yml | 10 min | None | None |
| 2 | Update ci.yml | 10 min | None | None |
| 2 | Test CI integration | 5 min | GitHub access | Low |
| 3 | Install git-secrets | 20 min | None | None |
| 3 | Create dev setup script | 20 min | None | None |
| 4 | Rotate MongoDB certs | 15 min | Certificate script | Medium |
| 4 | Document rotation | 10 min | Certs rotated | None |
| 4 | Cleanup git history | 30 min | Team coordination | HIGH |

**Total Time:** ~3 hours spread over 1 week

---

## Conflict Analysis

### ✅ No Conflicts Detected

**Existing CI/CD:**
- Bandit (code-quality.yml) - Scans Python code for security issues
- Trivy/Grype (container-security.yml) - Scans containers
- **NEW: Gitleaks/TruffleHog** - Scans git history for secrets
- **Result:** Complementary, no overlap

**Existing Hooks:**
- All hooks are samples (inactive)
- **NEW: pre-commit** - Fresh installation
- **Result:** No conflicts

**Existing Tools:**
- None installed
- **NEW: gitleaks, git-secrets** - First installation
- **Result:** No conflicts

---

## Testing Strategy

### Test 1: Pre-Commit Hook
```bash
# Should BLOCK
touch security/certs/mongodb/test.pem
git add security/certs/mongodb/test.pem
git commit -m "test"  # Should fail

# Should PASS
touch security/certs/mongodb/test.pem.example
git add security/certs/mongodb/test.pem.example
git commit -m "test"  # Should succeed
```

### Test 2: Gitleaks
```bash
# Scan current state
gitleaks detect --source . --verbose

# Expected findings:
# - security/certs/mongodb/mongodb.pem (historical)
# - Possibly hardcoded secrets from security audit
```

### Test 3: GitHub Actions
```bash
# Create test branch
git checkout -b test/secret-scanning

# Attempt to commit secret
echo "password='secret123456'" > test_secret.txt
git add test_secret.txt
git commit -m "test: secret detection"
git push origin test/secret-scanning

# Check GitHub Actions tab for failure
```

---

## Rollback Plan

If anything goes wrong:

```bash
# Remove pre-commit hook
rm .git/hooks/pre-commit

# Remove gitleaks config
rm .gitleaks.toml

# Uninstall gitleaks
sudo rm /usr/local/bin/gitleaks

# Revert GitHub Actions
git checkout .github/workflows/secret-scan.yml
git restore .github/workflows/ci.yml

# Remove git-secrets
git secrets --uninstall
```

---

## Success Metrics

After implementation, verify:

- [ ] Pre-commit hook blocks .pem files
- [ ] Gitleaks detects historical mongodb.pem
- [ ] GitHub Actions fail on secret commits
- [ ] .gitignore properly excludes cert directories
- [ ] Developer setup script works on fresh checkout
- [ ] All CI/CD workflows still pass
- [ ] No false positives blocking legitimate work

---

## Recommended Approach

**START HERE (30 minutes, zero risk):**

```bash
cd /home/rracine/hanalyx/openwatch

# 1. Install pre-commit hook (5 min)
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
if git diff --cached --name-only | grep -E '\.(pem|key)$' | grep -v '\.example'; then
    echo "ERROR: Attempting to commit private key!"
    exit 1
fi
EOF
chmod +x .git/hooks/pre-commit

# 2. Install gitleaks (15 min)
wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz
tar -xzf gitleaks_8.18.0_linux_x64.tar.gz
sudo mv gitleaks /usr/local/bin/

# 3. Create config (5 min)
# (Copy .gitleaks.toml from above)

# 4. Initial scan (5 min)
gitleaks detect --source . --verbose --report-path gitleaks-report.json

# 5. Review findings
cat gitleaks-report.json | jq '.'
```

**THEN:** Add CI/CD integration tomorrow (20 minutes)

**FINALLY:** Full git history cleanup when team is ready (coordinate timing)

---

**Generated:** October 15, 2025
**Status:** Ready to implement
**Reviewed:** Pre-implementation analysis complete
**Risk Level:** LOW (all phases independent, no conflicts)
