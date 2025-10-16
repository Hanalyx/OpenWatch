# Preventing Secrets from Being Committed to Git

## Critical Issue Found

The MongoDB private key was committed to git at:
```
security/certs/mongodb/mongodb.pem
```

This happened because the specific directory path wasn't properly excluded.

## Immediate Fix (3-Step Process)

### Step 1: Update .gitignore (Enhanced)

Add these specific patterns to `.gitignore`:

```bash
# MongoDB certificates - CRITICAL!
security/certs/mongodb/*.pem
security/certs/mongodb/*.key
security/certs/mongodb/*.crt
security/certs/mongodb/ca.*
security/certs/mongodb/server.*
security/certs/mongodb/client.*

# PostgreSQL certificates
security/certs/postgres/*.pem
security/certs/postgres/*.key
security/certs/postgres/*.crt

# Redis certificates
security/certs/redis/*.pem
security/certs/redis/*.key
security/certs/redis/*.crt
```

### Step 2: Remove Committed Secrets from Git History

⚠️ **WARNING:** This rewrites git history. Only do this if:
- Repository is private
- You can coordinate with all developers
- OR this is before public release

```bash
cd /home/rracine/hanalyx/openwatch

# Option A: BFG Repo-Cleaner (Recommended - Fast & Safe)
# Install BFG: https://rtyley.github.io/bfg-repo-cleaner/
java -jar bfg.jar --delete-files mongodb.pem
git reflog expire --expire=now --all
git gc --prune=now --aggressive

# Option B: git-filter-repo (Modern Alternative)
# Install: pip install git-filter-repo
git filter-repo --path security/certs/mongodb/mongodb.pem --invert-paths

# Option C: Manual filter-branch (Slower, works everywhere)
git filter-branch --force --index-filter \
  'git rm --cached --ignore-unmatch security/certs/mongodb/mongodb.pem' \
  --prune-empty --tag-name-filter cat -- --all

git reflog expire --expire=now --all
git gc --prune=now --aggressive
```

### Step 3: Force Push (Coordinate with Team!)

```bash
# Only after everyone has committed their work!
git push origin --force --all
git push origin --force --tags
```

## Prevention Strategy (Multi-Layer Defense)

### Layer 1: Enhanced .gitignore

Already updated - covers most cases.

### Layer 2: Pre-Commit Hook (Local Protection)

Create `.git/hooks/pre-commit`:

```bash
#!/bin/bash
# OpenWatch Pre-Commit Hook - Block Secrets

# Colors
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "Running pre-commit security checks..."

# Check for private keys
if git diff --cached --name-only | grep -E '\.(pem|key)$' | grep -v '\.example' | grep -v '\.template'; then
    echo -e "${RED}ERROR: Attempting to commit private key files!${NC}"
    echo "Blocked files:"
    git diff --cached --name-only | grep -E '\.(pem|key)$'
    echo ""
    echo "Add these to .gitignore or use .example versions"
    exit 1
fi

# Check for .env files
if git diff --cached --name-only | grep -E '^\.env$'; then
    echo -e "${RED}ERROR: Attempting to commit .env file with secrets!${NC}"
    exit 1
fi

# Check for common secret patterns in staged content
SECRETS_FOUND=$(git diff --cached -U0 | grep -E '(password|secret|api_key|private_key|token).*=.*["\047][^"\047]{8,}' || true)
if [ -n "$SECRETS_FOUND" ]; then
    echo -e "${YELLOW}WARNING: Potential secrets detected in commit:${NC}"
    echo "$SECRETS_FOUND"
    echo ""
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo "✓ Pre-commit security checks passed"
exit 0
```

Make it executable:
```bash
chmod +x .git/hooks/pre-commit
```

### Layer 3: git-secrets (AWS Tool - Industry Standard)

```bash
# Install git-secrets
git clone https://github.com/awslabs/git-secrets.git
cd git-secrets
sudo make install

# Configure for OpenWatch
cd /home/rracine/hanalyx/openwatch
git secrets --install
git secrets --register-aws  # AWS patterns

# Add custom patterns
git secrets --add '-----BEGIN (RSA |EC )?PRIVATE KEY-----'
git secrets --add 'password.*=.*["\047].*["\047]'
git secrets --add 'api[_-]?key.*=.*["\047].*["\047]'
git secrets --add 'secret.*=.*["\047].*["\047]'
git secrets --add 'AEGIS.*SECRET.*=.*'

# Scan entire repository
git secrets --scan
git secrets --scan-history
```

### Layer 4: GitHub Actions / GitLab CI (Server-Side Protection)

Create `.github/workflows/secret-scan.yml`:

```yaml
name: Secret Scanning

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0  # Full history for scanning

      - name: TruffleHog Secret Scan
        uses: trufflesecurity/trufflehog@main
        with:
          path: ./
          base: ${{ github.event.repository.default_branch }}
          head: HEAD

      - name: Gitleaks Secret Scan
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITLEAKS_LICENSE: ${{ secrets.GITLEAKS_LICENSE }}

      - name: Block on Secrets Found
        if: failure()
        run: |
          echo "::error::Secrets detected in commit! Review TruffleHog/Gitleaks output"
          exit 1
```

### Layer 5: Gitleaks Configuration (Local + CI)

Create `.gitleaks.toml`:

```toml
title = "OpenWatch Gitleaks Configuration"

[[rules]]
id = "private-key"
description = "Private Key"
regex = '''-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'''
tags = ["key", "private"]

[[rules]]
id = "mongodb-key"
description = "MongoDB Private Key"
path = '''security/certs/mongodb/.*\.(pem|key)'''
tags = ["mongodb", "certificate"]

[[rules]]
id = "jwt-private-key"
description = "JWT Private Key"
path = '''security/keys/.*private.*\.(pem|key)'''
tags = ["jwt", "private-key"]

[[rules]]
id = "env-file"
description = "Environment File with Secrets"
path = '''\.env$'''
tags = ["env", "config"]

[[rules]]
id = "hardcoded-password"
description = "Hardcoded Password"
regex = '''(?i)(password|passwd|pwd)\s*=\s*['"]['"].{8,}[''"]['']'''
tags = ["password", "hardcoded"]

[[rules]]
id = "hardcoded-api-key"
description = "Hardcoded API Key"
regex = '''(?i)(api[_-]?key|apikey|api[_-]?secret)\s*=\s*['"]['"].{16,}[''"]['']'''
tags = ["api-key", "hardcoded"]

[[rules]]
id = "aws-access-key"
description = "AWS Access Key"
regex = '''AKIA[0-9A-Z]{16}'''
tags = ["aws", "access-key"]

[[rules]]
id = "generic-secret"
description = "Generic Secret"
regex = '''(?i)secret.*=.*['"][''][a-zA-Z0-9]{16,}[''"]['']'''
tags = ["secret", "hardcoded"]

[allowlist]
description = "Allowlist for false positives"
paths = [
    '''\.env\.example$''',
    '''\.env\.template$''',
    '''\.sample$''',
    '''/test/''',
    '''/docs/examples/'''
]
```

Run locally:
```bash
# Install gitleaks
brew install gitleaks  # macOS
# or
wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz
tar -xzf gitleaks_8.18.0_linux_x64.tar.gz
sudo mv gitleaks /usr/local/bin/

# Scan repository
gitleaks detect --source . --verbose
gitleaks protect --staged --verbose  # Before commit
```

## Regenerate All Compromised Certificates

### MongoDB Certificates

Create `security/certs/mongodb/generate_certs.sh`:

```bash
#!/bin/bash
set -euo pipefail

CERT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DAYS_VALID=3650  # 10 years

echo "Generating new MongoDB certificates..."

# CA Certificate
openssl genrsa -out "${CERT_DIR}/ca.key" 4096
openssl req -new -x509 -days ${DAYS_VALID} -key "${CERT_DIR}/ca.key" \
    -out "${CERT_DIR}/ca.crt" \
    -subj "/C=US/ST=State/L=City/O=OpenWatch/OU=Security/CN=OpenWatch CA"

# Server Certificate
openssl genrsa -out "${CERT_DIR}/server.key" 4096
openssl req -new -key "${CERT_DIR}/server.key" \
    -out "${CERT_DIR}/server.csr" \
    -subj "/C=US/ST=State/L=City/O=OpenWatch/OU=Security/CN=mongodb"
openssl x509 -req -days ${DAYS_VALID} \
    -in "${CERT_DIR}/server.csr" \
    -CA "${CERT_DIR}/ca.crt" \
    -CAkey "${CERT_DIR}/ca.key" \
    -CAcreateserial \
    -out "${CERT_DIR}/server.crt"

# Combined PEM (for MongoDB)
cat "${CERT_DIR}/server.key" "${CERT_DIR}/server.crt" > "${CERT_DIR}/mongodb.pem"

# Client Certificate
openssl genrsa -out "${CERT_DIR}/client.key" 4096
openssl req -new -key "${CERT_DIR}/client.key" \
    -out "${CERT_DIR}/client.csr" \
    -subj "/C=US/ST=State/L=City/O=OpenWatch/OU=Security/CN=mongodb-client"
openssl x509 -req -days ${DAYS_VALID} \
    -in "${CERT_DIR}/client.csr" \
    -CA "${CERT_DIR}/ca.crt" \
    -CAkey "${CERT_DIR}/ca.key" \
    -CAcreateserial \
    -out "${CERT_DIR}/client.crt"

# Set permissions
chmod 600 "${CERT_DIR}"/*.key "${CERT_DIR}"/*.pem
chmod 644 "${CERT_DIR}"/*.crt

echo "✓ MongoDB certificates generated successfully"
echo ""
echo "Files created:"
ls -lh "${CERT_DIR}"/*.{key,crt,pem}
echo ""
echo "⚠️  IMPORTANT: These files are gitignored - do NOT commit!"
```

Run it:
```bash
chmod +x security/certs/mongodb/generate_certs.sh
./security/certs/mongodb/generate_certs.sh
```

## Verify Protection

After implementing all layers:

```bash
# Test 1: Try to commit a .pem file (should fail)
touch test_secret.pem
git add test_secret.pem
git commit -m "test"  # Should be blocked by pre-commit hook

# Test 2: Check .gitignore effectiveness
git check-ignore security/certs/mongodb/mongodb.pem
# Should output: security/certs/mongodb/mongodb.pem

# Test 3: Scan for existing secrets
gitleaks detect --source . --verbose

# Test 4: Check git-secrets
git secrets --scan

# Clean up test
git reset HEAD test_secret.pem
rm test_secret.pem
```

## Incident Response Checklist

If a secret was committed:

- [ ] Immediately regenerate the compromised secret/certificate
- [ ] Update all systems using the old secret
- [ ] Verify no production systems still using old secret
- [ ] Remove from git history (see Step 2 above)
- [ ] Force push (coordinate with team)
- [ ] Update .gitignore to prevent recurrence
- [ ] Install pre-commit hooks on all developer machines
- [ ] Document incident in security log
- [ ] Review access logs for unauthorized use of old secret

## Best Practices Summary

1. **Never commit**:
   - Private keys (*.pem, *.key)
   - Certificates (except public certs if needed)
   - .env files
   - Database credentials
   - API keys
   - Passwords

2. **Always use**:
   - .gitignore for file patterns
   - Pre-commit hooks for local protection
   - git-secrets or gitleaks for scanning
   - CI/CD secret scanning
   - Environment variables for secrets

3. **Alternative: Secret Management**:
   - HashiCorp Vault
   - AWS Secrets Manager
   - Azure Key Vault
   - Google Secret Manager
   - Kubernetes Secrets (for k8s deployments)

## Tools Summary

| Tool | Purpose | When to Use |
|------|---------|-------------|
| .gitignore | Prevent file types from being tracked | Always |
| Pre-commit hook | Block secrets before commit | Local development |
| git-secrets | AWS-focused secret scanning | All commits |
| Gitleaks | Comprehensive secret detection | CI/CD + Local |
| TruffleHog | Deep history scanning | CI/CD |
| BFG Repo-Cleaner | Remove secrets from history | After incident |

## Automated Setup Script

Create this as `scripts/setup-secret-protection.sh`:

```bash
#!/bin/bash
set -euo pipefail

echo "Setting up secret protection for OpenWatch..."

# 1. Install pre-commit hook
cat > .git/hooks/pre-commit << 'EOFHOOK'
#!/bin/bash
if git diff --cached --name-only | grep -E '\.(pem|key)$' | grep -v '\.example'; then
    echo "ERROR: Attempting to commit private key!"
    exit 1
fi
exit 0
EOFHOOK
chmod +x .git/hooks/pre-commit

# 2. Install gitleaks config
cp .gitleaks.toml .gitleaks.toml.backup 2>/dev/null || true
# (gitleaks config already shown above)

# 3. Test protection
echo "✓ Secret protection installed"
echo "Run: gitleaks detect --source . --verbose"
```

---

**Last Updated:** October 15, 2025
**Status:** Ready to implement
**Priority:** CRITICAL - Implement immediately
