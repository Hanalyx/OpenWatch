# OpenWatch Scripts

Utility scripts for OpenWatch setup, development, deployment, and maintenance.

## 📁 Directory Structure

```
scripts/
├── Production Scripts
│   ├── generate-certs.sh                   # SSL certificate generation (dev/test only)
│   ├── create-admin.sh                     # Create admin user
│   ├── production-health-check.sh          # Health verification for production
│   └── install-systemd-services.sh         # Install systemd service units
│
├── Development Scripts
│   ├── quality-check.sh                    # Pre-commit code quality validation
│   ├── setup-quality-tools.sh              # Install code quality tools
│   ├── codeql_fix_log_injection.py         # Auto-fix CodeQL log injection alerts
│   ├── codeql_fix_unused_imports.py        # Auto-fix CodeQL unused import alerts
│   └── run-e2e-tests.sh                    # End-to-end test execution
│
├── Security Scripts
│   ├── risk_assessment.py                  # Calculate risk scores for security alerts
│   └── security-fixes/
│       ├── apply-critical-fixes.sh         # Apply automated security fixes
│       └── README.md                        # Security fixes documentation
│
├── Utility Scripts
│   ├── utilities/
│   │   ├── clear_rate_limits.py            # Clear rate limit blocks
│   │   └── rate_limit_monitor.py           # Monitor rate limiting metrics
│   └── examples/
│       └── group_scan_api_usage.py         # Group Scan API example client
│
└── README.md                                # This file
```

---

## 🚀 Production Scripts

### generate-certs.sh
Generate self-signed SSL certificates for **development and testing only**.

**⚠️ WARNING**: Do NOT use self-signed certificates in production. Obtain certificates from a trusted Certificate Authority (CA).

**Usage**:
```bash
./scripts/generate-certs.sh
```

**What it does**:
- Creates self-signed SSL certificates
- Generates Diffie-Hellman parameters (2048-bit)
- Creates CA, server, and client certificates
- Sets appropriate file permissions

**Configuration** (via environment variables):
```bash
export CERT_COUNTRY="US"
export CERT_STATE="California"
export CERT_CITY="San Francisco"
export CERT_ORG="MyOrganization"
export CERT_OU="Engineering"
export CERT_CN="localhost"

./scripts/generate-certs.sh
```

---

### create-admin.sh
Create administrative user interactively.

**Usage**:
```bash
./scripts/create-admin.sh
```

**What it does**:
- Prompts for username, email, and password
- Assigns 'admin' role
- Creates user in PostgreSQL database
- Hashes password with Argon2id

**Security**:
- ✅ Password passed via stdin (NOT environment variables)
- ✅ No password exposure in `ps aux` or Docker logs
- ✅ Argon2id hashing with secure parameters

---

### production-health-check.sh
Comprehensive health verification for production deployments.

**Usage**:
```bash
./scripts/production-health-check.sh
```

**What it checks**:
- Container status (all services running)
- Service health endpoints (backend, frontend, worker, celery-beat)
- Database connectivity (PostgreSQL, MongoDB)
- Redis availability
- SSL certificate validity
- Log file access and rotation

---

### install-systemd-services.sh
Install and configure systemd service units for production deployment.

**Usage**:
```bash
sudo ./scripts/install-systemd-services.sh
```

**What it does**:
- Copies systemd service files to `/etc/systemd/system/`
- Reloads systemd daemon
- Enables services for automatic startup
- Starts OpenWatch services

---

## 💻 Development Scripts

### quality-check.sh
Pre-commit code quality validation.

**Usage**:
```bash
./scripts/quality-check.sh
```

**What it checks**:
- Large files (>1MB)
- Debug code (console.log, debugger, pdb)
- Potential secrets (passwords, API keys, tokens)
- File size limits

**Exit Codes**:
- `0` - All checks passed
- `1` - Quality issues found (commit blocked)

---

### setup-quality-tools.sh
Install code quality and development tools.

**Usage**:
```bash
./scripts/setup-quality-tools.sh
```

**What it installs**:
- Python tools: Black, Flake8, MyPy, Bandit, isort
- Node.js tools: ESLint, Prettier, TypeScript
- Pre-commit framework
- Git hooks

---

### codeql_fix_log_injection.py
Auto-fix CodeQL log injection security alerts.

**Usage**:
```bash
./scripts/codeql_fix_log_injection.py
```

**What it does**:
- Scans Python files for unsafe logging patterns
- Adds `sanitize_for_log()` wrapper to user-controlled inputs
- Prevents log injection attacks (OWASP A09:2021)

**Example Fix**:
```python
# Before:
logger.info(f"User logged in: {username}")

# After:
logger.info(f"User logged in: {sanitize_for_log(username)}")
```

---

### codeql_fix_unused_imports.py
Auto-fix CodeQL unused import alerts.

**Usage**:
```bash
./scripts/codeql_fix_unused_imports.py
```

**What it does**:
- Removes unused import statements
- Cleans up code bloat
- Improves maintainability

---

### run-e2e-tests.sh
Full environment setup and end-to-end test execution.

**Usage**:
```bash
./scripts/run-e2e-tests.sh
```

**What it does**:
- Starts Docker Compose environment
- Waits for all services to be healthy
- Runs Playwright E2E tests
- Cleans up test environment

**Test Coverage**:
- User authentication flow
- Host management
- Scan execution
- API endpoints

---

## 🔒 Security Scripts

### risk_assessment.py
Calculate risk scores for GitHub security alerts using configurable weights.

**Usage**:
```bash
./scripts/risk_assessment.py
```

**What it calculates**:
- Severity score (CVSS-based)
- Exploitability score
- Affected components score
- Overall risk priority

---

### security-fixes/apply-critical-fixes.sh
Apply automated security fixes for known vulnerabilities.

**Usage**:
```bash
./scripts/security-fixes/apply-critical-fixes.sh
```

**What it does**:
- Updates vulnerable packages
- Applies security patches
- Verifies package integrity

**⚠️ NOTE**: Review `security-fixes/README.md` before applying fixes.

---

## 🛠️ Utility Scripts

### utilities/clear_rate_limits.py
Clear rate limit blocks from in-memory store.

**Usage**:
```bash
docker exec openwatch-backend python3 /app/scripts/utilities/clear_rate_limits.py
# OR
python3 scripts/utilities/clear_rate_limits.py
```

**What it does**:
- Resets all IP blocks
- Clears request histories
- Resets error counters

---

### utilities/rate_limit_monitor.py
Real-time monitoring of rate limiting metrics.

**Usage**:
```bash
python3 scripts/utilities/rate_limit_monitor.py
```

**What it monitors**:
- Blocked IPs
- Request patterns
- Rate limit violations
- Error rates

---

### examples/group_scan_api_usage.py
Example client for Group Scan API demonstrating correct usage patterns.

**Usage**:
```bash
export OPENWATCH_API_TOKEN="your_token_here"
python3 scripts/examples/group_scan_api_usage.py
```

**What it demonstrates**:
- Group scan API endpoints
- Authentication with JWT
- Progress tracking
- Error handling

---

## 🎯 Common Workflows

### Docker-First Development (RECOMMENDED)

OpenWatch uses a **Docker-first architecture**. Always use Docker Compose for development:

```bash
# Start all services
./start-openwatch.sh --runtime docker --build

# View logs
docker logs openwatch-backend --tail 100 --follow

# Stop services
./stop-openwatch.sh
```

**See `docs/DEVELOPER_SETUP.md` for complete development workflow.**

---

### First Time Setup

```bash
# 1. Generate SSL certificates (dev only)
./scripts/generate-certs.sh

# 2. Start services
./start-openwatch.sh --runtime docker --build

# 3. Create admin user
./scripts/create-admin.sh

# 4. Verify health
./scripts/production-health-check.sh
```

---

### Code Quality Workflow

```bash
# 1. Install quality tools (one-time)
./scripts/setup-quality-tools.sh

# 2. Run quality checks before committing
./scripts/quality-check.sh

# 3. Fix CodeQL findings (if any)
./scripts/codeql_fix_log_injection.py
./scripts/codeql_fix_unused_imports.py
```

---

### Production Deployment

```bash
# 1. Verify environment
./scripts/production-health-check.sh

# 2. Install systemd services
sudo ./scripts/install-systemd-services.sh

# 3. Verify all services running
systemctl status openwatch-*
```

---

## 🔐 Security Best Practices

### Credential Handling

✅ **DO**:
- Use `create-admin.sh` for admin user creation (passwords via stdin)
- Store secrets in environment variables (`.env` file)
- Use strong passwords (12+ characters, complexity)

❌ **DON'T**:
- Pass passwords via command-line arguments (visible in `ps aux`)
- Hardcode credentials in scripts
- Commit `.env` files to git

### Certificate Management

✅ **DO**:
- Use `generate-certs.sh` for development/testing only
- Obtain certificates from trusted CA for production (Let's Encrypt, DigiCert, etc.)
- Monitor certificate expiration dates

❌ **DON'T**:
- Use self-signed certificates in production
- Share private keys across environments
- Commit certificate private keys to git

---

## 📝 Environment Variables

Scripts expect these variables (see `.env.example`):

```bash
# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/openwatch
MONGODB_URL=mongodb://localhost:27017/openwatch_rules

# Redis
REDIS_URL=redis://localhost:6379/0

# Application
SECRET_KEY=<generate with: openssl rand -hex 32>
MASTER_KEY=<generate with: openssl rand -hex 32>

# Frontend
REACT_APP_API_URL=http://localhost:8000
```

---

## 🚨 Removed/Deprecated Scripts

The following scripts have been **removed or deprecated**:

| Script | Reason | Alternative |
|--------|--------|-------------|
| `run-local.sh` | ❌ SQLite architecture incompatible with production | Use `./start-openwatch.sh --runtime docker` |
| `setup.sh` | ⚠️ Never existed (was referenced but not implemented) | See "First Time Setup" above |
| `setup-dev.sh` | ⚠️ Never existed (was referenced but not implemented) | Use `./scripts/setup-quality-tools.sh` |
| `setup-local-db.sh` | ⚠️ Never existed (was referenced but not implemented) | Database initialized automatically in Docker |
| `check-environment.sh` | ⚠️ Never existed (was referenced but not implemented) | Use `./scripts/production-health-check.sh` |
| `verify-setup.sh` | ⚠️ Never existed (was referenced but not implemented) | Use `./scripts/run-e2e-tests.sh` |

---

## 🐛 Troubleshooting

### Permission Issues

```bash
chmod +x scripts/*.sh
chmod +x scripts/utilities/*.py
chmod +x scripts/examples/*.py
```

### Database Connection Errors

Check PostgreSQL/MongoDB services:
```bash
docker ps | grep -E "postgres|mongo"
docker logs openwatch-db --tail 50
docker logs openwatch-mongodb --tail 50
```

### Certificate Errors

Regenerate certificates:
```bash
./scripts/generate-certs.sh
./stop-openwatch.sh
./start-openwatch.sh --runtime docker
```

### Rate Limiting Issues

Clear rate limits:
```bash
docker exec openwatch-backend python3 /app/scripts/utilities/clear_rate_limits.py
docker restart openwatch-backend
```

---

## 📚 Additional Documentation

- **Development Guide**: `docs/DEVELOPER_SETUP.md`
- **Security Audit**: `docs/SCRIPTS_SECURITY_AUDIT.md`
- **AI Development Guide**: `CLAUDE.md`
- **Architecture Overview**: `docs/COMPREHENSIVE_SECURITY_AND_CODE_ANALYSIS.md`

---

## ⚠️ Important Notes

1. **Docker-First**: OpenWatch is designed to run in Docker containers. Local execution without Docker is not supported.

2. **Self-Signed Certificates**: The `generate-certs.sh` script creates self-signed certificates suitable for development/testing ONLY. For production, obtain certificates from a trusted Certificate Authority.

3. **Credential Security**: All scripts follow secure credential handling practices. Passwords are passed via stdin, not environment variables.

4. **Script Versioning**: Scripts are version-controlled in git. Check commit history for changes.

5. **Security Scanning**: All scripts are scanned with Bandit (Python) and ShellCheck (Bash) for security vulnerabilities.

---

**Last Updated**: 2025-11-02
**Maintained By**: OpenWatch Security Team
**Security Audit**: See `docs/SCRIPTS_SECURITY_AUDIT.md`
