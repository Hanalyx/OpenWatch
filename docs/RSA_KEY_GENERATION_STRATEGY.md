# RSA Key Generation Strategy for Compliance Bundle Signatures

**Document Version:** 1.0
**Last Updated:** 2025-10-24
**Status:** Active

---

## Table of Contents

1. [Overview](#overview)
2. [Cryptographic Foundation](#cryptographic-foundation)
3. [Key Roles and Responsibilities](#key-roles-and-responsibilities)
4. [Development Environment](#development-environment)
5. [Production Environment](#production-environment)
6. [Key Lifecycle Management](#key-lifecycle-management)
7. [Security Best Practices](#security-best-practices)
8. [Troubleshooting](#troubleshooting)
9. [Appendix](#appendix)

---

## Overview

OpenWatch uses **RSA-PSS** (RSA Probabilistic Signature Scheme) to cryptographically sign compliance rule bundles. This document defines the strategy for generating, managing, and rotating RSA keypairs across development and production environments.

### Security Objectives

| Objective | Description |
|-----------|-------------|
| **Authenticity** | Verify bundle originated from a trusted source |
| **Integrity** | Detect tampering or corruption during transmission |
| **Non-repudiation** | Signer cannot deny having signed the bundle |
| **Trust Management** | Control which signers are trusted by OpenWatch instances |

### Signature Algorithm

```
Algorithm:    RSA-PSS (PKCS#1 v2.1)
Padding:      PSS with MGF1
Hash:         SHA-512 (primary), SHA-256/384 (supported)
Salt Length:  Maximum (PSS.MAX_LENGTH)
Encoding:     Hexadecimal
```

---

## Cryptographic Foundation

### RSA-PSS vs RSA-PKCS#1 v1.5

OpenWatch uses **RSA-PSS** instead of the older RSA-PKCS#1 v1.5 because:

- **Provable Security**: RSA-PSS has a formal security proof
- **Randomized Padding**: Each signature is unique (prevents certain attacks)
- **Modern Standard**: Recommended by NIST, FIPS 186-4, and RFC 8017

### Key Components

**Private Key (Secret)**
- Used to **SIGN** compliance bundles
- Must remain confidential and secure
- Compromise allows attacker to sign malicious bundles
- Format: PEM-encoded PKCS#8

**Public Key (Trusted)**
- Used to **VERIFY** bundle signatures
- Distributed with OpenWatch deployments
- Safe to commit to version control
- Format: PEM-encoded X.509 SubjectPublicKeyInfo

### Trust Model

```
┌─────────────────────────────────────┐
│   Bundle Publisher                  │
│   (ComplianceAsCode, Hanalyx, etc.) │
└─────────────┬───────────────────────┘
              │ Signs with Private Key
              ▼
      ┌───────────────┐
      │ Signed Bundle │
      │ + Signature   │
      └───────┬───────┘
              │ Distributed
              ▼
┌─────────────────────────────────────┐
│   OpenWatch Instance                │
│   - Has trusted public keys         │
│   - Verifies signature on upload    │
│   - Rejects untrusted/invalid sigs  │
└─────────────────────────────────────┘
```

---

## Key Roles and Responsibilities

### Bundle Publishers

Organizations that create and sign compliance rule bundles:

| Publisher | Use Case | Example |
|-----------|----------|---------|
| **ComplianceAsCode Project** | Upstream official SCAP content | `complianceascode.pem` |
| **Hanalyx Security Team** | Internal/custom rule bundles | `hanalyx-internal.pem` |
| **Customer Security Team** | Customer-specific compliance rules | `acmecorp-custom.pem` |

**Responsibilities:**
- Generate and securely store private keys
- Sign all published bundles before distribution
- Rotate keys according to policy (annually or on compromise)
- Maintain public key distribution channels

### OpenWatch Administrators

System administrators deploying OpenWatch:

**Responsibilities:**
- Configure signature verification mode (dev/production)
- Manage trusted public keys in deployment
- Monitor signature verification logs
- Respond to key compromise incidents

---

## Development Environment

### Purpose

Development mode allows rapid iteration and testing without strict signature requirements. Unsigned bundles are permitted with warnings.

### Key Generation (Development)

**Who Generates:** Individual developers, QA engineers, CI/CD pipelines

**Command:**
```bash
# Navigate to project root
cd /path/to/hanalyx

# Generate development keypair
python3 backend/security/generate_signing_keypair.py \
    --name dev-testing \
    --signer "Your Name - Development" \
    --key-size 2048
```

**Parameters:**
- `--name`: Identifier for the keypair (e.g., `dev-testing`, `ci-pipeline`)
- `--signer`: Human-readable signer name (appears in bundle manifests)
- `--key-size`: Key strength in bits (2048 for dev, 4096 for production)

**Output:**
```
Generating 2048-bit RSA keypair...
✅ Keypair generated successfully

Private key: backend/security/signing_keys/dev-testing_private.pem
Public key:  backend/security/signing_keys/dev-testing_public.pem
Key ID:      a3f2c8b941e6d7f2

⚠️  IMPORTANT: Keep the private key secure!
   - Never commit to version control
   - Set permissions: chmod 600 dev-testing_private.pem
   - Store securely or delete after testing
```

### File Structure

```
backend/security/
├── signing_keys/              # Private keys (in .gitignore)
│   ├── dev-testing_private.pem    ← Secret (600 permissions)
│   └── dev-testing_public.pem     ← Can be shared
│
├── compliance_bundle_keys/    # Trusted public keys (committed to git)
│   ├── complianceascode.pem      ← Official ComplianceAsCode
│   └── dev-testing.pem           ← Your dev key (optional)
│
└── generate_signing_keypair.py
```

### Trust Configuration (Development)

**Option 1: Copy public key to trusted directory**
```bash
# Make your dev key trusted
cp backend/security/signing_keys/dev-testing_public.pem \
   backend/security/compliance_bundle_keys/dev-testing.pem
```

**Option 2: Use permissive mode (recommended for dev)**
```yaml
# docker-compose.yml
environment:
  REQUIRE_BUNDLE_SIGNATURE: "false"  # Allow unsigned bundles
```

### Docker Configuration (Development)

```yaml
# docker-compose.yml
services:
  backend:
    environment:
      # Signature Verification - Development Mode
      REQUIRE_BUNDLE_SIGNATURE: "${REQUIRE_BUNDLE_SIGNATURE:-false}"
    volumes:
      # Mount trusted public keys (read-only)
      - ./backend/security/compliance_bundle_keys:/app/security/compliance_bundle_keys:ro
```

### Behavior Matrix (Development Mode)

| Bundle State | `REQUIRE_BUNDLE_SIGNATURE=false` | `REQUIRE_BUNDLE_SIGNATURE=true` |
|--------------|----------------------------------|----------------------------------|
| ✅ Unsigned | **ALLOWED** (⚠️ warning logged) | ❌ **REJECTED** |
| ✅ Signed + Trusted | **ACCEPTED** (ℹ️ info logged) | ✅ **ACCEPTED** |
| ⚠️ Signed + Untrusted | **ALLOWED** (⚠️ warning logged) | ❌ **REJECTED** |
| ❌ Invalid Signature | **ALLOWED** (⚠️ warning logged) | ❌ **REJECTED** |

### Signing Bundles (Development)

```bash
# Build and sign a compliance bundle
SIGN_BUNDLES=true \
PRIVATE_KEY_PATH=backend/security/signing_keys/dev-testing_private.pem \
SIGNER_NAME="Your Name - Development" \
./scripts/build_compliance_rules.sh rhel8

# Output: openwatch-rhel8-bundle_v1.0.4.tar.gz (signed)
```

---

## Production Environment

### Purpose

Production mode enforces strict signature verification. Only bundles signed by trusted keys are accepted, ensuring supply chain security.

### Key Generation (Production)

**Who Generates:**
- **Option A**: Security team on isolated build server
- **Option B**: CI/CD pipeline with secrets management
- **Option C**: Hardware Security Module (HSM)

#### Option A: Isolated Build Server

**Command:**
```bash
# On secure build server (no network access)
python3 backend/security/generate_signing_keypair.py \
    --name complianceascode \
    --signer "ComplianceAsCode Project <security@complianceascode.io>" \
    --key-size 4096
```

**Secure the Private Key:**
```bash
# Set restrictive permissions (owner read/write only)
chmod 600 backend/security/signing_keys/complianceascode_private.pem

# Verify permissions
ls -la backend/security/signing_keys/complianceascode_private.pem
# Output: -rw------- 1 user user 3272 Oct 24 10:00 complianceascode_private.pem
```

**Optional: Encrypt Private Key**
```bash
# Encrypt with AES-256 passphrase
openssl rsa -aes256 \
    -in complianceascode_private.pem \
    -out complianceascode_private_encrypted.pem

# Decrypt when needed for signing
openssl rsa \
    -in complianceascode_private_encrypted.pem \
    -out complianceascode_private.pem
```

#### Option B: CI/CD with Secrets Management

**GitHub Actions Example:**
```yaml
# .github/workflows/build-bundles.yml
name: Build Signed Compliance Bundles

on:
  push:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Retrieve Signing Key from Secrets
        env:
          PRIVATE_KEY: ${{ secrets.COMPLIANCE_SIGNING_KEY }}
        run: |
          echo "$PRIVATE_KEY" > /tmp/signing_key.pem
          chmod 600 /tmp/signing_key.pem

      - name: Build and Sign Bundles
        env:
          SIGN_BUNDLES: "true"
          PRIVATE_KEY_PATH: "/tmp/signing_key.pem"
        run: |
          ./scripts/build_compliance_rules.sh rhel8

      - name: Clean Up Key
        if: always()
        run: shred -vfz /tmp/signing_key.pem
```

**Store Secret:**
```bash
# Add to GitHub Secrets
# Settings → Secrets → Actions → New repository secret
# Name: COMPLIANCE_SIGNING_KEY
# Value: <paste contents of complianceascode_private.pem>
```

#### Option C: Hardware Security Module (HSM)

**Commercial HSM Options:**
- AWS CloudHSM
- Azure Dedicated HSM
- YubiKey HSM
- Thales Luna HSM

**Integration Example (AWS KMS):**
```python
import boto3

# Use AWS KMS to sign bundle hash
kms = boto3.client('kms')
response = kms.sign(
    KeyId='arn:aws:kms:us-east-1:123456789:key/abc-def',
    Message=bundle_hash,
    MessageType='DIGEST',
    SigningAlgorithm='RSASSA_PSS_SHA_512'
)
signature = response['Signature']
```

### Public Key Distribution (Production)

**Step 1: Extract Public Key**
```bash
# If not already generated by generate_signing_keypair.py
openssl rsa -in complianceascode_private.pem \
            -pubout \
            -out complianceascode_public.pem
```

**Step 2: Calculate Key ID**
```bash
# Key ID is first 16 chars of SHA-256 hash of public key
openssl rsa -pubin -in complianceascode_public.pem \
            -outform DER 2>/dev/null | \
    sha256sum | \
    cut -c1-16
# Output: a3f2c8b941e6d7f2
```

**Step 3: Distribute via Git**
```bash
# Copy to trusted keys directory
cp complianceascode_public.pem \
   backend/security/compliance_bundle_keys/complianceascode.pem

# Commit to version control (public keys are safe)
git add backend/security/compliance_bundle_keys/complianceascode.pem
git commit -m "feat: Add ComplianceAsCode official signing key"
git push
```

**Step 4: Docker Deployment**
```yaml
# docker-compose.yml (Production)
services:
  backend:
    environment:
      REQUIRE_BUNDLE_SIGNATURE: "true"  # Strict mode
    volumes:
      # Mount trusted keys into container
      - ./backend/security/compliance_bundle_keys:/app/security/compliance_bundle_keys:ro
```

### Production Signing Process

**Automated Build Pipeline:**
```bash
#!/bin/bash
# scripts/sign_and_publish_bundle.sh

set -euo pipefail

PRODUCT="rhel8"
VERSION="1.0.4"
PRIVATE_KEY="/secure/vault/complianceascode_private.pem"

# Verify private key exists and has correct permissions
if [ ! -f "$PRIVATE_KEY" ]; then
    echo "ERROR: Private key not found at $PRIVATE_KEY"
    exit 1
fi

if [ "$(stat -c %a "$PRIVATE_KEY")" != "600" ]; then
    echo "ERROR: Private key has insecure permissions"
    exit 1
fi

# Build signed bundle
SIGN_BUNDLES=true \
PRIVATE_KEY_PATH="$PRIVATE_KEY" \
SIGNER_NAME="ComplianceAsCode Project" \
./scripts/build_compliance_rules.sh "$PRODUCT"

# Verify signature before publishing
BUNDLE="openwatch-${PRODUCT}-bundle_v${VERSION}.tar.gz"
echo "Verifying signature on $BUNDLE..."

# Upload to distribution server
scp "$BUNDLE" release-server:/var/www/bundles/

echo "✅ Bundle signed and published successfully"
```

---

## Key Lifecycle Management

### Key Rotation Schedule

| Scenario | Rotation Frequency | Priority |
|----------|-------------------|----------|
| **Normal Operations** | Annually | Medium |
| **Security Audit Recommendation** | As needed | High |
| **Key Compromise** | Immediately | Critical |
| **Regulatory Requirement** | Per policy | High |
| **Algorithm Deprecation** | Before EOL | Critical |

### Rotation Procedure

**Step 1: Generate New Keypair**
```bash
# Generate new keypair with year suffix
python3 backend/security/generate_signing_keypair.py \
    --name complianceascode-2026 \
    --signer "ComplianceAsCode Project" \
    --key-size 4096
```

**Step 2: Maintain Backward Compatibility**
```bash
# Rename old public key (keep for verifying old bundles)
cp backend/security/compliance_bundle_keys/complianceascode.pem \
   backend/security/compliance_bundle_keys/complianceascode-2025.pem

# Install new public key
cp complianceascode-2026_public.pem \
   backend/security/compliance_bundle_keys/complianceascode-2026.pem

# Create symlink for current key
ln -sf complianceascode-2026.pem \
       backend/security/compliance_bundle_keys/complianceascode.pem
```

**Step 3: Update Signing Infrastructure**
```bash
# Update CI/CD secrets with new private key
# GitHub: Settings → Secrets → Update COMPLIANCE_SIGNING_KEY

# Update build scripts to use new key
export PRIVATE_KEY_PATH="./signing_keys/complianceascode-2026_private.pem"
```

**Step 4: Re-sign Critical Bundles**
```bash
# Re-sign latest stable releases with new key
for product in rhel8 rhel9 ubuntu2204; do
    SIGN_BUNDLES=true \
    PRIVATE_KEY_PATH="$PRIVATE_KEY_PATH" \
    ./scripts/build_compliance_rules.sh "$product"
done
```

**Step 5: Communicate to Users**
```markdown
# SECURITY ADVISORY

ComplianceAsCode has rotated its bundle signing key as part of
scheduled annual maintenance.

## Action Required

Update your OpenWatch installation to trust the new public key:

```bash
git pull origin main
docker-compose restart backend
```

## Key Details

- Old Key ID: a3f2c8b941e6d7f2 (still trusted for existing bundles)
- New Key ID: f7e1d9c3a8b4f2e6
- Effective Date: 2026-01-01

Old bundles remain verifiable. No re-download required.
```

### Key Revocation (Compromise Response)

**Immediate Actions:**
```bash
# 1. Remove compromised public key from all deployments
rm backend/security/compliance_bundle_keys/complianceascode-compromised.pem

# 2. Generate new emergency keypair
python3 backend/security/generate_signing_keypair.py \
    --name complianceascode-emergency-$(date +%Y%m%d) \
    --signer "ComplianceAsCode Project - Emergency Key" \
    --key-size 4096

# 3. Distribute new public key immediately
git add backend/security/compliance_bundle_keys/complianceascode-emergency-*.pem
git commit -m "SECURITY: Revoke compromised key, add emergency key"
git push

# 4. Notify all users
echo "SECURITY INCIDENT: Key compromise detected. Update immediately."
```

**Post-Incident:**
```bash
# 5. Audit all bundles signed with compromised key
grep -r "compromised-key-id" /var/www/bundles/

# 6. Re-sign all bundles with new key
for bundle in /var/www/bundles/*.tar.gz; do
    echo "Re-signing $bundle..."
    # Extract, re-sign, re-package
done

# 7. Forensic analysis
# - When was key compromised?
# - What bundles were signed during compromise window?
# - Were any malicious bundles distributed?
```

---

## Security Best Practices

### Private Key Storage

#### ✅ DO

- Store private keys with **600 permissions** (owner read/write only)
- Use **encrypted filesystems** for key storage
- Store in **secrets management systems** (Vault, AWS Secrets Manager)
- Use **Hardware Security Modules (HSM)** for high-security environments
- **Encrypt private keys** with strong passphrases
- **Back up private keys** securely (encrypted, offline)
- **Audit access** to private key storage

#### ❌ DON'T

- **NEVER commit private keys** to version control
- **NEVER share private keys** via email, Slack, etc.
- **NEVER store unencrypted keys** on network shares
- **NEVER use the same key** across dev/staging/production
- **NEVER leave private keys** on build servers after use

### Access Control

**Principle of Least Privilege:**
```bash
# Only security team can access signing keys
chown root:security-team complianceascode_private.pem
chmod 640 complianceascode_private.pem

# Audit who accessed the key
ausearch -f complianceascode_private.pem
```

**Role-Based Access:**
| Role | Private Key Access | Public Key Access | Signing Authority |
|------|-------------------|-------------------|-------------------|
| **Security Engineer** | ✅ Yes | ✅ Yes | ✅ Yes |
| **Build Pipeline** | ✅ Yes (via secrets) | ✅ Yes | ✅ Yes (automated) |
| **DevOps Engineer** | ❌ No | ✅ Yes | ❌ No |
| **Developer** | ❌ No | ✅ Yes | ❌ No |
| **End User** | ❌ No | ✅ Yes (implicit) | ❌ No |

### Key Strength

**Recommended Key Sizes:**
| Use Case | Key Size | Security Level | Performance |
|----------|----------|----------------|-------------|
| **Development/Testing** | 2048-bit | Adequate | Fast |
| **Production (Current)** | 4096-bit | Strong | Moderate |
| **High Security** | 8192-bit | Very Strong | Slow |

**Algorithm Evolution:**
```
Current (2025):     RSA-PSS with SHA-512
Transitioning:      Consider post-quantum algorithms
Future (2030+):     CRYSTALS-Dilithium, Falcon, SPHINCS+
```

### Monitoring and Auditing

**Log Signature Verification Events:**
```python
# backend/app/services/compliance_rules_signature_service.py

logger.info(
    f"Bundle signature verification PASSED: "
    f"bundle={bundle_name}, "
    f"signer={signer}, "
    f"key_id={key_id[:16]}, "
    f"algorithm={algorithm}"
)
```

**Alert on Failures:**
```python
if not signature_check.passed:
    logger.error(
        f"🚨 SECURITY ALERT: Bundle signature verification FAILED: "
        f"bundle={bundle_name}, "
        f"reason={signature_check.message}, "
        f"severity={signature_check.severity}"
    )
    # Send to SIEM, PagerDuty, etc.
    send_security_alert(signature_check)
```

**Compliance Reporting:**
```sql
-- Query signature verification events
SELECT
    timestamp,
    bundle_name,
    signer,
    verification_result,
    failure_reason
FROM signature_verification_logs
WHERE timestamp > NOW() - INTERVAL '30 days'
ORDER BY timestamp DESC;
```

---

## Troubleshooting

### Problem: "No signature provided"

**Symptom:**
```
Error: Upload failed: No signature provided
```

**Cause:** Bundle is unsigned, but signature verification is required.

**Solution:**
```bash
# Option 1: Disable signature requirement (dev only)
export REQUIRE_BUNDLE_SIGNATURE=false
docker-compose restart backend

# Option 2: Sign the bundle
SIGN_BUNDLES=true \
PRIVATE_KEY_PATH=./signing_keys/dev_private.pem \
./scripts/build_compliance_rules.sh rhel8
```

---

### Problem: "Signature verification failed: Invalid signature"

**Symptom:**
```
ERROR: Signature verification failed: Invalid signature
```

**Possible Causes:**
1. Bundle was tampered with after signing
2. Wrong public key used for verification
3. Bundle corruption during transmission

**Debugging:**
```bash
# 1. Verify bundle integrity
sha512sum openwatch-rhel8-bundle_v1.0.4.tar.gz

# 2. Extract and inspect manifest
tar -xzf openwatch-rhel8-bundle_v1.0.4.tar.gz manifest.json
cat manifest.json | jq '.signature'

# 3. Check if public key matches key_id
cd backend/security/compliance_bundle_keys
for key in *.pem; do
    echo "Checking $key..."
    openssl rsa -pubin -in "$key" -outform DER 2>/dev/null | \
        sha256sum | cut -c1-16
done

# 4. Re-download bundle (may be corrupted)
wget https://releases.complianceascode.io/bundles/rhel8/latest.tar.gz
```

---

### Problem: "Untrusted signer"

**Symptom:**
```
WARNING: Bundle signed by untrusted signer: unknown-org
```

**Cause:** Public key for this signer is not in `compliance_bundle_keys/`

**Solution:**
```bash
# Option 1: Add signer to trusted keys (if legitimate)
cp unknown-org_public.pem \
   backend/security/compliance_bundle_keys/unknown-org.pem
docker-compose restart backend

# Option 2: Use permissive mode (dev only)
export REQUIRE_BUNDLE_SIGNATURE=false

# Option 3: Reject bundle (if signer is unknown)
# Delete the bundle and request signed version from trusted source
```

---

### Problem: Private key permissions error

**Symptom:**
```
ERROR: Private key has insecure permissions (644). Should be 600.
```

**Solution:**
```bash
# Fix permissions
chmod 600 backend/security/signing_keys/complianceascode_private.pem

# Verify
ls -la backend/security/signing_keys/complianceascode_private.pem
# Should show: -rw------- (600)
```

---

## Appendix

### A. generate_signing_keypair.py Reference

**Full Usage:**
```bash
python3 backend/security/generate_signing_keypair.py \
    --name <identifier> \
    --signer <signer-name> \
    [--key-size <bits>] \
    [--output-dir <directory>]
```

**Parameters:**
| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `--name` | Yes | - | Keypair identifier (e.g., `complianceascode`) |
| `--signer` | Yes | - | Human-readable signer name |
| `--key-size` | No | 4096 | RSA key size in bits (2048, 4096, 8192) |
| `--output-dir` | No | `backend/security/signing_keys` | Output directory |

**Example:**
```bash
python3 backend/security/generate_signing_keypair.py \
    --name myorg-2025 \
    --signer "MyOrg Security Team <security@myorg.com>" \
    --key-size 4096 \
    --output-dir /secure/keys
```

---

### B. Bundle Manifest Signature Format

**Unsigned Bundle:**
```json
{
  "name": "openwatch-rhel8-bundle",
  "version": "1.0.4",
  "created_at": "2025-10-24T13:00:00Z",
  "rules_count": 2013,
  "bundle_hash": "sha512:abc123..."
}
```

**Signed Bundle:**
```json
{
  "name": "openwatch-rhel8-bundle",
  "version": "1.0.4",
  "created_at": "2025-10-24T13:00:00Z",
  "rules_count": 2013,
  "bundle_hash": "sha512:abc123...",
  "signature": {
    "algorithm": "SHA512",
    "signature": "a3f2c8b941e6d7f2e5c9a1b4d8f3e7c2...",
    "signer": "ComplianceAsCode Project",
    "public_key_id": "a3f2c8b941e6d7f2",
    "signed_at": "2025-10-24T13:05:00Z"
  }
}
```

---

### C. Environment Variable Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `REQUIRE_BUNDLE_SIGNATURE` | `false` (dev) / `true` (prod) | Enforce signature verification |
| `SIGN_BUNDLES` | `false` | Sign bundles during build |
| `PRIVATE_KEY_PATH` | - | Path to private signing key |
| `SIGNER_NAME` | `"ComplianceAsCode Project"` | Signer identifier in manifest |

---

### D. Related Documentation

- [COMPLIANCE_BUNDLE_SIGNATURES.md](./COMPLIANCE_BUNDLE_SIGNATURES.md) - Complete signature system guide
- [DATA_STRUCTURE_SPECIFICATION.md](./DATA_STRUCTURE_SPECIFICATION.md) - Manifest specification v1.2.0
- [COMPLIANCE_BUNDLE_VALIDATION.md](./COMPLIANCE_BUNDLE_VALIDATION.md) - 8-phase validation reference

---

### E. Compliance and Standards

**NIST Guidelines:**
- FIPS 186-4: Digital Signature Standard (DSS)
- SP 800-57: Recommendation for Key Management

**Key Size Recommendations:**
| Source | Minimum | Recommended | Equivalent Symmetric |
|--------|---------|-------------|---------------------|
| **NIST (2025)** | 2048-bit | 3072-bit | 112-bit |
| **BSI (Germany)** | 3000-bit | 4000-bit | 128-bit |
| **OpenWatch** | 2048-bit (dev) | 4096-bit (prod) | 128-bit |

**Certificate Lifetimes:**
- Development keys: 1 year
- Production keys: 2 years
- Emergency keys: 90 days

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-10-24 | Claude Code | Initial document creation |

---

**Document Classification:** Internal Use
**Audience:** Security Engineers, DevOps, Build Automation
**Review Cycle:** Annual or on algorithm/threat landscape changes
