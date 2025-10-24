# Compliance Bundle Signature Verification

**Version:** 1.0.0
**Date:** October 23, 2025
**Status:** Implemented

## Overview

OpenWatch implements RSA-PSS cryptographic signature verification for compliance rule bundles to ensure:

1. **Authenticity**: Bundles come from trusted publishers
2. **Integrity**: Bundles haven't been tampered with in transit or storage
3. **Non-repudiation**: Publishers cannot deny creating signed bundles
4. **Trust Chain**: Only bundles from trusted sources are accepted in production

## Architecture

### Components

1. **ComplianceRulesSignatureService** ([backend/app/services/compliance_rules_signature_service.py](../backend/app/services/compliance_rules_signature_service.py))
   - RSA-PSS signature generation and verification
   - Trusted key management
   - Public key caching

2. **ComplianceRulesUploadService** ([backend/app/services/compliance_rules_upload_service.py](../backend/app/services/compliance_rules_upload_service.py))
   - Integrated signature verification during Phase 2 (Parsing)
   - Dev vs production mode handling
   - Signature result reporting

3. **ComplianceAsCodeJSONConverter** ([backend/app/cli/scap_json_to_openwatch_converter.py](../backend/app/cli/scap_json_to_openwatch_converter.py))
   - Bundle signing during conversion
   - Manifest signature embedding

### Signature Algorithm

- **Algorithm**: RSA-PSS with MGF1 padding
- **Key Size**: 2048 bits minimum, 4096 bits recommended
- **Hash Algorithms**: SHA256, SHA384, SHA512 (SHA512 recommended)
- **Signature Encoding**: Hexadecimal
- **Signing Data**: Raw bundle tar.gz bytes

## Key Management

### Directory Structure

```
backend/security/
├── compliance_bundle_keys/          # Trusted public keys (committed to git)
│   ├── complianceascode.pem
│   └── README.md
└── signing_keys/                    # Private keys (NEVER committed - in .gitignore)
    └── complianceascode_private.pem
```

### Generating Keypairs

```bash
# Generate new RSA keypair
python3 backend/security/generate_signing_keypair.py \
    --name complianceascode \
    --signer "ComplianceAsCode Project"

# Output:
# - Private key: backend/security/signing_keys/complianceascode_private.pem
# - Public key: backend/security/compliance_bundle_keys/complianceascode.pem
# - Key ID: fdbeaa982e015e45
```

### Trust Management

**Adding Trusted Publisher**:
1. Obtain publisher's public key (PEM format)
2. Copy to `backend/security/compliance_bundle_keys/<publisher>.pem`
3. Restart OpenWatch backend to load new key
4. Verify key loaded: Check logs for "Loaded trusted bundle key"

**Removing Trusted Publisher**:
1. Delete `backend/security/compliance_bundle_keys/<publisher>.pem`
2. Restart OpenWatch backend

## Signing Bundles

### Method 1: During Conversion (Recommended)

```bash
# Build and sign RHEL 8 bundle
SIGN_BUNDLES=true ./scripts/build_compliance_rules.sh rhel8

# With custom signer name
SIGN_BUNDLES=true \
SIGNER_NAME="My Organization" \
./scripts/build_compliance_rules.sh rhel8
```

### Method 2: Sign Existing Bundle (Python)

```python
from pathlib import Path
from backend.app.services.compliance_rules_signature_service import ComplianceRulesSignatureService

# Read bundle
bundle_path = Path("/path/to/bundle.tar.gz")
with open(bundle_path, 'rb') as f:
    bundle_data = f.read()

# Sign bundle
service = ComplianceRulesSignatureService()
result = await service.sign_bundle(
    bundle_data=bundle_data,
    private_key_path=Path("/path/to/private_key.pem"),
    signer_name="ComplianceAsCode Project",
    algorithm="SHA512"
)

# Add signature to manifest and recreate bundle
if result['success']:
    signature = result['signature']
    # Update manifest.json with signature field
    # Recreate tar.gz with signed manifest
```

## Verification Process

### Development Mode (Default)

- Environment: `REQUIRE_BUNDLE_SIGNATURE=false` (default)
- Behavior:
  - Unsigned bundles: ALLOWED (warning logged)
  - Signed bundles with valid signature: ACCEPTED
  - Signed bundles with invalid signature: ALLOWED (warning logged)
  - Missing signer in trust store: ALLOWED (warning logged)

### Production Mode

- Environment: `REQUIRE_BUNDLE_SIGNATURE=true`
- Behavior:
  - Unsigned bundles: REJECTED
  - Signed bundles with valid signature from trusted signer: ACCEPTED
  - Signed bundles with invalid signature: REJECTED
  - Signed bundles from untrusted signer: REJECTED

### Verification Flow

```
1. Upload bundle → Phase 1: Security Validation (SHA-512 hash)
2. Phase 2: Parse manifest.json
3. Extract signature field from manifest
4. If REQUIRE_BUNDLE_SIGNATURE=true:
   a. Verify signature exists → REJECT if missing
   b. Verify signature format → REJECT if invalid
   c. Verify cryptographic signature → REJECT if tampered
   d. Verify signer is trusted → REJECT if untrusted
5. If REQUIRE_BUNDLE_SIGNATURE=false:
   a. Verify signature if present (informational only)
   b. Continue regardless of result
6. Continue with Phase 3-5: Import rules
```

## Bundle Manifest Signature Field

### Unsigned Bundle (Development)

```json
{
  "name": "complianceascode-rhel8",
  "version": "1.0.0",
  "rules_count": 2013,
  "created_at": "2025-10-22T19:55:05.419113+00:00"
}
```

### Signed Bundle (Production)

```json
{
  "name": "complianceascode-rhel8",
  "version": "1.0.0",
  "rules_count": 2013,
  "created_at": "2025-10-22T19:55:05.419113+00:00",
  "signature": {
    "algorithm": "SHA512",
    "signature": "a1b2c3d4e5f6789abc...",
    "signer": "ComplianceAsCode Project",
    "public_key_id": "fdbeaa982e015e45",
    "signed_at": "2025-10-22T19:55:05.419113+00:00"
  }
}
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `REQUIRE_BUNDLE_SIGNATURE` | `false` | Require valid signatures in production |

### Docker Compose

```yaml
backend:
  environment:
    REQUIRE_BUNDLE_SIGNATURE: "${REQUIRE_BUNDLE_SIGNATURE:-false}"
  volumes:
    - ./backend/security/compliance_bundle_keys:/app/security/compliance_bundle_keys:ro
```

## Security Considerations

### Private Key Protection

- **NEVER commit private keys to git**
- Store in `backend/security/signing_keys/` (already in .gitignore)
- Use file permissions `600` (owner read/write only)
- Consider using hardware security modules (HSM) for production signing
- Rotate keys periodically

### Key Compromise

If a private key is compromised:

1. **Immediate**: Remove public key from `compliance_bundle_keys/`
2. **Immediate**: Restart all OpenWatch instances
3. **Immediate**: Generate new keypair
4. **Within 24h**: Re-sign all bundles with new key
5. **Within 7 days**: Notify all OpenWatch users to update trusted keys

### Bundle Signature vs Rule Content Hash

| Feature | Bundle Signature | Rule Content Hash |
|---------|------------------|-------------------|
| **Purpose** | Verify publisher authenticity | Detect rule changes |
| **Algorithm** | RSA-PSS | SHA-256 |
| **Protects Against** | Malicious bundles | Duplicate imports |
| **Verification** | Cryptographic signature | Hash comparison |
| **Required** | Production only | Always |

## Troubleshooting

### Error: "No signature provided"

- **Cause**: Bundle uploaded in production mode without signature
- **Solution**:
  - Sign bundle: `SIGN_BUNDLES=true ./scripts/build_compliance_rules.sh`
  - OR disable requirement: `REQUIRE_BUNDLE_SIGNATURE=false`

### Error: "Public key not found: <key_id>"

- **Cause**: Signer's public key not in trusted keystore
- **Solution**:
  - Add public key to `backend/security/compliance_bundle_keys/`
  - Restart backend: `docker-compose restart backend`

### Error: "Invalid signature - bundle may have been tampered with"

- **Cause**: Bundle modified after signing OR wrong private key used
- **Solution**:
  - Re-sign bundle with correct private key
  - Verify bundle integrity (check SHA-512 hash)

### Error: "Signature valid but signer not in trusted list"

- **Cause**: Valid signature but signer not trusted
- **Solution**:
  - Add signer's public key to trusted keystore
  - OR reject bundle if signer shouldn't be trusted

## Testing

### Test Signature Generation

```bash
# Generate test keypair
python3 backend/security/generate_signing_keypair.py \
    --name test \
    --signer "Test Signer"

# Sign test bundle
SIGN_BUNDLES=true \
PRIVATE_KEY_PATH=backend/security/signing_keys/test_private.pem \
SIGNER_NAME="Test Signer" \
./scripts/build_compliance_rules.sh rhel8
```

### Test Signature Verification

```bash
# Test production mode (signature required)
export REQUIRE_BUNDLE_SIGNATURE=true
docker-compose up -d backend

# Upload signed bundle → should succeed
# Upload unsigned bundle → should fail

# Test development mode (signature optional)
export REQUIRE_BUNDLE_SIGNATURE=false
docker-compose up -d backend

# Upload signed bundle → should succeed
# Upload unsigned bundle → should succeed (with warning)
```

## References

- [DATA_STRUCTURE_SPECIFICATION.md](./DATA_STRUCTURE_SPECIFICATION.md) - Manifest signature field specification
- [RFC 8017](https://tools.ietf.org/html/rfc8017) - RSA-PSS specification
- [NIST FIPS 186-5](https://csrc.nist.gov/publications/detail/fips/186/5/final) - Digital Signature Standard
