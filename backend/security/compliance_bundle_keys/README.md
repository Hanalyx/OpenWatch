
# Trusted Public Keys for Compliance Bundle Verification

## complianceascode.pem

- **Signer**: ComplianceAsCode Project
- **Key ID**: fdbeaa982e015e45
- **Key Size**: 4096 bits
- **Algorithm**: RSA
- **Purpose**: Verify compliance rule bundles from ComplianceAsCode Project

### Usage

This public key is used by OpenWatch to verify the cryptographic signature of compliance rule bundles.
Only bundles signed with the corresponding private key (held by ComplianceAsCode Project) will be accepted in production mode.

### Trust

This key should only be added to the trusted keystore if you trust ComplianceAsCode Project to provide authentic, unmodified compliance rules.
