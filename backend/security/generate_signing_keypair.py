#!/usr/bin/env python3
"""
Generate RSA keypair for compliance bundle signing

Usage:
    python generate_signing_keypair.py --name complianceascode --signer "ComplianceAsCode Project"
"""
import argparse
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import hashlib


def generate_keypair(key_name: str, signer_name: str, key_size: int = 4096):
    """Generate RSA keypair for bundle signing"""

    print(f"Generating {key_size}-bit RSA keypair for: {signer_name}")

    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )

    # Get public key
    public_key = private_key.public_key()

    # Serialize private key (PEM format, unencrypted for automation)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serialize public key (PEM format)
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Calculate key ID (SHA-256 hash of public key, first 16 chars)
    key_id = hashlib.sha256(public_pem).hexdigest()[:16]

    # Save keys
    script_dir = Path(__file__).parent

    # Private key (for signing - keep secure!)
    private_key_path = script_dir / "signing_keys" / f"{key_name}_private.pem"
    private_key_path.parent.mkdir(parents=True, exist_ok=True)
    with open(private_key_path, 'wb') as f:
        f.write(private_pem)
    private_key_path.chmod(0o600)  # Restrict permissions

    # Public key (for verification - can be shared)
    public_key_path = script_dir / "compliance_bundle_keys" / f"{key_name}.pem"
    public_key_path.parent.mkdir(parents=True, exist_ok=True)
    with open(public_key_path, 'wb') as f:
        f.write(public_pem)

    # Create README with key info
    readme_path = script_dir / "compliance_bundle_keys" / "README.md"
    key_info = f"""
# Trusted Public Keys for Compliance Bundle Verification

## {key_name}.pem

- **Signer**: {signer_name}
- **Key ID**: {key_id}
- **Key Size**: {key_size} bits
- **Algorithm**: RSA
- **Purpose**: Verify compliance rule bundles from {signer_name}

### Usage

This public key is used by OpenWatch to verify the cryptographic signature of compliance rule bundles.
Only bundles signed with the corresponding private key (held by {signer_name}) will be accepted in production mode.

### Trust

This key should only be added to the trusted keystore if you trust {signer_name} to provide authentic, unmodified compliance rules.
"""

    with open(readme_path, 'a') as f:
        f.write(key_info)

    print(f"\n✅ Keypair generated successfully!")
    print(f"   Private key: {private_key_path} (KEEP SECURE - do not commit to git)")
    print(f"   Public key:  {public_key_path} (safe to share and commit)")
    print(f"   Key ID:      {key_id}")
    print(f"\n⚠️  IMPORTANT: Add {private_key_path} to .gitignore!")

    # Check if in .gitignore
    gitignore_path = script_dir.parent.parent / ".gitignore"
    if gitignore_path.exists():
        with open(gitignore_path, 'r') as f:
            gitignore_content = f.read()

        if "backend/security/signing_keys/" not in gitignore_content:
            print(f"\n⚠️  WARNING: Add this line to .gitignore:")
            print(f"   backend/security/signing_keys/")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate RSA keypair for compliance bundle signing")
    parser.add_argument("--name", required=True, help="Key name (e.g., 'complianceascode')")
    parser.add_argument("--signer", required=True, help="Signer name (e.g., 'ComplianceAsCode Project')")
    parser.add_argument("--key-size", type=int, default=4096, help="RSA key size in bits (default: 4096)")

    args = parser.parse_args()

    generate_keypair(args.name, args.signer, args.key_size)
