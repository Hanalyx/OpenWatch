#!/usr/bin/env python3
"""
Test script to verify new encryption service can decrypt existing credentials.

This script:
1. Loads the encryption service from app.encryption
2. Queries the database for system default credential
3. Attempts to decrypt using the new encryption service
4. Reports success or failure with details

Run from backend/ directory:
    python3 test_credential_decryption.py
"""
import sys
import os

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import base64
import logging
from sqlalchemy import text

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def test_credential_decryption():
    """Test that new encryption service can decrypt existing credentials"""
    print("=" * 70)
    print("Testing Credential Decryption with New Encryption Service")
    print("=" * 70)
    print()

    try:
        # Import dependencies
        from app.config import get_settings
        from app.encryption import create_encryption_service, EncryptionConfig
        from app.database import SessionLocal

        # Step 1: Create encryption service
        print("Step 1: Creating encryption service...")
        settings = get_settings()
        encryption_config = EncryptionConfig()  # Use production defaults
        encryption_service = create_encryption_service(
            master_key=settings.master_key,
            config=encryption_config
        )
        print(f"✓ Encryption service created")
        print(f"  - Algorithm: AES-256-GCM")
        print(f"  - KDF: PBKDF2-HMAC-SHA256")
        print(f"  - Iterations: {encryption_config.kdf_iterations}")
        print()

        # Step 2: Query database for credentials
        print("Step 2: Querying database for credentials...")
        db = SessionLocal()

        try:
            # Check unified_credentials table
            result = db.execute(text("""
                SELECT id, name, scope, username, auth_method,
                       encrypted_password, encrypted_private_key, encrypted_passphrase,
                       is_default, is_active
                FROM unified_credentials
                WHERE scope = 'system' AND is_active = true
                ORDER BY is_default DESC, created_at DESC
                LIMIT 5
            """))

            credentials = result.fetchall()

            if not credentials:
                print("⚠️  No credentials found in unified_credentials table")
                print()

                # Check legacy system_credentials table
                print("Checking legacy system_credentials table...")
                result = db.execute(text("""
                    SELECT id, username, auth_method,
                           encrypted_password, encrypted_private_key,
                           is_default, is_active
                    FROM system_credentials
                    WHERE is_active = true
                    ORDER BY is_default DESC
                    LIMIT 5
                """))

                legacy_creds = result.fetchall()

                if not legacy_creds:
                    print("❌ No credentials found in either table!")
                    print()
                    print("RECOMMENDATION:")
                    print("  Create a system default credential via the UI or API")
                    return False

                print(f"✓ Found {len(legacy_creds)} credential(s) in legacy table")
                credentials = legacy_creds
                table_name = "system_credentials"
            else:
                print(f"✓ Found {len(credentials)} credential(s) in unified_credentials")
                table_name = "unified_credentials"

            print()

            # Step 3: Test decryption on each credential
            print("Step 3: Testing decryption...")
            print()

            success_count = 0
            failure_count = 0

            for idx, cred in enumerate(credentials, 1):
                print(f"Credential {idx}/{len(credentials)}:")
                print(f"  - Table: {table_name}")
                if table_name == "unified_credentials":
                    print(f"  - Name: {cred.name}")
                    print(f"  - Scope: {cred.scope}")
                print(f"  - Username: {cred.username}")
                print(f"  - Auth Method: {cred.auth_method}")
                print(f"  - Is Default: {cred.is_default}")

                # Test password decryption
                if cred.encrypted_password:
                    try:
                        encrypted_data = cred.encrypted_password

                        # Handle memoryview
                        if isinstance(encrypted_data, memoryview):
                            encrypted_data = bytes(encrypted_data)

                        # Decode base64
                        if isinstance(encrypted_data, bytes):
                            decoded_bytes = base64.b64decode(encrypted_data)
                        else:
                            decoded_bytes = base64.b64decode(encrypted_data.encode('ascii'))

                        # Decrypt
                        decrypted_password = encryption_service.decrypt(decoded_bytes)
                        password_str = decrypted_password.decode('utf-8')

                        # Verify it's a reasonable password (not corrupted)
                        if len(password_str) > 0 and len(password_str) < 1000:
                            print(f"  ✓ Password decrypted successfully (length: {len(password_str)})")
                        else:
                            print(f"  ⚠️  Password decrypted but seems unusual (length: {len(password_str)})")

                    except Exception as e:
                        print(f"  ❌ Password decryption FAILED: {type(e).__name__}: {e}")
                        failure_count += 1
                        continue

                # Test private key decryption
                if cred.encrypted_private_key:
                    try:
                        encrypted_data = cred.encrypted_private_key

                        # Handle memoryview
                        if isinstance(encrypted_data, memoryview):
                            encrypted_data = bytes(encrypted_data)

                        # Decode base64
                        if isinstance(encrypted_data, bytes):
                            decoded_bytes = base64.b64decode(encrypted_data)
                        else:
                            decoded_bytes = base64.b64decode(encrypted_data.encode('ascii'))

                        # Decrypt
                        decrypted_key = encryption_service.decrypt(decoded_bytes)
                        key_str = decrypted_key.decode('utf-8')

                        # Verify it looks like a private key
                        if "BEGIN" in key_str and "PRIVATE KEY" in key_str:
                            print(f"  ✓ Private key decrypted successfully")
                        else:
                            print(f"  ⚠️  Private key decrypted but format unexpected")

                    except Exception as e:
                        print(f"  ❌ Private key decryption FAILED: {type(e).__name__}: {e}")
                        failure_count += 1
                        continue

                # Test passphrase decryption
                if hasattr(cred, 'encrypted_passphrase') and cred.encrypted_passphrase:
                    try:
                        encrypted_data = cred.encrypted_passphrase

                        # Handle memoryview
                        if isinstance(encrypted_data, memoryview):
                            encrypted_data = bytes(encrypted_data)

                        # Decode base64
                        if isinstance(encrypted_data, bytes):
                            decoded_bytes = base64.b64decode(encrypted_data)
                        else:
                            decoded_bytes = base64.b64decode(encrypted_data.encode('ascii'))

                        # Decrypt
                        decrypted_passphrase = encryption_service.decrypt(decoded_bytes)
                        passphrase_str = decrypted_passphrase.decode('utf-8')

                        print(f"  ✓ Passphrase decrypted successfully (length: {len(passphrase_str)})")

                    except Exception as e:
                        print(f"  ❌ Passphrase decryption FAILED: {type(e).__name__}: {e}")
                        failure_count += 1
                        continue

                success_count += 1
                print(f"  ✅ Credential {idx} decryption: SUCCESS")
                print()

        finally:
            db.close()

        # Step 4: Summary
        print("=" * 70)
        print("SUMMARY")
        print("=" * 70)
        print(f"Total Credentials Tested: {len(credentials)}")
        print(f"Successful Decryptions: {success_count}")
        print(f"Failed Decryptions: {failure_count}")
        print()

        if failure_count == 0 and success_count > 0:
            print("✅ ALL TESTS PASSED!")
            print()
            print("The new encryption service successfully decrypted all credentials.")
            print("Migration can proceed safely.")
            return True
        elif success_count > 0 and failure_count > 0:
            print("⚠️  PARTIAL SUCCESS")
            print()
            print(f"Some credentials could not be decrypted ({failure_count}/{len(credentials)}).")
            print("Review the errors above before proceeding with migration.")
            return False
        else:
            print("❌ ALL TESTS FAILED")
            print()
            print("The new encryption service could not decrypt any credentials.")
            print("DO NOT PROCEED with migration until this is resolved.")
            return False

    except Exception as e:
        import traceback
        print(f"❌ CRITICAL ERROR: {type(e).__name__}: {e}")
        print()
        print("Traceback:")
        print(traceback.format_exc())
        return False


if __name__ == "__main__":
    success = test_credential_decryption()
    sys.exit(0 if success else 1)
