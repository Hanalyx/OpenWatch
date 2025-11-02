#!/usr/bin/env python3
"""
Credential Re-encryption Script
Re-encrypts SSH credentials from old encryption key to new encryption key

Usage:
    python3 reencrypt_credentials.py --old-key OLD_KEY --new-key NEW_KEY

This script should be run when rotating the OPENWATCH_ENCRYPTION_KEY to ensure
existing encrypted credentials can still be accessed.
"""

import os
import sys
import argparse
import base64
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Updated to use new modular encryption module (encryption migration - Nov 2025)
from app.encryption import EncryptionService, create_encryption_service


def reencrypt_credentials(old_key: str, new_key: str, database_url: str, dry_run: bool = False):
    """
    Re-encrypt credentials from old key to new key

    Args:
        old_key: Old OPENWATCH_ENCRYPTION_KEY value
        new_key: New OPENWATCH_ENCRYPTION_KEY value
        database_url: Database connection string
        dry_run: If True, only show what would be changed
    """

    print(f"=== Credential Re-encryption Script ===")
    print(f"Mode: {'DRY RUN' if dry_run else 'LIVE'}")
    print(f"Old key: {old_key[:16]}...{old_key[-8:]}")
    print(f"New key: {new_key[:16]}...{new_key[-8:]}")
    print()

    # Create encryption services
    old_encryption = EncryptionService(master_key=old_key)
    new_encryption = EncryptionService(master_key=new_key)

    # Connect to database
    engine = create_engine(database_url)
    Session = sessionmaker(bind=engine)
    session = Session()

    try:
        # Get all credentials with encrypted data
        result = session.execute(text("""
            SELECT id, name, username, auth_method, encrypted_password, encrypted_private_key
            FROM unified_credentials
            WHERE encrypted_password IS NOT NULL OR encrypted_private_key IS NOT NULL
        """))

        credentials = result.fetchall()
        print(f"Found {len(credentials)} credentials to re-encrypt\n")

        success_count = 0
        error_count = 0

        for cred in credentials:
            cred_id = cred.id
            cred_name = cred.name or "Unnamed"
            username = cred.username
            auth_method = cred.auth_method
            old_password = cred.encrypted_password
            old_private_key = cred.encrypted_private_key

            print(f"Processing credential {cred_id} ({cred_name}, {auth_method}, user: {username})")

            try:
                new_password = None
                new_private_key = None

                # Decrypt and re-encrypt password
                if old_password:
                    try:
                        # old_password is already bytes (BYTEA column)
                        decrypted_password = old_encryption.decrypt(old_password)
                        new_encrypted_password = new_encryption.encrypt(decrypted_password)
                        new_password = new_encrypted_password  # Keep as bytes
                        print(f"  ✓ Password re-encrypted")
                    except Exception as e:
                        print(f"  ✗ Failed to decrypt/re-encrypt password: {e}")
                        error_count += 1
                        continue

                # Decrypt and re-encrypt private key
                if old_private_key:
                    try:
                        # old_private_key is already bytes (BYTEA column)
                        decrypted_key = old_encryption.decrypt(old_private_key)
                        new_encrypted_key = new_encryption.encrypt(decrypted_key)
                        new_private_key = new_encrypted_key  # Keep as bytes
                        print(f"  ✓ Private key re-encrypted")
                    except Exception as e:
                        print(f"  ✗ Failed to decrypt/re-encrypt private key: {e}")
                        error_count += 1
                        continue

                # Update database
                if not dry_run:
                    update_sql = """
                        UPDATE unified_credentials
                        SET encrypted_password = :password,
                            encrypted_private_key = :private_key,
                            updated_at = NOW()
                        WHERE id = :id
                    """
                    session.execute(text(update_sql), {
                        'id': cred_id,
                        'password': new_password,
                        'private_key': new_private_key
                    })
                    session.commit()
                    print(f"  ✓ Database updated")
                else:
                    print(f"  → Would update database (dry run)")

                success_count += 1

            except Exception as e:
                print(f"  ✗ Error processing credential: {e}")
                error_count += 1
                session.rollback()

        print(f"\n=== Summary ===")
        print(f"Total credentials: {len(credentials)}")
        print(f"Successfully re-encrypted: {success_count}")
        print(f"Errors: {error_count}")
        print(f"Mode: {'DRY RUN - No changes made' if dry_run else 'LIVE - Changes committed'}")

        if dry_run and success_count > 0:
            print(f"\nTo apply changes, run without --dry-run flag")

    except Exception as e:
        print(f"Fatal error: {e}")
        session.rollback()
        raise
    finally:
        session.close()


def main():
    parser = argparse.ArgumentParser(
        description='Re-encrypt SSH credentials with new encryption key'
    )
    parser.add_argument(
        '--old-key',
        required=True,
        help='Old OPENWATCH_ENCRYPTION_KEY value'
    )
    parser.add_argument(
        '--new-key',
        help='New OPENWATCH_ENCRYPTION_KEY value (defaults to current env var)'
    )
    parser.add_argument(
        '--database-url',
        help='Database URL (defaults to OPENWATCH_DATABASE_URL env var)'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be changed without making changes'
    )

    args = parser.parse_args()

    # Get new key from env if not provided
    new_key = args.new_key or os.getenv('OPENWATCH_ENCRYPTION_KEY')
    if not new_key:
        print("Error: --new-key not provided and OPENWATCH_ENCRYPTION_KEY not set")
        sys.exit(1)

    # Get database URL from env if not provided
    database_url = args.database_url or os.getenv('OPENWATCH_DATABASE_URL')
    if not database_url:
        print("Error: --database-url not provided and OPENWATCH_DATABASE_URL not set")
        sys.exit(1)

    # Confirm before proceeding
    if not args.dry_run:
        print("WARNING: This will modify encrypted credentials in the database!")
        response = input("Type 'yes' to proceed: ")
        if response.lower() != 'yes':
            print("Aborted")
            sys.exit(0)

    reencrypt_credentials(
        old_key=args.old_key,
        new_key=new_key,
        database_url=database_url,
        dry_run=args.dry_run
    )


if __name__ == '__main__':
    main()
