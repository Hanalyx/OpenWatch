"""
Credential Migration Service
Migrates existing credentials from the dual-system approach to unified format.

This solves the core issue where system credentials use AES encryption
but host credentials only use base64 encoding.
"""

import base64
import json
import logging
from typing import Dict, Tuple

from sqlalchemy import text
from sqlalchemy.orm import Session

from .auth_service import (
    AuthMethod,
    CentralizedAuthService,
    CredentialData,
    CredentialMetadata,
    CredentialScope,
)

logger = logging.getLogger(__name__)


class CredentialMigrationService:
    """
    Service to migrate existing credentials to the unified authentication system.
    """

    def __init__(self, db: Session):
        self.db = db
        self.auth_service = CentralizedAuthService(db)

    def migrate_all_credentials(self, dry_run: bool = False) -> Dict[str, int]:
        """
        Migrate all existing credentials to unified format.

        Args:
            dry_run: If True, only analyze what would be migrated without making changes

        Returns:
            Dict with migration statistics
        """
        logger.info(f"Starting credential migration (dry_run={dry_run})")

        stats = {
            "system_credentials_migrated": 0,
            "host_credentials_migrated": 0,
            "migration_errors": 0,
            "total_processed": 0,
        }

        try:
            # Migrate system credentials first (already properly encrypted)
            system_stats = self.migrate_system_credentials(dry_run)
            stats["system_credentials_migrated"] = system_stats

            # Migrate host credentials (need re-encryption from base64)
            host_stats = self.migrate_host_credentials(dry_run)
            stats["host_credentials_migrated"] = host_stats[0]
            stats["migration_errors"] = host_stats[1]

            stats["total_processed"] = (
                stats["system_credentials_migrated"]
                + stats["host_credentials_migrated"]
                + stats["migration_errors"]
            )

            if not dry_run:
                self.db.commit()
                logger.info("Credential migration completed successfully")
            else:
                logger.info("Dry run completed - no changes made")

            return stats

        except Exception as e:
            logger.error(f"Credential migration failed: {e}")
            if not dry_run:
                self.db.rollback()
            raise

    def migrate_system_credentials(self, dry_run: bool = False) -> int:
        """
        Migrate system credentials from system_credentials table.
        These are already properly encrypted with AES, just need schema transformation.

        Returns:
            int: Number of system credentials migrated
        """
        try:
            logger.info("Migrating system credentials...")

            # Get existing system credentials
            result = self.db.execute(
                text(
                    """
                SELECT id, name, description, username, auth_method,
                       encrypted_password, encrypted_private_key, private_key_passphrase,
                       ssh_key_fingerprint, ssh_key_type, ssh_key_bits, ssh_key_comment,
                       is_default, created_by, created_at, updated_at
                FROM system_credentials
                WHERE is_active = true
            """
                )
            )

            migrated_count = 0

            for row in result:
                try:
                    if dry_run:
                        logger.info(f"Would migrate system credential: {row.name}")
                        migrated_count += 1
                        continue

                    # Check if already migrated
                    check_result = self.db.execute(
                        text(
                            """
                        SELECT id FROM unified_credentials
                        WHERE scope = 'system' AND name = :name
                    """
                        ),
                        {"name": row.name},
                    )

                    if check_result.fetchone():
                        logger.info(f"System credential '{row.name}' already migrated, skipping")
                        continue

                    # Create unified credential entry
                    unified_id = str(row.id)  # Keep same ID

                    self.db.execute(
                        text(
                            """
                        INSERT INTO unified_credentials
                        (id, name, description, scope, target_id, username, auth_method,
                         encrypted_password, encrypted_private_key, encrypted_passphrase,
                         ssh_key_fingerprint, ssh_key_type, ssh_key_bits, ssh_key_comment,
                         is_default, is_active, created_by, created_at, updated_at)
                        VALUES (:id, :name, :description, 'system', NULL, :username, :auth_method,
                                :encrypted_password, :encrypted_private_key, :encrypted_passphrase,
                                :ssh_key_fingerprint, :ssh_key_type, :ssh_key_bits, :ssh_key_comment,
                                :is_default, true, :created_by, :created_at, :updated_at)
                    """
                        ),
                        {
                            "id": unified_id,
                            "name": row.name,
                            "description": row.description,
                            "username": row.username,
                            "auth_method": row.auth_method,
                            "encrypted_password": row.encrypted_password,
                            "encrypted_private_key": row.encrypted_private_key,
                            "encrypted_passphrase": row.private_key_passphrase,
                            "ssh_key_fingerprint": row.ssh_key_fingerprint,
                            "ssh_key_type": row.ssh_key_type,
                            "ssh_key_bits": row.ssh_key_bits,
                            "ssh_key_comment": row.ssh_key_comment,
                            "is_default": row.is_default,
                            "created_by": row.created_by,
                            "created_at": row.created_at,
                            "updated_at": row.updated_at,
                        },
                    )

                    migrated_count += 1
                    logger.info(f"Migrated system credential: {row.name}")

                except Exception as e:
                    logger.error(f"Failed to migrate system credential '{row.name}': {e}")
                    continue

            logger.info(f"Migrated {migrated_count} system credentials")
            return migrated_count

        except Exception as e:
            logger.error(f"System credential migration failed: {e}")
            raise

    def migrate_host_credentials(self, dry_run: bool = False) -> Tuple[int, int]:
        """
        Migrate host credentials from hosts.encrypted_credentials.
        These need to be re-encrypted from base64 to AES-256-GCM.

        Returns:
            Tuple[int, int]: (migrated_count, error_count)
        """
        try:
            logger.info("Migrating host credentials...")

            # Get hosts with credentials
            result = self.db.execute(
                text(
                    """
                SELECT id, hostname, username, auth_method, encrypted_credentials,
                       ssh_key_fingerprint, ssh_key_type, ssh_key_bits, ssh_key_comment
                FROM hosts
                WHERE encrypted_credentials IS NOT NULL
                AND username IS NOT NULL
                AND is_active = true
            """
                )
            )

            migrated_count = 0
            error_count = 0

            for row in result:
                try:
                    if dry_run:
                        logger.info(f"Would migrate host credential for: {row.hostname}")
                        migrated_count += 1
                        continue

                    # Check if already migrated
                    check_result = self.db.execute(
                        text(
                            """
                        SELECT id FROM unified_credentials
                        WHERE scope = 'host' AND target_id = :host_id
                    """
                        ),
                        {"host_id": str(row.id)},
                    )

                    if check_result.fetchone():
                        logger.info(
                            f"Host credential for '{row.hostname}' already migrated, skipping"
                        )
                        continue

                    # Decode and parse host credentials (base64 format)
                    try:
                        decoded_data = base64.b64decode(row.encrypted_credentials).decode("utf-8")
                        credentials_data = json.loads(decoded_data)
                    except Exception as e:
                        logger.error(f"Failed to decode credentials for host '{row.hostname}': {e}")
                        error_count += 1
                        continue

                    # Extract credential components
                    username = row.username
                    auth_method = row.auth_method or "ssh_key"
                    password = credentials_data.get("password")
                    private_key = credentials_data.get("ssh_key")  # Note: stored as 'ssh_key'
                    passphrase = credentials_data.get("passphrase")

                    # Create credential data for unified storage
                    credential_data = CredentialData(
                        username=username,
                        auth_method=AuthMethod(auth_method),
                        private_key=private_key,
                        password=password,
                        private_key_passphrase=passphrase,
                    )

                    # Create metadata
                    metadata = CredentialMetadata(
                        name=f"Host: {row.hostname}",
                        description=f"Migrated credential for host {row.hostname}",
                        scope=CredentialScope.HOST,
                        target_id=str(row.id),
                        is_default=False,
                    )

                    # Store using centralized service (will use AES-256-GCM)
                    credential_id = self.auth_service.store_credential(
                        credential_data=credential_data,
                        metadata=metadata,
                        created_by="00000000-0000-0000-0000-000000000000",  # System user
                    )

                    migrated_count += 1
                    logger.info(
                        f"Migrated host credential for: {row.hostname} (ID: {credential_id})"
                    )

                except Exception as e:
                    logger.error(f"Failed to migrate host credential for '{row.hostname}': {e}")
                    error_count += 1
                    continue

            logger.info(f"Migrated {migrated_count} host credentials with {error_count} errors")
            return migrated_count, error_count

        except Exception as e:
            logger.error(f"Host credential migration failed: {e}")
            raise

    def verify_migration(self) -> Dict[str, any]:
        """
        Verify that migration was successful by comparing old and new credential counts.

        Returns:
            Dict with verification results
        """
        try:
            logger.info("Verifying credential migration...")

            # Count original credentials
            system_result = self.db.execute(
                text(
                    """
                SELECT COUNT(*) as count FROM system_credentials WHERE is_active = true
            """
                )
            )
            original_system_count = system_result.fetchone().count

            host_result = self.db.execute(
                text(
                    """
                SELECT COUNT(*) as count FROM hosts
                WHERE encrypted_credentials IS NOT NULL AND username IS NOT NULL AND is_active = true
            """
                )
            )
            original_host_count = host_result.fetchone().count

            # Count migrated credentials
            unified_result = self.db.execute(
                text(
                    """
                SELECT scope, COUNT(*) as count FROM unified_credentials
                WHERE is_active = true
                GROUP BY scope
            """
                )
            )

            migrated_counts = {}
            for row in unified_result:
                migrated_counts[row.scope] = row.count

            migrated_system = migrated_counts.get("system", 0)
            migrated_host = migrated_counts.get("host", 0)

            verification_result = {
                "original_system_credentials": original_system_count,
                "original_host_credentials": original_host_count,
                "migrated_system_credentials": migrated_system,
                "migrated_host_credentials": migrated_host,
                "system_migration_complete": migrated_system >= original_system_count,
                "host_migration_complete": migrated_host >= original_host_count,
                "overall_success": (
                    migrated_system >= original_system_count
                    and migrated_host >= original_host_count
                ),
            }

            if verification_result["overall_success"]:
                logger.info("[PASS] Credential migration verification PASSED")
            else:
                logger.warning("[FAIL] Credential migration verification FAILED")
                logger.warning(f"System: {migrated_system}/{original_system_count}")
                logger.warning(f"Host: {migrated_host}/{original_host_count}")

            return verification_result

        except Exception as e:
            logger.error(f"Migration verification failed: {e}")
            return {"error": str(e), "overall_success": False}

    def test_credential_resolution(self, test_host_id: str = None) -> bool:
        """
        Test that credential resolution works with migrated data.

        Args:
            test_host_id: Optional host ID to test host-specific resolution

        Returns:
            bool: True if resolution tests pass
        """
        try:
            logger.info("Testing credential resolution...")

            # Test system default resolution
            system_credential = self.auth_service.resolve_credential(use_default=True)
            if not system_credential:
                logger.error("[FAIL] System default credential resolution failed")
                return False

            logger.info(f"[OK] System default resolution: {system_credential.source}")

            # Test host-specific resolution if host_id provided
            if test_host_id:
                host_credential = self.auth_service.resolve_credential(target_id=test_host_id)
                if not host_credential:
                    logger.error(f"[FAIL] Host credential resolution failed for {test_host_id}")
                    return False

                logger.info(f"[OK] Host resolution for {test_host_id}: {host_credential.source}")

            logger.info("[PASS] Credential resolution tests PASSED")
            return True

        except Exception as e:
            logger.error(f"Credential resolution test failed: {e}")
            return False


# Utility functions for migration scripts
def migrate_credentials(db: Session, dry_run: bool = False) -> Dict[str, int]:
    """Utility function to run credential migration"""
    migration_service = CredentialMigrationService(db)
    return migration_service.migrate_all_credentials(dry_run=dry_run)


def verify_migration(db: Session) -> Dict[str, any]:
    """Utility function to verify migration"""
    migration_service = CredentialMigrationService(db)
    return migration_service.verify_migration()
