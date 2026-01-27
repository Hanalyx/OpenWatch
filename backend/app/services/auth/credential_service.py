"""
Centralized Credential Service

Provides unified credential storage, encryption, and CRUD operations for OpenWatch.
This service handles all credential persistence and retrieval operations.

IMPORTANT: This service returns CredentialData objects with DECRYPTED values.
The CredentialData objects should be passed to SSH services - never raw encrypted data.
"""

import base64
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.encryption import EncryptionService
from app.services.ssh import extract_ssh_key_metadata, validate_ssh_key

from .exceptions import (
    AuthMethodMismatchError,
    CredentialDecryptionError,
    CredentialValidationError,
)
from .models import AuthMethod, CredentialData, CredentialMetadata, CredentialScope
from .validation import SecurityPolicyLevel, validate_credential_with_strict_policy

logger = logging.getLogger(__name__)


class CentralizedAuthService:
    """
    Centralized authentication service that provides unified credential management.

    This service handles:
    - Credential storage with AES-256-GCM encryption
    - Credential retrieval with automatic decryption
    - Credential resolution (host-specific -> system default fallback)
    - Credential validation with security policy enforcement

    IMPORTANT: All returned CredentialData objects contain DECRYPTED values.
    Pass these objects directly to SSH services like SSHConnectionManager.

    Args:
        db: Database session
        encryption_service: Encryption service instance (injected, not global)

    Example:
        auth_service = CentralizedAuthService(db, encryption_service)
        credential = auth_service.resolve_credential(target_id=str(host.id))
        # credential.private_key is already decrypted - pass to SSH service
        ssh_manager.connect_with_credentials(..., credential=credential.private_key)
    """

    def __init__(self, db: Session, encryption_service: EncryptionService):
        self.db = db
        self.encryption_service = encryption_service

    def store_credential(
        self,
        credential_data: CredentialData,
        metadata: CredentialMetadata,
        created_by: str,
    ) -> str:
        """
        Store credential with unified encryption and validation.

        All credentials use AES-256-GCM encryption regardless of scope.

        Args:
            credential_data: The credential information to store
            metadata: Metadata about the credential (scope, target, etc.)
            created_by: User ID who is creating the credential

        Returns:
            str: The credential ID

        Raises:
            CredentialValidationError: If credential validation fails
            Exception: If storage fails
        """
        try:
            # Validate credential format and connectivity
            validation_result = self.validate_credential(credential_data)
            if not validation_result[0]:
                raise CredentialValidationError(
                    message=f"Credential validation failed: {validation_result[1]}",
                    validation_errors=[validation_result[1]],
                )

            # Extract SSH key metadata if provided
            ssh_metadata = {}
            if credential_data.private_key:
                ssh_metadata = self._extract_ssh_key_metadata(
                    credential_data.private_key, credential_data.private_key_passphrase
                )

            # If setting as default, unset other defaults in same scope
            if metadata.is_default:
                self._unset_default_credentials(metadata.scope, metadata.target_id)

            # Encrypt sensitive data using unified AES-256-GCM
            encrypted_password = None
            encrypted_private_key = None
            encrypted_passphrase = None

            if credential_data.password:
                plaintext_bytes = credential_data.password.encode("utf-8")
                encrypted_bytes = self.encryption_service.encrypt(plaintext_bytes)
                encrypted_password = base64.b64encode(encrypted_bytes).decode("ascii")

            if credential_data.private_key:
                plaintext_bytes = credential_data.private_key.encode("utf-8")
                encrypted_bytes = self.encryption_service.encrypt(plaintext_bytes)
                encrypted_private_key = base64.b64encode(encrypted_bytes).decode("ascii")

            if credential_data.private_key_passphrase:
                plaintext_bytes = credential_data.private_key_passphrase.encode("utf-8")
                encrypted_bytes = self.encryption_service.encrypt(plaintext_bytes)
                encrypted_passphrase = base64.b64encode(encrypted_bytes).decode("ascii")

            # Store in unified credentials table
            current_time = datetime.utcnow()

            self.db.execute(
                text("""
                INSERT INTO unified_credentials
                (id, name, description, scope, target_id, username, auth_method,
                 encrypted_password, encrypted_private_key, encrypted_passphrase,
                 ssh_key_fingerprint, ssh_key_type, ssh_key_bits, ssh_key_comment,
                 is_default, is_active, created_by, created_at, updated_at)
                VALUES (:id, :name, :description, :scope, :target_id, :username, :auth_method,
                        :encrypted_password, :encrypted_private_key, :encrypted_passphrase,
                        :ssh_key_fingerprint, :ssh_key_type, :ssh_key_bits, :ssh_key_comment,
                        :is_default, :is_active, :created_by, :created_at, :updated_at)
            """),
                {
                    "id": metadata.id,
                    "name": metadata.name,
                    "description": metadata.description,
                    "scope": metadata.scope.value,
                    "target_id": metadata.target_id,
                    "username": credential_data.username,
                    "auth_method": credential_data.auth_method.value,
                    "encrypted_password": encrypted_password,
                    "encrypted_private_key": encrypted_private_key,
                    "encrypted_passphrase": encrypted_passphrase,
                    "ssh_key_fingerprint": ssh_metadata.get("fingerprint"),
                    "ssh_key_type": ssh_metadata.get("key_type"),
                    "ssh_key_bits": ssh_metadata.get("key_bits"),
                    "ssh_key_comment": ssh_metadata.get("key_comment"),
                    "is_default": metadata.is_default,
                    "is_active": metadata.is_active,
                    "created_by": created_by,
                    "created_at": current_time,
                    "updated_at": current_time,
                },
            )

            self.db.commit()

            logger.info(f"Stored {metadata.scope.value} credential '{metadata.name}' (ID: {metadata.id})")
            return metadata.id

        except CredentialValidationError:
            raise
        except Exception as e:
            logger.error(f"Failed to store credential: {e}")
            self.db.rollback()
            raise

    def get_credential(self, credential_id: str) -> Optional[CredentialData]:
        """
        Retrieve and decrypt a specific credential by ID.

        Args:
            credential_id: The credential ID to retrieve

        Returns:
            CredentialData: The decrypted credential data, or None if not found

        Raises:
            CredentialDecryptionError: If decryption fails
        """
        try:
            result = self.db.execute(
                text("""
                SELECT username, auth_method, encrypted_password, encrypted_private_key,
                       encrypted_passphrase, scope, target_id
                FROM unified_credentials
                WHERE id = :id AND is_active = true
            """),
                {"id": credential_id},
            )

            row = result.fetchone()
            if not row:
                return None

            # Decrypt credential data
            password = self._decrypt_field(row.encrypted_password, credential_id, "password")
            private_key = self._decrypt_field(row.encrypted_private_key, credential_id, "private_key")
            passphrase = self._decrypt_field(row.encrypted_passphrase, credential_id, "passphrase")

            return CredentialData(
                username=row.username,
                auth_method=AuthMethod(row.auth_method),
                password=password,
                private_key=private_key,
                private_key_passphrase=passphrase,
                source=f"{row.scope}:{row.target_id}" if row.target_id else row.scope,
            )

        except CredentialDecryptionError:
            raise
        except Exception as e:
            import traceback

            logger.error(f"Failed to get credential {credential_id}: {e}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            return None

    def _decrypt_field(self, encrypted_data: Any, credential_id: str, field_name: str) -> Optional[str]:
        """Decrypt a single encrypted field.

        Args:
            encrypted_data: The encrypted data (bytes, memoryview, or base64 string)
            credential_id: ID of the credential (for error reporting)
            field_name: Name of the field (for error reporting)

        Returns:
            Decrypted string value, or None if field was empty

        Raises:
            CredentialDecryptionError: If decryption fails
        """
        if not encrypted_data:
            return None

        try:
            # Handle memoryview from database
            if isinstance(encrypted_data, memoryview):
                encrypted_data = bytes(encrypted_data)

            # Decode base64 and decrypt
            if isinstance(encrypted_data, bytes):
                decoded_bytes = base64.b64decode(encrypted_data)
            else:
                decoded_bytes = base64.b64decode(encrypted_data.encode("ascii"))

            return self.encryption_service.decrypt(decoded_bytes).decode("utf-8")

        except Exception as e:
            logger.error(f"Failed to decrypt {field_name} for credential {credential_id}: {e}")
            raise CredentialDecryptionError(
                credential_id=credential_id,
                message=f"Failed to decrypt {field_name}: {e}",
            )

    def resolve_credential(
        self,
        target_id: Optional[str] = None,
        required_auth_method: Optional[str] = None,
        use_default: bool = False,
    ) -> Optional[CredentialData]:
        """
        Resolve effective credentials using inheritance logic.

        Resolution order:
        1. If use_default=True -> system default only
        2. If target_id provided -> try host-specific, fallback to system default
        3. Validate auth_method matches requirement if specified

        IMPORTANT: Returns CredentialData with DECRYPTED values ready for SSH use.

        Args:
            target_id: Target ID (host_id, group_id) to resolve credentials for
            required_auth_method: Required authentication method
            use_default: Force use of system default credentials

        Returns:
            CredentialData: Resolved credential with decrypted values, or None

        Raises:
            AuthMethodMismatchError: If available credential doesn't match required method
        """
        try:
            credential = None

            # If use_default=True or no target_id, use system default
            if use_default or not target_id:
                logger.info("Using unified_credentials table for credential resolution (system default)")
                credential = self._get_system_default()

                if credential and required_auth_method and required_auth_method != "system_default":
                    if not self._auth_method_compatible(credential.auth_method.value, required_auth_method):
                        logger.error(
                            f"System default auth_method '{credential.auth_method.value}' "
                            f"does not match required '{required_auth_method}'"
                        )
                        raise AuthMethodMismatchError(
                            f"Host requires {required_auth_method} authentication but "
                            f"system default uses {credential.auth_method.value}"
                        )

                return credential

            # Try host-specific credential first
            logger.info(f"Attempting to resolve host-specific credential for target: {target_id}")
            credential = self._get_host_credential(target_id)

            if credential:
                logger.info(f"[OK] Found host-specific credential (auth_method: {credential.auth_method})")

                # Validate auth method if required
                if required_auth_method and required_auth_method != "system_default":
                    if not self._auth_method_compatible(credential.auth_method.value, required_auth_method):
                        logger.error(
                            f"Host-specific credential auth_method '{credential.auth_method.value}' "
                            f"does not match required '{required_auth_method}'"
                        )
                        raise AuthMethodMismatchError(
                            f"Host requires {required_auth_method} authentication but "
                            f"host-specific credential uses {credential.auth_method.value}"
                        )

                return credential

            # Fall back to system default if no host-specific found
            logger.info(f"No host-specific credential found for {target_id}, falling back to system default")
            credential = self._get_system_default()

            if credential:
                logger.info(f"[OK] Found system default credential (auth_method: {credential.auth_method})")

                # Validate auth method if required
                if required_auth_method and required_auth_method != "system_default":
                    if not self._auth_method_compatible(credential.auth_method.value, required_auth_method):
                        logger.warning(
                            f"System default auth_method '{credential.auth_method.value}' "
                            f"does not match required '{required_auth_method}'. "
                            f"Consider creating a host-specific credential."
                        )
                        # For backwards compatibility, log warning but don't raise error

                return credential

            logger.error("No credentials available (neither host-specific nor system default)")
            return None

        except AuthMethodMismatchError:
            raise
        except Exception as e:
            logger.error(f"Failed to resolve credential: {e}")
            return None

    def _get_host_credential(self, target_id: str) -> Optional[CredentialData]:
        """Get host-specific credential from unified_credentials table."""
        try:
            result = self.db.execute(
                text("""
                SELECT id FROM unified_credentials
                WHERE scope = 'host'
                  AND target_id = :target_id
                  AND is_active = true
                ORDER BY created_at DESC
                LIMIT 1
            """),
                {"target_id": target_id},
            )

            row = result.fetchone()
            if row:
                credential = self.get_credential(row.id)
                if credential:
                    credential.source = f"host:{target_id}"
                    return credential

            return None

        except Exception as e:
            logger.error(f"Failed to get host credential for {target_id}: {e}")
            return None

    def _get_system_default(self) -> Optional[CredentialData]:
        """Get system default credential from unified_credentials table."""
        try:
            result = self.db.execute(text("""
                SELECT id FROM unified_credentials
                WHERE scope = 'system' AND is_default = true AND is_active = true
                LIMIT 1
            """))

            row = result.fetchone()
            if row:
                credential = self.get_credential(row.id)
                if credential:
                    credential.source = "system_default"
                    return credential

            logger.warning("No system default credential found in unified_credentials table")
            return None

        except Exception as e:
            logger.error(f"Failed to get system default credential: {e}")
            return None

    def _auth_method_compatible(self, available: str, required: str) -> bool:
        """Check if available auth method satisfies required auth method.

        Compatibility matrix:
        - 'both' satisfies: 'password', 'ssh_key', 'both'
        - 'password' satisfies: 'password' only
        - 'ssh_key' satisfies: 'ssh_key' only
        """
        if available == required:
            return True
        if available == "both":
            return required in ["password", "ssh_key", "both"]
        return False

    def validate_credential(self, credential_data: CredentialData, strict_mode: bool = True) -> Tuple[bool, str]:
        """
        Validate credential data with strict security policy enforcement.

        Args:
            credential_data: The credential to validate
            strict_mode: Whether to enforce strict security policies (default: True)

        Returns:
            Tuple[bool, str]: (is_valid, error_message)
        """
        try:
            # Basic format validation
            if not credential_data.username:
                return False, "Username is required"

            if credential_data.auth_method in [AuthMethod.PASSWORD, AuthMethod.BOTH]:
                if not credential_data.password:
                    return False, "Password is required for password authentication"

            if credential_data.auth_method in [AuthMethod.SSH_KEY, AuthMethod.BOTH]:
                if not credential_data.private_key:
                    return False, "SSH private key is required for key authentication"

            # Use strict validation by default
            if strict_mode:
                policy_level = SecurityPolicyLevel.STRICT
                is_valid, error_message = validate_credential_with_strict_policy(
                    username=credential_data.username,
                    auth_method=credential_data.auth_method.value,
                    private_key=credential_data.private_key,
                    password=credential_data.password,
                    policy_level=policy_level,
                )

                if not is_valid:
                    logger.warning(f"Credential rejected by strict security policy: {error_message}")
                    return False, error_message
            else:
                # Basic SSH key validation if not using strict mode
                if credential_data.private_key:
                    validation_result = validate_ssh_key(credential_data.private_key)
                    if not validation_result.is_valid:
                        return (
                            False,
                            f"Invalid SSH key: {validation_result.error_message}",
                        )

            return True, ""

        except Exception as e:
            logger.error(f"Credential validation error: {e}")
            return False, f"Validation error: {str(e)}"

    def _extract_ssh_key_metadata(self, private_key: str, passphrase: Optional[str] = None) -> Dict[str, Any]:
        """Extract SSH key metadata for storage."""
        try:
            metadata = extract_ssh_key_metadata(private_key, passphrase)
            key_bits_raw = metadata.get("key_bits")
            return {
                "fingerprint": metadata.get("fingerprint"),
                "key_type": metadata.get("key_type"),
                "key_bits": int(key_bits_raw) if key_bits_raw is not None else None,
                "key_comment": metadata.get("key_comment"),
            }
        except Exception as e:
            logger.warning(f"Failed to extract SSH key metadata: {e}")
            return {}

    def _unset_default_credentials(self, scope: CredentialScope, target_id: Optional[str] = None) -> None:
        """Unset existing default credentials in the same scope."""
        try:
            if scope == CredentialScope.SYSTEM:
                self.db.execute(text("""
                    UPDATE unified_credentials
                    SET is_default = false
                    WHERE scope = 'system' AND is_default = true
                """))
            else:
                self.db.execute(
                    text("""
                    UPDATE unified_credentials
                    SET is_default = false
                    WHERE scope = :scope AND target_id = :target_id AND is_default = true
                """),
                    {"scope": scope.value, "target_id": target_id},
                )

        except Exception as e:
            logger.error(f"Failed to unset default credentials: {e}")

    def list_credentials(
        self,
        scope: Optional[CredentialScope] = None,
        target_id: Optional[str] = None,
        user_id: Optional[str] = None,
        include_inactive: bool = False,
    ) -> List[Dict[str, Any]]:
        """
        List credentials with filtering options.

        Args:
            scope: Filter by credential scope
            target_id: Filter by target ID
            user_id: Filter by user (for access control)
            include_inactive: Include inactive credentials (for compliance/audit)

        Returns:
            List[Dict]: List of credential metadata (no sensitive data)
        """
        try:
            base_query = """
                SELECT id, name, description, scope, target_id, username, auth_method,
                       ssh_key_fingerprint, ssh_key_type, ssh_key_bits, ssh_key_comment,
                       is_default, is_active, created_at, updated_at
                FROM unified_credentials
                WHERE 1=1
            """
            params = {}

            if not include_inactive:
                base_query += " AND is_active = true"

            if scope:
                base_query += " AND scope = :scope"
                params["scope"] = scope.value

            if target_id:
                base_query += " AND target_id = :target_id"
                params["target_id"] = target_id

            if user_id:
                base_query += " AND created_by = :user_id"
                params["user_id"] = user_id

            base_query += " ORDER BY is_active DESC, scope, is_default DESC, name"

            result = self.db.execute(text(base_query), params)

            credentials = []
            for row in result:
                credentials.append(
                    {
                        "id": str(row.id),
                        "name": row.name,
                        "description": row.description,
                        "scope": row.scope,
                        "target_id": str(row.target_id) if row.target_id else None,
                        "username": row.username,
                        "auth_method": row.auth_method,
                        "ssh_key_fingerprint": row.ssh_key_fingerprint,
                        "ssh_key_type": row.ssh_key_type,
                        "ssh_key_bits": row.ssh_key_bits,
                        "ssh_key_comment": row.ssh_key_comment,
                        "is_default": row.is_default,
                        "is_active": row.is_active,
                        "created_at": row.created_at.isoformat(),
                        "updated_at": row.updated_at.isoformat(),
                    }
                )

            return credentials

        except Exception as e:
            logger.error(f"Failed to list credentials: {e}")
            return []

    def delete_credential(self, credential_id: str) -> bool:
        """
        Soft delete a credential by marking it inactive.

        Inactive credentials are retained for 90 days for compliance/audit,
        then auto-purged.

        Args:
            credential_id: The credential ID to delete

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            result = self.db.execute(
                text("""
                UPDATE unified_credentials
                SET is_active = false, updated_at = :updated_at
                WHERE id = :id
            """),
                {"id": credential_id, "updated_at": datetime.utcnow()},
            )

            rowcount: int = getattr(result, "rowcount", 0)
            if rowcount > 0:
                self.db.commit()
                logger.info(f"Soft deleted credential {credential_id} (90-day retention)")
                return True
            else:
                logger.warning(f"Credential {credential_id} not found for deletion")
                return False

        except Exception as e:
            logger.error(f"Failed to delete credential {credential_id}: {e}")
            self.db.rollback()
            return False

    def purge_old_inactive_credentials(self, retention_days: int = 90) -> int:
        """
        Hard delete inactive credentials older than retention period.

        Args:
            retention_days: Number of days to retain inactive credentials (default 90)

        Returns:
            int: Number of credentials purged
        """
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=retention_days)

            result = self.db.execute(
                text("""
                DELETE FROM unified_credentials
                WHERE is_active = false
                  AND updated_at < :cutoff_date
            """),
                {"cutoff_date": cutoff_date},
            )

            purged_count: int = getattr(result, "rowcount", 0)
            if purged_count > 0:
                self.db.commit()
                logger.info(f"Purged {purged_count} inactive credentials older than {retention_days} days")

            return purged_count

        except Exception as e:
            logger.error(f"Failed to purge old inactive credentials: {e}")
            self.db.rollback()
            return 0


# Factory function for service creation
def get_auth_service(db: Session, encryption_service: EncryptionService) -> CentralizedAuthService:
    """
    Factory function to create CentralizedAuthService instance.

    Args:
        db: Database session
        encryption_service: Encryption service instance

    Returns:
        CentralizedAuthService instance

    Example:
        from fastapi import Depends
        from app.database import get_db, get_encryption_service

        @router.post("/credentials")
        async def create_credential(
            db: Session = Depends(get_db),
            encryption_service = Depends(get_encryption_service)
        ):
            auth_service = get_auth_service(db, encryption_service)
            # Use auth_service...
    """
    return CentralizedAuthService(db, encryption_service)
