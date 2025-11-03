"""
Centralized Authentication Service
Provides unified credential storage, encryption, and validation for OpenWatch.
Replaces the dual-system approach with a single, consistent authentication layer.

MIGRATION NOTE: This service now uses dependency injection for encryption.
The encryption service is passed in the constructor instead of using global singleton.
"""

import base64
import json
import logging
import uuid
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Tuple

from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..encryption import EncryptionService  # NEW: Modular encryption service
from .credential_validation import SecurityPolicyLevel, validate_credential_with_strict_policy
from .unified_ssh_service import extract_ssh_key_metadata, parse_ssh_key, validate_ssh_key

logger = logging.getLogger(__name__)


class AuthMethodMismatchError(Exception):
    """Raised when credential auth method doesn't match requirement"""

    pass


class CredentialScope(str, Enum):
    """Credential scope types"""

    SYSTEM = "system"
    HOST = "host"
    GROUP = "group"


class AuthMethod(str, Enum):
    """Authentication method types"""

    SSH_KEY = "ssh_key"
    PASSWORD = "password"
    BOTH = "both"


class CredentialData(BaseModel):
    """Unified credential data structure"""

    username: str
    auth_method: AuthMethod
    private_key: Optional[str] = None
    password: Optional[str] = None
    private_key_passphrase: Optional[str] = None
    source: str = "unknown"


class CredentialMetadata(BaseModel):
    """Credential metadata for storage"""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: Optional[str] = None
    scope: CredentialScope
    target_id: Optional[str] = None
    is_default: bool = False
    is_active: bool = True


class CentralizedAuthService:
    """
    Centralized authentication service that provides unified credential management.
    Solves the issue where system credentials use AES encryption but host credentials only use base64.

    MIGRATION NOTE: Now uses dependency injection for encryption service.

    Args:
        db: Database session
        encryption_service: Encryption service instance (injected, not global)
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
        All credentials use AES-256-GCM regardless of scope.

        Args:
            credential_data: The credential information to store
            metadata: Metadata about the credential (scope, target, etc.)
            created_by: User ID who is creating the credential

        Returns:
            str: The credential ID

        Raises:
            ValueError: If credential validation fails
            Exception: If storage fails
        """
        try:
            # Validate credential format and connectivity
            validation_result = self.validate_credential(credential_data)
            if not validation_result[0]:
                raise ValueError(f"Credential validation failed: {validation_result[1]}")

            # Extract SSH key metadata if provided
            ssh_metadata = {}
            if credential_data.private_key:
                ssh_metadata = self._extract_ssh_key_metadata(
                    credential_data.private_key, credential_data.private_key_passphrase
                )

            # If setting as default, unset other defaults in same scope
            if metadata.is_default:
                self._unset_default_credentials(metadata.scope, metadata.target_id)

            # Encrypt sensitive data using unified AES-256-GCM (NEW: uses injected service)
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
                text(
                    """
                INSERT INTO unified_credentials
                (id, name, description, scope, target_id, username, auth_method,
                 encrypted_password, encrypted_private_key, encrypted_passphrase,
                 ssh_key_fingerprint, ssh_key_type, ssh_key_bits, ssh_key_comment,
                 is_default, is_active, created_by, created_at, updated_at)
                VALUES (:id, :name, :description, :scope, :target_id, :username, :auth_method,
                        :encrypted_password, :encrypted_private_key, :encrypted_passphrase,
                        :ssh_key_fingerprint, :ssh_key_type, :ssh_key_bits, :ssh_key_comment,
                        :is_default, :is_active, :created_by, :created_at, :updated_at)
            """
                ),
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
        """
        try:
            result = self.db.execute(
                text(
                    """
                SELECT username, auth_method, encrypted_password, encrypted_private_key,
                       encrypted_passphrase, scope, target_id
                FROM unified_credentials
                WHERE id = :id AND is_active = true
            """
                ),
                {"id": credential_id},
            )

            row = result.fetchone()
            if not row:
                return None

            # Decrypt credential data (NEW: uses injected encryption service)
            # Handle both string and memoryview from database
            password = None
            private_key = None
            passphrase = None

            if row.encrypted_password:
                encrypted_data = row.encrypted_password
                if isinstance(encrypted_data, memoryview):
                    # memoryview - convert to bytes
                    encrypted_data = bytes(encrypted_data)
                # encrypted_data is now either bytes or string (base64)
                # Decrypt using injected service
                if isinstance(encrypted_data, bytes):
                    # bytes - decode base64 then decrypt
                    decoded_bytes = base64.b64decode(encrypted_data)
                    password = self.encryption_service.decrypt(decoded_bytes).decode("utf-8")
                else:
                    # string - decode base64 then decrypt
                    decoded_bytes = base64.b64decode(encrypted_data.encode("ascii"))
                    password = self.encryption_service.decrypt(decoded_bytes).decode("utf-8")

            if row.encrypted_private_key:
                encrypted_data = row.encrypted_private_key
                if isinstance(encrypted_data, memoryview):
                    encrypted_data = bytes(encrypted_data)
                if isinstance(encrypted_data, bytes):
                    decoded_bytes = base64.b64decode(encrypted_data)
                    private_key = self.encryption_service.decrypt(decoded_bytes).decode("utf-8")
                else:
                    decoded_bytes = base64.b64decode(encrypted_data.encode("ascii"))
                    private_key = self.encryption_service.decrypt(decoded_bytes).decode("utf-8")

            if row.encrypted_passphrase:
                encrypted_data = row.encrypted_passphrase
                if isinstance(encrypted_data, memoryview):
                    encrypted_data = bytes(encrypted_data)
                if isinstance(encrypted_data, bytes):
                    decoded_bytes = base64.b64decode(encrypted_data)
                    passphrase = self.encryption_service.decrypt(decoded_bytes).decode("utf-8")
                else:
                    decoded_bytes = base64.b64decode(encrypted_data.encode("ascii"))
                    passphrase = self.encryption_service.decrypt(decoded_bytes).decode("utf-8")

            return CredentialData(
                username=row.username,
                auth_method=AuthMethod(row.auth_method),
                password=password,
                private_key=private_key,
                private_key_passphrase=passphrase,
                source=f"{row.scope}:{row.target_id}" if row.target_id else row.scope,
            )

        except Exception as e:
            import traceback

            logger.error(f"Failed to get credential {credential_id}: {e}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            return None

    def _get_host_credential(self, target_id: str) -> Optional[CredentialData]:
        """
        Get host-specific credential from unified_credentials table.

        Args:
            target_id: Host UUID

        Returns:
            CredentialData for the host, or None if not found
        """
        try:
            result = self.db.execute(
                text(
                    """
                SELECT id FROM unified_credentials
                WHERE scope = 'host'
                  AND target_id = :target_id
                  AND is_active = true
                ORDER BY created_at DESC
                LIMIT 1
            """
                ),
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

    def _auth_method_compatible(self, available: str, required: str) -> bool:
        """
        Check if available auth method satisfies required auth method.

        Compatibility matrix:
        - 'both' satisfies: 'password', 'ssh_key', 'both'
        - 'password' satisfies: 'password' only
        - 'ssh_key' satisfies: 'ssh_key' only

        Args:
            available: Auth method available in credential
            required: Auth method required by host

        Returns:
            True if compatible, False otherwise
        """
        # Exact match is always compatible
        if available == required:
            return True

        # 'both' can satisfy any password or ssh_key requirement
        if available == "both":
            return required in ["password", "ssh_key", "both"]

        return False

    def resolve_credential(
        self,
        target_id: str = None,
        required_auth_method: str = None,
        use_default: bool = False,
    ) -> Optional[CredentialData]:
        """
        Resolve effective credentials using inheritance logic with user intent enforcement.

        Resolution order:
        1. If use_default=True -> system default only
        2. If target_id provided -> try host-specific, fallback to system default
        3. Validate auth_method matches requirement if specified

        Args:
            target_id: Target ID (host_id, group_id) to resolve credentials for
            required_auth_method: Required authentication method ('password', 'ssh_key', 'both', 'system_default', None)
            use_default: Force use of system default credentials (ignores target_id)

        Returns:
            CredentialData: Resolved credential, or None if none available

        Raises:
            AuthMethodMismatchError: If available credential doesn't match required method
        """
        try:
            credential = None

            # BACKWARDS COMPATIBILITY: If use_default=True or no target_id, use system default
            # This ensures existing code continues to work without changes
            if use_default or not target_id:
                logger.info("Using unified_credentials table for credential resolution (system default)")
                credential = self._get_system_default()

                if credential and required_auth_method and required_auth_method != "system_default":
                    # NEW: Validate auth method if required
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

            # NEW FEATURE: Try host-specific credential first
            logger.info(f"Attempting to resolve host-specific credential for target: {target_id}")
            credential = self._get_host_credential(target_id)

            if credential:
                logger.info(f"✅ Found host-specific credential (auth_method: {credential.auth_method})")

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

            # BACKWARDS COMPATIBILITY: Fall back to system default if no host-specific found
            logger.info(f"No host-specific credential found for {target_id}, falling back to system default")
            credential = self._get_system_default()

            if credential:
                logger.info(f"✅ Found system default credential (auth_method: {credential.auth_method})")

                # Validate auth method if required
                if required_auth_method and required_auth_method != "system_default":
                    if not self._auth_method_compatible(credential.auth_method.value, required_auth_method):
                        logger.warning(
                            f"System default auth_method '{credential.auth_method.value}' "
                            f"does not match required '{required_auth_method}'. "
                            f"Consider creating a host-specific credential or updating system default."
                        )
                        # For backwards compatibility, we log a warning but don't raise error on fallback
                        # This allows existing hosts to continue working

                return credential

            logger.error("No credentials available (neither host-specific nor system default)")
            return None

        except AuthMethodMismatchError:
            # Re-raise auth method mismatch errors
            raise
        except Exception as e:
            logger.error(f"Failed to resolve credential: {e}")
            return None

    def _get_legacy_system_default(self) -> Optional[CredentialData]:
        """Get system default credential from legacy system_credentials table"""
        try:
            logger.info("Getting legacy system default credential from system_credentials table")
            result = self.db.execute(
                text(
                    """
                SELECT id, username, auth_method, encrypted_password, encrypted_private_key,
                       private_key_passphrase
                FROM system_credentials
                WHERE is_default = true AND is_active = true
                LIMIT 1
            """
                )
            )

            row = result.fetchone()
            if row:
                logger.info("Found legacy system default credential, decrypting...")

                # Decrypt legacy credential data (NEW: uses injected service)
                password = None
                private_key = None
                passphrase = None

                if row.encrypted_password:
                    try:
                        encrypted_data = row.encrypted_password
                        if isinstance(encrypted_data, memoryview):
                            encrypted_data = bytes(encrypted_data)
                        if isinstance(encrypted_data, bytes):
                            decoded_bytes = base64.b64decode(encrypted_data)
                            password = self.encryption_service.decrypt(decoded_bytes).decode("utf-8")
                        else:
                            decoded_bytes = base64.b64decode(encrypted_data.encode("ascii"))
                            password = self.encryption_service.decrypt(decoded_bytes).decode("utf-8")
                        logger.info("Successfully decrypted legacy password")
                    except Exception as e:
                        logger.warning(f"Failed to decrypt legacy password: {e}")

                if row.encrypted_private_key:
                    try:
                        encrypted_data = row.encrypted_private_key
                        if isinstance(encrypted_data, memoryview):
                            encrypted_data = bytes(encrypted_data)
                        if isinstance(encrypted_data, bytes):
                            decoded_bytes = base64.b64decode(encrypted_data)
                            private_key = self.encryption_service.decrypt(decoded_bytes).decode("utf-8")
                        else:
                            decoded_bytes = base64.b64decode(encrypted_data.encode("ascii"))
                            private_key = self.encryption_service.decrypt(decoded_bytes).decode("utf-8")
                        logger.info("Successfully decrypted legacy private key")
                    except Exception as e:
                        logger.warning(f"Failed to decrypt legacy private key: {e}")

                if row.private_key_passphrase:
                    try:
                        encrypted_data = row.private_key_passphrase
                        if isinstance(encrypted_data, memoryview):
                            encrypted_data = bytes(encrypted_data)
                        if isinstance(encrypted_data, bytes):
                            decoded_bytes = base64.b64decode(encrypted_data)
                            passphrase = self.encryption_service.decrypt(decoded_bytes).decode("utf-8")
                        else:
                            decoded_bytes = base64.b64decode(encrypted_data.encode("ascii"))
                            passphrase = self.encryption_service.decrypt(decoded_bytes).decode("utf-8")
                        logger.info("Successfully decrypted legacy passphrase")
                    except Exception as e:
                        logger.warning(f"Failed to decrypt legacy passphrase: {e}")

                credential = CredentialData(
                    username=row.username,
                    auth_method=AuthMethod(row.auth_method),
                    password=password,
                    private_key=private_key,
                    private_key_passphrase=passphrase,
                    source="legacy_system_default",
                )

                logger.info(f"Successfully resolved legacy system default credential for user: ***REDACTED***")
                return credential

            logger.warning("No legacy system default credential found in system_credentials table")
            return None

        except Exception as e:
            logger.error(f"Failed to get legacy system default credential: {e}")
            return None

    def _get_system_default(self) -> Optional[CredentialData]:
        """Get system default credential from unified_credentials table"""
        try:
            result = self.db.execute(
                text(
                    """
                SELECT id FROM unified_credentials
                WHERE scope = 'system' AND is_default = true AND is_active = true
                LIMIT 1
            """
                )
            )

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

            # Use strict validation by default (Security Fix 4)
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

    def _extract_ssh_key_metadata(self, private_key: str, passphrase: str = None) -> Dict:
        """Extract SSH key metadata for storage"""
        try:
            metadata = extract_ssh_key_metadata(private_key, passphrase)
            return {
                "fingerprint": metadata.get("fingerprint"),
                "key_type": metadata.get("key_type"),
                "key_bits": (int(metadata.get("key_bits")) if metadata.get("key_bits") else None),
                "key_comment": metadata.get("key_comment"),
            }
        except Exception as e:
            logger.warning(f"Failed to extract SSH key metadata: {e}")
            return {}

    def _unset_default_credentials(self, scope: CredentialScope, target_id: str = None):
        """Unset existing default credentials in the same scope"""
        try:
            if scope == CredentialScope.SYSTEM:
                self.db.execute(
                    text(
                        """
                    UPDATE unified_credentials
                    SET is_default = false
                    WHERE scope = 'system' AND is_default = true
                """
                    )
                )
            else:
                self.db.execute(
                    text(
                        """
                    UPDATE unified_credentials
                    SET is_default = false
                    WHERE scope = :scope AND target_id = :target_id AND is_default = true
                """
                    ),
                    {"scope": scope.value, "target_id": target_id},
                )

        except Exception as e:
            logger.error(f"Failed to unset default credentials: {e}")

    def list_credentials(
        self,
        scope: CredentialScope = None,
        target_id: str = None,
        user_id: str = None,
        include_inactive: bool = False,
    ) -> List[Dict]:
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
            # Build query with parameterized conditions to prevent SQL injection
            # WEEK 2 FIX: Include is_active in SELECT for compliance visibility
            base_query = """
                SELECT id, name, description, scope, target_id, username, auth_method,
                       ssh_key_fingerprint, ssh_key_type, ssh_key_bits, ssh_key_comment,
                       is_default, is_active, created_at, updated_at
                FROM unified_credentials
                WHERE 1=1
            """
            params = {}

            # WEEK 2 FIX: Only filter by is_active if not including inactive
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
                        "id": str(row.id),  # Convert UUID to string for Pydantic validation
                        "name": row.name,
                        "description": row.description,
                        "scope": row.scope,
                        "target_id": (str(row.target_id) if row.target_id else None),  # Convert UUID to string
                        "username": row.username,
                        "auth_method": row.auth_method,
                        "ssh_key_fingerprint": row.ssh_key_fingerprint,
                        "ssh_key_type": row.ssh_key_type,
                        "ssh_key_bits": row.ssh_key_bits,
                        "ssh_key_comment": row.ssh_key_comment,
                        "is_default": row.is_default,
                        "is_active": row.is_active,  # WEEK 2 FIX: Include is_active for compliance
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
        Inactive credentials are retained for 90 days for compliance/audit, then auto-purged.

        Args:
            credential_id: The credential ID to delete

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            result = self.db.execute(
                text(
                    """
                UPDATE unified_credentials
                SET is_active = false, updated_at = :updated_at
                WHERE id = :id
            """
                ),
                {"id": credential_id, "updated_at": datetime.utcnow()},
            )

            if result.rowcount > 0:
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
        This is for compliance - maintains audit trail while preventing unbounded growth.

        Args:
            retention_days: Number of days to retain inactive credentials (default 90)

        Returns:
            int: Number of credentials purged
        """
        try:
            from datetime import timedelta

            cutoff_date = datetime.utcnow() - timedelta(days=retention_days)

            result = self.db.execute(
                text(
                    """
                DELETE FROM unified_credentials
                WHERE is_active = false
                  AND updated_at < :cutoff_date
            """
                ),
                {"cutoff_date": cutoff_date},
            )

            purged_count = result.rowcount
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

    MIGRATION NOTE: Now requires encryption_service parameter (dependency injection).

    Args:
        db: Database session
        encryption_service: Encryption service instance (from app.state or Depends())

    Returns:
        CentralizedAuthService instance

    Example:
        # In FastAPI route
        from fastapi import Depends
        from backend.app.database import get_db, get_encryption_service

        @router.post("/credentials")
        async def create_credential(
            db: Session = Depends(get_db),
            encryption_service = Depends(get_encryption_service)
        ):
            auth_service = get_auth_service(db, encryption_service)
            # Use auth_service...
    """
    return CentralizedAuthService(db, encryption_service)
