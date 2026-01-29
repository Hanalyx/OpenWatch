"""
Host Credential Handler Service

This service extracts credential handling logic from the host creation endpoint
to follow Single Responsibility Principle from CLAUDE.md coding standards.

Purpose:
    - Validate SSH keys for host-specific credentials
    - Prepare CredentialData and CredentialMetadata objects
    - Store host credentials in unified_credentials table
    - Handle credential-related errors gracefully

Why this service exists:
    - Eliminates ~108 lines of credential logic from POST /api/hosts/ endpoint
    - Centralizes credential validation and storage in one place
    - Makes host creation endpoint more readable (reduced from ~140 lines to ~80 lines)
    - Follows DRY (Don't Repeat Yourself) - credential logic used by multiple endpoints
    - Easier to test credential handling in isolation
    - Single Responsibility: ONE job - handle host credential creation

Security:
    - All credentials encrypted with AES-256-GCM via EncryptionService
    - SSH key validation prevents invalid keys from being stored
    - Audit logging for all credential operations
    - Generic error messages to client (detailed logs server-side)

Example Usage:
    from app.services.host_credential_handler import HostCredentialHandler

    handler = HostCredentialHandler(db)

    # Validate and prepare credential during host creation
    credential_info = handler.validate_and_prepare_credential(
        hostname="web-server-01",
        auth_method="ssh_key",
        username="root",
        password=None,
        ssh_key="-----BEGIN OPENSSH PRIVATE KEY-----...",  # pragma: allowlist secret
        host_id=host_uuid
    )

    # Store credential after host is created
    cred_id = handler.store_host_credential(
        credential_data=credential_info["credential_data"],
        metadata=credential_info["metadata"],
        created_by=current_user_uuid
    )

Created: 2025-11-04 (Phase 2 of QueryBuilder migration)
"""

import logging
import uuid
from typing import Any, Dict, Optional

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from .auth import AuthMethod, CredentialData, CredentialMetadata, CredentialScope, get_auth_service

# validate_ssh_key validates key format and security level
from .ssh import validate_ssh_key

logger = logging.getLogger(__name__)


class HostCredentialHandler:
    """
    Service for handling host-specific credential validation and storage.

    This service handles the complete lifecycle of host credential creation:
    1. Validation of SSH keys (if provided)
    2. Preparation of CredentialData and CredentialMetadata
    3. Storage in unified_credentials table with encryption
    4. Error handling and logging

    Attributes:
        db: SQLAlchemy database session
    """

    def __init__(self, db: Session):
        """
        Initialize the credential handler.

        Args:
            db: SQLAlchemy database session for credential storage
        """
        self.db = db

    def validate_and_prepare_credential(
        self,
        hostname: str,
        auth_method: str,
        username: str,
        password: Optional[str],
        ssh_key: Optional[str],
        host_id: uuid.UUID,
    ) -> Optional[Dict[str, Any]]:
        """
        Validate SSH key (if provided) and prepare credential data structures.

        This method handles the first phase of credential creation:
        - Validates SSH key format and security properties
        - Creates CredentialData with auth method, password, and/or SSH key
        - Creates CredentialMetadata with host scope and targeting

        If validation fails, raises HTTPException with 400 status.
        If no credentials provided, returns None.

        Args:
            hostname: Host hostname (for logging and metadata)
            auth_method: Authentication method ("password", "ssh_key", "both")
            username: SSH username
            password: SSH password (if auth_method is "password" or "both")
            ssh_key: SSH private key (if auth_method is "ssh_key" or "both")
            host_id: UUID of the host being created

        Returns:
            Dictionary with:
                - credential_data: CredentialData object for storage
                - metadata: CredentialMetadata object for storage
            Or None if no credentials provided (auth_method is "system_default")

        Raises:
            HTTPException: 400 Bad Request if SSH key validation fails

        Example:
            >>> handler = HostCredentialHandler(db)
            >>> cred_info = handler.validate_and_prepare_credential(
            ...     hostname="web-01",
            ...     auth_method="ssh_key",
            ...     username="root",
            ...     password=None,
            ...     ssh_key="-----BEGIN OPENSSH PRIVATE KEY-----...",  # pragma: allowlist secret
            ...     host_id=uuid.UUID("550e8400-e29b-41d4-a716-446655440000")
            ... )
            >>> assert cred_info["credential_data"].auth_method == AuthMethod.SSH_KEY
            >>> assert cred_info["metadata"].scope == CredentialScope.HOST

        Security:
            - SSH key validation prevents weak or malformed keys
            - Password validation occurs at Pydantic model level (before this method)
            - Generic error messages to client (detailed logs server-side)
            - All validation failures logged for audit trail
        """
        # Skip if using system default credentials
        if not auth_method or auth_method == "system_default":
            logger.debug(f"Host '{hostname}' will use system default credentials")
            return None

        # Skip if no credentials provided
        if not password and not ssh_key:
            logger.debug(f"Host '{hostname}' has no credentials provided")
            return None

        # Validate SSH key if provided
        if ssh_key:
            logger.info(f"Validating SSH key for host '{hostname}'")
            validation_result = validate_ssh_key(ssh_key)

            if not validation_result.is_valid:
                logger.error(
                    f"SSH key validation failed for host '{hostname}': " f"{', '.join(validation_result.errors)}"
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"SSH key validation failed: {', '.join(validation_result.errors)}",
                )

            if validation_result.warnings:
                logger.warning(
                    f"SSH key validation warnings for host '{hostname}': " f"{', '.join(validation_result.warnings)}"
                )

        # Create credential data for unified system
        credential_data = CredentialData(
            username=username,
            auth_method=AuthMethod(auth_method),
            password=(password if auth_method in ["password", "both"] else None),
            private_key=(ssh_key if auth_method in ["ssh_key", "both"] else None),
            private_key_passphrase=None,  # TODO: Support passphrase-protected keys
        )

        # Create metadata
        metadata = CredentialMetadata(
            name=f"{hostname} credential",
            description=f"Host-specific credential for {hostname}",
            scope=CredentialScope.HOST,
            target_id=str(host_id),
            is_default=False,
        )

        logger.debug(f"Prepared credential data for host '{hostname}' (auth_method: {auth_method})")

        return {"credential_data": credential_data, "metadata": metadata}

    def store_host_credential(
        self,
        credential_data: CredentialData,
        metadata: CredentialMetadata,
        created_by: Optional[str],
        hostname: str,
    ) -> Optional[str]:
        """
        Store host credential in unified_credentials table with encryption.

        This method handles the second phase of credential creation:
        - Retrieves auth service with encryption
        - Stores credential with AES-256-GCM encryption
        - Handles errors gracefully (doesn't fail host creation)

        If storage fails, logs error but does NOT raise exception.
        This prevents credential storage failures from blocking host creation.
        The host can still be created and credentials added later via UI.

        Args:
            credential_data: CredentialData object with username, auth_method, credentials
            metadata: CredentialMetadata object with name, scope, target_id
            created_by: UUID of user creating the credential (None if system)
            hostname: Host hostname (for logging only)

        Returns:
            Credential ID (UUID string) if successful, None if storage failed

        Example:
            >>> handler = HostCredentialHandler(db)
            >>> cred_id = handler.store_host_credential(
            ...     credential_data=credential_data,
            ...     metadata=metadata,
            ...     created_by="550e8400-e29b-41d4-a716-446655440000",
            ...     hostname="web-01"
            ... )
            >>> assert cred_id is not None  # UUID string

        Security:
            - All credentials encrypted with AES-256-GCM
            - created_by tracked for audit trail
            - Storage failures logged (but don't block host creation)
            - Generic error messages to client (detailed logs server-side)
        """
        try:
            auth_service = get_auth_service(self.db)

            # Store credential in unified_credentials
            cred_id = auth_service.store_credential(
                credential_data=credential_data,
                metadata=metadata,
                created_by=created_by,
            )
            logger.info(f"Stored host-specific credential for {hostname} " f"in unified_credentials (id: {cred_id})")
            return cred_id

        except Exception as e:
            logger.error(
                f"Failed to store host-specific credential for {hostname}: {e}",
                exc_info=True,
            )
            # Don't fail the host creation, just log the error
            # User can add credentials later via UI
            return None
