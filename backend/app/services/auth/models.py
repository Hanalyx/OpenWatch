"""
Authentication Models

Data models for credential management in OpenWatch.

This module contains Pydantic models and enums used throughout the
authentication and credential management system.
"""

import uuid
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class CredentialScope(str, Enum):
    """Credential scope types.

    Defines the scope at which a credential applies:
    - SYSTEM: System-wide default credentials
    - HOST: Host-specific credentials
    - GROUP: Host group-specific credentials
    """

    SYSTEM = "system"
    HOST = "host"
    GROUP = "group"


class AuthMethod(str, Enum):
    """Authentication method types.

    Supported authentication methods for SSH connections:
    - SSH_KEY: Public key authentication
    - PASSWORD: Password authentication
    - BOTH: Either method can be used
    """

    SSH_KEY = "ssh_key"
    PASSWORD = "password"  # pragma: allowlist secret
    BOTH = "both"


class CredentialData(BaseModel):
    """Unified credential data structure.

    Contains decrypted credential information ready for use in SSH connections.
    This object should be passed to SSH services - never raw encrypted data.

    Attributes:
        username: SSH username for authentication
        auth_method: The authentication method to use
        private_key: Decrypted SSH private key content (if using key auth)
        password: Decrypted password (if using password auth)
        private_key_passphrase: Passphrase for encrypted private keys
        source: Origin of the credential (e.g., "system_default", "host:uuid")

    Example:
        credential = CredentialData(
            username="owadmin",
            auth_method=AuthMethod.SSH_KEY,
            private_key="<SSH_KEY_CONTENT>",
            source="system_default"
        )
    """

    username: str
    auth_method: AuthMethod
    private_key: Optional[str] = None
    password: Optional[str] = None
    private_key_passphrase: Optional[str] = None
    source: str = "unknown"


class CredentialMetadata(BaseModel):
    """Credential metadata for storage.

    Contains non-sensitive metadata about a stored credential.

    Attributes:
        id: Unique identifier (auto-generated UUID)
        name: Human-readable name for the credential
        description: Optional description
        scope: The scope at which this credential applies
        target_id: Target entity ID (host_id or group_id) for non-system scope
        is_default: Whether this is the default credential for its scope
        is_active: Whether the credential is active (soft delete support)
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: Optional[str] = None
    scope: CredentialScope
    target_id: Optional[str] = None
    is_default: bool = False
    is_active: bool = True
