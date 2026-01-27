"""
SSH Service Module

Provides centralized SSH connection management, key validation, configuration,
and metadata extraction with consistent security policies, comprehensive audit
logging, and automation-friendly host key handling.

Module Architecture:
    ssh/
    ├── __init__.py          # This file - public API and factory functions
    ├── models.py            # Data classes and enums
    ├── exceptions.py        # Custom exception classes
    ├── policies.py          # Host key verification policies
    ├── key_validator.py     # Key validation and security assessment
    ├── key_parser.py        # Key parsing and fingerprint generation
    ├── key_metadata.py      # Metadata extraction functions
    ├── config_manager.py    # SSH configuration and settings management
    ├── known_hosts.py       # Known hosts database operations
    └── connection_manager.py # SSH connection and command execution

Usage:
    # Key validation and security assessment
    from app.services.ssh import validate_ssh_key, SSHKeyType
    result = validate_ssh_key(key_content)
    if result.key_type == SSHKeyType.ED25519:
        print("Modern key type detected")

    # SSH configuration and policy management
    from app.services.ssh import SSHConfigManager
    config = SSHConfigManager(db)
    policy = config.get_ssh_policy()

    # SSH connection management
    from app.services.ssh import SSHConnectionManager
    conn_manager = SSHConnectionManager(db)
    result = conn_manager.connect_with_credentials(...)

Security Notes:
    - All SSH operations are logged for audit compliance
    - Key validation follows NIST SP 800-57 guidelines
    - Connection policies default to SecurityWarningPolicy
    - Credentials are never logged or stored in plaintext
"""

from typing import TYPE_CHECKING, Optional

from .config_manager import SSHConfigManager
from .connection_manager import SSHConnectionManager
from .exceptions import SSHCommandError, SSHConfigurationError, SSHConnectionError, SSHKeyError
from .key_metadata import extract_key_comment, extract_ssh_key_metadata, get_key_display_info
from .key_parser import (
    detect_key_type,
    get_key_fingerprint,
    get_key_fingerprint_sha256,
    parse_ssh_key,
)
from .key_validator import assess_key_security, is_key_secure, validate_ssh_key
from .known_hosts import KnownHostsManager
from .models import (
    KEY_TYPE_MAPPING,
    SSHCommandResult,
    SSHConnectionResult,
    SSHKeySecurityLevel,
    SSHKeyType,
    SSHKeyValidationResult,
)
from .policies import SecurityWarningPolicy, StrictHostKeyPolicy, create_host_key_policy

# =============================================================================
# Import data models and enums
# =============================================================================


# =============================================================================
# Import key validation and parsing functions
# =============================================================================


# =============================================================================
# Import service classes for SSH operations
# =============================================================================


# =============================================================================
# TYPE_CHECKING imports for type hints
# =============================================================================

if TYPE_CHECKING:
    from sqlalchemy.orm import Session


def get_config_manager(db: Optional["Session"] = None) -> SSHConfigManager:
    """
    Factory function to create SSH configuration manager.

    Args:
        db: Optional SQLAlchemy session for database operations.

    Returns:
        Configured SSHConfigManager instance

    Example:
        >>> from app.services.ssh import get_config_manager
        >>> config = get_config_manager(db)
        >>> policy = config.get_ssh_policy()
    """
    return SSHConfigManager(db)


def get_known_hosts_manager(db: Optional["Session"] = None) -> KnownHostsManager:
    """
    Factory function to create known hosts manager.

    Args:
        db: Optional SQLAlchemy session for database operations.

    Returns:
        Configured KnownHostsManager instance

    Example:
        >>> from app.services.ssh import get_known_hosts_manager
        >>> known_hosts = get_known_hosts_manager(db)
        >>> hosts = known_hosts.get_known_hosts()
    """
    return KnownHostsManager(db)


def get_connection_manager(db: Optional["Session"] = None) -> SSHConnectionManager:
    """
    Factory function to create SSH connection manager.

    Args:
        db: Optional SQLAlchemy session for database operations.

    Returns:
        Configured SSHConnectionManager instance

    Example:
        >>> from app.services.ssh import get_connection_manager
        >>> conn = get_connection_manager(db)
        >>> result = conn.connect_with_credentials(...)
    """
    return SSHConnectionManager(db)


# =============================================================================
# Public API exports
# =============================================================================

# This defines what is available via "from app.services.ssh import *"
# and documents the module's public interface
__all__ = [
    # Factory functions
    "get_config_manager",
    "get_known_hosts_manager",
    "get_connection_manager",
    # Service classes
    "SSHConfigManager",
    "KnownHostsManager",
    "SSHConnectionManager",
    # Models and enums (from models.py)
    "SSHKeyType",
    "SSHKeySecurityLevel",
    "SSHKeyValidationResult",
    "SSHConnectionResult",
    "SSHCommandResult",
    "KEY_TYPE_MAPPING",
    # Exceptions (from exceptions.py)
    "SSHKeyError",
    "SSHConnectionError",
    "SSHConfigurationError",
    "SSHCommandError",
    # Policies (from policies.py)
    "SecurityWarningPolicy",
    "StrictHostKeyPolicy",
    "create_host_key_policy",
    # Key validation functions (from key_validator.py)
    "assess_key_security",
    "validate_ssh_key",
    "is_key_secure",
    # Key parsing functions (from key_parser.py)
    "detect_key_type",
    "parse_ssh_key",
    "get_key_fingerprint",
    "get_key_fingerprint_sha256",
    # Key metadata functions (from key_metadata.py)
    "extract_ssh_key_metadata",
    "extract_key_comment",
    "get_key_display_info",
]
