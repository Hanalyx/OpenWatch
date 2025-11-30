"""
SSH Data Models and Enums

Provides type-safe data structures for SSH operations including key types,
security levels, and result containers. These models ensure consistent
data representation across all SSH-related operations in OpenWatch.

This module contains:
- SSHKeyType: Enum for supported SSH key algorithms
- SSHKeySecurityLevel: Enum for key security assessment results
- SSHKeyValidationResult: Container for key validation outcomes
- SSHConnectionResult: Container for connection attempt outcomes
- SSHCommandResult: Container for command execution outcomes

Security Considerations:
- All result containers are designed to never expose sensitive data
- Error messages are sanitized to prevent information leakage
- Dataclasses use Optional types to handle missing data gracefully

Usage:
    from backend.app.services.ssh.models import (
        SSHKeyType,
        SSHKeySecurityLevel,
        SSHKeyValidationResult,
        SSHConnectionResult,
        SSHCommandResult,
    )

    # Validate key type
    if key_type == SSHKeyType.ED25519:
        security_level = SSHKeySecurityLevel.SECURE

    # Create validation result
    result = SSHKeyValidationResult(
        is_valid=True,
        key_type=SSHKeyType.RSA,
        security_level=SSHKeySecurityLevel.ACCEPTABLE,
        key_size=4096
    )
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any, List, Optional


class SSHKeyType(Enum):
    """
    Supported SSH key types.

    Defines the cryptographic algorithms supported for SSH key authentication.
    Each type has different security characteristics and use cases.

    Attributes:
        RSA: RSA algorithm (legacy, widely supported)
        ED25519: Edwards-curve Digital Signature Algorithm (modern, recommended)
        ECDSA: Elliptic Curve Digital Signature Algorithm
        DSA: Digital Signature Algorithm (deprecated, insecure)

    Security Notes:
        - ED25519 is recommended for new keys (256-bit security, fast)
        - RSA 4096-bit is acceptable for legacy compatibility
        - DSA should never be used (rejected by OpenSSH 7.0+)
    """

    RSA = "rsa"
    ED25519 = "ed25519"
    ECDSA = "ecdsa"
    DSA = "dsa"


class SSHKeySecurityLevel(Enum):
    """
    Security assessment levels for SSH keys.

    Based on NIST SP 800-57 key management guidelines and current
    cryptographic best practices as of 2024.

    Attributes:
        SECURE: Key meets or exceeds current security recommendations
        ACCEPTABLE: Key is usable but should be upgraded when possible
        DEPRECATED: Key uses deprecated algorithms or insufficient key sizes
        REJECTED: Key is insecure and should not be used

    Assessment Criteria:
        SECURE:
            - Ed25519 (any)
            - RSA >= 4096 bits
            - ECDSA P-384 or P-521

        ACCEPTABLE:
            - RSA 2048-4095 bits
            - ECDSA P-256

        DEPRECATED:
            - RSA < 2048 bits
            - ECDSA < P-256

        REJECTED:
            - DSA (any size)
            - Unknown/unrecognized algorithms
    """

    SECURE = "secure"
    ACCEPTABLE = "acceptable"
    DEPRECATED = "deprecated"
    REJECTED = "rejected"


class SSHKeyValidationResult:
    """
    Result of SSH key validation with detailed security assessment.

    This class encapsulates all information about a key validation attempt,
    including the validation outcome, key characteristics, and security
    recommendations.

    Attributes:
        is_valid: Whether the key was successfully parsed and validated
        key_type: The detected SSH key algorithm type
        security_level: Security assessment of the key
        key_size: Key size in bits (if applicable)
        error_message: Description of validation failure (if invalid)
        warnings: List of security concerns about the key
        recommendations: List of suggested improvements

    Example:
        >>> result = SSHKeyValidationResult(
        ...     is_valid=True,
        ...     key_type=SSHKeyType.RSA,
        ...     security_level=SSHKeySecurityLevel.ACCEPTABLE,
        ...     key_size=2048,
        ...     warnings=[],
        ...     recommendations=["Consider upgrading to 4096-bit RSA or Ed25519"]
        ... )
        >>> if result.is_valid:
        ...     print(f"Key type: {result.key_type.value}")
    """

    def __init__(
        self,
        is_valid: bool,
        key_type: Optional[SSHKeyType] = None,
        security_level: Optional[SSHKeySecurityLevel] = None,
        key_size: Optional[int] = None,
        error_message: Optional[str] = None,
        warnings: Optional[List[str]] = None,
        recommendations: Optional[List[str]] = None,
    ) -> None:
        """
        Initialize SSH key validation result.

        Args:
            is_valid: Whether the key passed validation
            key_type: Detected key algorithm type
            security_level: Security assessment result
            key_size: Key size in bits
            error_message: Validation error description (if failed)
            warnings: Security warnings about the key
            recommendations: Suggested security improvements
        """
        self.is_valid = is_valid
        self.key_type = key_type
        self.security_level = security_level
        self.key_size = key_size
        self.error_message = error_message
        self.warnings = warnings or []
        self.recommendations = recommendations or []

    def __repr__(self) -> str:
        """Return string representation for debugging."""
        return (
            f"SSHKeyValidationResult(is_valid={self.is_valid}, "
            f"key_type={self.key_type}, security_level={self.security_level}, "
            f"key_size={self.key_size})"
        )

    def to_dict(self) -> dict:
        """
        Convert result to dictionary for JSON serialization.

        Returns:
            Dictionary representation of the validation result
        """
        return {
            "is_valid": self.is_valid,
            "key_type": self.key_type.value if self.key_type else None,
            "security_level": self.security_level.value if self.security_level else None,
            "key_size": self.key_size,
            "error_message": self.error_message,
            "warnings": self.warnings,
            "recommendations": self.recommendations,
        }


@dataclass
class SSHConnectionResult:
    """
    Result of SSH connection attempt with detailed diagnostic information.

    This dataclass captures all relevant information about an SSH connection
    attempt, including success status, connection object, and error details.

    Attributes:
        success: Whether the connection was established successfully
        connection: The paramiko SSHClient object (if successful)
        error_message: Human-readable error description (if failed)
        error_type: Categorized error type for programmatic handling
        host_key_fingerprint: SHA256 fingerprint of host key (if connected)
        auth_method_used: Authentication method that succeeded

    Error Types:
        - auth_failed: Authentication credentials rejected
        - key_error: SSH key parsing or validation failed
        - ssh_error: SSH protocol error (banner, negotiation)
        - timeout: Connection timed out
        - connection_error: Network-level connection failure

    Example:
        >>> result = ssh_service.connect_with_credentials(
        ...     hostname="server.example.com",
        ...     port=22,
        ...     username="admin",
        ...     auth_method="ssh_key",
        ...     credential=private_key_content,
        ...     service_name="scan_service"
        ... )
        >>> if result.success:
        ...     # Use result.connection for SSH operations
        ...     result.connection.exec_command("whoami")
        ... else:
        ...     logger.error(f"Connection failed: {result.error_message}")
    """

    success: bool
    connection: Optional[Any] = None  # paramiko.SSHClient, using Any to avoid import
    error_message: Optional[str] = None
    error_type: Optional[str] = None
    host_key_fingerprint: Optional[str] = None
    auth_method_used: Optional[str] = None

    def __repr__(self) -> str:
        """Return string representation for debugging."""
        if self.success:
            return (
                f"SSHConnectionResult(success=True, "
                f"auth_method={self.auth_method_used}, "
                f"fingerprint={self.host_key_fingerprint[:16]}...)"
                if self.host_key_fingerprint
                else f"SSHConnectionResult(success=True, auth_method={self.auth_method_used})"
            )
        return (
            f"SSHConnectionResult(success=False, "
            f"error_type={self.error_type}, "
            f"error_message={self.error_message})"
        )


@dataclass
class SSHCommandResult:
    """
    Result of SSH command execution with output and timing information.

    This dataclass captures the complete outcome of executing a command
    over an SSH connection, including stdout, stderr, exit code, and
    execution duration.

    Attributes:
        success: Whether the command completed with exit code 0
        stdout: Standard output from the command
        stderr: Standard error from the command
        exit_code: Process exit code (-1 if execution failed)
        duration: Execution time in seconds
        error_message: Error description if execution failed

    Example:
        >>> result = ssh_service.execute_command_advanced(
        ...     connection,
        ...     "cat /etc/os-release",
        ...     timeout=30
        ... )
        >>> if result.success:
        ...     print(f"OS info: {result.stdout}")
        ... else:
        ...     print(f"Command failed (exit {result.exit_code}): {result.stderr}")
    """

    success: bool
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    duration: float = 0.0
    error_message: Optional[str] = None

    def __repr__(self) -> str:
        """Return string representation for debugging."""
        return (
            f"SSHCommandResult(success={self.success}, "
            f"exit_code={self.exit_code}, "
            f"duration={self.duration:.2f}s)"
        )

    def to_dict(self) -> dict:
        """
        Convert result to dictionary for JSON serialization.

        Returns:
            Dictionary representation of the command result
        """
        return {
            "success": self.success,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "exit_code": self.exit_code,
            "duration": self.duration,
            "error_message": self.error_message,
        }


# Type alias for key type mapping used in validation
KEY_TYPE_MAPPING: dict = {
    "ssh-rsa": SSHKeyType.RSA,
    "ssh-ed25519": SSHKeyType.ED25519,
    "ecdsa-sha2-nistp256": SSHKeyType.ECDSA,
    "ecdsa-sha2-nistp384": SSHKeyType.ECDSA,
    "ecdsa-sha2-nistp521": SSHKeyType.ECDSA,
    "ssh-dss": SSHKeyType.DSA,
}


__all__ = [
    "SSHKeyType",
    "SSHKeySecurityLevel",
    "SSHKeyValidationResult",
    "SSHConnectionResult",
    "SSHCommandResult",
    "KEY_TYPE_MAPPING",
]
