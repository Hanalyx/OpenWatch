"""
Unified SSH Service for OpenWatch - Consolidated Version

Provides centralized SSH connection management, key validation, configuration,
and metadata extraction with consistent security policies, comprehensive audit
logging, and automation-friendly host key handling.

This service consolidates functionality from:
- ssh_service.py: Basic SSH connectivity and command execution
- ssh_utils.py: SSH key validation and security assessment
- ssh_config_service.py: SSH host key policies and configuration
- ssh_key_service.py: SSH key metadata extraction

All existing imports should be updated to use this unified service.
"""

import base64
import errno
import io
import ipaddress
import json
import logging
import os
import re
import socket
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import paramiko
from paramiko import DSSKey, ECDSAKey, Ed25519Key, RSAKey, SSHClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..database import Host

logger = logging.getLogger(__name__)


# ============================================================================
# ENUMS AND DATA CLASSES
# ============================================================================


class SSHKeyType(Enum):
    """Supported SSH key types"""

    RSA = "rsa"
    ED25519 = "ed25519"
    ECDSA = "ecdsa"
    DSA = "dsa"


class SSHKeySecurityLevel(Enum):
    """Security assessment levels for SSH keys"""

    SECURE = "secure"
    ACCEPTABLE = "acceptable"
    DEPRECATED = "deprecated"
    REJECTED = "rejected"


class SSHKeyValidationResult:
    """Result of SSH key validation"""

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
        self.is_valid = is_valid
        self.key_type = key_type
        self.security_level = security_level
        self.key_size = key_size
        self.error_message = error_message
        self.warnings = warnings or []
        self.recommendations = recommendations or []


class SSHKeyError(Exception):
    """Custom exception for SSH key related errors"""


@dataclass
class SSHConnectionResult:
    """Result of SSH connection attempt with detailed information."""

    success: bool
    connection: Optional[SSHClient] = None
    error_message: Optional[str] = None
    error_type: Optional[str] = None
    host_key_fingerprint: Optional[str] = None
    auth_method_used: Optional[str] = None


@dataclass
class SSHCommandResult:
    """Result of SSH command execution."""

    success: bool
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    duration: float = 0.0
    error_message: Optional[str] = None


# ============================================================================
# SSH HOST KEY POLICIES
# ============================================================================


class SecurityWarningPolicy(paramiko.MissingHostKeyPolicy):
    """
    Secure middle-ground SSH host key policy for automation environments.

    Logs security warnings for unknown hosts but allows connections to proceed.
    This balances security (full audit trail) with operational requirements
    (automation doesn't fail on new hosts).

    Follows industry best practices similar to Ansible's approach.
    """

    def __init__(self, audit_callback: Optional[Any] = None) -> None:
        """
        Initialize policy with optional audit callback.

        Args:
            audit_callback: Optional function to call for audit logging
        """
        self.audit_callback = audit_callback

    def missing_host_key(self, client: SSHClient, hostname: str, key: paramiko.PKey) -> None:
        """
        Handle missing host key by logging warning and storing key.

        Args:
            client: SSH client instance
            hostname: Target hostname
            key: SSH host key
        """
        # Get key fingerprint for logging (with safe fallback)
        try:
            fingerprint = key.get_fingerprint().hex()
            key_type = key.get_name()
        except Exception:
            fingerprint = "unknown"
            key_type = "unknown"

        # Log security warning (safe logging)
        try:
            logger.warning(
                f"SSH_SECURITY_WARNING: Unknown host key for {hostname} "
                f"(type: {key_type}, fingerprint: {fingerprint}). "
                f"Connection allowed but logged for audit."
            )
        except Exception:
            # Even logging can fail in some environments, ensure connection continues
            pass

        # Call audit callback if provided
        if self.audit_callback:
            try:
                self.audit_callback(hostname, key_type, fingerprint)
            except Exception:
                pass

        # Store key for this session (safe operation)
        try:
            client.get_host_keys().add(hostname, key.get_name(), key)
        except Exception:
            # Don't let host key storage errors prevent connections
            pass


# ============================================================================
# SSH KEY UTILITIES
# ============================================================================


def detect_key_type(key_content: str) -> Optional[SSHKeyType]:
    """
    DEPRECATED: Detect SSH key type from key content.

    This function is deprecated in favor of using paramiko.PKey.from_private_key()
    directly in validate_ssh_key(). It remains for backward compatibility with
    existing services but should not be used in new code.

    Args:
        key_content: SSH key content as string or bytes

    Returns:
        SSHKeyType if detected, None if unknown
    """
    try:
        # Handle bytes input (common from database)
        if isinstance(key_content, (bytes, memoryview)):
            key_content = key_content.decode("utf-8", errors="ignore")

        content_str = str(key_content).strip()

        # Check key type markers
        if "ssh-ed25519" in content_str or "BEGIN OPENSSH PRIVATE KEY" in content_str:
            # Ed25519 detection requires checking the actual key
            try:
                if "-----BEGIN OPENSSH PRIVATE KEY-----" in content_str:
                    # Private key - try to parse to determine type
                    paramiko.Ed25519Key.from_private_key_file(io.StringIO(content_str))
                    return SSHKeyType.ED25519
                elif content_str.startswith("ssh-ed25519"):
                    return SSHKeyType.ED25519
            except Exception:
                pass

        if any(marker in content_str for marker in ["ssh-rsa", "BEGIN RSA PRIVATE KEY", "RSA PRIVATE KEY"]):
            return SSHKeyType.RSA
        elif any(marker in content_str for marker in ["ecdsa-sha2-", "BEGIN EC PRIVATE KEY", "EC PRIVATE KEY"]):
            return SSHKeyType.ECDSA
        elif any(marker in content_str for marker in ["ssh-dss", "BEGIN DSA PRIVATE KEY", "DSA PRIVATE KEY"]):
            return SSHKeyType.DSA

        return None

    except Exception as e:
        logger.debug(f"Error detecting key type: {e}")
        return None


def parse_ssh_key(key_content: str, passphrase: Optional[str] = None) -> paramiko.PKey:
    """
    DEPRECATED: Parse SSH key content into paramiko PKey object.

    This function is deprecated in favor of using paramiko.PKey.from_private_key()
    directly. It remains for backward compatibility with existing services but
    should not be used in new code.

    Args:
        key_content: SSH key content as string
        passphrase: Optional passphrase for encrypted keys

    Returns:
        paramiko.PKey object

    Raises:
        SSHKeyError: If key cannot be parsed
    """
    try:
        # Handle bytes input
        if isinstance(key_content, (bytes, memoryview)):
            key_content = key_content.decode("utf-8", errors="ignore")

        content_str = str(key_content).strip()

        # Try parsing with different key types
        key_types = [
            (Ed25519Key, "Ed25519"),
            (RSAKey, "RSA"),
            (ECDSAKey, "ECDSA"),
            (DSSKey, "DSA"),
        ]

        for key_class, key_name in key_types:
            try:
                import io

                key_file = io.StringIO(content_str)
                if passphrase:
                    return key_class.from_private_key(key_file, password=passphrase)
                else:
                    return key_class.from_private_key(key_file)
            except (paramiko.PasswordRequiredException, paramiko.SSHException):
                continue
            except Exception:
                continue

        raise SSHKeyError("Unable to parse SSH key - unsupported format or incorrect passphrase")

    except SSHKeyError:
        raise
    except Exception as e:
        raise SSHKeyError(f"Error parsing SSH key: {str(e)}")


def get_key_size(pkey: paramiko.PKey) -> Optional[int]:
    """
    Get the size of an SSH key in bits.

    Args:
        pkey: paramiko PKey object

    Returns:
        Key size in bits, None if unable to determine
    """
    try:
        if isinstance(pkey, RSAKey):
            return pkey.get_bits()
        elif isinstance(pkey, Ed25519Key):
            return 256  # Ed25519 is always 256 bits
        elif isinstance(pkey, ECDSAKey):
            return pkey.get_bits()
        elif isinstance(pkey, DSSKey):
            return pkey.get_bits()
        else:
            # Try generic method
            try:
                return pkey.get_bits()
            except Exception:
                return None
    except Exception:
        return None


def assess_key_security(
    key_type: SSHKeyType, key_size: Optional[int]
) -> Tuple[SSHKeySecurityLevel, List[str], List[str]]:
    """
    Assess the security level of an SSH key based on type and size.

    Args:
        key_type: Type of SSH key
        key_size: Size of key in bits

    Returns:
        Tuple of (security_level, warnings, recommendations)
    """
    warnings: List[str] = []
    recommendations: List[str] = []

    if key_type == SSHKeyType.ED25519:
        # Ed25519 is always secure (256-bit equivalent to 3072-bit RSA)
        return SSHKeySecurityLevel.SECURE, warnings, recommendations

    elif key_type == SSHKeyType.RSA:
        if not key_size:
            warnings.append("Cannot determine RSA key size")
            return (
                SSHKeySecurityLevel.ACCEPTABLE,
                warnings,
                ["Verify key size is at least 2048 bits"],
            )
        elif key_size >= 4096:
            return SSHKeySecurityLevel.SECURE, warnings, recommendations
        elif key_size >= 2048:
            return (
                SSHKeySecurityLevel.ACCEPTABLE,
                warnings,
                ["Consider upgrading to 4096-bit RSA or Ed25519"],
            )
        else:
            warnings.append(f"RSA key size {key_size} is below current security standards")
            recommendations.append("Replace with at least 2048-bit RSA or Ed25519 key")
            return SSHKeySecurityLevel.DEPRECATED, warnings, recommendations

    elif key_type == SSHKeyType.ECDSA:
        if not key_size:
            return (
                SSHKeySecurityLevel.ACCEPTABLE,
                warnings,
                ["Verify ECDSA curve is P-256 or higher"],
            )
        elif key_size >= 384:  # P-384 or P-521
            return SSHKeySecurityLevel.SECURE, warnings, recommendations
        elif key_size >= 256:  # P-256
            return (
                SSHKeySecurityLevel.ACCEPTABLE,
                warnings,
                ["Consider Ed25519 for better security"],
            )
        else:
            warnings.append(f"ECDSA key size {key_size} may be insecure")
            recommendations.append("Replace with P-256 ECDSA or Ed25519 key")
            return SSHKeySecurityLevel.DEPRECATED, warnings, recommendations

    elif key_type == SSHKeyType.DSA:
        warnings.append("DSA keys are deprecated due to security vulnerabilities")
        recommendations.append("Replace with Ed25519 or RSA key immediately")
        return SSHKeySecurityLevel.REJECTED, warnings, recommendations

    else:
        warnings.append("Unknown key type")
        return SSHKeySecurityLevel.ACCEPTABLE, warnings, ["Use Ed25519 for new keys"]


def validate_ssh_key(key_content: str, passphrase: Optional[str] = None) -> SSHKeyValidationResult:
    """
    Simplified SSH key validation using paramiko's built-in capabilities.

    This refactored version eliminates complex manual key type detection and parsing
    in favor of paramiko's robust, battle-tested key handling. This fixes issues
    with modern OpenSSH key formats and reduces maintenance overhead.

    Args:
        key_content: SSH key content as string
        passphrase: Optional passphrase for encrypted keys

    Returns:
        SSHKeyValidationResult with detailed validation information
    """
    try:
        # Handle empty input
        if not key_content or not str(key_content).strip():
            return SSHKeyValidationResult(is_valid=False, error_message="Empty key content provided")

        # Let paramiko handle all the complexity of key parsing and validation
        try:
            # Handle bytes input (common from database)
            if isinstance(key_content, (bytes, memoryview)):
                key_content = key_content.decode("utf-8", errors="ignore")

            key_content = str(key_content).strip()

            # Try different key classes in order - paramiko requires specific classes
            key_classes = [
                (paramiko.Ed25519Key, "Ed25519"),
                (paramiko.RSAKey, "RSA"),
                (paramiko.ECDSAKey, "ECDSA"),
                (paramiko.DSSKey, "DSA"),
            ]

            pkey = None
            for key_class, key_name in key_classes:
                try:
                    pkey = key_class.from_private_key(io.StringIO(key_content), passphrase)
                    break
                except (paramiko.PasswordRequiredException, paramiko.SSHException):
                    continue
                except Exception:
                    continue

            if pkey is None:
                raise paramiko.SSHException("Unable to parse SSH key - unsupported format or incorrect passphrase")

            # Extract key information using paramiko's methods
            key_name = pkey.get_name()  # e.g., 'ssh-rsa', 'ssh-ed25519', 'ecdsa-sha2-nistp256'
            key_size = pkey.get_bits()

            # Map paramiko key names to our enum types for backward compatibility
            key_type_mapping = {
                "ssh-rsa": SSHKeyType.RSA,
                "ssh-ed25519": SSHKeyType.ED25519,
                "ecdsa-sha2-nistp256": SSHKeyType.ECDSA,
                "ecdsa-sha2-nistp384": SSHKeyType.ECDSA,
                "ecdsa-sha2-nistp521": SSHKeyType.ECDSA,
                "ssh-dss": SSHKeyType.DSA,
            }

            # Get key type, default to RSA if unknown (maintain compatibility)
            key_type = key_type_mapping.get(key_name, SSHKeyType.RSA)

            # Assess security using existing logic
            security_level, warnings, recommendations = assess_key_security(key_type, key_size)

            return SSHKeyValidationResult(
                is_valid=True,
                key_type=key_type,
                security_level=security_level,
                key_size=key_size,
                warnings=warnings,
                recommendations=recommendations,
            )

        except paramiko.PasswordRequiredException:
            return SSHKeyValidationResult(
                is_valid=False,
                error_message="SSH key is encrypted and requires a passphrase",
            )
        except paramiko.SSHException as e:
            return SSHKeyValidationResult(is_valid=False, error_message=f"Invalid SSH key format: {str(e)}")
        except Exception as e:
            return SSHKeyValidationResult(is_valid=False, error_message=f"SSH key parsing failed: {str(e)}")

    except Exception as e:
        return SSHKeyValidationResult(is_valid=False, error_message=f"Validation error: {str(e)}")


def get_key_fingerprint(key_content: str, passphrase: Optional[str] = None) -> Optional[str]:
    """
    Generate MD5 fingerprint for SSH key using paramiko's built-in method.

    Args:
        key_content: SSH key content as string
        passphrase: Optional passphrase for encrypted keys

    Returns:
        Fingerprint as hex string, None if unable to generate
    """
    try:
        # Handle bytes input (common from database)
        if isinstance(key_content, (bytes, memoryview)):
            key_content = key_content.decode("utf-8", errors="ignore")

        key_content = str(key_content).strip()

        # Use paramiko's built-in key parsing and fingerprint generation
        # Try different key classes in order
        key_classes = [
            paramiko.Ed25519Key,
            paramiko.RSAKey,
            paramiko.ECDSAKey,
            paramiko.DSSKey,
        ]

        pkey = None
        for key_class in key_classes:
            try:
                pkey = key_class.from_private_key(io.StringIO(key_content), passphrase)
                break
            except Exception:
                continue

        if pkey is None:
            raise Exception("Unable to parse SSH key")
        return pkey.get_fingerprint().hex()
    except Exception as e:
        logger.debug(f"Error generating key fingerprint: {e}")
        return None


def format_validation_message(result: SSHKeyValidationResult) -> str:
    """
    Format validation result into human-readable message.

    Args:
        result: SSHKeyValidationResult object

    Returns:
        Formatted message string
    """
    if not result.is_valid:
        return f"Invalid SSH key: {result.error_message}"

    message_parts: List[str] = []

    # Basic info
    key_type_str = result.key_type.value.upper() if result.key_type else "Unknown"
    key_info = f"{key_type_str} key"
    if result.key_size:
        key_info += f" ({result.key_size} bits)"

    message_parts.append(f"Valid {key_info}")

    # Security level
    if result.security_level:
        security_msg = f"Security level: {result.security_level.value}"
        message_parts.append(security_msg)

    # Warnings
    if result.warnings:
        warning_msg = "Warnings: " + "; ".join(result.warnings)
        message_parts.append(warning_msg)

    # Recommendations
    if result.recommendations:
        rec_msg = "Recommendations: " + "; ".join(result.recommendations)
        message_parts.append(rec_msg)

    return ". ".join(message_parts)


def recommend_key_type() -> str:
    """
    Get current SSH key type recommendation.

    Returns:
        Recommended key type with rationale
    """
    return (
        "Ed25519 (recommended): Modern, secure, fast algorithm with small key size. "
        "Alternatively, use RSA 4096-bit for maximum compatibility."
    )


# ============================================================================
# SSH KEY METADATA EXTRACTION
# ============================================================================


def extract_ssh_key_metadata(key_content: str, passphrase: Optional[str] = None) -> Dict[str, Optional[str]]:
    """
    Extract SSH key metadata for storage and display.

    Args:
        key_content: SSH private key content as string
        passphrase: Optional passphrase for encrypted keys

    Returns:
        Dictionary containing:
        - fingerprint: SHA256 fingerprint (format: SHA256:base64hash)
        - key_type: Key type (rsa, ed25519, ecdsa, dsa)
        - key_bits: Key size in bits as string
        - key_comment: Key comment/label if found
        - error: Error message if extraction failed
    """
    try:
        # Validate and get comprehensive key information
        result = validate_ssh_key(key_content, passphrase)

        if not result.is_valid:
            return {
                "fingerprint": None,
                "key_type": None,
                "key_bits": None,
                "key_comment": None,
                "error": result.error_message or "Invalid SSH key",
            }

        # Get fingerprint
        fingerprint_hex = get_key_fingerprint(key_content, passphrase)

        # Format fingerprint as SHA256:base64 (like GitHub/OpenSSH format)
        fingerprint = None
        if fingerprint_hex:
            try:
                # Convert hex to bytes then to base64
                fingerprint_bytes = bytes.fromhex(fingerprint_hex)
                fingerprint_b64 = base64.b64encode(fingerprint_bytes).decode("ascii")
                fingerprint = f"SHA256:{fingerprint_b64}"
            except Exception:
                # Fallback to hex format
                fingerprint = f"MD5:{fingerprint_hex}"

        # Extract comment from key
        key_comment = extract_key_comment(key_content)

        return {
            "fingerprint": fingerprint,
            "key_type": result.key_type.value if result.key_type else None,
            "key_bits": str(result.key_size) if result.key_size else None,
            "key_comment": key_comment,
            "error": None,
        }

    except Exception as e:
        logger.error(f"Error extracting SSH key metadata: {e}")
        return {
            "fingerprint": None,
            "key_type": None,
            "key_bits": None,
            "key_comment": None,
            "error": f"Metadata extraction failed: {str(e)}",
        }


def extract_key_comment(key_content: str) -> Optional[str]:
    """
    Extract comment/label from SSH key content.

    Args:
        key_content: SSH key content as string

    Returns:
        Key comment if found, None otherwise
    """
    try:
        # Handle bytes input
        if isinstance(key_content, (bytes, memoryview)):
            key_content = key_content.decode("utf-8", errors="ignore")

        content_str = str(key_content).strip()

        # Look for public key format first (ssh-rsa AAAAB3... comment)
        pub_key_pattern = r"^(ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-\S+)\s+\S+\s+(.+)$"
        for line in content_str.split("\n"):
            line = line.strip()
            if line and not line.startswith("#") and not line.startswith("-"):
                match = re.match(pub_key_pattern, line)
                if match:
                    comment = match.group(2).strip()
                    if comment:
                        return comment

        # Look for comment in private key format
        comment_patterns = [
            r'Comment:\s*"([^"]+)"',  # Comment: "description"
            r"Comment:\s*([^\s]+)",  # Comment: description
        ]

        for pattern in comment_patterns:
            match = re.search(pattern, content_str, re.IGNORECASE)
            if match:
                return match.group(1).strip()

        return None

    except Exception as e:
        logger.debug(f"Error extracting key comment: {e}")
        return None


def format_key_display_info(
    fingerprint: Optional[str],
    key_type: Optional[str],
    key_bits: Optional[str],
    key_comment: Optional[str],
    created_date: Any,
) -> str:
    """
    Format SSH key information for user-friendly display.

    Args:
        fingerprint: Key fingerprint
        key_type: Key type (rsa, ed25519, etc.)
        key_bits: Key size in bits
        key_comment: Key comment/label
        created_date: Key creation date

    Returns:
        Formatted display string
    """
    parts = []

    # Key type and size
    if key_type:
        type_display = key_type.upper()
        if key_bits:
            type_display += f" {key_bits}"
        parts.append(type_display)

    # Comment
    if key_comment:
        parts.append(f'"{key_comment}"')

    # Fingerprint (shortened for display)
    if fingerprint:
        if len(fingerprint) > 47:  # SHA256: + 43 chars
            short_fp = fingerprint[:15] + "..." + fingerprint[-8:]
        else:
            short_fp = fingerprint
        parts.append(short_fp)

    # Creation date
    if created_date:
        if isinstance(created_date, str):
            parts.append(f"Added {created_date}")
        else:
            parts.append(f"Added {created_date.strftime('%Y-%m-%d')}")

    return " · ".join(parts) if parts else "SSH Key"


def get_key_security_indicator(key_type: Optional[str], key_bits: Optional[str]) -> Tuple[str, str]:
    """
    Get security level indicator for UI display.

    Args:
        key_type: Key type string
        key_bits: Key size as string

    Returns:
        Tuple of (color, label) for UI display
    """
    if not key_type:
        return "gray", "Unknown"

    key_type_lower = key_type.lower()
    key_size = int(key_bits) if key_bits and key_bits.isdigit() else None

    if key_type_lower == "ed25519":
        return "green", "Secure"
    elif key_type_lower == "rsa":
        if key_size and key_size >= 4096:
            return "green", "Secure"
        elif key_size and key_size >= 2048:
            return "yellow", "Acceptable"
        else:
            return "red", "Weak"
    elif key_type_lower == "ecdsa":
        if key_size and key_size >= 384:
            return "green", "Secure"
        elif key_size and key_size >= 256:
            return "yellow", "Acceptable"
        else:
            return "red", "Weak"
    elif key_type_lower == "dsa":
        return "red", "Deprecated"
    else:
        return "gray", "Unknown"


# ============================================================================
# UNIFIED SSH SERVICE
# ============================================================================


class UnifiedSSHService:
    """
    Unified SSH Service for OpenWatch

    Provides centralized SSH connection management across all OpenWatch services
    with consistent security policies, comprehensive audit logging, and
    automation-friendly host key handling.

    This service consolidates functionality from:
    - ssh_service.py: Basic SSH connectivity and command execution
    - ssh_utils.py: SSH key validation and security assessment
    - ssh_config_service.py: SSH host key policies and configuration
    - ssh_key_service.py: SSH key metadata extraction
    """

    def __init__(self, db: Optional[Session] = None) -> None:
        """Initialize unified SSH service"""
        self.db = db
        self.client: Optional[SSHClient] = None
        self.current_host: Optional[Host] = None
        self._settings_cache: Dict[str, Any] = {}
        self._cache_expiry: Optional[datetime] = None
        self._debug_mode = False  # Enable detailed SSH debugging

    def enable_debug_mode(self) -> None:
        """Enable detailed SSH debugging"""
        self._debug_mode = True
        # Enable paramiko debug logging
        paramiko.util.log_to_file("/tmp/paramiko_debug.log")
        logger.info("SSH debug mode enabled - detailed logs will be written to /tmp/paramiko_debug.log")

    def disable_debug_mode(self) -> None:
        """Disable SSH debugging"""
        self._debug_mode = False
        logger.info("SSH debug mode disabled")

    # ========================================================================
    # BASIC SSH CONNECTIVITY (from ssh_service.py)
    # ========================================================================

    def connect(self, host: Host, timeout: int = 10) -> bool:
        """
        Establish SSH connection to a host

        Args:
            host: Host object to connect to
            timeout: Connection timeout in seconds

        Returns:
            True if connection successful, False otherwise
        """
        try:
            if self.client:
                self.disconnect()

            self.client = paramiko.SSHClient()

            # Configure with security policy
            self.configure_ssh_client(self.client, host.ip_address)

            # Extract connection details
            hostname = host.ip_address or host.hostname
            port = host.port or 22
            username = host.username

            # For now, we'll handle key-based authentication
            # In a real implementation, you'd decrypt the stored credentials
            self.client.connect(
                hostname=hostname,
                port=port,
                username=username,
                timeout=timeout,
                look_for_keys=True,
                allow_agent=True,
            )

            self.current_host = host
            logger.info(f"Successfully connected to {hostname}:{port}")
            return True

        except Exception as e:
            logger.error(f"Failed to connect to {hostname if 'hostname' in locals() else 'host'}: {e}")
            return False

    def disconnect(self) -> None:
        """Close SSH connection"""
        try:
            if self.client:
                self.client.close()
                self.client = None
            self.current_host = None
            logger.debug("SSH connection closed")
        except Exception as e:
            logger.warning(f"Error closing SSH connection: {e}")

    def execute_command(self, command: str, timeout: int = 30) -> Dict[str, Any]:
        """
        Execute a command over SSH

        Args:
            command: Command to execute
            timeout: Command timeout in seconds

        Returns:
            Dictionary with execution results
        """
        if not self.client:
            return {
                "success": False,
                "error": "No SSH connection established",
                "stdout": "",
                "stderr": "",
                "exit_code": -1,
            }

        try:
            start_time = datetime.now()

            # Execute command
            stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)

            # Read output
            stdout_data = stdout.read().decode("utf-8", errors="ignore")
            stderr_data = stderr.read().decode("utf-8", errors="ignore")
            exit_code = stdout.channel.recv_exit_status()

            duration = (datetime.now() - start_time).total_seconds()

            result = {
                "success": exit_code == 0,
                "stdout": stdout_data,
                "stderr": stderr_data,
                "exit_code": exit_code,
                "duration": duration,
                "command": command,
            }

            logger.debug(f"Command executed: {command} (exit_code: {exit_code}, duration: {duration:.2f}s)")
            return result

        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "stdout": "",
                "stderr": "",
                "exit_code": -1,
                "command": command,
            }

    async def execute_command_async(
        self, host: Any, credentials: Any, command: str, timeout: int = 30  # pragma: allowlist secret
    ) -> Any:
        """
        Async wrapper for execute_command for use by readiness check modules.

        Creates a temporary SSH connection, executes command, returns result.
        This is a compatibility layer for the readiness check modules.

        Args:
            host: Host model instance
            credentials: CredentialData from AuthService  # pragma: allowlist secret
            command: Command to execute
            timeout: Command timeout in seconds

        Returns:
            Object with exit_code, stdout, stderr attributes
        """
        import asyncio
        from types import SimpleNamespace

        def _execute_sync() -> Any:
            """Synchronous SSH execution"""
            UnifiedSSHService()

            # Create temporary SSHClient
            temp_client = paramiko.SSHClient()
            temp_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            try:
                # Build connection parameters
                hostname = host.ip_address or host.hostname
                port = host.port if hasattr(host, "port") else 22

                # Connect based on auth method
                # Handle both enum and string values for auth_method
                auth_method_str = (
                    credentials.auth_method
                    if isinstance(credentials.auth_method, str)
                    else credentials.auth_method.value
                )
                if auth_method_str == "ssh_key" and credentials.private_key:  # pragma: allowlist secret
                    # Use SSH key authentication
                    import io

                    key_file = io.StringIO(credentials.private_key)  # pragma: allowlist secret

                    # Determine key type and load
                    try:
                        pkey = paramiko.RSAKey.from_private_key(key_file)
                    except Exception:
                        key_file.seek(0)
                        try:
                            pkey = paramiko.Ed25519Key.from_private_key(key_file)
                        except Exception:
                            key_file.seek(0)
                            pkey = paramiko.ECDSAKey.from_private_key(key_file)

                    temp_client.connect(
                        hostname=hostname,
                        port=port,
                        username=credentials.username,  # pragma: allowlist secret
                        pkey=pkey,
                        timeout=timeout,
                        look_for_keys=False,
                        allow_agent=False,
                    )
                else:
                    # Use password authentication
                    temp_client.connect(
                        hostname=hostname,
                        port=port,
                        username=credentials.username,  # pragma: allowlist secret
                        password=credentials.password,  # pragma: allowlist secret
                        timeout=timeout,
                        look_for_keys=False,
                        allow_agent=False,
                    )

                # Execute command
                stdin, stdout, stderr = temp_client.exec_command(command, timeout=timeout)

                # Read output
                stdout_data = stdout.read().decode("utf-8", errors="ignore")
                stderr_data = stderr.read().decode("utf-8", errors="ignore")
                exit_code = stdout.channel.recv_exit_status()

                return SimpleNamespace(
                    exit_code=exit_code,
                    stdout=stdout_data,
                    stderr=stderr_data,
                    success=(exit_code == 0),
                )

            except Exception as e:
                logger.error(f"SSH command execution failed: {e}")
                return SimpleNamespace(exit_code=-1, stdout="", stderr=str(e), success=False)
            finally:
                if temp_client:
                    temp_client.close()

        # Run synchronous SSH in thread pool to avoid blocking async event loop
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, _execute_sync)
        return result

    def is_connected(self) -> bool:
        """Check if SSH connection is active"""
        try:
            if not self.client:
                return False

            # Try to get transport status
            transport = self.client.get_transport()
            return transport is not None and transport.is_active()
        except Exception:
            return False

    def test_connection(self, host: Host) -> Dict[str, Any]:
        """
        Test SSH connectivity without establishing persistent connection

        Args:
            host: Host object to test

        Returns:
            Dictionary with test results
        """
        temp_client = None
        try:
            temp_client = paramiko.SSHClient()
            self.configure_ssh_client(temp_client, host.ip_address)

            hostname = host.ip_address or host.hostname
            port = host.port or 22
            username = host.username

            start_time = datetime.now()
            temp_client.connect(
                hostname=hostname,
                port=port,
                username=username,
                timeout=10,
                look_for_keys=True,
                allow_agent=True,
            )

            duration = (datetime.now() - start_time).total_seconds()

            return {
                "success": True,
                "hostname": hostname,
                "port": port,
                "username": username,
                "duration": duration,
                "message": f"Successfully connected to {hostname}:{port}",
            }

        except Exception as e:
            return {
                "success": False,
                "hostname": hostname if "hostname" in locals() else "unknown",
                "port": port if "port" in locals() else 22,
                "username": username if "username" in locals() else "unknown",
                "error": str(e),
                "message": f"Failed to connect: {str(e)}",
            }
        finally:
            if temp_client:
                try:
                    temp_client.close()
                except Exception:
                    pass

    # ========================================================================
    # SSH CONFIGURATION AND POLICIES (from ssh_config_service.py)
    # ========================================================================

    def get_setting(self, key: str, default: Any = None) -> Any:
        """
        Get a system setting value with caching.

        Returns the default value if the system_settings table doesn't exist yet,
        as this is expected during initial setup or when the feature is not in use.
        """
        if not self.db:
            logger.warning("No database session available for SSH config service")
            return default

        try:
            # Import here to avoid circular imports
            from ..models.system_models import SystemSettings

            setting = self.db.query(SystemSettings).filter(SystemSettings.setting_key == key).first()

            if not setting:
                return default

            # Convert based on type
            if setting.setting_type == "json":
                return json.loads(setting.setting_value) if setting.setting_value else default
            elif setting.setting_type == "boolean":
                return setting.setting_value.lower() in ("true", "1", "yes") if setting.setting_value else default
            elif setting.setting_type == "integer":
                return int(setting.setting_value) if setting.setting_value else default
            else:
                return setting.setting_value or default

        except Exception as e:
            # Check if error is due to missing table (expected during setup)
            error_msg = str(e).lower()
            if "does not exist" in error_msg or "relation" in error_msg:
                # Table doesn't exist yet - this is expected, use default silently
                logger.debug(f"system_settings table not found, using default for {key}: {default}")
            else:
                # Unexpected error - log it
                logger.error(f"Error getting setting {key}: {e}")

            # Rollback transaction on error to prevent "aborted transaction" state
            if self.db:
                self.db.rollback()
            return default

    def set_setting(self, key: str, value: Any, setting_type: str, description: str, user_id: int) -> bool:
        """Set a system setting value"""
        if not self.db:
            logger.warning("No database session available for SSH config service")
            return False

        try:
            # Import here to avoid circular imports
            from ..models.system_models import SystemSettings

            # Convert value to string based on type
            if setting_type == "json":
                string_value = json.dumps(value)
            elif setting_type == "boolean":
                string_value = str(value).lower()
            else:
                string_value = str(value)

            # Update or create setting
            setting = self.db.query(SystemSettings).filter(SystemSettings.setting_key == key).first()

            if setting:
                setting.setting_value = string_value
                setting.setting_type = setting_type
                setting.description = description
                setting.modified_by = user_id
                setting.modified_at = datetime.utcnow()
            else:
                setting = SystemSettings(
                    setting_key=key,
                    setting_value=string_value,
                    setting_type=setting_type,
                    description=description,
                    created_by=user_id,
                    modified_by=user_id,
                )
                self.db.add(setting)

            self.db.commit()
            logger.info(f"Updated setting {key} = {string_value}")
            return True

        except Exception as e:
            logger.error(f"Error setting {key}: {e}")
            if self.db:
                self.db.rollback()
            return False

    def get_ssh_policy(self) -> str:
        """Get current SSH host key policy"""
        return self.get_setting("ssh_host_key_policy", "auto_add_warning")

    def set_ssh_policy(self, policy: str, user_id: Optional[int] = None) -> bool:
        """Set SSH host key policy"""
        valid_policies = ["strict", "auto_add", "auto_add_warning", "bypass_trusted"]

        if policy not in valid_policies:
            logger.error(f"Invalid SSH policy: {policy}. Valid options: {valid_policies}")
            return False

        return self.set_setting(
            "ssh_host_key_policy",
            policy,
            "string",
            f"SSH host key verification policy: {policy}",
            user_id or 1,
        )

    def get_trusted_networks(self) -> List[str]:
        """Get trusted network ranges"""
        networks = self.get_setting("ssh_trusted_networks", [])
        if isinstance(networks, str):
            try:
                networks = json.loads(networks)
            except Exception:
                networks = []
        return networks if isinstance(networks, list) else []

    def set_trusted_networks(self, networks: List[str], user_id: Optional[int] = None) -> bool:
        """Set trusted network ranges"""
        # Validate network ranges
        valid_networks = []
        for network in networks:
            try:
                ipaddress.ip_network(network, strict=False)
                valid_networks.append(network)
            except ValueError as e:
                logger.warning(f"Invalid network range {network}: {e}")

        return self.set_setting(
            "ssh_trusted_networks",
            valid_networks,
            "json",
            "Trusted network ranges for SSH host key bypass",
            user_id or 1,
        )

    def is_host_in_trusted_network(self, host_ip: str) -> bool:
        """Check if host is in trusted network range"""
        try:
            host_addr = ipaddress.ip_address(host_ip)
            trusted_networks = self.get_trusted_networks()

            for network_str in trusted_networks:
                try:
                    network = ipaddress.ip_network(network_str, strict=False)
                    if host_addr in network:
                        return True
                except ValueError:
                    continue

            return False
        except ValueError:
            return False

    def create_ssh_policy(self, host_ip: Optional[str] = None) -> paramiko.MissingHostKeyPolicy:
        """Create paramiko policy object based on configuration"""
        policy = self.get_ssh_policy()

        if policy == "strict":
            return paramiko.RejectPolicy()
        elif policy == "auto_add":
            return paramiko.AutoAddPolicy()
        elif policy == "auto_add_warning":
            return SecurityWarningPolicy()
        elif policy == "bypass_trusted":
            if host_ip and self.is_host_in_trusted_network(host_ip):
                return paramiko.AutoAddPolicy()
            else:
                return SecurityWarningPolicy()
        else:
            # Default to warning policy
            return SecurityWarningPolicy()

    def configure_ssh_client(self, ssh: paramiko.SSHClient, host_ip: Optional[str] = None) -> None:
        """Configure SSH client with security policy"""
        try:
            policy = self.create_ssh_policy(host_ip)
            ssh.set_missing_host_key_policy(policy)

            # Load system host keys
            try:
                ssh.load_system_host_keys()
            except Exception as e:
                logger.debug(f"Could not load system host keys: {e}")

            # Load user host keys
            try:
                ssh.load_host_keys(os.path.expanduser("~/.ssh/known_hosts"))
            except Exception as e:
                logger.debug(f"Could not load user host keys: {e}")

        except Exception as e:
            logger.warning(f"Error configuring SSH client: {e}")
            # Fallback to warning policy
            ssh.set_missing_host_key_policy(SecurityWarningPolicy())

    # ========================================================================
    # ADVANCED CONNECTION METHODS (from unified_ssh_service.py)
    # ========================================================================

    def connect_with_credentials(
        self,
        hostname: str,
        port: int,
        username: str,
        auth_method: str,
        credential: str,
        service_name: str,
        timeout: Optional[int] = None,
        password: Optional[str] = None,
    ) -> SSHConnectionResult:
        """
        Advanced SSH connection with various authentication methods.

        Args:
            hostname: Target hostname or IP
            port: SSH port
            username: Username for authentication
            auth_method: Authentication method (password, key, ssh_key, ssh-key, agent, both)
            credential: Password or private key content (used for single auth methods)
            service_name: Service name for logging
            timeout: Connection timeout
            password: Password for "both" authentication method (optional)

        Returns:
            SSHConnectionResult with detailed connection information

        Note:
            When auth_method='both', credential should contain private key and password param contains password.
            The method will try SSH key first, then fallback to password if key authentication fails.
        """
        start_time = datetime.utcnow()
        client = None

        try:
            client = SSHClient()
            self.configure_ssh_client(client, hostname)

            # Set timeouts
            connect_timeout = timeout or 30

            if self._debug_mode:
                logger.info(f"[DEBUG] SSH connection attempt to {hostname}:{port} as {username}")
                logger.info(f"[DEBUG] Auth method: {auth_method}, Timeout: {connect_timeout}s")
                logger.info(f"[DEBUG] Service: {service_name}")

            # NEW: Handle "both" authentication with fallback (Phase 3)
            if auth_method == "both":
                logger.info(f"Credential has 'both' auth method, attempting SSH key first for {username}@{hostname}")

                # Try SSH key first (faster, more secure)
                if credential:  # credential contains private key for "both"
                    try:
                        pkey = parse_ssh_key(credential)
                        logger.debug(f"SSH key parsed successfully - Type: {pkey.get_name()}, Bits: {pkey.get_bits()}")

                        try:
                            client.connect(
                                hostname=hostname,
                                port=port,
                                username=username,
                                pkey=pkey,
                                timeout=connect_timeout,
                                allow_agent=False,
                                look_for_keys=False,
                            )
                            auth_method_used = "private_key"
                            logger.info(f"SSH key authentication successful for {username}@{hostname} (both method)")
                        except paramiko.AuthenticationException as e:
                            logger.warning(f"SSH key authentication failed for {username}@{hostname}: {str(e)}")
                            # Close failed connection before retry
                            if client:
                                client.close()
                                client = None
                            # Will try password below
                    except SSHKeyError as e:
                        logger.warning(f"SSH key parsing failed for {username}@{hostname}: {str(e)}")
                        # Will try password below

                # Fallback to password if SSH key didn't succeed
                if not client or not client.get_transport() or not client.get_transport().is_active():
                    if password:
                        logger.info(f"Falling back to password authentication for {username}@{hostname}")
                        if not client:
                            client = SSHClient()
                            self.configure_ssh_client(client, hostname)

                        try:
                            client.connect(
                                hostname=hostname,
                                port=port,
                                username=username,
                                password=password,
                                timeout=connect_timeout,
                                allow_agent=False,
                                look_for_keys=False,
                            )
                            auth_method_used = "password"
                            logger.info(
                                f"Password authentication successful for {username}@{hostname} (both method fallback)"
                            )
                        except paramiko.AuthenticationException:
                            if client:
                                client.close()
                            logger.error(f"Both SSH key and password authentication failed for {username}@{hostname}")
                            return SSHConnectionResult(
                                success=False,
                                error_message=f"Both SSH key and password authentication failed for {username}@{hostname}",
                                error_type="auth_failed",
                            )
                    else:
                        if client:
                            client.close()
                        logger.error(
                            "SSH key authentication failed and no password provided for fallback (both method)"
                        )
                        return SSHConnectionResult(
                            success=False,
                            error_message="SSH key authentication failed and no password provided for fallback",
                            error_type="auth_failed",
                        )

            elif auth_method == "password":
                client.connect(
                    hostname=hostname,
                    port=port,
                    username=username,
                    password=credential,
                    timeout=connect_timeout,
                    allow_agent=False,
                    look_for_keys=False,
                )
                auth_method_used = "password"

            elif auth_method in ["key", "ssh_key", "ssh-key"]:
                # Parse private key (handle both "key" and "ssh_key" for compatibility)
                try:
                    pkey = parse_ssh_key(credential)
                    # Log key info for debugging (without exposing sensitive data)
                    logger.debug(f"SSH key parsed successfully - Type: {pkey.get_name()}, Bits: {pkey.get_bits()}")

                    client.connect(
                        hostname=hostname,
                        port=port,
                        username=username,
                        pkey=pkey,
                        timeout=connect_timeout,
                        allow_agent=False,
                        look_for_keys=False,
                    )
                    auth_method_used = "private_key"
                except SSHKeyError as e:
                    logger.error(f"SSH key parsing failed: {str(e)}")
                    return SSHConnectionResult(
                        success=False,
                        error_message=f"Invalid private key: {str(e)}",
                        error_type="key_error",
                    )

            elif auth_method == "agent":
                client.connect(
                    hostname=hostname,
                    port=port,
                    username=username,
                    timeout=connect_timeout,
                    allow_agent=True,
                    look_for_keys=True,
                )
                auth_method_used = "ssh_agent"

            else:
                return SSHConnectionResult(
                    success=False,
                    error_message=f"Unsupported authentication method: {auth_method}. Supported methods: password, key, ssh_key, ssh-key, agent, both",
                    error_type="auth_error",
                )

            # Get host key fingerprint
            transport = client.get_transport()
            host_key = transport.get_remote_server_key()
            host_key_fingerprint = host_key.get_fingerprint().hex() if host_key else None

            # Log successful connection
            duration = (datetime.utcnow() - start_time).total_seconds()
            logger.info(
                f"SSH connection successful: {service_name} -> {username}@{hostname}:{port} "
                f"(auth: {auth_method_used}, duration: {duration:.2f}s)"
            )

            return SSHConnectionResult(
                success=True,
                connection=client,
                host_key_fingerprint=host_key_fingerprint,
                auth_method_used=auth_method_used,
            )

        except paramiko.AuthenticationException as e:
            if client:
                client.close()
            # Enhanced error logging for authentication failures
            logger.error(f"SSH authentication failed for {username}@{hostname}:{port} using {auth_method} auth")
            logger.debug(f"AuthenticationException details: {str(e)}")

            # Try to determine specific authentication failure reason
            error_details = str(e).lower()
            if "no authentication methods available" in error_details:
                specific_error = "No authentication methods accepted by server"
            elif "authentication failed" in error_details:
                specific_error = "Invalid credentials or key not accepted"
            elif "permission denied" in error_details:
                specific_error = "Permission denied (check username/key permissions)"
            else:
                specific_error = "Authentication failed"

            return SSHConnectionResult(
                success=False,
                error_message=f"{specific_error} for {username}@{hostname}",
                error_type="auth_failed",
            )

        except paramiko.SSHException as e:
            if client:
                client.close()
            logger.error(f"SSH connection error to {hostname}:{port}: {str(e)}")

            # Provide more specific SSH error messages
            error_details = str(e).lower()
            if "unable to connect" in error_details:
                specific_error = "Unable to establish SSH connection"
            elif "host key" in error_details:
                specific_error = "Host key verification failed"
            elif "banner" in error_details:
                specific_error = "SSH banner exchange failed"
            else:
                specific_error = f"SSH protocol error: {str(e)}"

            return SSHConnectionResult(success=False, error_message=specific_error, error_type="ssh_error")

        except socket.timeout:
            if client:
                client.close()
            logger.warning(f"SSH connection timeout to {hostname}:{port} after {connect_timeout}s")
            return SSHConnectionResult(
                success=False,
                error_message=f"Connection timeout to {hostname}:{port} after {connect_timeout}s",
                error_type="timeout",
            )

        except socket.error as e:
            if client:
                client.close()
            logger.error(f"Socket error connecting to {hostname}:{port}: {str(e)}")

            # Provide specific socket error messages
            if hasattr(e, "errno"):
                if e.errno == errno.ECONNREFUSED:  # Connection refused
                    specific_error = "Connection refused (SSH service may not be running)"
                elif e.errno == errno.EHOSTUNREACH:  # No route to host
                    specific_error = "No route to host (network unreachable)"
                elif e.errno == errno.ETIMEDOUT:  # Connection timed out
                    specific_error = "Connection timed out"
                else:
                    specific_error = f"Network error (errno {e.errno}): {str(e)}"
            else:
                specific_error = f"Network error: {str(e)}"

            return SSHConnectionResult(
                success=False,
                error_message=specific_error,
                error_type="connection_error",
            )

        except Exception as e:
            if client:
                client.close()
            logger.error(f"Unexpected SSH connection error: {type(e).__name__}: {str(e)}")
            logger.debug("Full exception details:", exc_info=True)
            return SSHConnectionResult(
                success=False,
                error_message=f"Connection failed: {type(e).__name__}: {str(e)}",
                error_type="connection_error",
            )

    def execute_command_advanced(
        self, ssh_connection: SSHClient, command: str, timeout: Optional[int] = None
    ) -> SSHCommandResult:
        """
        Execute command with advanced result handling.

        Args:
            ssh_connection: Active SSH connection
            command: Command to execute
            timeout: Command timeout

        Returns:
            SSHCommandResult with detailed execution information
        """
        start_time = datetime.utcnow()
        command_timeout = timeout or 300  # 5 minute default

        try:
            # Execute command
            stdin, stdout, stderr = ssh_connection.exec_command(command, timeout=command_timeout)

            # Read output with timeout handling
            stdout_data = stdout.read().decode("utf-8", errors="replace").strip()
            stderr_data = stderr.read().decode("utf-8", errors="replace").strip()
            exit_code = stdout.channel.recv_exit_status()

            duration = (datetime.utcnow() - start_time).total_seconds()

            return SSHCommandResult(
                success=exit_code == 0,
                stdout=stdout_data,
                stderr=stderr_data,
                exit_code=exit_code,
                duration=duration,
            )

        except socket.timeout:
            return SSHCommandResult(
                success=False,
                error_message=f"Command timed out after {command_timeout} seconds",
            )
        except Exception as e:
            return SSHCommandResult(success=False, error_message=f"Command execution failed: {str(e)}")

    # ========================================================================
    # SSH KEY UTILITIES (wrapped from module functions)
    # ========================================================================

    def validate_ssh_key(self, key_content: str, passphrase: Optional[str] = None) -> SSHKeyValidationResult:
        """Validate SSH key with security assessment"""
        return validate_ssh_key(key_content, passphrase)

    def extract_ssh_key_metadata(self, key_content: str, passphrase: Optional[str] = None) -> Dict[str, Optional[str]]:
        """Extract SSH key metadata for storage and display"""
        return extract_ssh_key_metadata(key_content, passphrase)

    def get_key_fingerprint(self, key_content: str, passphrase: Optional[str] = None) -> Optional[str]:
        """Generate fingerprint for SSH key"""
        return get_key_fingerprint(key_content, passphrase)

    def format_validation_message(self, result: SSHKeyValidationResult) -> str:
        """Format validation result into human-readable message"""
        return format_validation_message(result)

    def recommend_key_type(self) -> str:
        """Get current SSH key type recommendation"""
        return recommend_key_type()

    def extract_key_comment(self, key_content: str) -> Optional[str]:
        """Extract comment/label from SSH key content"""
        return extract_key_comment(key_content)

    def format_key_display_info(
        self,
        fingerprint: Optional[str],
        key_type: Optional[str],
        key_bits: Optional[str],
        key_comment: Optional[str],
        created_date: Any,
    ) -> str:
        """Format SSH key information for user-friendly display"""
        return format_key_display_info(fingerprint, key_type, key_bits, key_comment, created_date)

    def get_key_security_indicator(self, key_type: Optional[str], key_bits: Optional[str]) -> Tuple[str, str]:
        """Get security level indicator for UI display"""
        return get_key_security_indicator(key_type, key_bits)

    def execute_minimal_system_check(
        self,
        hostname: str,
        port: int,
        username: str,
        auth_method: str,
        credential: str,
        service_name: str,
    ) -> Dict[str, Any]:
        """
        Execute minimal system discovery commands to reduce reconnaissance footprint.

        This replaces the original 7-command system discovery with just 2 essential
        checks that are required for SCAP compliance scanning.

        Args:
            hostname: Target hostname or IP address
            port: SSH port
            username: SSH username
            auth_method: Authentication method
            credential: Password or SSH key
            service_name: Name of calling service

        Returns:
            Dict containing essential system information
        """
        # Essential commands for SCAP scanning (reduced from 7 to 2)
        essential_commands = {
            "os_family": (
                "[ -f /etc/redhat-release ] && echo 'redhat' || "
                "([ -f /etc/debian_version ] && echo 'debian' || echo 'unknown')"
            ),
            "oscap_available": "command -v oscap >/dev/null 2>&1 && echo 'yes' || echo 'no'",
        }

        # Establish connection
        connection_result = self.connect_with_credentials(
            hostname=hostname,
            port=port,
            username=username,
            auth_method=auth_method,
            credential=credential,
            service_name=service_name,
        )

        if not connection_result.success:
            return {
                "error": connection_result.error_message,
                "error_type": connection_result.error_type,
                "commands_attempted": list(essential_commands.keys()),
            }

        # Execute essential commands
        results = {}
        ssh = connection_result.connection

        try:
            for key, command in essential_commands.items():
                logger.debug(f"Executing minimal discovery command '{key}': {command}")

                command_result = self.execute_command_advanced(ssh, command)

                if command_result.success:
                    results[key] = command_result.stdout
                    logger.debug(f"Command '{key}' result: {command_result.stdout}")
                else:
                    results[key] = "unknown"
                    logger.warning(f"Command '{key}' failed: {command_result.error_message}")

            # Log successful minimal discovery
            logger.info(f"Minimal system discovery completed for {hostname}: {results}")

        except Exception as e:
            logger.error(f"Error during minimal system discovery for {hostname}: {e}")
            results["error"] = str(e)

        finally:
            # Always close the SSH connection
            try:
                ssh.close()
            except Exception as e:
                logger.debug(f"Error closing SSH connection to {hostname}: {e}")

        return results

    def get_known_hosts(self, hostname: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get SSH known hosts from database.

        Args:
            hostname: Optional filter by hostname

        Returns:
            List[Dict]: List of known host entries
        """
        try:
            if not self.db:
                logger.warning("No database session available for SSH known hosts")
                return []

            query = """
                SELECT id, hostname, ip_address, key_type, fingerprint,
                       first_seen, last_verified, is_trusted, notes
                FROM ssh_known_hosts
                WHERE 1=1
            """
            params = {}

            if hostname:
                query += " AND hostname = :hostname"
                params["hostname"] = hostname

            query += " ORDER BY first_seen DESC"

            result = self.db.execute(text(query), params)

            hosts = []
            for row in result:
                hosts.append(
                    {
                        "id": row.id,
                        "hostname": row.hostname,
                        "ip_address": row.ip_address,
                        "key_type": row.key_type,
                        "fingerprint": row.fingerprint,
                        "first_seen": (row.first_seen.isoformat() if row.first_seen else None),
                        "last_verified": (row.last_verified.isoformat() if row.last_verified else None),
                        "is_trusted": row.is_trusted,
                        "notes": row.notes,
                    }
                )

            return hosts

        except Exception as e:
            logger.error(f"Failed to get known hosts: {e}")
            return []

    def add_known_host(
        self,
        hostname: str,
        ip_address: Optional[str],
        key_type: str,
        public_key: str,
        notes: Optional[str] = None,
    ) -> bool:
        """
        Add a known host to the database.

        Args:
            hostname: Hostname or IP
            ip_address: IP address (optional)
            key_type: SSH key type (rsa, ecdsa, ed25519, dsa)
            public_key: Public key content
            notes: Optional notes

        Returns:
            bool: True if successful
        """
        try:
            if not self.db:
                logger.warning("No database session available for adding known host")
                return False

            # Generate fingerprint from public key
            import base64
            import hashlib

            key_data = base64.b64decode(public_key.split()[1])
            fingerprint = hashlib.sha256(key_data).hexdigest()
            fingerprint = f"SHA256:{base64.b64encode(hashlib.sha256(key_data).digest()).decode().rstrip('=')}"

            self.db.execute(
                text(
                    """
                INSERT INTO ssh_known_hosts
                (hostname, ip_address, key_type, public_key, fingerprint, first_seen, is_trusted, notes)
                VALUES (:hostname, :ip_address, :key_type, :public_key, :fingerprint, :first_seen, :is_trusted, :notes)
            """
                ),
                {
                    "hostname": hostname,
                    "ip_address": ip_address,
                    "key_type": key_type,
                    "public_key": public_key,
                    "fingerprint": fingerprint,
                    "first_seen": datetime.utcnow(),
                    "is_trusted": True,
                    "notes": notes,
                },
            )

            self.db.commit()
            logger.info(f"Added known host: {hostname} ({key_type})")
            return True

        except Exception as e:
            logger.error(f"Failed to add known host {hostname}: {e}")
            self.db.rollback()
            return False

    def remove_known_host(self, hostname: str, key_type: str) -> bool:
        """
        Remove a known host from the database.

        Args:
            hostname: Hostname to remove
            key_type: Key type to remove

        Returns:
            bool: True if successful
        """
        try:
            if not self.db:
                logger.warning("No database session available for removing known host")
                return False

            result = self.db.execute(
                text(
                    """
                DELETE FROM ssh_known_hosts
                WHERE hostname = :hostname AND key_type = :key_type
            """
                ),
                {"hostname": hostname, "key_type": key_type},
            )

            self.db.commit()

            if result.rowcount > 0:
                logger.info(f"Removed known host: {hostname} ({key_type})")
                return True
            else:
                logger.warning(f"Known host not found: {hostname} ({key_type})")
                return False

        except Exception as e:
            logger.error(f"Failed to remove known host {hostname}: {e}")
            self.db.rollback()
            return False


# ============================================================================
# CONVENIENCE FUNCTIONS FOR BACKWARD COMPATIBILITY
# ============================================================================


def get_ssh_config_service(db: Optional[Session] = None) -> UnifiedSSHService:
    """Factory function for backward compatibility"""
    return UnifiedSSHService(db)


def configure_ssh_client_with_policy(ssh: paramiko.SSHClient, host_ip: Optional[str] = None) -> None:
    """Convenience function for SSH client configuration"""
    service = UnifiedSSHService()
    service.configure_ssh_client(ssh, host_ip)


# Legacy class aliases for backward compatibility
SSHService = UnifiedSSHService
SSHConfigService = UnifiedSSHService

# Export all public functions and classes
__all__ = [
    # Main service class
    "UnifiedSSHService",
    # Legacy aliases
    "SSHService",
    "SSHConfigService",
    # Data classes and enums
    "SSHKeyType",
    "SSHKeySecurityLevel",
    "SSHKeyValidationResult",
    "SSHKeyError",
    "SSHConnectionResult",
    "SSHCommandResult",
    "SecurityWarningPolicy",
    # Utility functions
    "detect_key_type",
    "parse_ssh_key",
    "get_key_size",
    "assess_key_security",
    "validate_ssh_key",
    "get_key_fingerprint",
    "format_validation_message",
    "recommend_key_type",
    "extract_ssh_key_metadata",
    "extract_key_comment",
    "format_key_display_info",
    "get_key_security_indicator",
    # Configuration functions
    "get_ssh_config_service",
    "configure_ssh_client_with_policy",
]
