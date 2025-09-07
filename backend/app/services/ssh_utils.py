"""
SSH Key Utility Module for OpenWatch

Provides unified SSH key parsing, validation, and security recommendations
for all supported key types (RSA, Ed25519, ECDSA, DSA).
"""

import re
import base64
from typing import Dict, Optional, Tuple, Union
from enum import Enum
import paramiko
from paramiko import RSAKey, Ed25519Key, ECDSAKey, DSSKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, ec, dsa
import logging

logger = logging.getLogger(__name__)


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
        warnings: Optional[list] = None,
        recommendations: Optional[list] = None,
    ):
        self.is_valid = is_valid
        self.key_type = key_type
        self.security_level = security_level
        self.key_size = key_size
        self.error_message = error_message
        self.warnings = warnings or []
        self.recommendations = recommendations or []


class SSHKeyError(Exception):
    """Custom exception for SSH key operations"""

    pass


def detect_key_type(key_content: str) -> Optional[SSHKeyType]:
    """
    Detect SSH key type based on PEM headers or content analysis.

    Args:
        key_content: SSH private key content as string

    Returns:
        SSHKeyType if detected, None if unrecognized
    """
    # Handle both string and bytes/memoryview input (for database compatibility)
    if isinstance(key_content, (bytes, memoryview)):
        try:
            key_content = (
                key_content.decode("utf-8")
                if isinstance(key_content, bytes)
                else key_content.tobytes().decode("utf-8")
            )
        except (UnicodeDecodeError, AttributeError):
            return None

    if not isinstance(key_content, str):
        return None

    key_content = key_content.strip()

    # RSA key patterns
    if "BEGIN RSA PRIVATE KEY" in key_content:
        return SSHKeyType.RSA

    # Modern RSA keys in PKCS#8 format
    if "BEGIN PRIVATE KEY" in key_content:
        try:
            # Try to parse as PKCS#8 and determine algorithm
            key_bytes = key_content.encode("utf-8")
            private_key = serialization.load_pem_private_key(key_bytes, password=None)
            if isinstance(private_key, rsa.RSAPrivateKey):
                return SSHKeyType.RSA
            elif isinstance(private_key, ed25519.Ed25519PrivateKey):
                return SSHKeyType.ED25519
            elif isinstance(private_key, ec.EllipticCurvePrivateKey):
                return SSHKeyType.ECDSA
            elif isinstance(private_key, dsa.DSAPrivateKey):
                return SSHKeyType.DSA
        except Exception:
            pass

    # OpenSSH format keys (can be RSA, Ed25519, ECDSA, etc.)
    if "BEGIN OPENSSH PRIVATE KEY" in key_content:
        # Try to detect key type by attempting to parse with each key class
        key_bytes = key_content.encode("utf-8")

        # Check for Ed25519 identifier first (most specific)
        if "ssh-ed25519" in key_content or "Ed25519" in key_content:
            return SSHKeyType.ED25519

        # Try parsing as each type to detect the actual key type
        from io import StringIO

        key_io = StringIO(key_content)

        try:
            key_io.seek(0)
            Ed25519Key.from_private_key(key_io, password=None)
            return SSHKeyType.ED25519
        except Exception:
            pass

        try:
            key_io.seek(0)
            RSAKey.from_private_key(key_io, password=None)
            return SSHKeyType.RSA
        except Exception:
            pass

        try:
            key_io.seek(0)
            ECDSAKey.from_private_key(key_io, password=None)
            return SSHKeyType.ECDSA
        except Exception:
            pass

        try:
            key_io.seek(0)
            DSSKey.from_private_key(key_io, password=None)
            return SSHKeyType.DSA
        except Exception:
            pass

    # ECDSA keys
    if "BEGIN EC PRIVATE KEY" in key_content:
        return SSHKeyType.ECDSA

    # DSA keys
    if "BEGIN DSA PRIVATE KEY" in key_content:
        return SSHKeyType.DSA

    return None


def parse_ssh_key(key_content: str, passphrase: Optional[str] = None) -> paramiko.PKey:
    """
    Parse SSH private key content using appropriate Paramiko key class.

    Args:
        key_content: SSH private key content as string
        passphrase: Optional passphrase for encrypted keys

    Returns:
        Paramiko PKey object

    Raises:
        SSHKeyError: If key cannot be parsed
    """
    # Handle both string and bytes/memoryview input (for database compatibility)
    if isinstance(key_content, (bytes, memoryview)):
        try:
            key_content = (
                key_content.decode("utf-8")
                if isinstance(key_content, bytes)
                else key_content.tobytes().decode("utf-8")
            )
        except (UnicodeDecodeError, AttributeError):
            raise SSHKeyError("Invalid key format - could not decode key content")

    if not isinstance(key_content, str):
        raise SSHKeyError("Invalid key format - key content must be string")

    key_content = key_content.strip()

    # Try each key type in order of preference
    key_classes = [(Ed25519Key, "Ed25519"), (ECDSAKey, "ECDSA"), (RSAKey, "RSA"), (DSSKey, "DSA")]

    last_error = None
    for key_class, key_name in key_classes:
        try:
            from io import StringIO

            key_io = StringIO(key_content)
            return key_class.from_private_key(key_io, password=passphrase)
        except Exception as e:
            last_error = e
            logger.debug(f"Failed to parse as {key_name} key: {e}")
            continue

    raise SSHKeyError(f"Unable to parse SSH key: {last_error}")


def get_key_size(pkey: paramiko.PKey) -> Optional[int]:
    """
    Get the size/length of an SSH key.

    Args:
        pkey: Paramiko PKey object

    Returns:
        Key size in bits, or None if cannot determine
    """
    try:
        if isinstance(pkey, RSAKey):
            return pkey.get_bits()
        elif isinstance(pkey, Ed25519Key):
            return 256  # Ed25519 is always 256-bit
        elif isinstance(pkey, ECDSAKey):
            # ECDSA key size depends on the curve
            return pkey.get_bits()
        elif isinstance(pkey, DSSKey):
            return pkey.get_bits()
    except Exception:
        pass

    return None


def assess_key_security(
    key_type: SSHKeyType, key_size: Optional[int]
) -> Tuple[SSHKeySecurityLevel, list, list]:
    """
    Assess security level of SSH key based on type and size.

    Args:
        key_type: Type of SSH key
        key_size: Key size in bits

    Returns:
        Tuple of (security_level, warnings, recommendations)
    """
    warnings = []
    recommendations = []

    if key_type == SSHKeyType.ED25519:
        return SSHKeySecurityLevel.SECURE, warnings, recommendations

    elif key_type == SSHKeyType.RSA:
        if key_size is None:
            warnings.append("Unable to determine RSA key size")
            return (
                SSHKeySecurityLevel.ACCEPTABLE,
                warnings,
                ["Verify key size meets security requirements"],
            )

        if key_size < 2048:
            return (
                SSHKeySecurityLevel.REJECTED,
                ["RSA key size too small"],
                ["Use RSA-4096 or Ed25519 keys"],
            )
        elif key_size < 3072:
            return (
                SSHKeySecurityLevel.DEPRECATED,
                ["RSA-2048 keys are deprecated"],
                ["Upgrade to RSA-4096 or Ed25519"],
            )
        elif key_size < 4096:
            warnings.append("RSA-3072 keys are acceptable but RSA-4096 is recommended")
            return (
                SSHKeySecurityLevel.ACCEPTABLE,
                warnings,
                ["Consider upgrading to RSA-4096 or Ed25519"],
            )
        else:
            return SSHKeySecurityLevel.SECURE, warnings, recommendations

    elif key_type == SSHKeyType.ECDSA:
        if key_size and key_size >= 256:
            return SSHKeySecurityLevel.SECURE, warnings, recommendations
        else:
            warnings.append("ECDSA key size may be insufficient")
            return (
                SSHKeySecurityLevel.ACCEPTABLE,
                warnings,
                ["Verify ECDSA curve meets requirements"],
            )

    elif key_type == SSHKeyType.DSA:
        return (
            SSHKeySecurityLevel.REJECTED,
            ["DSA keys are deprecated and insecure"],
            ["Use Ed25519 or RSA-4096 keys"],
        )

    return SSHKeySecurityLevel.ACCEPTABLE, ["Unknown key type security assessment"], []


def validate_ssh_key(key_content: str, passphrase: Optional[str] = None) -> SSHKeyValidationResult:
    """
    Validate SSH private key with comprehensive security assessment.

    Args:
        key_content: SSH private key content as string
        passphrase: Optional passphrase for encrypted keys

    Returns:
        SSHKeyValidationResult with validation details
    """
    # Handle both string and bytes/memoryview input (for database compatibility)
    if isinstance(key_content, (bytes, memoryview)):
        try:
            key_content = (
                key_content.decode("utf-8")
                if isinstance(key_content, bytes)
                else key_content.tobytes().decode("utf-8")
            )
        except (UnicodeDecodeError, AttributeError):
            return SSHKeyValidationResult(
                is_valid=False,
                error_message="Invalid key format - could not decode key content",
                key_type=None,
                key_size=None,
                security_level=None,
                warnings=[],
                recommendations=[],
            )

    if not isinstance(key_content, str):
        return SSHKeyValidationResult(
            is_valid=False,
            error_message="Invalid key format - key content must be string",
            key_type=None,
            key_size=None,
            security_level=None,
            warnings=[],
            recommendations=[],
        )
    if not key_content or not key_content.strip():
        return SSHKeyValidationResult(is_valid=False, error_message="SSH key content is empty")

    # Detect key type
    key_type = detect_key_type(key_content)
    if not key_type:
        return SSHKeyValidationResult(
            is_valid=False,
            error_message="Unable to detect SSH key type. Supported types: RSA, Ed25519, ECDSA, DSA",
        )

    # Parse the key
    try:
        pkey = parse_ssh_key(key_content, passphrase)
    except SSHKeyError as e:
        return SSHKeyValidationResult(is_valid=False, key_type=key_type, error_message=str(e))
    except Exception as e:
        return SSHKeyValidationResult(
            is_valid=False, key_type=key_type, error_message=f"Failed to parse SSH key: {e}"
        )

    # Get key size
    key_size = get_key_size(pkey)

    # Assess security
    security_level, warnings, recommendations = assess_key_security(key_type, key_size)

    # Check if key should be rejected
    is_valid = security_level != SSHKeySecurityLevel.REJECTED

    return SSHKeyValidationResult(
        is_valid=is_valid,
        key_type=key_type,
        security_level=security_level,
        key_size=key_size,
        error_message=None if is_valid else "SSH key rejected due to security policy",
        warnings=warnings,
        recommendations=recommendations,
    )


def get_key_fingerprint(key_content: str, passphrase: Optional[str] = None) -> Optional[str]:
    """
    Get SSH key fingerprint for identification.

    Args:
        key_content: SSH private key content
        passphrase: Optional passphrase for encrypted keys

    Returns:
        SHA256 fingerprint string or None if unable to generate
    """
    # Handle both string and bytes/memoryview input (for database compatibility)
    if isinstance(key_content, (bytes, memoryview)):
        try:
            key_content = (
                key_content.decode("utf-8")
                if isinstance(key_content, bytes)
                else key_content.tobytes().decode("utf-8")
            )
        except (UnicodeDecodeError, AttributeError):
            return None

    if not isinstance(key_content, str):
        return None
    try:
        pkey = parse_ssh_key(key_content, passphrase)
        return pkey.get_fingerprint().hex()
    except Exception:
        return None


def format_validation_message(result: SSHKeyValidationResult) -> str:
    """
    Format validation result into a user-friendly message.

    Args:
        result: SSH key validation result

    Returns:
        Formatted message string
    """
    if not result.is_valid:
        return f"Invalid SSH key: {result.error_message}"

    message = f"Valid {result.key_type.value.upper()} key"
    if result.key_size:
        message += f" ({result.key_size} bits)"

    if result.security_level:
        message += f" - Security: {result.security_level.value}"

    if result.warnings:
        message += f"\nWarnings: {'; '.join(result.warnings)}"

    if result.recommendations:
        message += f"\nRecommendations: {'; '.join(result.recommendations)}"

    return message


def recommend_key_type() -> str:
    """
    Return current best practice SSH key recommendation.

    Returns:
        Recommendation text
    """
    return (
        "Recommended SSH key types (in order of preference):\n"
        "1. Ed25519 (most secure, fastest, smallest)\n"
        "2. RSA-4096 (widely supported, secure)\n"
        "3. ECDSA P-256 or higher (good security, smaller than RSA)\n"
        "4. RSA-3072 (minimum acceptable for new keys)\n\n"
        "Avoid: DSA keys (deprecated), RSA keys < 3072 bits"
    )
