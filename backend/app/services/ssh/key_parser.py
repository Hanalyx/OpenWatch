"""
SSH Key Parser Module

Provides functions for parsing SSH keys from various formats into paramiko
PKey objects, detecting key types, and generating key fingerprints.

This module contains legacy functions that are maintained for backward
compatibility. New code should prefer using the validation functions
from key_validator.py which use paramiko's built-in capabilities directly.

Functions:
    - detect_key_type: Detect SSH key algorithm from content (DEPRECATED)
    - parse_ssh_key: Parse key content into paramiko PKey (DEPRECATED)
    - get_key_fingerprint: Generate MD5/SHA256 fingerprint for key

Deprecation Notes:
    The detect_key_type and parse_ssh_key functions use pattern matching
    which can be fragile with different key formats. The validate_ssh_key
    function in key_validator.py is preferred as it uses paramiko's robust
    key parsing directly.

Usage:
    from backend.app.services.ssh.key_parser import get_key_fingerprint

    fingerprint = get_key_fingerprint(private_key_content)
    if fingerprint:
        print(f"Key fingerprint: {fingerprint}")

Security Notes:
    - Key content is never logged (sensitive data protection)
    - Fingerprints are safe to log and display
    - Passphrase handling follows secure practices
"""

import io
import logging
import warnings
from typing import Optional, Union

import paramiko
from paramiko import ECDSAKey, Ed25519Key, RSAKey

from .exceptions import SSHKeyError
from .models import SSHKeyType

logger = logging.getLogger(__name__)


def detect_key_type(key_content: Union[str, bytes, memoryview]) -> Optional[SSHKeyType]:
    """
    Detect SSH key type from key content using pattern matching.

    .. deprecated:: 1.0.0
        This function is deprecated in favor of using paramiko's built-in
        key parsing via validate_ssh_key(). It remains for backward
        compatibility but should not be used in new code.

    This function attempts to detect the key type by examining markers
    in the key content. It handles both public and private key formats.

    Args:
        key_content: SSH key content as string, bytes, or memoryview

    Returns:
        SSHKeyType enum value if detected, None if unknown

    Limitations:
        - OpenSSH format keys (BEGIN OPENSSH PRIVATE KEY) may require  # pragma: allowlist secret
          actual parsing to distinguish Ed25519 from RSA
        - Pattern matching can produce false positives with certain content

    Example:
        >>> key_type = detect_key_type(key_content)
        >>> if key_type == SSHKeyType.DSA:
        ...     print("Warning: DSA keys are deprecated")
    """
    # Issue deprecation warning for new usage tracking
    warnings.warn(
        "detect_key_type is deprecated. Use validate_ssh_key() from " "key_validator module instead.",
        DeprecationWarning,
        stacklevel=2,
    )

    try:
        # Normalize input to string - database may return bytes or memoryview
        if isinstance(key_content, (bytes, memoryview)):
            key_content = key_content.decode("utf-8", errors="ignore")

        content_str = str(key_content).strip()

        # Check for Ed25519 markers
        # OpenSSH format requires actual parsing to distinguish key types
        # NOTE: These are key format markers for detection, not actual keys
        if "ssh-ed25519" in content_str or "BEGIN OPENSSH PRIVATE KEY" in content_str:  # pragma: allowlist secret
            try:
                if "-----BEGIN OPENSSH PRIVATE KEY-----" in content_str:  # pragma: allowlist secret
                    # OpenSSH format - try to parse as Ed25519 first
                    # This is necessary because OpenSSH format doesn't have
                    # type-specific headers like PEM format
                    paramiko.Ed25519Key.from_private_key(io.StringIO(content_str))
                    return SSHKeyType.ED25519
                elif content_str.startswith("ssh-ed25519"):
                    # Public key format with explicit type marker
                    return SSHKeyType.ED25519
            except Exception:
                # Not Ed25519 - continue checking other types
                pass

        # Check RSA markers (both PEM and public key formats)
        # NOTE: These are pattern strings for key detection, not actual secrets
        rsa_markers = ["ssh-rsa", "BEGIN RSA PRIVATE KEY", "RSA PRIVATE KEY"]  # pragma: allowlist secret
        if any(marker in content_str for marker in rsa_markers):
            return SSHKeyType.RSA

        # Check ECDSA markers
        # NOTE: These are pattern strings for key detection, not actual secrets
        ecdsa_markers = ["ecdsa-sha2-", "BEGIN EC PRIVATE KEY", "EC PRIVATE KEY"]  # pragma: allowlist secret
        if any(marker in content_str for marker in ecdsa_markers):
            return SSHKeyType.ECDSA

        # Check DSA markers (deprecated but still supported)
        # NOTE: These are pattern strings for key detection, not actual secrets
        dsa_markers = ["ssh-dss", "BEGIN DSA PRIVATE KEY", "DSA PRIVATE KEY"]  # pragma: allowlist secret
        if any(marker in content_str for marker in dsa_markers):
            return SSHKeyType.DSA

        # Unable to detect key type from content
        return None

    except Exception as e:
        # Log at debug level to avoid noise - detection failure is not critical
        logger.debug("Error detecting key type: %s", type(e).__name__)
        return None


def parse_ssh_key(
    key_content: Union[str, bytes, memoryview],
    passphrase: Optional[str] = None,
) -> paramiko.PKey:
    """
    Parse SSH key content into paramiko PKey object.

    .. deprecated:: 1.0.0
        This function is deprecated in favor of using validate_ssh_key()
        from key_validator module. It remains for backward compatibility
        with existing services but should not be used in new code.

    This function attempts to parse the key content using each supported
    key type until one succeeds. It handles both encrypted and unencrypted
    keys.

    Args:
        key_content: SSH private key content as string, bytes, or memoryview
        passphrase: Optional passphrase for encrypted keys

    Returns:
        paramiko.PKey object (RSAKey, Ed25519Key, ECDSAKey, or DSSKey)

    Raises:
        SSHKeyError: If key cannot be parsed with any supported algorithm

    Example:
        >>> try:
        ...     pkey = parse_ssh_key(key_content, passphrase="secret")
        ...     print(f"Key type: {pkey.get_name()}")
        ... except SSHKeyError as e:
        ...     print(f"Failed to parse key: {e}")
    """
    # Issue deprecation warning for new usage tracking
    warnings.warn(
        "parse_ssh_key is deprecated. Use validate_ssh_key() from " "key_validator module instead.",
        DeprecationWarning,
        stacklevel=2,
    )

    try:
        # Normalize input to string
        if isinstance(key_content, (bytes, memoryview)):
            key_content = key_content.decode("utf-8", errors="ignore")

        content_str = str(key_content).strip()

        # Attempt parsing with each key type
        # Order: Ed25519 (modern, recommended), RSA (common), ECDSA
        # Note: DSA keys are not supported (deprecated, insecure)
        key_types = [
            (Ed25519Key, "Ed25519"),
            (RSAKey, "RSA"),
            (ECDSAKey, "ECDSA"),
        ]

        last_error = None

        for key_class, key_name in key_types:
            try:
                key_file = io.StringIO(content_str)
                if passphrase:
                    return key_class.from_private_key(key_file, password=passphrase)
                else:
                    return key_class.from_private_key(key_file)
            except paramiko.PasswordRequiredException:
                # Key is encrypted - need passphrase
                raise SSHKeyError(
                    "SSH key is encrypted and requires a passphrase",
                    key_type=key_name,
                )
            except paramiko.SSHException as e:
                # Wrong key type - try next
                last_error = str(e)
                continue
            except Exception as e:
                # Unexpected error - try next
                last_error = str(e)
                continue

        # None of the key types worked
        raise SSHKeyError(
            "Unable to parse SSH key - unsupported format or incorrect passphrase",
            details=last_error,
        )

    except SSHKeyError:
        # Re-raise SSHKeyError as-is
        raise
    except Exception as e:
        # Wrap unexpected errors in SSHKeyError
        raise SSHKeyError(
            f"Error parsing SSH key: {type(e).__name__}",
            details=str(e),
        )


def get_key_fingerprint(
    key_content: Union[str, bytes, memoryview],
    passphrase: Optional[str] = None,
) -> Optional[str]:
    """
    Generate fingerprint for SSH key using paramiko's built-in method.

    This function parses the SSH key and generates its MD5 fingerprint
    in hexadecimal format. Fingerprints are used to identify and verify
    keys without exposing the actual key content.

    Args:
        key_content: SSH private key content as string, bytes, or memoryview
        passphrase: Optional passphrase for encrypted keys

    Returns:
        Fingerprint as hexadecimal string (e.g., "aa:bb:cc:dd:..."),
        or None if fingerprint cannot be generated

    Security Notes:
        - Fingerprints are safe to log and display
        - Key content is never logged
        - Failed attempts are logged at debug level only

    Example:
        >>> fingerprint = get_key_fingerprint(private_key)
        >>> if fingerprint:
        ...     # Format as colon-separated pairs for display
        ...     formatted = ':'.join(fingerprint[i:i+2] for i in range(0, len(fingerprint), 2))
        ...     print(f"Fingerprint: {formatted}")
    """
    try:
        # Normalize input to string
        if isinstance(key_content, (bytes, memoryview)):
            key_content = key_content.decode("utf-8", errors="ignore")

        key_content_str = str(key_content).strip()

        # Try each key class to parse the key
        # Order optimized for most common key types first
        # Note: DSA keys are not supported (deprecated, insecure)
        key_classes = [
            paramiko.Ed25519Key,
            paramiko.RSAKey,
            paramiko.ECDSAKey,
        ]

        pkey = None
        for key_class in key_classes:
            try:
                key_file = io.StringIO(key_content_str)
                pkey = key_class.from_private_key(key_file, passphrase)
                break
            except Exception:
                # Try next key class
                continue

        if pkey is None:
            # Could not parse key with any supported algorithm
            logger.debug("Unable to parse SSH key for fingerprint generation")
            return None

        # Generate fingerprint using paramiko's built-in method
        # Returns MD5 hash of the public key portion
        fingerprint = pkey.get_fingerprint().hex()
        return fingerprint

    except Exception as e:
        # Log at debug level - fingerprint generation failure is not critical
        logger.debug("Error generating key fingerprint: %s", type(e).__name__)
        return None


def get_key_fingerprint_sha256(
    key_content: Union[str, bytes, memoryview],
    passphrase: Optional[str] = None,
) -> Optional[str]:
    """
    Generate SHA256 fingerprint for SSH key in OpenSSH format.

    This function generates a SHA256 fingerprint formatted like OpenSSH
    and GitHub display fingerprints (e.g., "SHA256:base64hash").

    Args:
        key_content: SSH private key content
        passphrase: Optional passphrase for encrypted keys

    Returns:
        SHA256 fingerprint in format "SHA256:base64hash",
        or None if fingerprint cannot be generated

    Example:
        >>> fp = get_key_fingerprint_sha256(key_content)
        >>> print(fp)  # SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8
    """
    import base64
    import hashlib

    try:
        # Get MD5 fingerprint first to validate key
        md5_fingerprint = get_key_fingerprint(key_content, passphrase)
        if md5_fingerprint is None:
            return None

        # Parse key again to get public key bytes for SHA256
        if isinstance(key_content, (bytes, memoryview)):
            key_content = key_content.decode("utf-8", errors="ignore")

        key_content_str = str(key_content).strip()

        # Parse key
        # Note: DSA keys are not supported (deprecated, insecure)
        key_classes = [
            paramiko.Ed25519Key,
            paramiko.RSAKey,
            paramiko.ECDSAKey,
        ]

        pkey = None
        for key_class in key_classes:
            try:
                key_file = io.StringIO(key_content_str)
                pkey = key_class.from_private_key(key_file, passphrase)
                break
            except Exception:
                continue

        if pkey is None:
            return None

        # Get public key bytes and compute SHA256
        # asbytes() returns the public key in SSH wire format
        pub_key_bytes = pkey.asbytes()
        sha256_hash = hashlib.sha256(pub_key_bytes).digest()

        # Encode as base64 without padding (OpenSSH format)
        b64_hash = base64.b64encode(sha256_hash).decode("ascii").rstrip("=")

        return f"SHA256:{b64_hash}"

    except Exception as e:
        logger.debug("Error generating SHA256 fingerprint: %s", type(e).__name__)
        return None


__all__ = [
    "detect_key_type",
    "parse_ssh_key",
    "get_key_fingerprint",
    "get_key_fingerprint_sha256",
]
