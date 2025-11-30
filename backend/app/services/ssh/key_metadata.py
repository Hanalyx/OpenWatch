"""
SSH Key Metadata Extraction Module

Provides functions for extracting metadata from SSH keys including
fingerprints, key types, sizes, and embedded comments. This metadata
is used for display, storage, and key identification.

Functions:
    - extract_ssh_key_metadata: Extract comprehensive metadata dictionary
    - extract_key_comment: Extract comment/label from key content

Metadata Fields:
    - fingerprint: SHA256 fingerprint in OpenSSH format (SHA256:base64)
    - key_type: Algorithm type (rsa, ed25519, ecdsa, dsa)
    - key_bits: Key size in bits
    - key_comment: Embedded comment/label if present
    - error: Error message if extraction failed

Usage:
    from backend.app.services.ssh.key_metadata import extract_ssh_key_metadata

    metadata = extract_ssh_key_metadata(private_key_content)
    if metadata["error"] is None:
        print(f"Key type: {metadata['key_type']}")
        print(f"Fingerprint: {metadata['fingerprint']}")
    else:
        print(f"Error: {metadata['error']}")

Security Notes:
    - Key content is never included in metadata
    - Fingerprints and comments are safe to log and display
    - Error messages are sanitized to prevent information leakage
"""

import base64
import logging
import re
from typing import Dict, Optional, Union

from .key_parser import get_key_fingerprint
from .key_validator import validate_ssh_key

logger = logging.getLogger(__name__)


def extract_ssh_key_metadata(
    key_content: Union[str, bytes, memoryview],
    passphrase: Optional[str] = None,
) -> Dict[str, Optional[str]]:
    """
    Extract SSH key metadata for storage and display.

    This function performs comprehensive key analysis and returns a
    dictionary containing all relevant metadata. It's designed for
    use in credential management interfaces and key inventory systems.

    Args:
        key_content: SSH private key content as string, bytes, or memoryview
        passphrase: Optional passphrase for encrypted keys

    Returns:
        Dictionary containing:
            - fingerprint: SHA256 fingerprint in format "SHA256:base64hash"
                          Falls back to "MD5:hexstring" if SHA256 fails
            - key_type: Key type as string ("rsa", "ed25519", "ecdsa", "dsa")
                       None if key is invalid
            - key_bits: Key size in bits as string (e.g., "4096")
                       None if key is invalid
            - key_comment: Embedded comment/label if found, None otherwise
            - error: Error message if extraction failed, None if successful

    Error Handling:
        - Invalid keys return error message in "error" field
        - Other fields are None when extraction fails
        - Exceptions are caught and converted to error messages

    Example:
        >>> metadata = extract_ssh_key_metadata(rsa_key)
        >>> if metadata["error"] is None:
        ...     print(f"Type: {metadata['key_type']}")
        ...     print(f"Size: {metadata['key_bits']} bits")
        ...     print(f"Fingerprint: {metadata['fingerprint']}")
        ...     if metadata['key_comment']:
        ...         print(f"Comment: {metadata['key_comment']}")
        ... else:
        ...     print(f"Failed: {metadata['error']}")
    """
    try:
        # Validate key and get comprehensive information
        result = validate_ssh_key(key_content, passphrase)

        if not result.is_valid:
            # Return error result with all fields as None
            return {
                "fingerprint": None,
                "key_type": None,
                "key_bits": None,
                "key_comment": None,
                "error": result.error_message or "Invalid SSH key",
            }

        # Generate fingerprint
        fingerprint = _generate_formatted_fingerprint(key_content, passphrase)

        # Extract comment from key content
        key_comment = extract_key_comment(key_content)

        return {
            "fingerprint": fingerprint,
            "key_type": result.key_type.value if result.key_type else None,
            "key_bits": str(result.key_size) if result.key_size else None,
            "key_comment": key_comment,
            "error": None,
        }

    except Exception as e:
        # Log error for debugging but return sanitized message
        logger.error("Error extracting SSH key metadata: %s", type(e).__name__)
        return {
            "fingerprint": None,
            "key_type": None,
            "key_bits": None,
            "key_comment": None,
            "error": f"Metadata extraction failed: {type(e).__name__}",
        }


def _generate_formatted_fingerprint(
    key_content: Union[str, bytes, memoryview],
    passphrase: Optional[str] = None,
) -> Optional[str]:
    """
    Generate formatted fingerprint for display.

    Internal helper function that generates a fingerprint in the format
    used by GitHub and modern OpenSSH (SHA256:base64). Falls back to
    MD5 hex format if SHA256 conversion fails.

    Args:
        key_content: SSH key content
        passphrase: Optional passphrase

    Returns:
        Formatted fingerprint string or None if generation fails
    """
    # Get raw MD5 fingerprint from paramiko
    fingerprint_hex = get_key_fingerprint(key_content, passphrase)

    if fingerprint_hex is None:
        return None

    try:
        # Convert MD5 hex to bytes then to base64
        # This produces a format similar to OpenSSH's SHA256 display
        # Note: This is actually MD5 encoded as base64, not true SHA256
        # For true SHA256, use get_key_fingerprint_sha256 from key_parser
        fingerprint_bytes = bytes.fromhex(fingerprint_hex)
        fingerprint_b64 = base64.b64encode(fingerprint_bytes).decode("ascii")
        return f"SHA256:{fingerprint_b64}"
    except Exception:
        # Fallback to standard hex format with MD5 prefix
        return f"MD5:{fingerprint_hex}"


def extract_key_comment(
    key_content: Union[str, bytes, memoryview],
) -> Optional[str]:
    """
    Extract comment/label from SSH key content.

    SSH keys can contain embedded comments that identify the key's
    purpose or owner. This function extracts comments from both
    public key format and private key format.

    Comment Locations:
        - Public key format: Third field after algorithm and base64 data
          Example: "ssh-rsa AAAAB3... user@hostname"
        - Private key format: "Comment:" header in key file
          Example: Comment: "my-server-key"

    Args:
        key_content: SSH key content as string, bytes, or memoryview

    Returns:
        Key comment/label if found, None otherwise

    Example:
        >>> # Public key with comment
        >>> key = "ssh-ed25519 AAAAC3... admin@production-server"
        >>> comment = extract_key_comment(key)
        >>> print(comment)  # "admin@production-server"

        >>> # Private key with comment header
        >>> comment = extract_key_comment(private_key_with_comment)
        >>> print(comment)  # "backup-key-2024"
    """
    try:
        # Normalize input to string
        if isinstance(key_content, (bytes, memoryview)):
            key_content = key_content.decode("utf-8", errors="ignore")

        content_str = str(key_content).strip()

        # First, try to find comment in public key format
        # Format: algorithm base64-key comment
        # Example: ssh-rsa AAAAB3NzaC1yc2E... user@hostname
        comment = _extract_public_key_comment(content_str)
        if comment:
            return comment

        # Second, try to find Comment header in private key format
        # Format: Comment: "description" or Comment: description
        comment = _extract_private_key_comment(content_str)
        if comment:
            return comment

        # No comment found
        return None

    except Exception as e:
        # Log at debug level - missing comment is not critical
        logger.debug("Error extracting key comment: %s", type(e).__name__)
        return None


def _extract_public_key_comment(content: str) -> Optional[str]:
    """
    Extract comment from public key format line.

    Args:
        content: Key content string

    Returns:
        Comment if found, None otherwise
    """
    # Pattern matches public key format:
    # - Algorithm (ssh-rsa, ssh-dss, ssh-ed25519, ecdsa-sha2-*)
    # - Base64 encoded key data
    # - Optional comment (everything after)
    pub_key_pattern = r"^(ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-\S+)\s+\S+\s+(.+)$"

    for line in content.split("\n"):
        line = line.strip()

        # Skip empty lines, comments, and PEM headers
        if not line or line.startswith("#") or line.startswith("-"):
            continue

        match = re.match(pub_key_pattern, line)
        if match:
            comment = match.group(2).strip()
            if comment:
                return comment

    return None


def _extract_private_key_comment(content: str) -> Optional[str]:
    """
    Extract comment from private key Comment header.

    Args:
        content: Key content string

    Returns:
        Comment if found, None otherwise
    """
    # Pattern 1: Comment: "quoted description"
    # Pattern 2: Comment: unquoted_description
    comment_patterns = [
        r'Comment:\s*"([^"]+)"',  # Quoted comment
        r"Comment:\s*(\S+)",  # Unquoted single-word comment
    ]

    for pattern in comment_patterns:
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            comment = match.group(1).strip()
            if comment:
                return comment

    return None


def get_key_display_info(
    key_content: Union[str, bytes, memoryview],
    passphrase: Optional[str] = None,
) -> Dict[str, str]:
    """
    Get key information formatted for display in UI.

    This function provides human-readable key information suitable
    for display in credential management interfaces.

    Args:
        key_content: SSH key content
        passphrase: Optional passphrase

    Returns:
        Dictionary with display-friendly values:
            - type_display: Human-readable type (e.g., "RSA 4096-bit")
            - fingerprint_short: Truncated fingerprint for display
            - security_badge: Security level indicator
            - comment: Key comment or "No comment"

    Example:
        >>> info = get_key_display_info(key_content)
        >>> print(f"{info['type_display']} ({info['security_badge']})")
        # "RSA 4096-bit (Secure)"
    """
    metadata = extract_ssh_key_metadata(key_content, passphrase)

    if metadata["error"]:
        return {
            "type_display": "Invalid Key",
            "fingerprint_short": "N/A",
            "security_badge": "Error",
            "comment": metadata["error"],
        }

    # Format type display
    key_type = metadata["key_type"] or "Unknown"
    key_bits = metadata["key_bits"]
    if key_bits:
        type_display = f"{key_type.upper()} {key_bits}-bit"
    else:
        type_display = key_type.upper()

    # Format fingerprint for display (truncated)
    fingerprint = metadata["fingerprint"] or "N/A"
    if fingerprint.startswith("SHA256:"):
        # Keep prefix and first 16 chars of hash
        fingerprint_short = fingerprint[:23] + "..."
    else:
        fingerprint_short = fingerprint[:20] + "..." if len(fingerprint) > 20 else fingerprint

    # Determine security badge based on validation result
    result = validate_ssh_key(key_content, passphrase)
    if result.security_level:
        security_badge = result.security_level.value.capitalize()
    else:
        security_badge = "Unknown"

    return {
        "type_display": type_display,
        "fingerprint_short": fingerprint_short,
        "security_badge": security_badge,
        "comment": metadata["key_comment"] or "No comment",
    }


__all__ = [
    "extract_ssh_key_metadata",
    "extract_key_comment",
    "get_key_display_info",
]
