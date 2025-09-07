"""
SSH Key Metadata Service

Provides functions to extract SSH key metadata including fingerprints,
types, sizes, and comments for storage and display purposes.
"""

import re
from typing import Dict, Optional, Tuple
from .ssh_utils import get_key_fingerprint, detect_key_type, validate_ssh_key
import logging

logger = logging.getLogger(__name__)


def extract_ssh_key_metadata(
    key_content: str, passphrase: Optional[str] = None
) -> Dict[str, Optional[str]]:
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
            # Convert hex to base64 for cleaner display
            import base64

            hex_bytes = bytes.fromhex(fingerprint_hex)
            b64_fingerprint = base64.b64encode(hex_bytes).decode("ascii")
            fingerprint = f"SHA256:{b64_fingerprint}"

        # Extract comment from key content if present
        key_comment = extract_key_comment(key_content)

        return {
            "fingerprint": fingerprint,
            "key_type": result.key_type.value if result.key_type else None,
            "key_bits": str(result.key_size) if result.key_size else None,
            "key_comment": key_comment,
            "error": None,
        }

    except Exception as e:
        logger.error(f"Failed to extract SSH key metadata: {str(e)}")
        return {
            "fingerprint": None,
            "key_type": None,
            "key_bits": None,
            "key_comment": None,
            "error": str(e),
        }


def extract_key_comment(key_content: str) -> Optional[str]:
    """
    Extract comment/label from SSH key content.

    Args:
        key_content: SSH key content (private or public)

    Returns:
        Key comment if found, None otherwise
    """
    try:
        # Look for public key format in private key content
        # Some private key files include the public key with comment
        lines = key_content.split("\n")
        for line in lines:
            if line.strip().startswith(("ssh-rsa", "ssh-ed25519", "ecdsa-sha2-", "ssh-dss")):
                parts = line.strip().split()
                if len(parts) >= 3:
                    # Third part is usually the comment
                    return parts[2]

        # Look for comment patterns in OpenSSH format
        comment_patterns = [
            r'Comment:\s*"([^"]+)"',  # Comment: "description"
            r"Comment:\s*([^\s]+)",  # Comment: description
        ]

        for pattern in comment_patterns:
            match = re.search(pattern, key_content, re.IGNORECASE)
            if match:
                return match.group(1)

    except Exception:
        pass

    return None


def format_key_display_info(
    fingerprint: Optional[str],
    key_type: Optional[str],
    key_bits: Optional[str],
    key_comment: Optional[str],
    created_date: Optional[str] = None,
) -> str:
    """
    Format SSH key information for display (similar to GitHub format).

    Args:
        fingerprint: SHA256 fingerprint
        key_type: Key type (rsa, ed25519, ecdsa, dsa)
        key_bits: Key size in bits
        key_comment: Key comment/label
        created_date: When the key was added (optional)

    Returns:
        Formatted string for display
    """
    if not fingerprint:
        return "No SSH key configured"

    # Build display string
    parts = []

    # Add fingerprint (truncated for display)
    if len(fingerprint) > 20:
        short_fingerprint = fingerprint[:12] + "..." + fingerprint[-8:]
    else:
        short_fingerprint = fingerprint
    parts.append(short_fingerprint)

    # Add key type and size
    if key_type:
        type_display = key_type.upper()
        if key_bits:
            type_display += f" {key_bits}-bit"
        parts.append(f"({type_display})")

    result = " ".join(parts)

    # Add creation date if provided
    if created_date:
        result += f"\nAdded on {created_date}"

    # Add comment if available
    if key_comment:
        result += f"\nComment: {key_comment}"

    return result


def get_key_security_indicator(key_type: Optional[str], key_bits: Optional[str]) -> Tuple[str, str]:
    """
    Get security level indicator for SSH key.

    Args:
        key_type: Key type (rsa, ed25519, ecdsa, dsa)
        key_bits: Key size in bits

    Returns:
        Tuple of (security_level, color) for UI display
        - security_level: "secure", "acceptable", "deprecated", "rejected"
        - color: "success", "warning", "error"
    """
    if not key_type:
        return ("unknown", "info")

    key_type = key_type.lower()
    bits = int(key_bits) if key_bits and key_bits.isdigit() else 0

    if key_type == "ed25519":
        return ("secure", "success")
    elif key_type == "rsa":
        if bits >= 3072:
            return ("secure", "success")
        elif bits >= 2048:
            return ("acceptable", "warning")
        else:
            return ("deprecated", "error")
    elif key_type == "ecdsa":
        if bits >= 256:
            return ("secure", "success")
        else:
            return ("acceptable", "warning")
    elif key_type == "dsa":
        return ("deprecated", "error")

    return ("unknown", "info")
