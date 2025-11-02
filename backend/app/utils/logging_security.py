"""
Security Logging Utilities for OpenWatch
Prevents log injection attacks (CWE-117) and information disclosure in logs.

SECURITY FEATURES:
- Input sanitization to prevent log injection
- Sensitive data redaction
- Consistent log formatting
- Safe error message sanitization
"""

import re
import logging
from typing import Optional, Any, Union
from urllib.parse import quote

logger = logging.getLogger(__name__)

# Patterns for detecting potentially malicious content
LOG_INJECTION_PATTERNS = [
    r"[\r\n]",  # CRLF injection
    r"%0[ad]",  # URL-encoded CRLF
    r"\\[rn]",  # Escaped newlines
    r"\x00",  # Null bytes
    r"[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]",  # Control characters
]

# Pattern for safe characters in logs
SAFE_LOG_PATTERN = re.compile(r"^[a-zA-Z0-9._@\-\s]+$")


def sanitize_for_log(
    value: Optional[Any], max_length: int = 100, allow_special: bool = False
) -> str:
    """
    Sanitize any value for safe logging.

    Args:
        value: Value to sanitize
        max_length: Maximum length of output
        allow_special: Whether to allow some special characters

    Returns:
        str: Sanitized string safe for logging
    """
    if value is None:
        return "null"

    # Convert to string
    str_value = str(value)

    # Truncate if too long
    if len(str_value) > max_length:
        str_value = str_value[:max_length] + "..."

    # Remove/replace dangerous characters
    for pattern in LOG_INJECTION_PATTERNS:
        str_value = re.sub(pattern, "", str_value)

    # If not allowing special chars, keep only safe characters
    if not allow_special and not SAFE_LOG_PATTERN.match(str_value):
        # Keep only alphanumeric, dots, underscores, @, hyphens, spaces
        str_value = re.sub(r"[^a-zA-Z0-9._@\-\s]", "", str_value)

    # Final safety check - if empty after sanitization, return placeholder
    if not str_value.strip():
        return "[sanitized]"

    return str_value.strip()


def sanitize_username_for_log(username: Optional[str]) -> str:
    """
    Sanitize username for logging.

    Args:
        username: Username to sanitize

    Returns:
        str: Sanitized username
    """
    if not username:
        return "[no_username]"

    sanitized = sanitize_for_log(username, max_length=50)

    # Additional username-specific rules
    if sanitized.lower() in ["admin", "root", "administrator"]:
        return f"privileged_user_{sanitized[:10]}"

    return sanitized


def sanitize_id_for_log(id_value: Optional[Any]) -> str:
    """
    Sanitize ID values for logging.

    Args:
        id_value: ID to sanitize (string, int, UUID, etc.)

    Returns:
        str: Sanitized ID
    """
    if id_value is None:
        return "[no_id]"

    str_id = str(id_value)

    # UUIDs are generally safe
    uuid_pattern = re.compile(
        r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    )
    if uuid_pattern.match(str_id):
        return str_id

    # Numeric IDs are safe
    if str_id.isdigit():
        return str_id

    # Otherwise sanitize
    return sanitize_for_log(str_id, max_length=50)


def sanitize_path_for_log(path: Optional[str]) -> str:
    """
    Sanitize file/URL paths for logging.

    Args:
        path: Path to sanitize

    Returns:
        str: Sanitized path
    """
    if not path:
        return "[no_path]"

    # URL encode special characters for safety
    try:
        sanitized = quote(path, safe="/.:-_")
        return sanitize_for_log(sanitized, max_length=200, allow_special=True)
    except Exception:
        return sanitize_for_log(path, max_length=200)


def sanitize_ip_for_log(ip_address: Optional[str]) -> str:
    """
    Sanitize IP address for logging.

    Args:
        ip_address: IP address to sanitize

    Returns:
        str: Sanitized IP address
    """
    if not ip_address:
        return "[no_ip]"

    # Basic IP pattern check
    ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    if ip_pattern.match(ip_address):
        return ip_address

    # IPv6 pattern (simplified)
    ipv6_pattern = re.compile(r"^[0-9a-fA-F:]+$")
    if ipv6_pattern.match(ip_address) and "::" in ip_address:
        return ip_address

    # Sanitize unknown format
    return sanitize_for_log(ip_address, max_length=45)


def sanitize_error_message_for_log(error_msg: Optional[str]) -> str:
    """
    Sanitize error messages for logging to prevent information disclosure.

    Args:
        error_msg: Error message to sanitize

    Returns:
        str: Sanitized error message
    """
    if not error_msg:
        return "[no_error_message]"

    str_msg = str(error_msg)

    # Patterns that might contain sensitive information
    sensitive_patterns = [
        (r"password[=:\s]+[^\s]+", "password=[REDACTED]"),
        (r"token[=:\s]+[^\s]+", "token=[REDACTED]"),
        (r"key[=:\s]+[^\s]+", "key=[REDACTED]"),
        (r"secret[=:\s]+[^\s]+", "secret=[REDACTED]"),
        (r"api[_-]?key[=:\s]+[^\s]+", "apikey=[REDACTED]"),
        (r"/[a-zA-Z0-9+/]{20,}={0,2}", "[BASE64_REDACTED]"),  # Base64 patterns
        (r"[0-9a-fA-F]{32,}", "[HEX_REDACTED]"),  # Long hex strings
    ]

    for pattern, replacement in sensitive_patterns:
        str_msg = re.sub(pattern, replacement, str_msg, flags=re.IGNORECASE)

    # Apply general sanitization
    return sanitize_for_log(str_msg, max_length=500, allow_special=True)


def sanitize_resource_for_log(
    resource_type: Optional[str], resource_id: Optional[str]
) -> str:
    """
    Sanitize resource information for logging.

    Args:
        resource_type: Type of resource
        resource_id: Resource identifier

    Returns:
        str: Sanitized resource description
    """
    safe_type = sanitize_for_log(resource_type) if resource_type else "unknown_type"
    safe_id = sanitize_id_for_log(resource_id)

    return f"{safe_type}:{safe_id}"


def create_audit_log_entry(
    action: str,
    user_id: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    success: bool = True,
    error_message: Optional[str] = None,
    additional_context: Optional[dict] = None,
) -> str:
    """
    Create a standardized audit log entry.

    Args:
        action: Action being performed
        user_id: User performing the action
        resource_type: Type of resource being accessed
        resource_id: Resource identifier
        ip_address: Client IP address
        success: Whether the action succeeded
        error_message: Error message if action failed
        additional_context: Additional context data

    Returns:
        str: Formatted audit log entry
    """
    parts = [
        f"action={sanitize_for_log(action)}",
        f"user={sanitize_id_for_log(user_id)}",
        f"resource={sanitize_resource_for_log(resource_type, resource_id)}",
        f"ip={sanitize_ip_for_log(ip_address)}",
        f"success={success}",
    ]

    if error_message and not success:
        parts.append(f"error={sanitize_error_message_for_log(error_message)}")

    if additional_context:
        for key, value in additional_context.items():
            safe_key = sanitize_for_log(key, max_length=20)
            safe_value = sanitize_for_log(value, max_length=100)
            parts.append(f"{safe_key}={safe_value}")

    return " | ".join(parts)
