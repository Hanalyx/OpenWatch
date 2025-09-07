"""
OpenWatch Secure Logging Utilities
Provides functions to safely sanitize user input before logging to prevent
log injection attacks (CWE-117).
"""
import re
from typing import Any, Optional


def sanitize_for_log(value: Any, max_length: int = 1000) -> str:
    """
    Sanitize user input for safe logging to prevent log injection attacks.
    
    Args:
        value: The value to sanitize (any type will be converted to string)
        max_length: Maximum length of sanitized output (default 1000)
    
    Returns:
        Sanitized string safe for logging
        
    Security:
        - Removes newlines, carriage returns, and tab characters
        - Strips ANSI escape sequences that could affect log display
        - Limits output length to prevent log flooding
        - Handles None values gracefully
    """
    if value is None:
        return "None"
    
    str_value = str(value)
    
    # Remove control characters and potential injection sequences
    sanitized = str_value.replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
    
    # Remove ANSI escape sequences (e.g., color codes)
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    sanitized = ansi_escape.sub('', sanitized)
    
    # Remove other potentially dangerous control characters
    sanitized = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', sanitized)
    
    # Limit length to prevent log flooding
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length] + "...[TRUNCATED]"
    
    return sanitized


def sanitize_path_for_log(path: Optional[str], max_length: int = 500) -> str:
    """
    Sanitize file paths for safe logging with additional path-specific protections.
    
    Args:
        path: File path to sanitize
        max_length: Maximum length of sanitized output (default 500)
    
    Returns:
        Sanitized path safe for logging
    """
    if path is None:
        return "None"
    
    # Basic sanitization first
    sanitized = sanitize_for_log(path, max_length)
    
    # Additional path-specific sanitization
    # Replace potentially sensitive patterns with placeholders
    sanitized = re.sub(r'/home/[^/]+', '/home/[USER]', sanitized)
    sanitized = re.sub(r'/Users/[^/]+', '/Users/[USER]', sanitized)
    
    return sanitized


def sanitize_id_for_log(identifier: Any) -> str:
    """
    Sanitize user/host/resource IDs for safe logging.
    
    Args:
        identifier: The ID to sanitize
    
    Returns:
        Sanitized ID safe for logging
    """
    if identifier is None:
        return "None"
    
    str_id = str(identifier)
    
    # For IDs, be more restrictive - allow only alphanumeric, hyphens, and underscores
    sanitized = re.sub(r'[^a-zA-Z0-9_-]', '[FILTERED]', str_id)
    
    # Limit length for IDs
    if len(sanitized) > 100:
        sanitized = sanitized[:100] + "...[TRUNCATED]"
    
    return sanitized


def sanitize_username_for_log(username: Optional[str]) -> str:
    """
    Sanitize usernames for safe logging with username-specific protections.
    
    Args:
        username: Username to sanitize
    
    Returns:
        Sanitized username safe for logging
    """
    if username is None:
        return "None"
    
    # Username-specific sanitization
    str_username = str(username)
    
    # Allow typical username characters but filter others
    sanitized = re.sub(r'[^a-zA-Z0-9._@-]', '[FILTERED]', str_username)
    
    # Limit username length in logs
    if len(sanitized) > 50:
        sanitized = sanitized[:50] + "...[TRUNCATED]"
    
    return sanitized