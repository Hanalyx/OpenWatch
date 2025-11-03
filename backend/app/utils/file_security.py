"""
File Security Utilities
Provides secure filename sanitization and path validation to prevent path traversal attacks
"""

import os
import re
import unicodedata
from pathlib import Path
from typing import Optional, Union


def sanitize_filename(filename: str, max_length: int = 255) -> str:
    """
    Sanitize filename to prevent path traversal and other security issues

    Security measures:
    - Removes path separators (/, \)
    - Removes null bytes
    - Removes directory traversal patterns (../)
    - Normalizes unicode characters
    - Removes control characters
    - Ensures filename is not empty
    - Limits length

    Args:
        filename: Original filename from upload
        max_length: Maximum allowed filename length (default: 255)

    Returns:
        Sanitized filename safe for filesystem storage

    Raises:
        ValueError: If filename is invalid or becomes empty after sanitization
    """
    if not filename:
        raise ValueError("Filename cannot be empty")

    # Normalize unicode characters (NFKD normalization)
    filename = unicodedata.normalize("NFKD", filename)

    # Remove any path components (handle both Unix and Windows paths)
    filename = os.path.basename(filename)
    filename = filename.replace("\\", "").replace("/", "")

    # Remove null bytes and control characters
    filename = "".join(char for char in filename if ord(char) >= 32)

    # Remove directory traversal patterns
    filename = filename.replace("..", "")

    # Remove leading/trailing dots and spaces
    filename = filename.strip(". ")

    # Replace problematic characters with underscores
    # Keep: alphanumeric, dash, underscore, period
    filename = re.sub(r"[^a-zA-Z0-9._-]", "_", filename)

    # Ensure at least one character before extension
    if filename.startswith("."):
        filename = "file" + filename

    # Limit length while preserving extension
    if len(filename) > max_length:
        name, ext = os.path.splitext(filename)
        name = name[: max_length - len(ext) - 1]
        filename = name + ext

    # Final validation
    if not filename or filename in ("", ".", ".."):
        raise ValueError("Invalid filename after sanitization")

    # Prevent reserved names on Windows
    reserved_names = {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "COM1",
        "COM2",
        "COM3",
        "COM4",
        "COM5",
        "COM6",
        "COM7",
        "COM8",
        "COM9",
        "LPT1",
        "LPT2",
        "LPT3",
        "LPT4",
        "LPT5",
        "LPT6",
        "LPT7",
        "LPT8",
        "LPT9",
    }

    name_without_ext = os.path.splitext(filename)[0].upper()
    if name_without_ext in reserved_names:
        filename = "_" + filename

    return filename


def validate_file_extension(filename: str, allowed_extensions: list[str]) -> bool:
    """
    Validate that filename has an allowed extension

    Supports both simple extensions (.xml, .zip) and compound extensions (.tar.gz, .tar.bz2)

    Args:
        filename: Filename to validate
        allowed_extensions: List of allowed extensions (e.g., ['.xml', '.zip', '.tar.gz'])

    Returns:
        True if extension is allowed, False otherwise
    """
    filename_lower = filename.lower()
    allowed_lower = [e.lower() for e in allowed_extensions]

    # Check if filename ends with any of the allowed extensions
    # This handles both simple (.gz) and compound (.tar.gz) extensions
    return any(filename_lower.endswith(ext) for ext in allowed_lower)


def validate_storage_path(base_path: Union[str, Path], file_path: Union[str, Path], allow_create: bool = False) -> Path:
    """
    Validate that file_path is within base_path (prevent path traversal)

    Args:
        base_path: Base directory that should contain the file
        file_path: File path to validate
        allow_create: Whether to create parent directories if they don't exist

    Returns:
        Resolved absolute path if valid

    Raises:
        ValueError: If path is outside base_path or invalid
    """
    base = Path(base_path).resolve()
    target = Path(file_path).resolve()

    # Check if target is within base
    try:
        target.relative_to(base)
    except ValueError:
        raise ValueError(f"Path traversal detected: {file_path} is outside allowed directory")

    # Validate parent directory exists or can be created
    if allow_create:
        target.parent.mkdir(parents=True, exist_ok=True)
    elif not target.parent.exists():
        raise ValueError(f"Parent directory does not exist: {target.parent}")

    return target


def generate_secure_filepath(base_dir: Union[str, Path], filename: str, subdirectory: Optional[str] = None) -> Path:
    """
    Generate a secure file path for storage

    Args:
        base_dir: Base storage directory
        filename: Original filename
        subdirectory: Optional subdirectory within base_dir

    Returns:
        Secure path for file storage

    Raises:
        ValueError: If any component is invalid
    """
    # Sanitize filename
    safe_filename = sanitize_filename(filename)

    # Start with base directory
    base = Path(base_dir).resolve()

    # Add subdirectory if provided
    if subdirectory:
        # Sanitize subdirectory (no slashes, no traversal)
        safe_subdir = sanitize_filename(subdirectory)
        storage_path = base / safe_subdir
    else:
        storage_path = base

    # Combine with sanitized filename
    final_path = storage_path / safe_filename

    # Validate no path traversal occurred
    validate_storage_path(base, final_path, allow_create=True)

    return final_path


def get_safe_file_extension(filename: str) -> str:
    """
    Safely extract file extension

    Args:
        filename: Filename to extract extension from

    Returns:
        Lowercase file extension including the dot (e.g., '.xml')
        Empty string if no extension
    """
    sanitized = sanitize_filename(filename)
    return Path(sanitized).suffix.lower()
