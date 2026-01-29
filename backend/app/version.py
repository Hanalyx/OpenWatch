"""
OpenWatch Version Module

Single source of truth for application version.
Reads from the VERSION file at the repository root.

Usage:
    from app.version import __version__, get_version_info

    print(__version__)  # "0.1.0"
    print(get_version_info())  # {"version": "0.1.0", "codename": "Eyrie", ...}
"""

import os
import subprocess
from functools import lru_cache
from pathlib import Path
from typing import Optional

# Codename for the current major version series
# Updated when major version changes (see docs/core/VERSIONING.md)
CODENAME = "Eyrie"

# API version (independent of application version)
API_VERSION = "1"


def _find_version_file() -> Optional[Path]:
    """
    Find the VERSION file by searching up from the current file.

    Returns:
        Path to VERSION file or None if not found
    """
    # Start from this file's directory and go up
    current = Path(__file__).resolve().parent

    # Check up to 5 levels (backend/app -> backend -> openwatch -> ...)
    for _ in range(5):
        version_file = current / "VERSION"
        if version_file.exists():
            return version_file
        current = current.parent

    return None


def get_version() -> str:
    """
    Read version from VERSION file.

    Returns:
        Version string (e.g., "0.1.0") or "0.0.0-unknown" if not found
    """
    version_file = _find_version_file()
    if version_file and version_file.exists():
        try:
            return version_file.read_text().strip()
        except OSError:
            pass
    return "0.0.0-unknown"


@lru_cache(maxsize=1)
def get_git_commit() -> Optional[str]:
    """
    Get the current git commit hash (short form).

    Returns:
        Short git commit hash or None if not in a git repo
    """
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
            cwd=Path(__file__).resolve().parent,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return None


@lru_cache(maxsize=1)
def get_build_date() -> Optional[str]:
    """
    Get the build date from environment variable or None.

    Set BUILD_DATE environment variable during CI/CD build.

    Returns:
        ISO format date string or None
    """
    return os.environ.get("BUILD_DATE")


def get_version_info() -> dict:
    """
    Get complete version information for API responses.

    Returns:
        Dictionary with version, codename, api_version, git_commit, build_date
    """
    return {
        "version": get_version(),
        "codename": CODENAME,
        "api_version": API_VERSION,
        "git_commit": get_git_commit(),
        "build_date": get_build_date(),
    }


# Module-level version string for easy import
__version__ = get_version()
