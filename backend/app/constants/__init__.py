"""
OpenWatch Constants Module

Centralized constants for compliance frameworks, platforms, and other configuration values.
Following CLAUDE.md best practices - single source of truth for all constants.
"""

from .compliance_frameworks import (
    FRAMEWORK_DISPLAY_NAMES,
    PLATFORM_DISPLAY_NAMES,
    PLATFORM_VERSIONS,
    SUPPORTED_FRAMEWORKS,
    SUPPORTED_PLATFORMS,
    get_framework_display_name,
    get_platform_display_name,
    get_supported_versions,
    is_framework_supported,
    is_platform_supported,
)

__all__ = [
    "SUPPORTED_FRAMEWORKS",
    "SUPPORTED_PLATFORMS",
    "FRAMEWORK_DISPLAY_NAMES",
    "PLATFORM_DISPLAY_NAMES",
    "PLATFORM_VERSIONS",
    "is_framework_supported",
    "is_platform_supported",
    "get_framework_display_name",
    "get_platform_display_name",
    "get_supported_versions",
]
