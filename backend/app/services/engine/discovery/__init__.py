"""
Engine Discovery Module - Just-In-Time Platform Detection for Scans

This module provides platform detection capabilities specifically for scan operations.
Unlike the host_discovery_service (which persists data to the host table), this module
is designed for transient, scan-time-only platform detection.

Architecture:
    The discovery module is part of the engine layer because:
    1. Platform detection is required for accurate SCAP/OVAL content generation
    2. The data serves only the current scan operation (not persisted)
    3. It integrates with the scanner's SSH connection (reuses existing connection)

Components:
    - PlatformDetector: Core class for detecting OS platform via SSH
    - PlatformInfo: Data class containing detected platform information
    - detect_platform_for_scan: Factory function for scan-time detection

Usage:
    from backend.app.services.engine.discovery import (
        PlatformDetector,
        PlatformInfo,
        detect_platform_for_scan,
    )

    # Quick detection for scan API
    platform_info = await detect_platform_for_scan(
        hostname="192.168.1.100",
        connection_params={"username": "root", "port": 22},
        encryption_service=enc_service,
    )

    # Use detected platform for OVAL selection
    effective_platform = platform_info.platform_identifier  # e.g., "rhel9"

Design Principles:
    - Single Purpose: Only provides platform info for scan operations
    - No Persistence: Does NOT write to database (host table)
    - Stateless: Each call is independent, no caching
    - Fail-Safe: Returns None/fallback on detection failure
    - Reusable Connection: Can use existing SSH connection from scanner

Security Notes:
    - Credentials are passed through, never stored
    - SSH operations use existing SSHConnectionManager security policies
    - No sensitive data logged
"""

import logging

from .platform_detector import (
    PlatformDetector,
    PlatformInfo,
    detect_platform_for_scan,
)  # noqa: F401

logger = logging.getLogger(__name__)

__all__ = [
    "PlatformDetector",
    "PlatformInfo",
    "detect_platform_for_scan",
]

logger.debug("Engine discovery module loaded")
