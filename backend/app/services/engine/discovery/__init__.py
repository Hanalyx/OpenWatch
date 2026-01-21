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

SSH Connection Pattern:
    This module follows the SSH Connection Best Practices from CLAUDE.md.
    It accepts CredentialData objects with pre-decrypted values - it does NOT
    handle encryption/decryption internally.

Usage:
    from backend.app.services.auth import CentralizedAuthService, CredentialData
    from backend.app.services.engine.discovery import (
        PlatformDetector,
        PlatformInfo,
        detect_platform_for_scan,
    )

    # Step 1: Resolve credentials at the entry point (API/task)
    auth_service = CentralizedAuthService(db, encryption_service)
    credential_data = auth_service.resolve_credential(target_id=str(host.id))

    # Step 2: Pass CredentialData to detector
    platform_info = await detect_platform_for_scan(
        hostname="192.168.1.100",
        port=22,
        credential_data=credential_data,
        db=db,
    )

    # Use detected platform for OVAL selection
    if platform_info.detection_success:
        effective_platform = platform_info.platform_identifier  # e.g., "rhel9"

Design Principles:
    - Single Purpose: Only provides platform info for scan operations
    - No Persistence: Does NOT write to database (host table)
    - Stateless: Each call is independent, no caching
    - Fail-Safe: Returns PlatformInfo with detection_error on failure
    - CredentialData Pattern: Accepts pre-decrypted credentials

Security Notes:
    - Credentials must be resolved at API/task layer using CentralizedAuthService
    - Never pass encrypted credentials to this module
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
