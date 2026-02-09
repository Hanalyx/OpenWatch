"""
Aegis Compliance Plugin for OpenWatch

Aegis is the default, preinstalled compliance scanning plugin for OpenWatch.
This module provides the integration layer between OpenWatch and the Aegis
compliance engine.

The aegis package (backend/aegis/) provides:
    - 338 canonical YAML rules across 8 security categories
    - SSH-based remote execution
    - Capability-gated rule implementations
    - Framework mappings for NIST, CIS, STIG
    - Remediation with rollback support

This plugin provides:
    - AegisScanner: BaseScanner implementation for ScannerFactory integration
    - AegisRuleSyncService: Syncs YAML rules to PostgreSQL
    - FrameworkMapper: Maps rules to compliance framework controls
    - OpenWatchCredentialProvider: Bridges OpenWatch credentials to Aegis
    - AegisConfig: Plugin configuration

Installation:
    Aegis is included in the backend/aegis/ directory.
    The symlink backend/runner -> backend/aegis/runner enables imports.

Usage:
    from app.plugins.aegis import AegisScanner, register_aegis_scanner

    # Register on startup
    register_aegis_scanner()

    # Via ScannerFactory
    scanner = ScannerFactory.get_scanner("aegis")
    result = await scanner.scan(host_id, db)

    # Sync rules to PostgreSQL
    from app.plugins.aegis import AegisRuleSyncService
    sync_service = AegisRuleSyncService(db)
    await sync_service.sync_all_rules()

    # Query framework mappings
    from app.plugins.aegis import FrameworkMapper
    mapper = FrameworkMapper(db)
    rules = await mapper.get_rules_for_framework("cis", "rhel9_v2")

Version: 1.0.0
"""

import logging

logger = logging.getLogger(__name__)

# Version info
__version__ = "1.0.0"
__author__ = "Hanalyx"

# Public API exports - noqa needed for module re-exports
from .config import AegisConfig, get_aegis_config  # noqa: E402
from .exceptions import (  # noqa: E402
    AegisCapabilityError,
    AegisConnectionError,
    AegisError,
    AegisExecutionError,
    AegisLicenseError,
    AegisRuleLoadError,
)
from .executor import AegisSessionFactory, OpenWatchCredentialProvider, secure_key_file  # noqa: E402
from .framework_mapper import FrameworkMapper  # noqa: E402
from .scanner import AegisScanner, register_aegis_scanner  # noqa: E402
from .sync_service import AEGIS_VERSION, AegisRuleSyncService  # noqa: E402

__all__ = [
    # Version
    "__version__",
    "AEGIS_VERSION",
    # Config
    "AegisConfig",
    "get_aegis_config",
    # Scanner
    "AegisScanner",
    "register_aegis_scanner",
    # Sync & Mapping Services (PostgreSQL-only)
    "AegisRuleSyncService",
    "FrameworkMapper",
    # Credential Bridge
    "OpenWatchCredentialProvider",
    "AegisSessionFactory",
    "secure_key_file",
    # Exceptions
    "AegisError",
    "AegisCapabilityError",
    "AegisConnectionError",
    "AegisExecutionError",
    "AegisLicenseError",
    "AegisRuleLoadError",
]
