"""
Kensa Compliance Plugin for OpenWatch

Kensa is the default, preinstalled compliance scanning plugin for OpenWatch.
This module provides the integration layer between OpenWatch and the Kensa
compliance engine.

Kensa (pip-installed) provides:
    - 338 canonical YAML rules across 8 security categories
    - SSH-based remote execution
    - Capability-gated rule implementations
    - Framework mappings for NIST, CIS, STIG
    - Remediation with rollback support

This plugin provides:
    - KensaScanner: BaseScanner implementation for ScannerFactory integration
    - KensaORSAPlugin: ORSA v2.0 compliant plugin for ORSAPluginRegistry
    - KensaRuleSyncService: Syncs YAML rules to PostgreSQL
    - FrameworkMapper: Maps rules to compliance framework controls
    - OpenWatchCredentialProvider: Bridges OpenWatch credentials to Kensa
    - KensaConfig: Plugin configuration

Installation:
    Kensa is installed via pip: kensa @ git+https://github.com/Hanalyx/kensa.git@v1.1.0
    The runner module is available in site-packages.

Usage:
    # ScannerFactory integration (legacy)
    from app.plugins.kensa import KensaScanner, register_kensa_scanner
    register_kensa_scanner()
    scanner = ScannerFactory.get_scanner("kensa")
    result = await scanner.scan(host_id, db)

    # ORSA v2.0 integration (recommended)
    from app.plugins.kensa import KensaORSAPlugin, register_kensa_orsa_plugin
    await register_kensa_orsa_plugin(db)
    registry = ORSAPluginRegistry.instance()
    plugin = await registry.get("kensa")
    results = await plugin.check(host_id)

    # Sync rules to PostgreSQL
    from app.plugins.kensa import KensaRuleSyncService
    sync_service = KensaRuleSyncService(db)
    await sync_service.sync_all_rules()

    # Query framework mappings
    from app.plugins.kensa import FrameworkMapper
    mapper = FrameworkMapper(db)
    rules = await mapper.get_rules_for_framework("cis", "rhel9_v2")

Version: 1.1.0
"""

import logging

logger = logging.getLogger(__name__)

# Version info
__version__ = "1.1.0"
__author__ = "Hanalyx"

# Public API exports - noqa needed for module re-exports
from .config import KensaConfig, get_kensa_config  # noqa: E402
from .exceptions import (  # noqa: E402
    KensaCapabilityError,
    KensaConnectionError,
    KensaError,
    KensaExecutionError,
    KensaLicenseError,
    KensaRuleLoadError,
)
from .executor import KensaSessionFactory, OpenWatchCredentialProvider, secure_key_file  # noqa: E402
from .framework_mapper import FrameworkMapper  # noqa: E402
from .orsa_plugin import KensaORSAPlugin, register_kensa_orsa_plugin  # noqa: E402
from .scanner import KensaScanner, register_kensa_scanner  # noqa: E402
from .sync_service import KENSA_VERSION, KensaRuleSyncService  # noqa: E402

__all__ = [
    # Version
    "__version__",
    "KENSA_VERSION",
    # Config
    "KensaConfig",
    "get_kensa_config",
    # Scanner (ScannerFactory integration)
    "KensaScanner",
    "register_kensa_scanner",
    # ORSA v2.0 Plugin (ORSAPluginRegistry integration)
    "KensaORSAPlugin",
    "register_kensa_orsa_plugin",
    # Sync & Mapping Services (PostgreSQL-only)
    "KensaRuleSyncService",
    "FrameworkMapper",
    # Credential Bridge
    "OpenWatchCredentialProvider",
    "KensaSessionFactory",
    "secure_key_file",
    # Exceptions
    "KensaError",
    "KensaCapabilityError",
    "KensaConnectionError",
    "KensaExecutionError",
    "KensaLicenseError",
    "KensaRuleLoadError",
]
