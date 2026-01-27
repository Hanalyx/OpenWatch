"""
Plugin Security Subpackage

Provides comprehensive security validation and cryptographic signature
verification for plugins. This is the first line of defense against
malicious plugins.

Components:
    - PluginSecurityService: Multi-layered security validation
    - PluginSignatureService: Cryptographic signature verification

Security Checks Performed:
    - Package size validation
    - Path traversal protection
    - Manifest validation
    - Dangerous code pattern detection
    - Forbidden file access detection
    - Network backdoor detection
    - File permission validation
    - Malware scanning (if ClamAV available)
    - Cryptographic signature verification

Usage:
    from app.services.plugins.security import (
        PluginSecurityService,
        PluginSignatureService,
    )

    security = PluginSecurityService()
    is_valid, checks, package = await security.validate_plugin_package(data)

    signature = PluginSignatureService()
    result = await signature.verify_plugin_signature(package)
"""

from .signature import PluginSignatureService
from .validator import PluginSecurityService

__all__ = [
    "PluginSecurityService",
    "PluginSignatureService",
]
