"""
Plugin Import/Export Subpackage

Provides secure import and export functionality for plugins. This subpackage
handles the complete import workflow including validation, security scanning,
signature verification, and storage.

Components:
    - PluginImportService: Main service for importing plugins from files and URLs

Security Features:
    - File size limits (50MB default)
    - Package format validation (.tar.gz, .zip, .owplugin)
    - Multi-layer security scanning via PluginSecurityService
    - Cryptographic signature verification via PluginSignatureService
    - URL validation (HTTPS only, no private networks)
    - Duplicate detection before import

Import Flow:
    1. Validate import request (size, format)
    2. Run security scanning
    3. Verify signature (optional but recommended)
    4. Check for existing plugin
    5. Calculate trust level
    6. Store plugin in database
    7. Post-import validation

Usage:
    from backend.app.services.plugins.import_export import PluginImportService

    importer = PluginImportService()
    result = await importer.import_plugin_from_file(content, filename, user_id)

Example:
    >>> from backend.app.services.plugins.import_export import PluginImportService
    >>> importer = PluginImportService()
    >>> with open("my-plugin.tar.gz", "rb") as f:
    ...     content = f.read()
    >>> result = await importer.import_plugin_from_file(
    ...     content, "my-plugin.tar.gz", "user-123"
    ... )
    >>> if result["success"]:
    ...     print(f"Imported: {result['plugin_id']}")
"""

from .importer import PluginImportService

__all__ = [
    "PluginImportService",
]
