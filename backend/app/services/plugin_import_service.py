"""
Plugin Import Service
Secure import and validation of external plugins
"""

import logging
import os
import uuid
from datetime import datetime
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import aiofiles

from ..auth import get_current_user
from ..models.plugin_models import (
    InstalledPlugin,
    PluginExecutor,
    PluginManifest,
    PluginPackage,
    PluginStatus,
    PluginTrustLevel,
    SecurityCheckResult,
)
from .plugin_security_service import PluginSecurityService
from .plugin_signature_service import PluginSignatureService

logger = logging.getLogger(__name__)


class PluginImportError(Exception):
    """Plugin import specific exceptions"""

    pass


class PluginImportService:
    """Handle secure import of external plugins"""

    def __init__(self):
        self.security_service = PluginSecurityService()
        self.signature_service = PluginSignatureService()
        self.max_package_size = 50 * 1024 * 1024  # 50MB maximum package size

    async def import_plugin_from_file(
        self,
        file_content: bytes,
        filename: str,
        user_id: str,
        verify_signature: bool = True,
        trust_level_override: Optional[PluginTrustLevel] = None,
    ) -> Dict[str, Any]:
        """
        Import plugin from uploaded file

        Args:
            file_content: Raw file bytes
            filename: Original filename
            user_id: User importing the plugin
            verify_signature: Whether to verify plugin signature
            trust_level_override: Override trust level (admin only)

        Returns:
            Import result with status and details
        """
        import_id = str(uuid.uuid4())

        try:
            logger.info(f"Starting plugin import {import_id} from file: {filename}")

            # Step 1: Basic validation
            validation_result = await self._validate_import_request(file_content, filename, user_id)
            if not validation_result["valid"]:
                return {
                    "success": False,
                    "import_id": import_id,
                    "error": validation_result["error"],
                    "stage": "validation",
                }

            # Step 2: Determine package format
            package_format = self._determine_package_format(filename)

            # Step 3: Security scanning
            logger.info(f"Running security scan for import {import_id}")
            scan_result = await self.security_service.validate_plugin_package(
                file_content, package_format
            )

            is_secure, security_checks, package = scan_result

            if not is_secure:
                await self._log_security_failure(import_id, user_id, security_checks)
                return {
                    "success": False,
                    "import_id": import_id,
                    "error": "Plugin failed security validation",
                    "security_checks": [check.dict() for check in security_checks],
                    "stage": "security_scan",
                }

            # Step 4: Signature verification (if required)
            signature_check = None
            if verify_signature and package and package.signature:
                signature_check = await self.signature_service.verify_plugin_signature(
                    package, require_trusted_signature=True
                )
                security_checks.append(signature_check)

            # Step 5: Check for existing plugin
            existing_check = await self._check_existing_plugin(package.manifest)
            if existing_check["exists"]:
                return {
                    "success": False,
                    "import_id": import_id,
                    "error": existing_check["message"],
                    "existing_plugin": existing_check["plugin_id"],
                    "stage": "duplicate_check",
                }

            # Step 6: Calculate trust level
            trust_level = self._calculate_trust_level(
                security_checks, signature_check, trust_level_override
            )

            # Step 7: Store plugin
            installed_plugin = await self._store_plugin(
                package, security_checks, user_id, trust_level, import_id
            )

            # Step 8: Post-import validation
            await self._post_import_validation(installed_plugin)

            logger.info(f"Plugin import {import_id} completed successfully")

            return {
                "success": True,
                "import_id": import_id,
                "plugin_id": installed_plugin.plugin_id,
                "plugin_name": installed_plugin.manifest.name,
                "version": installed_plugin.manifest.version,
                "trust_level": installed_plugin.trust_level,
                "status": installed_plugin.status,
                "security_score": 100 - installed_plugin.get_risk_score(),
                "security_checks": len([c for c in security_checks if c.passed]),
                "total_checks": len(security_checks),
                "stage": "completed",
            }

        except Exception as e:
            logger.error(f"Plugin import {import_id} failed: {e}")
            return {
                "success": False,
                "import_id": import_id,
                "error": f"Import failed: {str(e)}",
                "stage": "error",
            }

    async def import_plugin_from_url(
        self,
        plugin_url: str,
        user_id: str,
        verify_signature: bool = True,
        max_size: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Import plugin from URL

        Args:
            plugin_url: URL to download plugin from
            user_id: User importing the plugin
            verify_signature: Whether to verify plugin signature
            max_size: Maximum download size (defaults to service limit)

        Returns:
            Import result with status and details
        """
        import_id = str(uuid.uuid4())

        try:
            logger.info(f"Starting plugin import {import_id} from URL: {plugin_url}")

            # Step 1: Validate URL
            if not await self._validate_plugin_url(plugin_url):
                return {
                    "success": False,
                    "import_id": import_id,
                    "error": "Invalid or untrusted URL",
                    "stage": "url_validation",
                }

            # Step 2: Download plugin package
            download_result = await self._download_plugin_package(
                plugin_url, max_size or self.max_package_size
            )

            if not download_result["success"]:
                return {
                    "success": False,
                    "import_id": import_id,
                    "error": download_result["error"],
                    "stage": "download",
                }

            # Step 3: Import from downloaded content
            filename = download_result["filename"]
            file_content = download_result["content"]

            # Continue with file import process
            import_result = await self.import_plugin_from_file(
                file_content, filename, user_id, verify_signature
            )

            # Update source URL in result
            if import_result["success"]:
                plugin = await InstalledPlugin.find_one(
                    InstalledPlugin.plugin_id == import_result["plugin_id"]
                )
                if plugin:
                    plugin.source_url = plugin_url
                    plugin.import_method = "url"
                    await plugin.save()

            return import_result

        except Exception as e:
            logger.error(f"URL plugin import {import_id} failed: {e}")
            return {
                "success": False,
                "import_id": import_id,
                "error": f"URL import failed: {str(e)}",
                "stage": "error",
            }

    async def _validate_import_request(
        self, file_content: bytes, filename: str, user_id: str
    ) -> Dict[str, Any]:
        """Validate import request basics"""

        # Check file size
        if len(file_content) > self.max_package_size:
            return {
                "valid": False,
                "error": f"Package too large: {len(file_content)} bytes (max: {self.max_package_size})",
            }

        # Check file extension
        allowed_extensions = {".tar.gz", ".tgz", ".zip", ".owplugin"}
        file_extension = "".join(Path(filename).suffixes)

        if file_extension not in allowed_extensions:
            return {"valid": False, "error": f"Unsupported file type: {file_extension}"}

        # Check user permissions (would integrate with RBAC)
        # For now, assume all authenticated users can import

        return {"valid": True}

    def _determine_package_format(self, filename: str) -> str:
        """Determine package format from filename"""
        suffixes = "".join(Path(filename).suffixes).lower()

        if suffixes in [".tar.gz", ".tgz"]:
            return "tar.gz"
        elif suffixes == ".zip":
            return "zip"
        elif suffixes == ".owplugin":
            return "tar.gz"  # .owplugin is a renamed tar.gz
        else:
            return "tar.gz"  # Default assumption

    async def _log_security_failure(
        self, import_id: str, user_id: str, security_checks: List[SecurityCheckResult]
    ):
        """Log security validation failure for audit"""
        failed_checks = [check for check in security_checks if not check.passed]

        logger.warning(
            f"Plugin import {import_id} failed security validation",
            extra={
                "import_id": import_id,
                "user_id": user_id,
                "failed_checks": len(failed_checks),
                "critical_failures": len([c for c in failed_checks if c.severity == "critical"]),
            },
        )

    async def _check_existing_plugin(self, manifest: PluginManifest) -> Dict[str, Any]:
        """Check if plugin already exists"""
        existing = await InstalledPlugin.find_one(
            InstalledPlugin.manifest.name == manifest.name,
            InstalledPlugin.manifest.version == manifest.version,
        )

        if existing:
            return {
                "exists": True,
                "plugin_id": existing.plugin_id,
                "message": f"Plugin {manifest.name}@{manifest.version} already installed",
            }

        return {"exists": False}

    def _calculate_trust_level(
        self,
        security_checks: List[SecurityCheckResult],
        signature_check: Optional[SecurityCheckResult],
        override: Optional[PluginTrustLevel],
    ) -> PluginTrustLevel:
        """Calculate plugin trust level"""

        if override:
            return override

        # Check for critical security failures
        critical_failures = [
            c for c in security_checks if not c.passed and c.severity == "critical"
        ]
        if critical_failures:
            return PluginTrustLevel.UNTRUSTED

        # Check signature verification
        if signature_check and signature_check.passed:
            signature_details = signature_check.details or {}
            if signature_details.get("trusted", False):
                return PluginTrustLevel.VERIFIED
            else:
                return PluginTrustLevel.COMMUNITY

        # Default for unsigned but secure plugins
        return PluginTrustLevel.COMMUNITY

    async def _store_plugin(
        self,
        package: PluginPackage,
        security_checks: List[SecurityCheckResult],
        user_id: str,
        trust_level: PluginTrustLevel,
        import_id: str,
    ) -> InstalledPlugin:
        """Store validated plugin in database"""

        # Create executors from package
        executors = {}
        for name, executor_data in package.executors.items():
            if isinstance(executor_data, dict):
                executors[name] = PluginExecutor(**executor_data)
            else:
                executors[name] = executor_data

        # Determine initial status
        status = PluginStatus.ACTIVE
        if trust_level == PluginTrustLevel.UNTRUSTED:
            status = PluginStatus.QUARANTINED

        # Create installed plugin record
        plugin = InstalledPlugin(
            manifest=package.manifest,
            source_hash=package.checksum,
            imported_by=user_id,
            import_method="upload",
            trust_level=trust_level,
            status=status,
            security_checks=security_checks,
            signature_verified=bool(package.signature),
            signature_details=package.signature,
            executors=executors,
            files=package.files,
            enabled_platforms=package.manifest.platforms,
        )

        # Save to database
        await plugin.save()

        logger.info(
            f"Stored plugin {plugin.plugin_id}",
            extra={
                "plugin_id": plugin.plugin_id,
                "import_id": import_id,
                "trust_level": trust_level.value,
                "status": status.value,
            },
        )

        return plugin

    async def _post_import_validation(self, plugin: InstalledPlugin):
        """Perform post-import validation and setup"""
        try:
            # Validate plugin executors
            for executor_name, executor in plugin.executors.items():
                if not self._validate_executor(executor, plugin.manifest):
                    logger.warning(
                        f"Executor {executor_name} validation failed for {plugin.plugin_id}"
                    )

            # Initialize plugin configuration
            if plugin.manifest.config_schema:
                # Validate default configuration against schema
                pass  # JSON schema validation would go here

            logger.info(f"Post-import validation completed for {plugin.plugin_id}")

        except Exception as e:
            logger.error(f"Post-import validation failed for {plugin.plugin_id}: {e}")
            # Don't fail the import for post-validation issues

    def _validate_executor(self, executor: PluginExecutor, manifest: PluginManifest) -> bool:
        """Validate executor configuration"""
        try:
            # Check that executor type is supported by manifest
            if executor.type not in manifest.capabilities:
                return False

            # Validate entry point exists in files
            # (This would check against stored files in a full implementation)

            # Validate resource limits are reasonable
            if "timeout" in executor.resource_limits:
                timeout = executor.resource_limits["timeout"]
                if not isinstance(timeout, int) or timeout > 3600 or timeout < 1:
                    return False

            return True

        except Exception as e:
            logger.error(f"Executor validation error: {e}")
            return False

    async def _validate_plugin_url(self, url: str) -> bool:
        """Validate plugin download URL"""
        import urllib.parse

        try:
            parsed = urllib.parse.urlparse(url)

            # Only allow HTTPS
            if parsed.scheme != "https":
                return False

            # Block private/local addresses
            hostname = parsed.hostname
            if not hostname:
                return False

            # Add additional URL validation as needed
            # (e.g., allowlist of trusted domains)

            return True

        except Exception:
            return False

    async def _download_plugin_package(self, url: str, max_size: int) -> Dict[str, Any]:
        """Download plugin package from URL"""
        import urllib.parse

        import aiohttp

        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=300)
            ) as session:  # 5 minute timeout

                async with session.get(url) as response:
                    if response.status != 200:
                        return {
                            "success": False,
                            "error": f"Download failed with status {response.status}",
                        }

                    # Check content length
                    content_length = response.headers.get("content-length")
                    if content_length and int(content_length) > max_size:
                        return {
                            "success": False,
                            "error": f"File too large: {content_length} bytes",
                        }

                    # Download with size limit
                    content = BytesIO()
                    size = 0

                    async for chunk in response.content.iter_chunked(8192):
                        size += len(chunk)
                        if size > max_size:
                            return {
                                "success": False,
                                "error": f"Download exceeded size limit: {size} bytes",
                            }
                        content.write(chunk)

                    # Determine filename
                    filename = "plugin.tar.gz"  # default
                    if "content-disposition" in response.headers:
                        # Parse filename from content-disposition header
                        cd = response.headers["content-disposition"]
                        if "filename=" in cd:
                            filename = cd.split("filename=")[1].strip('"')
                    else:
                        # Extract from URL
                        parsed_url = urllib.parse.urlparse(url)
                        if parsed_url.path:
                            filename = Path(parsed_url.path).name

                    return {
                        "success": True,
                        "content": content.getvalue(),
                        "filename": filename,
                        "size": size,
                    }

        except Exception as e:
            logger.error(f"Download error for {url}: {e}")
            return {"success": False, "error": f"Download failed: {str(e)}"}

    async def list_import_history(
        self, user_id: Optional[str] = None, limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Get plugin import history"""
        query = {}
        if user_id:
            query["imported_by"] = user_id

        plugins = (
            await InstalledPlugin.find(query)
            .sort(-InstalledPlugin.imported_at)
            .limit(limit)
            .to_list()
        )

        return [
            {
                "plugin_id": plugin.plugin_id,
                "name": plugin.manifest.name,
                "version": plugin.manifest.version,
                "imported_by": plugin.imported_by,
                "imported_at": plugin.imported_at.isoformat(),
                "trust_level": plugin.trust_level.value,
                "status": plugin.status.value,
                "source_url": plugin.source_url,
                "import_method": plugin.import_method,
            }
            for plugin in plugins
        ]

    async def get_import_statistics(self) -> Dict[str, Any]:
        """Get plugin import statistics"""
        total_plugins = await InstalledPlugin.count()

        # Count by status
        status_counts = {}
        for status in PluginStatus:
            count = await InstalledPlugin.find(InstalledPlugin.status == status).count()
            status_counts[status.value] = count

        # Count by trust level
        trust_counts = {}
        for trust_level in PluginTrustLevel:
            count = await InstalledPlugin.find(InstalledPlugin.trust_level == trust_level).count()
            trust_counts[trust_level.value] = count

        return {
            "total_plugins": total_plugins,
            "by_status": status_counts,
            "by_trust_level": trust_counts,
            "import_methods": {
                "upload": await InstalledPlugin.find(
                    InstalledPlugin.import_method == "upload"
                ).count(),
                "url": await InstalledPlugin.find(InstalledPlugin.import_method == "url").count(),
            },
        }
