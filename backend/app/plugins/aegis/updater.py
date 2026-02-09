"""
Aegis Plugin Updater for Phase 5

Handles Aegis independent updates with:
- Version checking against registry
- Package download and verification
- Backup and rollback support
- Database sync after update

Part of Phase 5: Control Plane (Aegis Integration Plan)
"""

import hashlib
import json
import logging
import shutil
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID, uuid4

import aiohttp
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.plugins.aegis.config import AegisConfig, get_aegis_config
from app.schemas.plugin_update_schemas import (
    ChangeType,
    PluginUpdateStatus,
    UpdateCheckResponse,
    UpdateInstallResponse,
    VersionChange,
    VersionInfo,
)

logger = logging.getLogger(__name__)


class UpdateError(Exception):
    """Error during update process."""

    pass


class AegisUpdater:
    """
    Handles Aegis plugin updates.

    Provides:
    - Check for available updates
    - Download and verify packages
    - Backup current installation
    - Install updates with rollback on failure
    - Sync new rules to database
    """

    # Timeout for registry requests
    REGISTRY_TIMEOUT = 30

    # Maximum package size (100MB)
    MAX_PACKAGE_SIZE = 100 * 1024 * 1024

    def __init__(self, db: Session, config: Optional[AegisConfig] = None):
        """
        Initialize the updater.

        Args:
            db: Database session for tracking updates
            config: Optional Aegis configuration (uses global if not provided)
        """
        self.db = db
        self.config = config or get_aegis_config()
        self.registry_url = self.config.update_registry_url

    async def check_for_updates(self) -> UpdateCheckResponse:
        """
        Check the registry for available updates.

        Returns:
            UpdateCheckResponse with version info and availability
        """
        current_version = self._get_current_version()
        checked_at = datetime.now(timezone.utc)

        # Offline mode - no update checks
        if self.config.offline_mode:
            return UpdateCheckResponse(
                update_available=False,
                current_version=current_version,
                checked_at=checked_at,
                error="Offline mode enabled - update checks disabled",
            )

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.registry_url}/versions",
                    timeout=aiohttp.ClientTimeout(total=self.REGISTRY_TIMEOUT),
                ) as response:
                    if response.status != 200:
                        return UpdateCheckResponse(
                            update_available=False,
                            current_version=current_version,
                            checked_at=checked_at,
                            error=f"Registry unavailable (HTTP {response.status})",
                        )

                    data = await response.json()

            latest_version = data.get("latest", "")
            latest_stable = data.get("current_stable", latest_version)
            min_ow_version = data.get("min_openwatch_version")

            # Parse version info
            versions = []
            changes = []
            for v in data.get("versions", []):
                version_changes = [
                    VersionChange(
                        type=ChangeType(c.get("type", "updated")),
                        description=c.get("description", ""),
                    )
                    for c in v.get("changes", [])
                ]
                versions.append(
                    VersionInfo(
                        version=v.get("version", ""),
                        released=datetime.fromisoformat(v.get("released", datetime.now(timezone.utc).isoformat())),
                        changes=version_changes,
                        breaking_changes=v.get("breaking_changes", []),
                        min_openwatch_version=v.get("min_openwatch_version"),
                    )
                )
                # Collect changes from latest version
                if v.get("version") == latest_version:
                    changes = version_changes

            # Check OpenWatch compatibility
            ow_compatible = True
            compat_message = None
            if min_ow_version:
                from app.core.config import settings

                ow_compatible = self._version_gte(settings.VERSION, min_ow_version)
                if not ow_compatible:
                    compat_message = f"Requires OpenWatch {min_ow_version}+, " f"current: {settings.VERSION}"

            update_available = self._version_gt(latest_version, current_version) and ow_compatible

            # Store notification if update available
            if update_available:
                await self._store_update_notification(current_version, latest_version, changes, min_ow_version)

            return UpdateCheckResponse(
                update_available=update_available,
                current_version=current_version,
                latest_version=latest_version,
                latest_stable_version=latest_stable,
                versions=versions,
                changes=changes,
                min_openwatch_version=min_ow_version,
                openwatch_compatible=ow_compatible,
                compatibility_message=compat_message,
                checked_at=checked_at,
            )

        except aiohttp.ClientError as e:
            logger.warning(f"Failed to check for updates: {e}")
            return UpdateCheckResponse(
                update_available=False,
                current_version=current_version,
                checked_at=checked_at,
                error=f"Network error: {str(e)}",
            )
        except Exception as e:
            logger.exception(f"Unexpected error checking for updates: {e}")
            return UpdateCheckResponse(
                update_available=False,
                current_version=current_version,
                checked_at=checked_at,
                error=f"Error: {str(e)}",
            )

    async def perform_update(
        self,
        version: str,
        user_id: int,
        skip_backup: bool = False,
    ) -> UpdateInstallResponse:
        """
        Perform a full update to the specified version.

        Args:
            version: Target version to install
            user_id: User initiating the update
            skip_backup: Skip backup (not recommended)

        Returns:
            UpdateInstallResponse with result details
        """
        current_version = self._get_current_version()
        started_at = datetime.now(timezone.utc)
        update_id = uuid4()
        backup_path: Optional[Path] = None

        # Create update record
        self._create_update_record(update_id, current_version, version, user_id)

        try:
            # Step 1: Download package
            self._update_status(update_id, PluginUpdateStatus.DOWNLOADING, 10)
            package_path, checksum = await self._download_package(version)

            # Step 2: Verify package
            self._update_status(update_id, PluginUpdateStatus.VERIFYING, 30)
            manifest = await self._verify_package(package_path, checksum)

            # Step 3: Backup current installation
            if not skip_backup:
                self._update_status(update_id, PluginUpdateStatus.INSTALLING, 40)
                backup_path = await self._backup_current(current_version)

            # Step 4: Install update
            self._update_status(update_id, PluginUpdateStatus.INSTALLING, 50)
            await self._install_package(package_path, manifest)

            # Step 5: Validate installation
            self._update_status(update_id, PluginUpdateStatus.INSTALLING, 80)
            if not await self._validate_installation():
                raise UpdateError("Installation validation failed")

            # Step 6: Sync rules to database
            self._update_status(update_id, PluginUpdateStatus.INSTALLING, 90)
            await self._sync_rules_to_database()

            # Success
            self._update_status(update_id, PluginUpdateStatus.COMPLETED, 100)

            # Remove backup on success
            if backup_path and backup_path.exists():
                shutil.rmtree(backup_path)

            completed_at = datetime.now(timezone.utc)

            # Parse changes
            changes = [
                VersionChange(
                    type=ChangeType(c.get("type", "updated")),
                    description=c.get("description", ""),
                )
                for c in manifest.get("changes", [])
            ]

            logger.info(f"Successfully updated Aegis from {current_version} to {version}")

            return UpdateInstallResponse(
                success=True,
                update_id=update_id,
                from_version=current_version,
                to_version=version,
                status=PluginUpdateStatus.COMPLETED,
                stats=manifest.get("stats"),
                changes=changes,
                started_at=started_at,
                completed_at=completed_at,
            )

        except Exception as e:
            logger.exception(f"Update failed: {e}")

            # Attempt rollback
            if backup_path and backup_path.exists():
                try:
                    await self._rollback(backup_path)
                    self._update_status(update_id, PluginUpdateStatus.ROLLED_BACK, 0, str(e))
                except Exception as rollback_error:
                    logger.error(f"Rollback failed: {rollback_error}")
                    self._update_status(
                        update_id,
                        PluginUpdateStatus.FAILED,
                        0,
                        f"Update failed: {e}. Rollback also failed: {rollback_error}",
                    )
            else:
                self._update_status(update_id, PluginUpdateStatus.FAILED, 0, str(e))

            return UpdateInstallResponse(
                success=False,
                update_id=update_id,
                from_version=current_version,
                to_version=version,
                status=PluginUpdateStatus.FAILED,
                error=str(e),
                backup_path=str(backup_path) if backup_path else None,
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
            )

    async def install_offline_package(
        self,
        package_path: Path,
        expected_checksum: str,
        user_id: int,
    ) -> UpdateInstallResponse:
        """
        Install an update from a local package (air-gapped mode).

        Args:
            package_path: Path to the package file
            expected_checksum: Expected SHA256 checksum
            user_id: User initiating the update

        Returns:
            UpdateInstallResponse with result details
        """
        current_version = self._get_current_version()
        started_at = datetime.now(timezone.utc)
        update_id = uuid4()

        try:
            # Verify checksum
            actual_checksum = self._compute_checksum(package_path)
            if actual_checksum != expected_checksum:
                raise UpdateError(f"Checksum mismatch: expected {expected_checksum}, " f"got {actual_checksum}")

            # Extract and read manifest
            manifest = self._extract_manifest(package_path)
            target_version = manifest.get("version", "unknown")

            # Create update record
            self._create_update_record(update_id, current_version, target_version, user_id)

            # Backup
            backup_path = await self._backup_current(current_version)

            # Install
            await self._install_package(package_path, manifest)

            # Validate
            if not await self._validate_installation():
                await self._rollback(backup_path)
                raise UpdateError("Installation validation failed")

            # Sync database
            await self._sync_rules_to_database()

            # Success
            self._update_status(update_id, PluginUpdateStatus.COMPLETED, 100)

            if backup_path.exists():
                shutil.rmtree(backup_path)

            return UpdateInstallResponse(
                success=True,
                update_id=update_id,
                from_version=current_version,
                to_version=target_version,
                status=PluginUpdateStatus.COMPLETED,
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
            )

        except Exception as e:
            logger.exception(f"Offline update failed: {e}")
            return UpdateInstallResponse(
                success=False,
                update_id=update_id,
                from_version=current_version,
                to_version="unknown",
                status=PluginUpdateStatus.FAILED,
                error=str(e),
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
            )

    def get_changelog(self) -> str:
        """Get the changelog from the current installation."""
        changelog_path = self.config.aegis_path / "CHANGELOG.md"
        if changelog_path.exists():
            return changelog_path.read_text()
        return "No changelog available."

    def _get_current_version(self) -> str:
        """Get the currently installed Aegis version."""
        version_file = self.config.aegis_path / "VERSION"
        if version_file.exists():
            return version_file.read_text().strip()

        # Fallback: check runner module
        try:
            from runner import __version__

            return __version__
        except (ImportError, AttributeError):
            pass

        return "0.1.0"

    async def _download_package(self, version: str) -> Tuple[Path, str]:
        """Download update package from registry."""
        package_url = f"{self.registry_url}/packages/{version}/aegis-{version}.tar.gz"
        checksum_url = f"{self.registry_url}/packages/{version}/aegis-{version}.sha256"

        temp_dir = Path(tempfile.mkdtemp())

        async with aiohttp.ClientSession() as session:
            # Download checksum first
            async with session.get(checksum_url) as response:
                if response.status != 200:
                    raise UpdateError(f"Failed to download checksum: HTTP {response.status}")
                expected_checksum = (await response.text()).strip().split()[0]

            # Download package
            async with session.get(package_url) as response:
                if response.status != 200:
                    raise UpdateError(f"Failed to download package: HTTP {response.status}")

                # Check content length
                content_length = response.content_length or 0
                if content_length > self.MAX_PACKAGE_SIZE:
                    raise UpdateError(f"Package too large: {content_length} bytes " f"(max {self.MAX_PACKAGE_SIZE})")

                package_path = temp_dir / f"aegis-{version}.tar.gz"
                with open(package_path, "wb") as f:
                    async for chunk in response.content.iter_chunked(8192):
                        f.write(chunk)

        return package_path, expected_checksum

    async def _verify_package(self, package_path: Path, expected_checksum: str) -> Dict[str, Any]:
        """Verify package integrity and extract manifest."""
        # Verify checksum
        actual_checksum = self._compute_checksum(package_path)
        if actual_checksum != expected_checksum:
            raise UpdateError(f"Checksum mismatch: expected {expected_checksum}, got {actual_checksum}")

        # Extract and return manifest
        return self._extract_manifest(package_path)

    def _compute_checksum(self, file_path: Path) -> str:
        """Compute SHA256 checksum of a file."""
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def _extract_manifest(self, package_path: Path) -> Dict[str, Any]:
        """Extract and parse manifest from package."""
        with tarfile.open(package_path, "r:gz") as tar:
            # Security: check for path traversal
            for member in tar.getmembers():
                if member.name.startswith("/") or ".." in member.name:
                    raise UpdateError(f"Suspicious path in package: {member.name}")

            # Find manifest
            manifest_member = None
            for member in tar.getmembers():
                if member.name.endswith("manifest.json"):
                    manifest_member = member
                    break

            if not manifest_member:
                raise UpdateError("Package missing manifest.json")

            f = tar.extractfile(manifest_member)
            if f is None:
                raise UpdateError("Could not read manifest.json")

            return json.load(f)

    async def _backup_current(self, current_version: str) -> Path:
        """Create backup of current installation."""
        self.config.backup_path.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        backup_path = self.config.backup_path / f"aegis.backup.{current_version}.{timestamp}"

        if self.config.aegis_path.exists():
            shutil.copytree(self.config.aegis_path, backup_path)
            logger.info(f"Created backup at {backup_path}")

        return backup_path

    async def _install_package(self, package_path: Path, manifest: Dict[str, Any]) -> None:
        """Install update from package."""
        # Extract to temp directory
        temp_extract = Path(tempfile.mkdtemp())

        with tarfile.open(package_path, "r:gz") as tar:
            tar.extractall(temp_extract)

        # Find the extracted aegis directory
        extracted_dirs = list(temp_extract.iterdir())
        if len(extracted_dirs) == 1 and extracted_dirs[0].is_dir():
            source_dir = extracted_dirs[0]
        else:
            source_dir = temp_extract

        # Remove current installation
        if self.config.aegis_path.exists():
            shutil.rmtree(self.config.aegis_path)

        # Move new installation
        shutil.move(str(source_dir), str(self.config.aegis_path))

        # Run migrations if any
        migrations = manifest.get("migrations", [])
        if migrations:
            await self._run_migrations(migrations)

        logger.info(f"Installed Aegis version {manifest.get('version')}")

    async def _run_migrations(self, migrations: List[Dict[str, str]]) -> None:
        """Run database migrations from package."""
        for migration in migrations:
            migration_file = self.config.aegis_path / migration.get("file", "")
            if migration_file.exists():
                sql = migration_file.read_text()
                self.db.execute(text(sql))
        self.db.commit()

    async def _validate_installation(self) -> bool:
        """Validate the new installation works correctly."""
        try:
            # Try to import runner and load rules
            from runner.engine import load_rules

            rules = load_rules(str(self.config.rules_path))
            if not rules:
                logger.error("No rules loaded after update")
                return False

            logger.info(f"Validation passed: {len(rules)} rules loaded")
            return True

        except Exception as e:
            logger.error(f"Validation failed: {e}")
            return False

    async def _sync_rules_to_database(self) -> None:
        """Sync new rules to database after update."""
        try:
            from app.plugins.aegis.sync_service import AegisSyncService

            sync_service = AegisSyncService(self.db)
            await sync_service.sync_rules()
            logger.info("Rules synced to database")
        except Exception as e:
            logger.error(f"Failed to sync rules: {e}")
            raise UpdateError(f"Failed to sync rules to database: {e}")

    async def _rollback(self, backup_path: Path) -> None:
        """Rollback to backup version."""
        if not backup_path.exists():
            raise UpdateError(f"Backup not found: {backup_path}")

        # Remove failed installation
        if self.config.aegis_path.exists():
            shutil.rmtree(self.config.aegis_path)

        # Restore backup
        shutil.move(str(backup_path), str(self.config.aegis_path))

        # Re-sync database
        await self._sync_rules_to_database()

        logger.info(f"Rolled back to backup from {backup_path}")

    def _create_update_record(
        self,
        update_id: UUID,
        from_version: str,
        to_version: str,
        user_id: int,
    ) -> None:
        """Create update record in database."""
        query = """
            INSERT INTO plugin_updates (
                id, plugin_id, from_version, to_version, status, initiated_by
            ) VALUES (
                :id, 'aegis', :from_version, :to_version, 'pending', :user_id
            )
        """
        self.db.execute(
            text(query),
            {
                "id": update_id,
                "from_version": from_version,
                "to_version": to_version,
                "user_id": user_id,
            },
        )
        self.db.commit()

    def _update_status(
        self,
        update_id: UUID,
        status: PluginUpdateStatus,
        progress: int,
        error_message: Optional[str] = None,
    ) -> None:
        """Update status of an update record."""
        query = """
            UPDATE plugin_updates
            SET status = :status,
                progress = :progress,
                error_message = :error,
                started_at = CASE WHEN started_at IS NULL AND :status != 'pending'
                    THEN CURRENT_TIMESTAMP ELSE started_at END,
                completed_at = CASE WHEN :status IN ('completed', 'failed', 'rolled_back')
                    THEN CURRENT_TIMESTAMP ELSE completed_at END
            WHERE id = :id
        """
        self.db.execute(
            text(query),
            {
                "id": update_id,
                "status": status.value,
                "progress": progress,
                "error": error_message,
            },
        )
        self.db.commit()

    async def _store_update_notification(
        self,
        current_version: str,
        available_version: str,
        changes: List[VersionChange],
        min_ow_version: Optional[str],
    ) -> None:
        """Store update availability notification."""
        query = """
            INSERT INTO plugin_update_notifications (
                plugin_id, current_version, available_version,
                min_openwatch_version, changes, checked_at
            ) VALUES (
                'aegis', :current, :available, :min_ow,
                :changes::jsonb, CURRENT_TIMESTAMP
            )
            ON CONFLICT (plugin_id, available_version)
            DO UPDATE SET checked_at = CURRENT_TIMESTAMP
        """
        changes_json = json.dumps([{"type": c.type.value, "description": c.description} for c in changes])
        self.db.execute(
            text(query),
            {
                "current": current_version,
                "available": available_version,
                "min_ow": min_ow_version,
                "changes": changes_json,
            },
        )
        self.db.commit()

    def _version_gt(self, a: str, b: str) -> bool:
        """Check if version a is greater than version b."""
        try:
            from packaging.version import parse

            return parse(a) > parse(b)
        except ImportError:
            # Fallback: simple string comparison
            return a > b

    def _version_gte(self, a: str, b: str) -> bool:
        """Check if version a is greater than or equal to version b."""
        try:
            from packaging.version import parse

            return parse(a) >= parse(b)
        except ImportError:
            return a >= b
