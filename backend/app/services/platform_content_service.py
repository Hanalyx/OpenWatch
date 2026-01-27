"""
Platform-Aware Content Selection Service

Provides intelligent SCAP content selection based on host platform detection.
This service ensures each host receives the correct SCAP content for its
specific platform and version during both single and bulk scan operations.

Architecture:
    This service bridges the gap between:
    1. Platform detection (PlatformDetector / host.platform_identifier)
    2. SCAP content storage (scap_content table)

    It provides:
    - Platform-to-content mapping
    - JIT fallback detection for hosts without platform data
    - Content validation before scan execution

SSH Connection Pattern:
    This service follows the SSH Connection Best Practices from CLAUDE.md.
    When JIT platform detection is needed, it accepts CredentialData objects
    with pre-decrypted values from CentralizedAuthService.

Usage:
    from backend.app.services.platform_content_service import (
        PlatformContentService,
        get_platform_content_service,
    )

    # Get content for a host with known platform
    service = get_platform_content_service(db)
    content = await service.get_content_for_host(host_id)

    # Get content with JIT fallback detection
    content = await service.get_content_for_host_with_detection(
        host_id=host_id,
        credential_data=credential_data,  # From CentralizedAuthService
    )
"""

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

from sqlalchemy import text
from sqlalchemy.orm import Session

if TYPE_CHECKING:
    from backend.app.services.auth import CredentialData

logger = logging.getLogger(__name__)


@dataclass
class PlatformContent:
    """
    SCAP content matched to a specific platform.

    Attributes:
        content_id: ID in scap_content table
        file_path: Path to SCAP content file
        name: Human-readable content name
        os_family: Target OS family (rhel, ubuntu, etc.)
        os_version: Target OS version
        profiles: Available scan profiles
        compliance_framework: Framework (STIG, CIS, etc.)
        match_type: How the content was matched (exact, family, default)
    """

    content_id: int
    file_path: str
    name: str
    os_family: Optional[str] = None
    os_version: Optional[str] = None
    profiles: Optional[List[str]] = None
    compliance_framework: Optional[str] = None
    match_type: str = "exact"  # exact, family, default


@dataclass
class HostPlatformInfo:
    """
    Platform information for a host.

    Attributes:
        host_id: UUID of the host
        hostname: Host's hostname
        ip_address: Host's IP address
        port: SSH port
        platform: OS family (rhel, ubuntu, etc.)
        platform_version: OS version (9.3, 22.04, etc.)
        platform_identifier: Normalized identifier (rhel9, ubuntu2204)
        architecture: System architecture (x86_64, arm64)
        source: Where the platform info came from (database, jit_detection)
    """

    host_id: str
    hostname: str
    ip_address: str
    port: int
    platform: Optional[str] = None
    platform_version: Optional[str] = None
    platform_identifier: Optional[str] = None
    architecture: Optional[str] = None
    source: str = "database"


class PlatformContentService:
    """
    Service for mapping host platforms to appropriate SCAP content.

    This service handles:
    1. Looking up host platform information from database
    2. JIT platform detection via SSH when database info is missing
    3. Matching platforms to SCAP content files
    4. Content selection for bulk scans with mixed platforms

    SSH Connection Pattern:
        When JIT detection is needed, this service requires CredentialData
        objects from CentralizedAuthService. It does NOT handle credential
        resolution or decryption internally.
    """

    # Platform family mappings for content matching
    # Maps various OS names to normalized family names
    PLATFORM_FAMILY_MAP = {
        "rhel": "rhel",
        "red hat": "rhel",
        "redhat": "rhel",
        "centos": "rhel",
        "rocky": "rhel",
        "alma": "rhel",
        "almalinux": "rhel",
        "oracle": "rhel",
        "fedora": "fedora",
        "ubuntu": "ubuntu",
        "debian": "debian",
        "suse": "suse",
        "sles": "suse",
        "opensuse": "suse",
    }

    def __init__(self, db: Session):
        """
        Initialize the platform content service.

        Args:
            db: SQLAlchemy database session
        """
        self.db = db

    async def get_host_platform_info(self, host_id: str) -> Optional[HostPlatformInfo]:
        """
        Get platform information for a host from the database.

        Args:
            host_id: UUID of the host

        Returns:
            HostPlatformInfo if host exists, None otherwise
        """
        query = text("""
            SELECT id, hostname, ip_address, port,
                   os_family, os_version, platform_identifier, architecture
            FROM hosts
            WHERE id = :host_id AND is_active = true
        """)

        result = self.db.execute(query, {"host_id": host_id}).fetchone()

        if not result:
            logger.warning(f"Host {host_id} not found or inactive")
            return None

        return HostPlatformInfo(
            host_id=str(result.id),
            hostname=result.hostname,
            ip_address=result.ip_address,
            port=result.port or 22,
            platform=result.os_family,
            platform_version=result.os_version,
            platform_identifier=result.platform_identifier,
            architecture=result.architecture,
            source="database",
        )

    async def get_host_platform_with_jit_detection(
        self,
        host_id: str,
        credential_data: "CredentialData",
    ) -> Optional[HostPlatformInfo]:
        """
        Get platform information with JIT detection fallback.

        If the host doesn't have platform information in the database,
        performs Just-In-Time detection via SSH and updates the database.

        SSH Connection Pattern:
            This method follows the SSH Connection Best Practices from CLAUDE.md.
            The credential_data parameter must contain DECRYPTED values from
            CentralizedAuthService.resolve_credential().

        Args:
            host_id: UUID of the host
            credential_data: CredentialData with DECRYPTED credentials

        Returns:
            HostPlatformInfo with platform data (from DB or JIT detection)
        """
        # First, check database
        platform_info = await self.get_host_platform_info(host_id)

        if not platform_info:
            logger.error(f"Host {host_id} not found")
            return None

        # If we have platform_identifier, we're good
        if platform_info.platform_identifier:
            logger.debug(
                f"Host {host_id} has platform info in database: "
                f"{platform_info.platform_identifier}"
            )
            return platform_info

        # Need JIT detection
        logger.info(
            f"Host {host_id} ({platform_info.hostname}) missing platform info, "
            "performing JIT detection"
        )

        try:
            # Import here to avoid circular imports
            from backend.app.services.engine.discovery import PlatformDetector

            detector = PlatformDetector(self.db)
            detection_result = await detector.detect(
                hostname=platform_info.ip_address or platform_info.hostname,
                port=platform_info.port,
                credential_data=credential_data,
            )

            if detection_result.detection_success:
                # Update database with detected platform
                await self._update_host_platform(
                    host_id=host_id,
                    platform=detection_result.platform,
                    platform_version=detection_result.platform_version,
                    platform_identifier=detection_result.platform_identifier,
                    architecture=detection_result.architecture,
                )

                # Return updated info
                platform_info.platform = detection_result.platform
                platform_info.platform_version = detection_result.platform_version
                platform_info.platform_identifier = detection_result.platform_identifier
                platform_info.architecture = detection_result.architecture
                platform_info.source = "jit_detection"

                logger.info(
                    f"JIT detection successful for host {host_id}: "
                    f"{detection_result.platform_identifier}"
                )
            else:
                logger.warning(
                    f"JIT detection failed for host {host_id}: "
                    f"{detection_result.detection_error}"
                )
                # Continue with what we have (may be incomplete)

        except Exception as e:
            logger.error(f"JIT platform detection failed for host {host_id}: {e}")
            # Continue with incomplete platform info

        return platform_info

    async def get_content_for_platform(
        self,
        platform_identifier: str,
        compliance_framework: Optional[str] = None,
    ) -> Optional[PlatformContent]:
        """
        Find SCAP content matching a platform identifier.

        Matching priority:
        1. Exact match on platform_identifier (e.g., rhel9)
        2. Match on os_family + major version
        3. Match on os_family only
        4. Default content (if any)

        Args:
            platform_identifier: Normalized platform ID (e.g., "rhel9", "ubuntu2204")
            compliance_framework: Optional framework filter (STIG, CIS, etc.)

        Returns:
            PlatformContent if found, None otherwise
        """
        if not platform_identifier:
            return await self._get_default_content(compliance_framework)

        # Parse platform identifier
        # Format: {family}{version} like "rhel9" or "ubuntu2204"
        platform_lower = platform_identifier.lower()

        # Extract family and version
        family = None
        version = None
        for known_family in ["rhel", "ubuntu", "debian", "fedora", "suse", "centos"]:
            if platform_lower.startswith(known_family):
                family = known_family
                version = platform_lower[len(known_family) :]
                break

        if not family:
            logger.warning(f"Could not parse platform identifier: {platform_identifier}")
            return await self._get_default_content(compliance_framework)

        # Normalize family for content lookup
        normalized_family = self.PLATFORM_FAMILY_MAP.get(family, family)

        # Try exact match first
        content = await self._find_content_exact(normalized_family, version, compliance_framework)
        if content:
            content.match_type = "exact"
            return content

        # Try family + major version
        if version and len(version) > 1:
            major_version = version[0]  # First character is typically major version
            content = await self._find_content_exact(
                normalized_family, major_version, compliance_framework
            )
            if content:
                content.match_type = "major_version"
                return content

        # Try family only
        content = await self._find_content_by_family(normalized_family, compliance_framework)
        if content:
            content.match_type = "family"
            return content

        # Fall back to default
        return await self._get_default_content(compliance_framework)

    async def get_content_for_host(
        self,
        host_id: str,
        compliance_framework: Optional[str] = None,
    ) -> Tuple[Optional[PlatformContent], Optional[HostPlatformInfo]]:
        """
        Get SCAP content for a host based on its platform.

        This uses the platform information stored in the database.
        For hosts without platform info, use get_content_for_host_with_detection().

        Args:
            host_id: UUID of the host
            compliance_framework: Optional framework filter

        Returns:
            Tuple of (PlatformContent, HostPlatformInfo)
        """
        platform_info = await self.get_host_platform_info(host_id)

        if not platform_info:
            return None, None

        content = await self.get_content_for_platform(
            platform_info.platform_identifier,
            compliance_framework,
        )

        return content, platform_info

    async def get_content_for_host_with_detection(
        self,
        host_id: str,
        credential_data: "CredentialData",
        compliance_framework: Optional[str] = None,
    ) -> Tuple[Optional[PlatformContent], Optional[HostPlatformInfo]]:
        """
        Get SCAP content for a host with JIT platform detection fallback.

        This is the recommended method for scan execution, as it ensures
        platform information is available even if OS discovery hasn't run.

        SSH Connection Pattern:
            This method follows the SSH Connection Best Practices from CLAUDE.md.
            The credential_data parameter must contain DECRYPTED values.

        Args:
            host_id: UUID of the host
            credential_data: CredentialData with DECRYPTED credentials
            compliance_framework: Optional framework filter

        Returns:
            Tuple of (PlatformContent, HostPlatformInfo)
        """
        platform_info = await self.get_host_platform_with_jit_detection(host_id, credential_data)

        if not platform_info:
            return None, None

        content = await self.get_content_for_platform(
            platform_info.platform_identifier,
            compliance_framework,
        )

        return content, platform_info

    async def get_content_for_multiple_hosts(
        self,
        host_ids: List[str],
        compliance_framework: Optional[str] = None,
    ) -> Dict[str, Tuple[Optional[PlatformContent], Optional[HostPlatformInfo]]]:
        """
        Get SCAP content for multiple hosts efficiently.

        This method batches database queries for better performance when
        planning bulk scans.

        Note: This uses database-stored platform info only. For JIT detection,
        call get_content_for_host_with_detection() for each host.

        Args:
            host_ids: List of host UUIDs
            compliance_framework: Optional framework filter

        Returns:
            Dict mapping host_id to (PlatformContent, HostPlatformInfo)
        """
        if not host_ids:
            return {}

        # Batch query for all hosts
        placeholders = ", ".join([f"'{hid}'" for hid in host_ids])
        query = text(f"""
            SELECT id, hostname, ip_address, port,
                   os_family, os_version, platform_identifier, architecture
            FROM hosts
            WHERE id IN ({placeholders}) AND is_active = true
        """)

        results = {}
        host_rows = self.db.execute(query).fetchall()

        for row in host_rows:
            platform_info = HostPlatformInfo(
                host_id=str(row.id),
                hostname=row.hostname,
                ip_address=row.ip_address,
                port=row.port or 22,
                platform=row.os_family,
                platform_version=row.os_version,
                platform_identifier=row.platform_identifier,
                architecture=row.architecture,
                source="database",
            )

            content = await self.get_content_for_platform(
                platform_info.platform_identifier,
                compliance_framework,
            )

            results[str(row.id)] = (content, platform_info)

        # Log hosts without content
        for host_id in host_ids:
            if host_id not in results:
                logger.warning(f"Host {host_id} not found in database")
                results[host_id] = (None, None)

        return results

    async def _find_content_exact(
        self,
        os_family: str,
        os_version: str,
        compliance_framework: Optional[str] = None,
    ) -> Optional[PlatformContent]:
        """Find content with exact os_family and os_version match."""
        query = text("""
            SELECT id, file_path, name, os_family, os_version,
                   profiles, compliance_framework
            FROM scap_content
            WHERE LOWER(os_family) = LOWER(:os_family)
              AND (os_version = :os_version OR os_version LIKE :os_version_prefix)
              AND (:framework IS NULL OR LOWER(compliance_framework) = LOWER(:framework))
            ORDER BY uploaded_at DESC
            LIMIT 1
        """)

        result = self.db.execute(
            query,
            {
                "os_family": os_family,
                "os_version": os_version,
                "os_version_prefix": f"{os_version}%",
                "framework": compliance_framework,
            },
        ).fetchone()

        if result:
            return self._row_to_platform_content(result)
        return None

    async def _find_content_by_family(
        self,
        os_family: str,
        compliance_framework: Optional[str] = None,
    ) -> Optional[PlatformContent]:
        """Find content by os_family only."""
        query = text("""
            SELECT id, file_path, name, os_family, os_version,
                   profiles, compliance_framework
            FROM scap_content
            WHERE LOWER(os_family) = LOWER(:os_family)
              AND (:framework IS NULL OR LOWER(compliance_framework) = LOWER(:framework))
            ORDER BY uploaded_at DESC
            LIMIT 1
        """)

        result = self.db.execute(
            query,
            {
                "os_family": os_family,
                "framework": compliance_framework,
            },
        ).fetchone()

        if result:
            return self._row_to_platform_content(result)
        return None

    async def _get_default_content(
        self,
        compliance_framework: Optional[str] = None,
    ) -> Optional[PlatformContent]:
        """Get default SCAP content when no platform match found."""
        query = text("""
            SELECT id, file_path, name, os_family, os_version,
                   profiles, compliance_framework
            FROM scap_content
            WHERE (:framework IS NULL OR LOWER(compliance_framework) = LOWER(:framework))
            ORDER BY uploaded_at DESC
            LIMIT 1
        """)

        result = self.db.execute(
            query,
            {
                "framework": compliance_framework,
            },
        ).fetchone()

        if result:
            content = self._row_to_platform_content(result)
            content.match_type = "default"
            return content
        return None

    async def _update_host_platform(
        self,
        host_id: str,
        platform: Optional[str],
        platform_version: Optional[str],
        platform_identifier: Optional[str],
        architecture: Optional[str],
    ) -> None:
        """Update host record with detected platform information."""
        query = text("""
            UPDATE hosts
            SET os_family = :platform,
                os_version = :platform_version,
                platform_identifier = :platform_identifier,
                architecture = :architecture,
                last_os_detection = :detected_at,
                updated_at = :updated_at
            WHERE id = :host_id
        """)

        now = datetime.utcnow()
        self.db.execute(
            query,
            {
                "host_id": host_id,
                "platform": platform,
                "platform_version": platform_version,
                "platform_identifier": platform_identifier,
                "architecture": architecture,
                "detected_at": now,
                "updated_at": now,
            },
        )
        self.db.commit()

        logger.info(f"Updated host {host_id} platform info: {platform_identifier}")

    def _row_to_platform_content(self, row) -> PlatformContent:
        """Convert database row to PlatformContent object."""
        profiles = None
        if row.profiles:
            # Profiles stored as comma-separated or JSON
            if row.profiles.startswith("["):
                import json

                profiles = json.loads(row.profiles)
            else:
                profiles = [p.strip() for p in row.profiles.split(",")]

        return PlatformContent(
            content_id=row.id,
            file_path=row.file_path,
            name=row.name,
            os_family=row.os_family,
            os_version=row.os_version,
            profiles=profiles,
            compliance_framework=row.compliance_framework,
        )


def get_platform_content_service(db: Session) -> PlatformContentService:
    """
    Factory function to create a PlatformContentService.

    Args:
        db: SQLAlchemy database session

    Returns:
        Configured PlatformContentService instance
    """
    return PlatformContentService(db)
