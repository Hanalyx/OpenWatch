"""
SCAP Repository Management Service
Handles automatic downloading and synchronization of SCAP content from various repositories
"""

import asyncio
import aiohttp
import logging
import os
import json
import hashlib
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Set
from dataclasses import dataclass
from pathlib import Path
import xml.etree.ElementTree as ET
from sqlalchemy.orm import Session
from sqlalchemy import text

logger = logging.getLogger(__name__)


@dataclass
class RepositoryConfig:
    id: str
    name: str
    url: str
    type: str  # 'official', 'custom', 'mirror'
    enabled: bool
    os_families: List[str]
    last_sync: Optional[datetime] = None
    credentials: Optional[Dict[str, str]] = None


@dataclass
class ContentMetadata:
    name: str
    filename: str
    content_type: str
    description: str
    version: str
    os_family: str
    os_version: str
    compliance_framework: str
    url: str
    checksum: str
    size_bytes: int
    last_modified: datetime


class SCAPRepositoryManager:
    """Manages SCAP content repositories and automatic synchronization"""

    def __init__(self):
        self.repositories: Dict[str, RepositoryConfig] = {}
        self.sync_running = False
        self.last_global_sync: Optional[datetime] = None
        self.content_cache_dir = Path("/app/data/scap_cache")
        self.content_cache_dir.mkdir(parents=True, exist_ok=True)

        # Initialize default repositories
        self._setup_default_repositories()

    def _setup_default_repositories(self):
        """Setup default SCAP content repositories"""
        default_repos = [
            RepositoryConfig(
                id="nist_official",
                name="NIST Official Repository",
                url="https://ncp.nist.gov/repository",
                type="official",
                enabled=True,
                os_families=["rhel", "ubuntu", "windows"],
            ),
            RepositoryConfig(
                id="redhat_security",
                name="Red Hat Security Data",
                url="https://access.redhat.com/security/data/oval",
                type="official",
                enabled=True,
                os_families=["rhel", "centos"],
            ),
            RepositoryConfig(
                id="ubuntu_security",
                name="Ubuntu Security Notices",
                url="https://people.canonical.com/~ubuntu-security/oval",
                type="official",
                enabled=True,
                os_families=["ubuntu", "debian"],
            ),
        ]

        for repo in default_repos:
            self.repositories[repo.id] = repo

    async def sync_repositories(
        self, db: Session, repository_ids: Optional[List[str]] = None
    ) -> Dict[str, str]:
        """
        Synchronize content from repositories
        Returns dict of repository_id -> status
        """
        if self.sync_running:
            return {"error": "Sync already in progress"}

        self.sync_running = True
        results = {}

        try:
            repos_to_sync = (
                [self.repositories[rid] for rid in repository_ids if rid in self.repositories]
                if repository_ids
                else [repo for repo in self.repositories.values() if repo.enabled]
            )

            logger.info(f"Starting sync for {len(repos_to_sync)} repositories")

            for repo in repos_to_sync:
                try:
                    result = await self._sync_repository(db, repo)
                    results[repo.id] = result
                    repo.last_sync = datetime.utcnow()
                except Exception as e:
                    logger.error(f"Failed to sync repository {repo.name}: {e}")
                    results[repo.id] = f"error: {str(e)}"

            self.last_global_sync = datetime.utcnow()

        finally:
            self.sync_running = False

        return results

    async def _sync_repository(self, db: Session, repo: RepositoryConfig) -> str:
        """Sync a single repository"""
        logger.info(f"Syncing repository: {repo.name}")

        # Get repository catalog/index
        content_list = await self._fetch_repository_catalog(repo)

        new_content = 0
        updated_content = 0

        for content_meta in content_list:
            # Check if content already exists
            existing = await self._get_existing_content(db, content_meta)

            if not existing:
                # Download and import new content
                if await self._download_and_import_content(db, repo, content_meta):
                    new_content += 1
            elif self._should_update_content(existing, content_meta):
                # Update existing content
                if await self._update_existing_content(db, repo, content_meta, existing):
                    updated_content += 1

        return f"synced: {new_content} new, {updated_content} updated"

    async def _fetch_repository_catalog(self, repo: RepositoryConfig) -> List[ContentMetadata]:
        """Fetch the catalog/index of available content from repository"""

        # This is a simplified implementation - real repositories would have
        # standardized APIs or catalog formats
        catalog_url = f"{repo.url}/catalog.json"

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(catalog_url, timeout=30) as response:
                    if response.status == 200:
                        catalog_data = await response.json()
                        return self._parse_catalog_data(catalog_data, repo)
                    else:
                        # Fallback to discovery methods
                        return await self._discover_content(repo)
        except Exception as e:
            logger.warning(f"Failed to fetch catalog for {repo.name}: {e}")
            return await self._discover_content(repo)

    def _parse_catalog_data(
        self, catalog_data: Dict, repo: RepositoryConfig
    ) -> List[ContentMetadata]:
        """Parse catalog JSON into ContentMetadata objects"""
        content_list = []

        for item in catalog_data.get("content", []):
            # Skip content not matching repository's OS families
            if item.get("os_family") not in repo.os_families:
                continue

            content_meta = ContentMetadata(
                name=item["name"],
                filename=item["filename"],
                content_type=item.get("content_type", "datastream"),
                description=item.get("description", ""),
                version=item.get("version", "1.0"),
                os_family=item["os_family"],
                os_version=item.get("os_version", ""),
                compliance_framework=item.get("compliance_framework", "unknown"),
                url=f"{repo.url}/{item['filename']}",
                checksum=item.get("checksum", ""),
                size_bytes=item.get("size_bytes", 0),
                last_modified=datetime.fromisoformat(
                    item.get("last_modified", datetime.utcnow().isoformat())
                ),
            )
            content_list.append(content_meta)

        return content_list

    async def _discover_content(self, repo: RepositoryConfig) -> List[ContentMetadata]:
        """Fallback content discovery for repositories without catalogs"""
        # This would implement various discovery methods:
        # - Directory listing parsing
        # - RSS/Atom feeds
        # - API endpoints
        # - File pattern matching

        logger.info(f"Discovering content for {repo.name} (no catalog available)")

        # Mock discovery for demonstration
        if "nist" in repo.url.lower():
            return await self._discover_nist_content(repo)
        elif "redhat" in repo.url.lower():
            return await self._discover_redhat_content(repo)
        elif "ubuntu" in repo.url.lower():
            return await self._discover_ubuntu_content(repo)

        return []

    async def _discover_nist_content(self, repo: RepositoryConfig) -> List[ContentMetadata]:
        """Discover NIST SCAP content"""
        # Mock NIST content discovery
        content_list = [
            ContentMetadata(
                name="RHEL 9 STIG",
                filename="U_RHEL_9_STIG_V1R5_Manual-xccdf.xml",
                content_type="datastream",
                description="Red Hat Enterprise Linux 9 Security Technical Implementation Guide",
                version="1.5",
                os_family="rhel",
                os_version="9",
                compliance_framework="STIG",
                url=f"{repo.url}/rhel9/U_RHEL_9_STIG_V1R5_Manual-xccdf.xml",
                checksum="abc123...",
                size_bytes=2048576,
                last_modified=datetime.utcnow() - timedelta(days=7),
            ),
            ContentMetadata(
                name="Ubuntu 22.04 CIS Benchmark",
                filename="ubuntu2204-cis-v1.0.0-xccdf.xml",
                content_type="datastream",
                description="Center for Internet Security Benchmark for Ubuntu 22.04",
                version="1.0.0",
                os_family="ubuntu",
                os_version="22.04",
                compliance_framework="CIS",
                url=f"{repo.url}/ubuntu/ubuntu2204-cis-v1.0.0-xccdf.xml",
                checksum="def456...",
                size_bytes=1536000,
                last_modified=datetime.utcnow() - timedelta(days=14),
            ),
        ]

        return [c for c in content_list if c.os_family in repo.os_families]

    async def _discover_redhat_content(self, repo: RepositoryConfig) -> List[ContentMetadata]:
        """Discover Red Hat security content"""
        # Mock Red Hat content discovery
        return []

    async def _discover_ubuntu_content(self, repo: RepositoryConfig) -> List[ContentMetadata]:
        """Discover Ubuntu security content"""
        # Mock Ubuntu content discovery
        return []

    async def _get_existing_content(
        self, db: Session, content_meta: ContentMetadata
    ) -> Optional[Dict]:
        """Check if content already exists in database"""
        try:
            result = db.execute(
                text(
                    """
                SELECT id, name, version, checksum, updated_at
                FROM scap_content 
                WHERE name = :name AND os_family = :os_family AND os_version = :os_version
            """
                ),
                {
                    "name": content_meta.name,
                    "os_family": content_meta.os_family,
                    "os_version": content_meta.os_version,
                },
            )

            row = result.fetchone()
            if row:
                return {
                    "id": row.id,
                    "name": row.name,
                    "version": row.version,
                    "checksum": row.checksum,
                    "updated_at": row.updated_at,
                }
            return None
        except Exception as e:
            logger.error(f"Error checking existing content: {e}")
            return None

    def _should_update_content(self, existing: Dict, content_meta: ContentMetadata) -> bool:
        """Determine if existing content should be updated"""
        # Check version
        if content_meta.version != existing.get("version"):
            return True

        # Check checksum if available
        if content_meta.checksum and content_meta.checksum != existing.get("checksum"):
            return True

        # Check age (update if repository content is newer than 30 days)
        if existing.get("updated_at"):
            age = datetime.utcnow() - existing["updated_at"]
            if age > timedelta(days=30):
                return True

        return False

    async def _download_and_import_content(
        self, db: Session, repo: RepositoryConfig, content_meta: ContentMetadata
    ) -> bool:
        """Download content file and import to database"""
        try:
            # Download content
            content_data = await self._download_content_file(content_meta.url)

            # Validate checksum if provided
            if content_meta.checksum:
                actual_checksum = hashlib.sha256(content_data).hexdigest()
                if actual_checksum != content_meta.checksum:
                    logger.warning(f"Checksum mismatch for {content_meta.name}")
                    return False

            # Parse and validate SCAP content
            profiles = await self._extract_profiles_from_content(content_data)

            # Save to cache directory
            cache_file = self.content_cache_dir / f"{content_meta.filename}"
            cache_file.write_bytes(content_data)

            # Insert into database
            current_time = datetime.utcnow()
            result = db.execute(
                text(
                    """
                INSERT INTO scap_content 
                (name, filename, content_type, description, version, profiles,
                 os_family, os_version, compliance_framework, source, status,
                 checksum, file_size, file_path, uploaded_at, uploaded_by)
                VALUES (:name, :filename, :content_type, :description, :version, :profiles,
                        :os_family, :os_version, :compliance_framework, 'repository', 'current',
                        :checksum, :file_size, :file_path, :uploaded_at, :uploaded_by)
                RETURNING id
            """
                ),
                {
                    "name": content_meta.name,
                    "filename": content_meta.filename,
                    "content_type": content_meta.content_type,
                    "description": content_meta.description,
                    "version": content_meta.version,
                    "profiles": json.dumps(profiles),
                    "os_family": content_meta.os_family,
                    "os_version": content_meta.os_version,
                    "compliance_framework": content_meta.compliance_framework,
                    "checksum": content_meta.checksum,
                    "file_size": len(content_data),
                    "file_path": str(cache_file),
                    "uploaded_at": current_time,
                    "uploaded_by": 1,  # System user
                },
            )

            content_id = result.fetchone().id
            db.commit()

            logger.info(f"Imported new content: {content_meta.name} (ID: {content_id})")
            return True

        except Exception as e:
            logger.error(f"Failed to download and import {content_meta.name}: {e}")
            db.rollback()
            return False

    async def _update_existing_content(
        self,
        db: Session,
        repo: RepositoryConfig,
        content_meta: ContentMetadata,
        existing: Dict,
    ) -> bool:
        """Update existing content with new version"""
        try:
            # Download updated content
            content_data = await self._download_content_file(content_meta.url)

            # Parse profiles
            profiles = await self._extract_profiles_from_content(content_data)

            # Update cache file
            cache_file = self.content_cache_dir / f"{content_meta.filename}"
            cache_file.write_bytes(content_data)

            # Update database record
            db.execute(
                text(
                    """
                UPDATE scap_content 
                SET version = :version, profiles = :profiles, checksum = :checksum,
                    file_size = :file_size, file_path = :file_path, updated_at = :updated_at,
                    status = 'current'
                WHERE id = :id
            """
                ),
                {
                    "id": existing["id"],
                    "version": content_meta.version,
                    "profiles": json.dumps(profiles),
                    "checksum": content_meta.checksum,
                    "file_size": len(content_data),
                    "file_path": str(cache_file),
                    "updated_at": datetime.utcnow(),
                },
            )

            db.commit()

            logger.info(f"Updated content: {content_meta.name} to version {content_meta.version}")
            return True

        except Exception as e:
            logger.error(f"Failed to update {content_meta.name}: {e}")
            db.rollback()
            return False

    async def _download_content_file(self, url: str) -> bytes:
        """Download content file from URL"""
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=300) as response:  # 5 minute timeout
                if response.status == 200:
                    return await response.read()
                else:
                    raise Exception(f"Failed to download: HTTP {response.status}")

    async def _extract_profiles_from_content(self, content_data: bytes) -> List[Dict]:
        """Extract profile information from SCAP content"""
        try:
            # Parse XML content
            root = ET.fromstring(content_data)

            # Find profiles (simplified - real implementation would handle various formats)
            profiles = []

            # XCCDF profiles
            for profile in root.findall(".//{http://checklists.nist.gov/xccdf/1.2}Profile"):
                profile_id = profile.get("id", "")
                title_elem = profile.find(".//{http://checklists.nist.gov/xccdf/1.2}title")
                desc_elem = profile.find(".//{http://checklists.nist.gov/xccdf/1.2}description")

                profiles.append(
                    {
                        "id": profile_id,
                        "title": (title_elem.text if title_elem is not None else profile_id),
                        "description": desc_elem.text if desc_elem is not None else "",
                    }
                )

            return profiles

        except Exception as e:
            logger.warning(f"Failed to extract profiles: {e}")
            # Return basic profile if parsing fails
            return [
                {
                    "id": "default",
                    "title": "Default Profile",
                    "description": "Default security profile",
                }
            ]

    def get_repository_status(self) -> Dict:
        """Get status of all repositories"""
        return {
            "repositories": [
                {
                    "id": repo.id,
                    "name": repo.name,
                    "type": repo.type,
                    "enabled": repo.enabled,
                    "last_sync": repo.last_sync.isoformat() if repo.last_sync else None,
                    "os_families": repo.os_families,
                }
                for repo in self.repositories.values()
            ],
            "sync_running": self.sync_running,
            "last_global_sync": (
                self.last_global_sync.isoformat() if self.last_global_sync else None
            ),
        }

    def enable_repository(self, repo_id: str, enabled: bool = True):
        """Enable or disable a repository"""
        if repo_id in self.repositories:
            self.repositories[repo_id].enabled = enabled
            logger.info(f"Repository {repo_id} {'enabled' if enabled else 'disabled'}")

    def add_custom_repository(self, config: RepositoryConfig):
        """Add a custom repository"""
        self.repositories[config.id] = config
        logger.info(f"Added custom repository: {config.name}")


# Global repository manager instance
scap_repository_manager = SCAPRepositoryManager()
