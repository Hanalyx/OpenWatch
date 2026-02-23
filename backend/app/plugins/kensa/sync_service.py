"""
Kensa Rule Sync Service

Synchronizes Kensa YAML rules to PostgreSQL for fast querying.
This replaces MongoDB rule storage as part of the MongoDB deprecation.

The sync process:
1. Loads all YAML rules from Kensa's rules directory
2. Computes file hashes for change detection
3. Upserts rules to kensa_rules table
4. Extracts framework mappings to framework_mappings table

Usage:
    from app.plugins.kensa.sync_service import KensaRuleSyncService

    sync_service = KensaRuleSyncService(db)
    result = await sync_service.sync_all_rules()
    print(f"Synced {result['rules_synced']} rules")
"""

import hashlib
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from sqlalchemy import text
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


def _get_rules_path() -> Path:
    """Get the Kensa rules path using runner.paths discovery."""
    try:
        from runner.paths import get_rules_path

        return Path(get_rules_path())
    except ImportError:
        logger.warning("runner.paths not available, cannot discover rules path")
        return Path("rules")


def _get_mappings_path() -> Optional[str]:
    """Get the Kensa mappings path using runner.paths discovery."""
    try:
        from runner.paths import get_mappings_path

        return str(get_mappings_path())
    except ImportError:
        logger.warning("runner.paths not available, cannot discover mappings path")
        return None


# Translate mapping IDs to framework_version strings used in DB.
# Must match the version keys in framework_mapper.py FRAMEWORKS dict.
MAPPING_VERSION_MAP = {
    "cis-rhel8-v4.0.0": "rhel8_v4",
    "cis-rhel9-v2.0.0": "rhel9_v2",
    "stig-rhel8-v2r6": "rhel8_v2r6",
    "stig-rhel9-v2r7": "rhel9_v2r7",
    "nist-800-53-r5": "r5",
    "pci-dss-v4.0": "v4",
    "fedramp-moderate": "moderate",
}


def _get_kensa_version() -> str:
    """Get the Kensa version from the installed package."""
    try:
        from runner.paths import get_version

        return get_version()
    except ImportError:
        return "unknown"


KENSA_VERSION = _get_kensa_version()


class KensaRuleSyncService:
    """
    Synchronizes Kensa YAML rules to PostgreSQL.

    This service:
    - Loads rules from Kensa's rules directory (discovered via runner.paths)
    - Upserts to kensa_rules table (PostgreSQL)
    - Extracts framework mappings
    - Tracks file hashes for incremental updates

    No MongoDB involved - PostgreSQL only.
    """

    def __init__(self, db: Session):
        """
        Initialize sync service.

        Args:
            db: SQLAlchemy database session.
        """
        self.db = db
        self.rules_path = _get_rules_path()

    def sync_all_rules(self, force: bool = False) -> Dict[str, Any]:
        """
        Sync all Kensa rules to PostgreSQL.

        Args:
            force: If True, sync all rules regardless of hash changes.

        Returns:
            Dict with sync statistics.
        """
        start_time = datetime.utcnow()
        stats = {
            "rules_found": 0,
            "rules_synced": 0,
            "rules_skipped": 0,
            "mappings_created": 0,
            "errors": [],
        }

        # Load all YAML rules
        rules = self._load_all_rules()
        stats["rules_found"] = len(rules)

        for rule_data in rules:
            try:
                # Compute file hash
                file_hash = rule_data.get("_file_hash")
                rule_id = rule_data.get("id")

                if not force:
                    # Check if rule already exists with same hash
                    existing = self._get_existing_rule(rule_id)
                    if existing and existing.get("file_hash") == file_hash:
                        stats["rules_skipped"] += 1
                        continue

                # Upsert rule to kensa_rules
                self._upsert_rule(rule_data)
                stats["rules_synced"] += 1

                # Extract and insert framework mappings
                mappings_count = self._sync_framework_mappings(rule_data)
                stats["mappings_created"] += mappings_count

            except Exception as e:
                logger.error("Failed to sync rule %s: %s", rule_data.get("id"), e)
                stats["errors"].append(
                    {
                        "rule_id": rule_data.get("id"),
                        "error": str(e),
                    }
                )

        # Sync mapping files (additive — fills gaps left by inline refs)
        mapping_file_count = self._sync_mapping_files()
        stats["mapping_file_mappings"] = mapping_file_count

        # Commit all changes
        self.db.commit()

        stats["duration_ms"] = int((datetime.utcnow() - start_time).total_seconds() * 1000)
        logger.info(
            "Kensa rule sync complete: %d synced, %d skipped, " "%d inline mappings, %d mapping file mappings",
            stats["rules_synced"],
            stats["rules_skipped"],
            stats["mappings_created"],
            stats["mapping_file_mappings"],
        )

        return stats

    def _load_all_rules(self) -> List[Dict[str, Any]]:
        """Load all YAML rules from the rules directory."""
        rules = []

        if not self.rules_path.exists():
            logger.warning("Kensa rules path not found: %s", self.rules_path)
            return rules

        for yaml_file in self.rules_path.rglob("*.yml"):
            try:
                rule_data = self._load_rule_file(yaml_file)
                if rule_data:
                    rules.append(rule_data)
            except Exception as e:
                logger.warning("Failed to load rule %s: %s", yaml_file, e)

        return rules

    def _load_rule_file(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """Load a single YAML rule file."""
        with open(file_path, "r") as f:
            content = f.read()

        # Compute hash for change detection
        file_hash = hashlib.sha256(content.encode()).hexdigest()

        rule_data = yaml.safe_load(content)
        if not rule_data or not rule_data.get("id"):
            return None

        # Add metadata
        rule_data["_file_path"] = str(file_path.relative_to(self.rules_path.parent))
        rule_data["_file_hash"] = file_hash

        return rule_data

    def _get_existing_rule(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """Get existing rule from database by rule_id."""
        query = text(
            """
            SELECT rule_id, file_hash
            FROM kensa_rules
            WHERE rule_id = :rule_id
        """
        )
        result = self.db.execute(query, {"rule_id": rule_id}).fetchone()

        if result:
            return {"rule_id": result[0], "file_hash": result[1]}
        return None

    def _upsert_rule(self, rule_data: Dict[str, Any]) -> None:
        """Upsert a rule to the kensa_rules table."""
        import json

        query = text(
            """
            INSERT INTO kensa_rules (
                rule_id, title, description, rationale, severity, category,
                tags, platforms, "references", implementations,
                kensa_version, file_path, file_hash, created_at, updated_at
            )
            VALUES (
                :rule_id, :title, :description, :rationale, :severity, :category,
                :tags, :platforms, :references, :implementations,
                :kensa_version, :file_path, :file_hash, NOW(), NOW()
            )
            ON CONFLICT (rule_id) DO UPDATE SET
                title = EXCLUDED.title,
                description = EXCLUDED.description,
                rationale = EXCLUDED.rationale,
                severity = EXCLUDED.severity,
                category = EXCLUDED.category,
                tags = EXCLUDED.tags,
                platforms = EXCLUDED.platforms,
                "references" = EXCLUDED."references",
                implementations = EXCLUDED.implementations,
                kensa_version = EXCLUDED.kensa_version,
                file_path = EXCLUDED.file_path,
                file_hash = EXCLUDED.file_hash,
                updated_at = NOW()
        """
        )

        self.db.execute(
            query,
            {
                "rule_id": rule_data.get("id"),
                "title": rule_data.get("title", ""),
                "description": rule_data.get("description", ""),
                "rationale": rule_data.get("rationale", ""),
                "severity": rule_data.get("severity", "medium"),
                "category": rule_data.get("category", ""),
                "tags": json.dumps(rule_data.get("tags", [])),
                "platforms": json.dumps(rule_data.get("platforms", [])),
                "references": json.dumps(rule_data.get("references", {})),
                "implementations": json.dumps(rule_data.get("implementations", [])),
                "kensa_version": KENSA_VERSION,
                "file_path": rule_data.get("_file_path"),
                "file_hash": rule_data.get("_file_hash"),
            },
        )

    def _sync_framework_mappings(self, rule_data: Dict[str, Any]) -> int:
        """
        Extract and sync framework mappings from a rule.

        Returns the number of mappings created.
        """
        rule_id = rule_data.get("id")
        references = rule_data.get("references", {})
        mappings_count = 0

        # Delete existing mappings for this rule
        delete_query = text(
            """
            DELETE FROM framework_mappings
            WHERE kensa_rule_id = :rule_id
        """
        )
        self.db.execute(delete_query, {"rule_id": rule_id})

        # Process CIS mappings
        cis_refs = references.get("cis", {})
        for version, mapping in cis_refs.items():
            self._insert_cis_mapping(rule_id, version, mapping)
            mappings_count += 1

        # Process STIG mappings
        stig_refs = references.get("stig", {})
        for version, mapping in stig_refs.items():
            self._insert_stig_mapping(rule_id, version, mapping)
            mappings_count += 1

        # Process NIST 800-53 mappings
        nist_refs = references.get("nist_800_53", [])
        if nist_refs:
            for control_id in nist_refs:
                self._insert_nist_mapping(rule_id, control_id)
                mappings_count += 1

        # Process PCI-DSS mappings
        pci_refs = references.get("pci_dss_4", [])
        if pci_refs:
            for control_id in pci_refs:
                self._insert_simple_mapping(rule_id, "pci_dss", "v4", control_id)
                mappings_count += 1

        # Process SRG mappings
        srg_refs = references.get("srg", [])
        if srg_refs:
            for control_id in srg_refs:
                self._insert_simple_mapping(rule_id, "srg", None, control_id)
                mappings_count += 1

        return mappings_count

    def _sync_mapping_files(self) -> int:
        """
        Sync framework mappings from Kensa mapping files.

        Mapping files are the authoritative source for framework coverage.
        They supplement inline rule references which are sparse for PCI/NIST/FedRAMP.

        Uses ON CONFLICT DO NOTHING so inline refs (already inserted per-rule)
        take priority and mapping file data fills gaps.

        Returns:
            Number of mapping rows inserted from mapping files.
        """
        mappings_path = _get_mappings_path()
        if not mappings_path:
            logger.info("Kensa mappings path not available, skipping mapping file sync")
            return 0

        try:
            from runner.mappings import load_all_mappings
        except ImportError:
            logger.warning("runner.mappings not available, skipping mapping file sync")
            return 0

        try:
            all_mappings = load_all_mappings(mappings_path)
        except Exception as e:
            logger.error("Failed to load Kensa mapping files: %s", e)
            return 0

        count = 0
        for mapping_id, framework_mapping in all_mappings.items():
            framework = framework_mapping.framework
            version = MAPPING_VERSION_MAP.get(mapping_id)
            if version is None:
                logger.warning(
                    "Unknown mapping ID %s (framework=%s), skipping",
                    mapping_id,
                    framework,
                )
                continue

            for control_id, entry in framework_mapping.sections.items():
                rule_ids = entry.metadata.get("rules", [])
                title = entry.title or ""

                for rule_id in rule_ids:
                    try:
                        count += self._insert_mapping_file_entry(
                            framework=framework,
                            version=version,
                            control_id=control_id,
                            control_title=title,
                            rule_id=rule_id,
                            entry=entry,
                        )
                    except Exception as e:
                        logger.debug(
                            "Mapping file insert failed for %s/%s/%s: %s",
                            framework,
                            control_id,
                            rule_id,
                            e,
                        )

        logger.info(
            "Mapping file sync: loaded %d mapping files, inserted %d rows",
            len(all_mappings),
            count,
        )
        return count

    def _insert_mapping_file_entry(
        self,
        framework: str,
        version: str,
        control_id: str,
        control_title: str,
        rule_id: str,
        entry: Any,
    ) -> int:
        """
        Insert a single mapping file entry with ON CONFLICT DO NOTHING.

        Populates framework-specific columns (CIS, STIG) from entry metadata.

        Returns:
            1 if inserted, 0 if conflict (already exists from inline refs).
        """
        metadata = entry.metadata or {}

        # Build framework-specific column values
        cis_section = None
        cis_level = None
        cis_type = None
        severity = None

        if framework == "cis":
            cis_section = control_id
            cis_level = metadata.get("level")
            cis_type = metadata.get("type")
        elif framework == "stig":
            severity = metadata.get("severity")

        query = text(
            """
            INSERT INTO framework_mappings (
                framework, framework_version, control_id, control_title,
                cis_section, cis_level, cis_type, severity,
                kensa_rule_id, created_at
            )
            VALUES (
                :framework, :version, :control_id, :control_title,
                :cis_section, :cis_level, :cis_type, :severity,
                :rule_id, NOW()
            )
            ON CONFLICT (framework, framework_version, control_id, kensa_rule_id)
            DO NOTHING
        """
        )

        result = self.db.execute(
            query,
            {
                "framework": framework,
                "version": version,
                "control_id": control_id,
                "control_title": control_title,
                "cis_section": cis_section,
                "cis_level": cis_level,
                "cis_type": cis_type,
                "severity": severity,
                "rule_id": rule_id,
            },
        )

        return result.rowcount

    def _insert_cis_mapping(self, rule_id: str, version: str, mapping: Dict[str, Any]) -> None:
        """Insert a CIS framework mapping."""
        query = text(
            """
            INSERT INTO framework_mappings (
                framework, framework_version, control_id, cis_section,
                cis_level, cis_type, kensa_rule_id, created_at
            )
            VALUES (
                'cis', :version, :control_id, :section,
                :level, :cis_type, :rule_id, NOW()
            )
        """
        )

        section = mapping.get("section", "")
        self.db.execute(
            query,
            {
                "version": version,
                "control_id": section,
                "section": section,
                "level": mapping.get("level"),
                "cis_type": mapping.get("type"),
                "rule_id": rule_id,
            },
        )

    def _insert_stig_mapping(self, rule_id: str, version: str, mapping: Dict[str, Any]) -> None:
        """Insert a STIG framework mapping."""
        import json

        query = text(
            """
            INSERT INTO framework_mappings (
                framework, framework_version, control_id, stig_id,
                vuln_id, cci, severity, kensa_rule_id, created_at
            )
            VALUES (
                'stig', :version, :control_id, :stig_id,
                :vuln_id, :cci, :severity, :rule_id, NOW()
            )
        """
        )

        stig_id = mapping.get("stig_id", "")
        self.db.execute(
            query,
            {
                "version": version,
                "control_id": stig_id,
                "stig_id": stig_id,
                "vuln_id": mapping.get("vuln_id"),
                "cci": json.dumps(mapping.get("cci", [])),
                "severity": mapping.get("severity"),
                "rule_id": rule_id,
            },
        )

    def _insert_nist_mapping(self, rule_id: str, control_id: str) -> None:
        """Insert a NIST 800-53 framework mapping."""
        query = text(
            """
            INSERT INTO framework_mappings (
                framework, framework_version, control_id, kensa_rule_id, created_at
            )
            VALUES ('nist_800_53', 'r5', :control_id, :rule_id, NOW())
        """
        )

        self.db.execute(
            query,
            {
                "control_id": control_id,
                "rule_id": rule_id,
            },
        )

    def _insert_simple_mapping(self, rule_id: str, framework: str, version: Optional[str], control_id: str) -> None:
        """Insert a simple framework mapping (PCI-DSS, SRG, etc.)."""
        query = text(
            """
            INSERT INTO framework_mappings (
                framework, framework_version, control_id, kensa_rule_id, created_at
            )
            VALUES (:framework, :version, :control_id, :rule_id, NOW())
        """
        )

        self.db.execute(
            query,
            {
                "framework": framework,
                "version": version,
                "control_id": control_id,
                "rule_id": rule_id,
            },
        )

    def get_sync_stats(self) -> Dict[str, Any]:
        """Get current sync statistics from the database."""
        rules_query = text("SELECT COUNT(*) FROM kensa_rules")
        mappings_query = text("SELECT COUNT(*) FROM framework_mappings")
        frameworks_query = text(
            """
            SELECT framework, COUNT(*) as count
            FROM framework_mappings
            GROUP BY framework
        """
        )

        rules_count = self.db.execute(rules_query).scalar()
        mappings_count = self.db.execute(mappings_query).scalar()
        frameworks = self.db.execute(frameworks_query).fetchall()

        return {
            "total_rules": rules_count,
            "total_mappings": mappings_count,
            "frameworks": {row[0]: row[1] for row in frameworks},
            "kensa_version": KENSA_VERSION,
        }


__all__ = ["KensaRuleSyncService", "KENSA_VERSION"]
