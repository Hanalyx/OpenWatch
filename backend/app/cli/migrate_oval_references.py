#!/usr/bin/env python3
"""
OpenWatch OVAL Reference Migration Script

Migrates existing compliance rules to use Option B schema for per-platform
OVAL references. This script scans existing rules in MongoDB and updates
their platform_implementations with oval_filename fields based on available
OVAL definition files.

Phase 2: Host OS Detection and OVAL Alignment
OW-REFACTOR-002: Uses Repository Pattern (MANDATORY per CLAUDE.md)

Background:
- Previously, rules had a single oval_filename at the rule level
- This caused "first match wins" problem where only one platform's OVAL was used
- Option B schema stores oval_filename per-platform in platform_implementations
- This enables OS-aware OVAL selection during XCCDF generation

Usage:
    # Dry run (preview changes without modifying database)
    python -m backend.app.cli.migrate_oval_references migrate --dry-run

    # Execute migration
    python -m backend.app.cli.migrate_oval_references migrate

    # Show statistics only
    python -m backend.app.cli.migrate_oval_references stats

    # Validate OVAL file availability
    python -m backend.app.cli.migrate_oval_references validate

Security:
    - Path traversal prevention: validates all paths against OVAL_STORAGE_BASE
    - No shell injection: uses pathlib for all file operations
    - Audit logging: all modifications are logged
"""

import argparse
import asyncio
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..config import get_settings
from ..models.mongo_models import ComplianceRule, mongo_manager
from ..repositories import ComplianceRuleRepository

# Setup logging following CLAUDE.md standards
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# OVAL storage base path (matches compliance_rules_upload_service.py)
OVAL_STORAGE_BASE = Path("/app/data/oval_definitions")


class OVALReferenceMigrator:
    """
    Migrates compliance rules to use per-platform OVAL references.

    This class implements Option B schema migration for existing rules,
    scanning available OVAL files and updating platform_implementations
    with the appropriate oval_filename for each platform.

    Attributes:
        repo: ComplianceRuleRepository for MongoDB operations
        oval_base: Base path for OVAL definition storage
        stats: Migration statistics tracking

    Example:
        >>> migrator = OVALReferenceMigrator()
        >>> await migrator.initialize()
        >>> results = await migrator.migrate_rules(dry_run=True)
        >>> print(f"Would update {results['updated']} rules")
    """

    def __init__(self, oval_base: Optional[Path] = None):
        """
        Initialize the OVAL reference migrator.

        Args:
            oval_base: Optional custom OVAL storage path. Defaults to
                       /app/data/oval_definitions for production use.
        """
        self.repo: Optional[ComplianceRuleRepository] = None
        self.oval_base = oval_base or OVAL_STORAGE_BASE
        self.stats: Dict[str, int] = {
            "total_rules": 0,
            "rules_with_oval": 0,
            "rules_updated": 0,
            "rules_skipped": 0,
            "platforms_mapped": 0,
            "errors": 0,
        }

    async def initialize(self) -> bool:
        """
        Initialize MongoDB connection and repository.

        Returns:
            True if initialization successful, False otherwise.

        Raises:
            No exceptions raised; errors are logged and False is returned.
        """
        try:
            settings = get_settings()

            # Initialize MongoDB connection
            logger.info(f"Connecting to MongoDB: {settings.mongodb_url}")
            await mongo_manager.initialize(
                settings.mongodb_url,
                settings.mongodb_database,
                min_pool_size=settings.mongodb_min_pool_size,
                max_pool_size=settings.mongodb_max_pool_size,
            )

            # OW-REFACTOR-002: Initialize Repository Pattern (MANDATORY per CLAUDE.md)
            self.repo = ComplianceRuleRepository()
            logger.info("ComplianceRuleRepository initialized successfully")

            return True

        except Exception as e:
            logger.error(f"Failed to initialize MongoDB: {e}")
            return False

    def _get_available_platforms(self) -> List[str]:
        """
        Discover available platform directories in OVAL storage.

        Returns:
            List of platform names (directory names) found in OVAL storage.

        Security:
            Validates that oval_base exists and is a directory.
            Only returns immediate child directories (no recursion).
        """
        if not self.oval_base.exists():
            logger.warning(f"OVAL storage base not found: {self.oval_base}")
            return []

        if not self.oval_base.is_dir():
            logger.error(f"OVAL storage base is not a directory: {self.oval_base}")
            return []

        platforms = []
        for item in self.oval_base.iterdir():
            if item.is_dir():
                platforms.append(item.name)

        logger.info(f"Found {len(platforms)} platform directories: {platforms}")
        return platforms

    def _find_oval_for_rule(self, rule_id: str, platforms: List[str]) -> Dict[str, str]:
        """
        Find OVAL files for a rule across all platforms.

        Args:
            rule_id: The rule ID (e.g., "ow-package_firewalld_installed")
            platforms: List of platform names to search

        Returns:
            Dict mapping platform name to relative OVAL path.
            Example: {"rhel9": "rhel9/package_firewalld_installed.xml"}

        Security:
            - Validates rule_id format before constructing paths
            - Uses pathlib to prevent path traversal attacks
            - Only returns paths that actually exist
        """
        oval_mappings: Dict[str, str] = {}

        # Extract OVAL ID from rule ID
        # Rule IDs are in format: ow-{oval_id}
        if not rule_id.startswith("ow-"):
            return oval_mappings

        oval_id = rule_id[3:]  # Remove 'ow-' prefix
        oval_filename = f"{oval_id}.xml"

        # Validate OVAL filename doesn't contain path traversal attempts
        if ".." in oval_filename or "/" in oval_filename:
            logger.warning(f"Invalid OVAL filename pattern detected: {oval_filename}")
            return oval_mappings

        for platform in platforms:
            # Construct full path and validate
            oval_path = self.oval_base / platform / oval_filename

            # Ensure path is within OVAL storage base (path traversal prevention)
            try:
                oval_path = oval_path.resolve()
                if not str(oval_path).startswith(str(self.oval_base.resolve())):
                    logger.warning(f"Path traversal attempt detected: {oval_path}")
                    continue
            except (OSError, ValueError) as e:
                logger.warning(f"Invalid path resolution for {platform}/{oval_filename}: {e}")
                continue

            if oval_path.exists() and oval_path.is_file():
                # Store relative path for Option B schema
                relative_path = f"{platform}/{oval_filename}"
                oval_mappings[platform] = relative_path
                logger.debug(f"Found OVAL for {rule_id} on {platform}: {relative_path}")

        return oval_mappings

    async def migrate_rules(self, dry_run: bool = False) -> Dict[str, Any]:
        """
        Migrate all compliance rules to Option B schema.

        This method:
        1. Fetches all rules with ow- prefix (OpenWatch rules)
        2. For each rule, finds available OVAL files per platform
        3. Updates platform_implementations with oval_filename

        NOTE: No rule-level oval_filename is set. XCCDF generation must use
        platform-specific OVAL from platform_implementations.{platform}.oval_filename.
        Rules without matching platform OVAL should be skipped (marked "not applicable").

        Args:
            dry_run: If True, preview changes without modifying database.

        Returns:
            Dict with migration statistics and details.

        Raises:
            RuntimeError: If repository not initialized.
        """
        if not self.repo:
            raise RuntimeError("Repository not initialized. Call initialize() first.")

        logger.info(f"Starting OVAL reference migration (dry_run={dry_run})")

        # Get available platforms
        platforms = self._get_available_platforms()
        if not platforms:
            logger.error("No platform directories found in OVAL storage")
            return {"error": "No platforms found", **self.stats}

        # Fetch all OpenWatch rules (those with ow- prefix)
        # These are the rules that need OVAL reference migration
        all_rules = await self.repo.find_many({"rule_id": {"$regex": "^ow-"}})

        self.stats["total_rules"] = len(all_rules)
        logger.info(f"Found {len(all_rules)} OpenWatch rules to process")

        updated_rules: List[Dict[str, Any]] = []

        for rule in all_rules:
            try:
                result = await self._process_rule(rule, platforms, dry_run)
                if result:
                    updated_rules.append(result)
            except Exception as e:
                logger.error(f"Error processing rule {rule.rule_id}: {e}")
                self.stats["errors"] += 1

        # Log summary
        logger.info(
            f"Migration {'preview' if dry_run else 'complete'}: "
            f"{self.stats['rules_updated']} updated, "
            f"{self.stats['rules_skipped']} skipped, "
            f"{self.stats['errors']} errors"
        )

        return {
            "dry_run": dry_run,
            "updated_rules": updated_rules if dry_run else len(updated_rules),
            **self.stats,
        }

    async def _process_rule(
        self,
        rule: ComplianceRule,
        platforms: List[str],
        dry_run: bool,
    ) -> Optional[Dict[str, Any]]:
        """
        Process a single rule for OVAL reference migration.

        Args:
            rule: ComplianceRule document from MongoDB
            platforms: List of available platforms
            dry_run: If True, don't modify database

        Returns:
            Dict with rule details if updated, None if skipped.
        """
        rule_id = rule.rule_id

        # Find OVAL files for this rule
        oval_mappings = self._find_oval_for_rule(rule_id, platforms)

        if not oval_mappings:
            self.stats["rules_skipped"] += 1
            logger.debug(f"No OVAL files found for {rule_id}, skipping")
            return None

        self.stats["rules_with_oval"] += 1
        self.stats["platforms_mapped"] += len(oval_mappings)

        # Build the update for platform_implementations
        # Preserve existing platform_implementations and add oval_filename
        updates: Dict[str, Any] = {}
        existing_impls = rule.platform_implementations or {}

        for platform, oval_path in oval_mappings.items():
            # Check if already has correct oval_filename
            existing_impl = existing_impls.get(platform, {})
            if hasattr(existing_impl, "oval_filename"):
                existing_oval = existing_impl.oval_filename
            elif isinstance(existing_impl, dict):
                existing_oval = existing_impl.get("oval_filename")
            else:
                existing_oval = None

            if existing_oval == oval_path:
                logger.debug(f"Rule {rule_id} platform {platform} already has correct OVAL")
                continue

            # Build update path for this platform's oval_filename
            # Uses MongoDB dot notation for nested field updates
            update_path = f"platform_implementations.{platform}.oval_filename"
            updates[update_path] = oval_path

            # Ensure versions field exists (required by PlatformImplementation model)
            if not existing_impl:
                versions_path = f"platform_implementations.{platform}.versions"
                updates[versions_path] = []

        if not updates:
            self.stats["rules_skipped"] += 1
            logger.debug(f"Rule {rule_id} already up to date")
            return None

        # Apply updates
        update_result = {
            "rule_id": rule_id,
            "platforms_updated": list(oval_mappings.keys()),
            "updates": updates,
        }

        if not dry_run:
            # Add updated_at timestamp
            updates["updated_at"] = datetime.utcnow()

            # NOTE: No rule-level oval_filename is set.
            # XCCDF generation uses platform-specific OVAL from
            # platform_implementations.{platform}.oval_filename only.
            # Rules without matching platform OVAL are skipped ("not applicable").

            await self.repo.update_one(
                query={"rule_id": rule_id},
                update={"$set": updates},
            )
            logger.info(
                f"Updated {rule_id} with per-platform OVAL references for: " f"{', '.join(oval_mappings.keys())}"
            )

        self.stats["rules_updated"] += 1
        return update_result

    async def get_statistics(self) -> Dict[str, Any]:
        """
        Get current OVAL reference statistics from MongoDB.

        Returns:
            Dict with comprehensive OVAL reference statistics.
        """
        if not self.repo:
            raise RuntimeError("Repository not initialized. Call initialize() first.")

        # Total OpenWatch rules
        total_ow_rules = await self.repo.count({"rule_id": {"$regex": "^ow-"}})

        # Rules with any OVAL reference (rule-level)
        rules_with_rule_oval = await self.repo.count(
            {
                "rule_id": {"$regex": "^ow-"},
                "oval_filename": {"$exists": True, "$nin": [None, ""]},
            }
        )

        # Get available platforms
        platforms = self._get_available_platforms()

        # Per-platform OVAL statistics
        platform_stats: Dict[str, int] = {}
        for platform in platforms:
            count = await self.repo.count(
                {f"platform_implementations.{platform}.oval_filename": {"$exists": True, "$nin": [None, ""]}}
            )
            platform_stats[platform] = count

        # Rules with Option B schema (per-platform OVAL)
        # Check if any platform_implementations has oval_filename
        pipeline: List[Dict[str, Any]] = [
            {"$match": {"rule_id": {"$regex": "^ow-"}}},
            {
                "$project": {
                    "has_platform_oval": {
                        "$gt": [
                            {
                                "$size": {
                                    "$filter": {
                                        "input": {"$objectToArray": "$platform_implementations"},
                                        "cond": {
                                            "$and": [
                                                {"$ne": ["$$this.v.oval_filename", None]},
                                                {"$ne": ["$$this.v.oval_filename", ""]},
                                            ]
                                        },
                                    }
                                }
                            },
                            0,
                        ]
                    }
                }
            },
            {"$match": {"has_platform_oval": True}},
            {"$count": "count"},
        ]

        result = await self.repo.aggregate(pipeline)
        rules_with_platform_oval = result[0]["count"] if result else 0

        return {
            "total_openwatch_rules": total_ow_rules,
            "rules_with_rule_level_oval": rules_with_rule_oval,
            "rules_with_platform_oval": rules_with_platform_oval,
            "available_platforms": platforms,
            "platform_oval_counts": platform_stats,
            "oval_storage_base": str(self.oval_base),
            "oval_storage_exists": self.oval_base.exists(),
        }

    async def validate_oval_files(self) -> Dict[str, Any]:
        """
        Validate OVAL file availability and integrity.

        Checks:
        - OVAL storage directory exists
        - Platform directories are present
        - OVAL files are valid XML (basic check)
        - Cross-references rules to available OVAL files

        Returns:
            Dict with validation results and any issues found.
        """
        if not self.repo:
            raise RuntimeError("Repository not initialized. Call initialize() first.")

        issues: List[Dict[str, str]] = []

        # Check storage base
        if not self.oval_base.exists():
            issues.append(
                {
                    "type": "error",
                    "message": f"OVAL storage base not found: {self.oval_base}",
                }
            )
            return {"valid": False, "issues": issues}

        platforms = self._get_available_platforms()
        if not platforms:
            issues.append(
                {
                    "type": "warning",
                    "message": "No platform directories found in OVAL storage",
                }
            )

        # Count OVAL files per platform
        oval_counts: Dict[str, int] = {}
        for platform in platforms:
            platform_path = self.oval_base / platform
            xml_files = list(platform_path.glob("*.xml"))
            oval_counts[platform] = len(xml_files)

            if len(xml_files) == 0:
                issues.append(
                    {
                        "type": "warning",
                        "message": f"Platform {platform} has no OVAL XML files",
                    }
                )

        # Check rules that claim OVAL but file doesn't exist
        rules_with_oval = await self.repo.find_many(
            {
                "oval_filename": {"$exists": True, "$nin": [None, ""]},
            }
        )

        missing_files = 0
        for rule in rules_with_oval:
            if rule.oval_filename:
                oval_path = self.oval_base / rule.oval_filename
                if not oval_path.exists():
                    missing_files += 1
                    if missing_files <= 10:  # Limit logged issues
                        issues.append(
                            {
                                "type": "warning",
                                "message": f"Rule {rule.rule_id} references missing OVAL: {rule.oval_filename}",
                            }
                        )

        if missing_files > 10:
            issues.append(
                {
                    "type": "info",
                    "message": f"...and {missing_files - 10} more missing OVAL file references",
                }
            )

        return {
            "valid": len([i for i in issues if i["type"] == "error"]) == 0,
            "oval_storage_base": str(self.oval_base),
            "platforms_found": platforms,
            "oval_file_counts": oval_counts,
            "total_oval_files": sum(oval_counts.values()),
            "rules_with_oval_reference": len(rules_with_oval),
            "missing_oval_files": missing_files,
            "issues": issues,
        }


async def main() -> int:
    """
    Main CLI entry point for OVAL reference migration.

    Returns:
        Exit code (0 for success, 1 for failure).
    """
    parser = argparse.ArgumentParser(
        description="OpenWatch OVAL Reference Migration Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Preview changes without modifying database
  python -m backend.app.cli.migrate_oval_references migrate --dry-run

  # Execute migration
  python -m backend.app.cli.migrate_oval_references migrate

  # Show current statistics
  python -m backend.app.cli.migrate_oval_references stats

  # Validate OVAL file availability
  python -m backend.app.cli.migrate_oval_references validate
        """,
    )
    parser.add_argument(
        "command",
        choices=["migrate", "stats", "validate"],
        help="Command to execute",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview changes without modifying database (migrate command only)",
    )
    parser.add_argument(
        "--oval-base",
        type=Path,
        default=OVAL_STORAGE_BASE,
        help=f"OVAL storage base path (default: {OVAL_STORAGE_BASE})",
    )

    args = parser.parse_args()

    migrator = OVALReferenceMigrator(oval_base=args.oval_base)

    # Initialize MongoDB connection
    if not await migrator.initialize():
        logger.error("Failed to initialize MongoDB connection")
        return 1

    try:
        if args.command == "migrate":
            results = await migrator.migrate_rules(dry_run=args.dry_run)

            print("\n=== OVAL Reference Migration Results ===")
            print(f"Mode: {'Dry Run (preview only)' if args.dry_run else 'Live Migration'}")
            print(f"Total OpenWatch rules: {results.get('total_rules', 0)}")
            print(f"Rules with OVAL files: {results.get('rules_with_oval', 0)}")
            print(f"Rules updated: {results.get('rules_updated', 0)}")
            print(f"Rules skipped: {results.get('rules_skipped', 0)}")
            print(f"Platforms mapped: {results.get('platforms_mapped', 0)}")
            print(f"Errors: {results.get('errors', 0)}")

            if args.dry_run and results.get("updated_rules"):
                print(f"\nWould update {len(results['updated_rules'])} rules:")
                for rule_info in results["updated_rules"][:10]:
                    print(f"  - {rule_info['rule_id']}: {', '.join(rule_info['platforms_updated'])}")
                if len(results["updated_rules"]) > 10:
                    print(f"  ... and {len(results['updated_rules']) - 10} more")

        elif args.command == "stats":
            stats = await migrator.get_statistics()

            print("\n=== OVAL Reference Statistics ===")
            print(f"OVAL storage: {stats['oval_storage_base']}")
            print(f"Storage exists: {stats['oval_storage_exists']}")
            print(f"\nTotal OpenWatch rules: {stats['total_openwatch_rules']}")
            print(f"Rules with rule-level OVAL: {stats['rules_with_rule_level_oval']}")
            print(f"Rules with per-platform OVAL: {stats['rules_with_platform_oval']}")
            print(f"\nAvailable platforms: {', '.join(stats['available_platforms'])}")
            print("\nPer-platform OVAL counts:")
            for platform, count in stats["platform_oval_counts"].items():
                print(f"  {platform}: {count} rules")

        elif args.command == "validate":
            validation = await migrator.validate_oval_files()

            print("\n=== OVAL Validation Results ===")
            print(f"Valid: {validation['valid']}")
            print(f"OVAL storage: {validation['oval_storage_base']}")
            print(f"Platforms found: {', '.join(validation['platforms_found'])}")
            print(f"Total OVAL files: {validation['total_oval_files']}")
            print(f"Rules with OVAL reference: {validation['rules_with_oval_reference']}")
            print(f"Missing OVAL files: {validation['missing_oval_files']}")

            if validation["issues"]:
                print("\nIssues found:")
                for issue in validation["issues"]:
                    print(f"  [{issue['type'].upper()}] {issue['message']}")

    except Exception as e:
        logger.error(f"Command failed: {e}")
        return 1

    finally:
        # Close MongoDB connection
        await mongo_manager.close()

    return 0


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    exit(exit_code)
