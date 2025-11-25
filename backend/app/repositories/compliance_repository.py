"""
Compliance Rule Repository
OW-REFACTOR-002: MongoDB Repository Pattern

Provides compliance-specific query methods for ComplianceRule collection.
Centralizes all compliance rule query logic in one place.
"""

import logging
from typing import Any, Dict, List, Optional

from ..models.mongo_models import ComplianceRule
from .base_repository import BaseRepository

logger = logging.getLogger(__name__)


class ComplianceRuleRepository(BaseRepository[ComplianceRule]):
    """
    Repository for ComplianceRule operations.

    Provides compliance-specific query methods:
    - Find by framework and version
    - Find by platform and version
    - Search by title or description
    - Filter by severity
    - Get statistics

    Example:
        repo = ComplianceRuleRepository()
        rules = await repo.find_by_framework("CIS", version="2.0.0")
    """

    def __init__(self):
        super().__init__(ComplianceRule)

    async def find_by_framework(self, framework: str, version: Optional[str] = None) -> List[ComplianceRule]:
        """
        Find rules by framework and optional version.

        Args:
            framework: Framework ID (e.g., "CIS", "NIST", "PCI_DSS")
            version: Optional framework version (e.g., "2.0.0")

        Returns:
            List of compliance rules for the framework

        Example:
            # All CIS rules
            rules = await repo.find_by_framework("CIS")

            # CIS 2.0.0 rules only
            rules = await repo.find_by_framework("CIS", version="2.0.0")
        """
        query = {f"frameworks.{framework}": {"$exists": True}}

        if version:
            query[f"frameworks.{framework}.versions.{version}"] = {"$exists": True}

        return await self.find_many(query)

    async def find_by_platform(self, platform: str, version: Optional[str] = None) -> List[ComplianceRule]:
        """
        Find rules by platform and optional version.

        Args:
            platform: Platform ID (e.g., "RHEL", "Ubuntu", "Windows")
            version: Optional platform version (e.g., "8", "22.04")

        Returns:
            List of compliance rules for the platform

        Example:
            # All RHEL rules
            rules = await repo.find_by_platform("RHEL")

            # RHEL 8 rules only
            rules = await repo.find_by_platform("RHEL", version="8")
        """
        query = {f"platforms.{platform}": {"$exists": True}}

        if version:
            query[f"platforms.{platform}.versions"] = version

        return await self.find_many(query)

    async def search_by_title(self, search_term: str, case_sensitive: bool = False) -> List[ComplianceRule]:
        """
        Search rules by title (supports regex).

        Args:
            search_term: Search term to find in title
            case_sensitive: Whether search is case-sensitive (default: False)

        Returns:
            List of matching compliance rules

        Example:
            # Case-insensitive search
            rules = await repo.search_by_title("password")

            # Case-sensitive search
            rules = await repo.search_by_title("SSH", case_sensitive=True)
        """
        options = "" if case_sensitive else "i"
        query = {"title": {"$regex": search_term, "$options": options}}
        return await self.find_many(query)

    async def search_by_description(self, search_term: str, case_sensitive: bool = False) -> List[ComplianceRule]:
        """
        Search rules by description (supports regex).

        Args:
            search_term: Search term to find in description
            case_sensitive: Whether search is case-sensitive (default: False)

        Returns:
            List of matching compliance rules

        Example:
            rules = await repo.search_by_description("authentication")
        """
        options = "" if case_sensitive else "i"
        query = {"description": {"$regex": search_term, "$options": options}}
        return await self.find_many(query)

    async def find_by_severity(self, severity: str) -> List[ComplianceRule]:
        """
        Find rules by severity level.

        Args:
            severity: Severity level ("critical", "high", "medium", "low")

        Returns:
            List of rules with specified severity

        Example:
            critical_rules = await repo.find_by_severity("critical")
        """
        query = {"severity": severity}
        return await self.find_many(query)

    async def find_by_rule_id(self, rule_id: str) -> Optional[ComplianceRule]:
        """
        Find rule by unique rule_id.

        Args:
            rule_id: Unique rule identifier

        Returns:
            ComplianceRule if found, None otherwise

        Example:
            rule = await repo.find_by_rule_id("xccdf_org.ssgproject.content_rule_accounts_password_minlen_login_defs")
        """
        query = {"rule_id": rule_id}
        return await self.find_one(query)

    async def find_by_multiple_frameworks(self, frameworks: List[str]) -> List[ComplianceRule]:
        """
        Find rules that apply to any of the specified frameworks.

        Args:
            frameworks: List of framework IDs

        Returns:
            List of rules matching any framework

        Example:
            rules = await repo.find_by_multiple_frameworks(["CIS", "NIST", "PCI_DSS"])
        """
        # Build OR query for multiple frameworks
        or_conditions = []
        for framework in frameworks:
            or_conditions.append({f"frameworks.{framework}": {"$exists": True}})

        query = {"$or": or_conditions}
        return await self.find_many(query)

    async def find_by_framework_and_platform(self, framework: str, platform: str) -> List[ComplianceRule]:
        """
        Find rules that apply to both a framework and platform.

        Args:
            framework: Framework ID
            platform: Platform ID

        Returns:
            List of rules matching both framework and platform

        Example:
            rules = await repo.find_by_framework_and_platform("CIS", "RHEL")
        """
        query = {
            f"frameworks.{framework}": {"$exists": True},
            f"platforms.{platform}": {"$exists": True},
        }
        return await self.find_many(query)

    async def get_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive statistics about compliance rules.

        Returns:
            Dictionary with statistics:
            - total_rules: Total number of rules
            - by_severity: Count by severity level
            - by_framework: Count by framework
            - by_platform: Count by platform

        Example:
            stats = await repo.get_statistics()
            print(f"Total rules: {stats['total_rules']}")
            print(f"Critical: {stats['by_severity']['critical']}")
        """
        try:
            # Get total count
            total = await self.count()

            # Count by severity
            severity_counts = {}
            for severity in ["critical", "high", "medium", "low", "unknown"]:
                count = await self.count({"severity": severity})
                if count > 0:
                    severity_counts[severity] = count

            # Count by framework using aggregation
            framework_pipeline = [
                {"$project": {"frameworks": {"$objectToArray": "$frameworks"}}},
                {"$unwind": "$frameworks"},
                {"$group": {"_id": "$frameworks.k", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
            ]
            framework_results = await self.aggregate(framework_pipeline)
            framework_counts = {item["_id"]: item["count"] for item in framework_results}

            # Count by platform using aggregation
            platform_pipeline = [
                {"$project": {"platforms": {"$objectToArray": "$platforms"}}},
                {"$unwind": "$platforms"},
                {"$group": {"_id": "$platforms.k", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
            ]
            platform_results = await self.aggregate(platform_pipeline)
            platform_counts = {item["_id"]: item["count"] for item in platform_results}

            return {
                "total_rules": total,
                "by_severity": severity_counts,
                "by_framework": framework_counts,
                "by_platform": platform_counts,
            }
        except Exception as e:
            logger.error(f"Error getting compliance statistics: {e}")
            raise

    async def get_framework_versions(self, framework: str) -> List[str]:
        """
        Get all available versions for a framework.

        Args:
            framework: Framework ID

        Returns:
            List of version strings

        Example:
            versions = await repo.get_framework_versions("CIS")
            # Returns: ["1.0.0", "2.0.0"]
        """
        try:
            pipeline = [
                {"$match": {f"frameworks.{framework}": {"$exists": True}}},
                {"$project": {"versions": {"$objectToArray": f"$frameworks.{framework}.versions"}}},
                {"$unwind": "$versions"},
                {"$group": {"_id": "$versions.k"}},
                {"$sort": {"_id": 1}},
            ]

            results = await self.aggregate(pipeline)
            return [item["_id"] for item in results]
        except Exception as e:
            logger.error(f"Error getting framework versions for {framework}: {e}")
            raise

    async def get_platform_versions(self, platform: str) -> List[str]:
        """
        Get all available versions for a platform.

        Args:
            platform: Platform ID

        Returns:
            List of version strings

        Example:
            versions = await repo.get_platform_versions("RHEL")
            # Returns: ["7", "8", "9"]
        """
        try:
            pipeline = [
                {"$match": {f"platforms.{platform}": {"$exists": True}}},
                {"$project": {"versions": f"$platforms.{platform}.versions"}},
                {"$unwind": "$versions"},
                {"$group": {"_id": "$versions"}},
                {"$sort": {"_id": 1}},
            ]

            results = await self.aggregate(pipeline)
            return [item["_id"] for item in results if item["_id"]]
        except Exception as e:
            logger.error(f"Error getting platform versions for {platform}: {e}")
            raise

    async def bulk_upsert(
        self, rules: List[ComplianceRule], batch_size: int = 100, progress_callback=None
    ) -> Dict[str, int]:
        """
        Bulk upsert compliance rules with deduplication.

        This method handles large-scale rule uploads (2000+ rules) efficiently by:
        1. Processing in batches to avoid memory issues
        2. Using rule_id for deduplication (upsert semantics)
        3. Tracking inserted vs updated vs skipped counts

        Args:
            rules: List of ComplianceRule objects to upsert
            batch_size: Number of rules to process per batch (default: 100)
            progress_callback: Optional callback function(processed, total, stats) for progress updates

        Returns:
            Dictionary with operation statistics:
            - inserted: Number of new rules created
            - updated: Number of existing rules updated
            - skipped: Number of rules that were unchanged
            - errors: Number of rules that failed

        Example:
            # Basic usage
            rules = [ComplianceRule(...), ComplianceRule(...)]
            result = await repo.bulk_upsert(rules, batch_size=100)
            # Returns: {"inserted": 1234, "updated": 567, "skipped": 89, "errors": 0}

            # With progress callback for CLI
            def progress(processed, total, stats):
                print(f"Progress: {processed}/{total} - {stats}")

            result = await repo.bulk_upsert(rules, batch_size=100, progress_callback=progress)
        """
        import time
        from datetime import datetime

        start_time = time.time()
        stats = {"inserted": 0, "updated": 0, "skipped": 0, "errors": 0}

        try:
            # Process in batches
            for i in range(0, len(rules), batch_size):
                batch = rules[i : i + batch_size]
                batch_start = time.time()

                for rule in batch:
                    try:
                        # Check if rule exists by rule_id
                        existing = await self.find_by_rule_id(rule.rule_id)

                        if existing:
                            # Update existing rule
                            # Compare source_hash to detect if content changed
                            if hasattr(rule, "source_hash") and hasattr(existing, "source_hash"):
                                if rule.source_hash == existing.source_hash:
                                    stats["skipped"] += 1
                                    continue

                            # Update the rule
                            update_data = rule.dict(exclude={"id"})
                            update_data["updated_at"] = datetime.utcnow()
                            await self.update_one(query={"rule_id": rule.rule_id}, update={"$set": update_data})
                            stats["updated"] += 1
                        else:
                            # Insert new rule
                            await self.create(rule)
                            stats["inserted"] += 1

                    except Exception as e:
                        logger.error(f"Error upserting rule {rule.rule_id}: {e}")
                        stats["errors"] += 1

                batch_duration = time.time() - batch_start
                logger.debug(f"Processed batch {i // batch_size + 1}: " f"{len(batch)} rules in {batch_duration:.2f}s")

                # Call progress callback if provided
                if progress_callback:
                    processed = min(i + batch_size, len(rules))
                    progress_callback(processed, len(rules), stats.copy())

            duration = time.time() - start_time
            logger.info(
                f"Bulk upsert complete: {stats['inserted']} inserted, "
                f"{stats['updated']} updated, {stats['skipped']} skipped, "
                f"{stats['errors']} errors in {duration:.2f}s"
            )

            # Warn on slow operations
            if duration > 10:
                logger.warning(f"Slow bulk upsert: {len(rules)} rules took {duration:.2f}s " f"(>{10}s threshold)")

            return stats

        except Exception as e:
            logger.error(f"Error in bulk_upsert: {e}")
            raise

    async def find_duplicates(self) -> List[Dict[str, Any]]:
        """
        Find duplicate rules based on rule_id.

        Returns:
            List of dictionaries containing duplicate information:
            - _id: The rule_id that has duplicates
            - count: Number of occurrences
            - rule_ids: List of MongoDB _id values for the duplicates

        Example:
            duplicates = await repo.find_duplicates()
            # Returns: [
            #   {"_id": "xccdf_rule_123", "count": 3, "ids": ["...", "...", "..."]},
            #   ...
            # ]
        """
        try:
            pipeline = [
                {"$group": {"_id": "$rule_id", "count": {"$sum": 1}, "ids": {"$push": "$_id"}}},
                {"$match": {"count": {"$gt": 1}}},
                {"$sort": {"count": -1}},
            ]

            results = await self.aggregate(pipeline)
            logger.info(f"Found {len(results)} duplicate rule_id values")
            return results

        except Exception as e:
            logger.error(f"Error finding duplicates: {e}")
            raise

    async def find_by_source_hash(self, source_hash: str) -> Optional[ComplianceRule]:
        """
        Find rule by content hash.

        This is used for deduplication during bulk uploads to detect if rule
        content has changed even if other metadata differs.

        Args:
            source_hash: SHA-256 hash of rule content

        Returns:
            ComplianceRule if found, None otherwise

        Example:
            rule = await repo.find_by_source_hash("sha256_hash_here")
        """
        query = {"source_hash": source_hash}
        return await self.find_one(query)

    async def update_by_id(self, rule_id: str, update_data: Dict[str, Any]) -> Optional[ComplianceRule]:
        """
        Update a rule by its MongoDB _id or rule_id.

        Args:
            rule_id: Either MongoDB ObjectId string or rule_id field value
            update_data: Dictionary of fields to update

        Returns:
            Updated ComplianceRule if found, None otherwise

        Example:
            updated = await repo.update_by_id(
                "xccdf_org.ssgproject.content_rule_...",
                {"severity": "critical", "updated_at": datetime.utcnow()}
            )
        """
        from datetime import datetime

        # Add updated_at timestamp
        update_data["updated_at"] = datetime.utcnow()

        # Try finding by rule_id first (more common)
        query = {"rule_id": rule_id}
        result = await self.update_one(query, {"$set": update_data})

        if result:
            return result

        # If not found, try MongoDB _id
        try:
            from bson import ObjectId

            if ObjectId.is_valid(rule_id):
                query = {"_id": ObjectId(rule_id)}
                return await self.update_one(query, {"$set": update_data})
        except Exception:
            pass

        return None

    async def delete_by_rule_id_pattern(self, pattern: str) -> int:
        """
        Delete rules matching a rule_id pattern.

        This is useful for removing all rules from a specific source or benchmark.

        Args:
            pattern: Regex pattern to match against rule_id field

        Returns:
            Number of rules deleted

        Example:
            # Delete all rules from RHEL 8 STIG
            deleted = await repo.delete_by_rule_id_pattern("xccdf_.*_rhel8_stig_.*")
            # Returns: 234
        """
        try:
            query = {"rule_id": {"$regex": pattern}}

            # Count before deletion
            count_before = await self.count(query)

            # Delete matching rules
            # Note: delete_many returns DeleteResult, we need count
            result = await self.model_class.find(query).delete()

            logger.info(
                f"Deleted {count_before} rules matching pattern '{pattern}' "
                f"(actual deleted: {result.deleted_count if hasattr(result, 'deleted_count') else 'unknown'})"
            )

            return count_before

        except Exception as e:
            logger.error(f"Error deleting rules by pattern '{pattern}': {e}")
            raise
