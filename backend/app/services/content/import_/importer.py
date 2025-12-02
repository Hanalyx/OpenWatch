"""
Content Importer for OpenWatch

This module provides bulk import services for importing transformed compliance
rules into MongoDB. It handles:
- Batched import for large rule sets
- Progress tracking with callbacks
- Deduplication strategies (skip, update, replace)
- Rule intelligence generation
- Import integrity validation

Security Considerations:
- Uses repository pattern for database access
- Input validation on all rule data
- Audit logging for all import operations

Usage:
    from backend.app.services.content.import import ContentImporter

    importer = ContentImporter(mongo_service)
    result = await importer.import_rules(
        rules=transformed_rules,
        deduplication_strategy="update_existing",
        batch_size=100,
    )
    print(f"Imported: {result.imported_count}, Updated: {result.updated_count}")
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Awaitable, Callable, Dict, List, Optional

from backend.app.models.mongo_models import ComplianceRule, RuleIntelligence
from backend.app.repositories import ComplianceRuleRepository

from ..exceptions import ContentImportError  # noqa: F401

logger = logging.getLogger(__name__)


@dataclass
class ImportProgress:
    """
    Progress tracking for bulk import operations.

    Provides real-time progress information during long-running imports,
    including estimated time remaining and error tracking.

    Attributes:
        total_rules: Total number of rules to import
        processed_rules: Number of rules processed so far
        imported_rules: Number of new rules imported
        updated_rules: Number of existing rules updated
        skipped_rules: Number of rules skipped (duplicates)
        error_count: Number of rules that failed import
        start_time: When the import started
        current_phase: Current import phase description
        current_rule: Current rule being processed
        errors: List of error details
        warnings: List of warning messages
    """

    total_rules: int = 0
    processed_rules: int = 0
    imported_rules: int = 0
    updated_rules: int = 0
    skipped_rules: int = 0
    error_count: int = 0
    start_time: datetime = field(default_factory=datetime.utcnow)
    current_phase: str = "initializing"
    current_rule: str = ""
    errors: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def update(
        self,
        processed: int = 0,
        imported: int = 0,
        updated: int = 0,
        skipped: int = 0,
        errors: int = 0,
        phase: Optional[str] = None,
        current_rule: Optional[str] = None,
    ) -> None:
        """
        Update progress counters.

        Args:
            processed: Number of rules processed in this update
            imported: Number of rules imported in this update
            updated: Number of rules updated in this update
            skipped: Number of rules skipped in this update
            errors: Number of errors in this update
            phase: New phase description
            current_rule: Current rule identifier
        """
        if processed > 0:
            self.processed_rules += processed
        if imported > 0:
            self.imported_rules += imported
        if updated > 0:
            self.updated_rules += updated
        if skipped > 0:
            self.skipped_rules += skipped
        if errors > 0:
            self.error_count += errors
        if phase:
            self.current_phase = phase
        if current_rule:
            self.current_rule = current_rule

    @property
    def progress_percent(self) -> float:
        """Calculate progress as a percentage."""
        if self.total_rules == 0:
            return 0.0
        return (self.processed_rules / self.total_rules) * 100.0

    @property
    def elapsed_seconds(self) -> float:
        """Calculate elapsed time since start."""
        return (datetime.utcnow() - self.start_time).total_seconds()

    @property
    def estimated_remaining_seconds(self) -> float:
        """Estimate remaining time based on current rate."""
        if self.processed_rules == 0:
            return 0.0

        rate = self.processed_rules / self.elapsed_seconds
        remaining_rules = self.total_rules - self.processed_rules

        return remaining_rules / rate if rate > 0 else 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert progress to dictionary for JSON serialization."""
        return {
            "total_rules": self.total_rules,
            "processed_rules": self.processed_rules,
            "imported_rules": self.imported_rules,
            "updated_rules": self.updated_rules,
            "skipped_rules": self.skipped_rules,
            "error_count": self.error_count,
            "progress_percentage": self.progress_percent,
            "current_phase": self.current_phase,
            "current_rule": self.current_rule,
            "elapsed_seconds": self.elapsed_seconds,
            "estimated_remaining": self.estimated_remaining_seconds,
            "errors": self.errors[-10:],  # Last 10 errors
            "warnings": self.warnings[-10:],  # Last 10 warnings
        }


@dataclass
class ImportResult:
    """
    Result of an import operation.

    Contains statistics and details about the import outcome.

    Attributes:
        status: Overall status (completed, failed)
        imported_count: Number of new rules imported
        updated_count: Number of existing rules updated
        skipped_count: Number of rules skipped
        error_count: Number of rules that failed
        errors: List of error details
        warnings: List of warning messages
        start_time: When the import started
        end_time: When the import completed
        source_file: Source file path (if applicable)
    """

    status: str = "pending"
    imported_count: int = 0
    updated_count: int = 0
    skipped_count: int = 0
    error_count: int = 0
    errors: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    start_time: datetime = field(default_factory=datetime.utcnow)
    end_time: Optional[datetime] = None
    source_file: str = ""

    @property
    def total_processed(self) -> int:
        """Total number of rules processed."""
        return self.imported_count + self.updated_count + self.skipped_count + self.error_count

    @property
    def success_rate(self) -> float:
        """Calculate success rate as percentage."""
        if self.total_processed == 0:
            return 0.0
        successful = self.imported_count + self.updated_count
        return (successful / self.total_processed) * 100.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary for JSON serialization."""
        return {
            "status": self.status,
            "imported_count": self.imported_count,
            "updated_count": self.updated_count,
            "skipped_count": self.skipped_count,
            "error_count": self.error_count,
            "total_processed": self.total_processed,
            "success_rate": self.success_rate,
            "errors": self.errors,
            "warnings": self.warnings,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "source_file": self.source_file,
        }


# Type alias for progress callback
ProgressCallback = Callable[[Dict[str, Any]], Awaitable[None]]


class ContentImporter:
    """
    Service for importing compliance rules into MongoDB.

    Handles bulk import with progress tracking, batching, and deduplication.
    Supports multiple deduplication strategies:
    - skip_existing: Skip rules that already exist
    - update_existing: Update existing rules with new data
    - replace_all: Delete and recreate existing rules

    Attributes:
        progress: Current import progress (if import in progress)

    Example:
        >>> importer = ContentImporter()
        >>> result = await importer.import_rules(
        ...     rules=transformed_rules,
        ...     deduplication_strategy="update_existing",
        ...     batch_size=100,
        ... )
        >>> print(f"Imported {result.imported_count} rules")
    """

    def __init__(self) -> None:
        """Initialize the content importer."""
        self.progress: Optional[ImportProgress] = None
        self._repository = ComplianceRuleRepository()

    async def import_rules(
        self,
        rules: List[Dict[str, Any]],
        deduplication_strategy: str = "skip_existing",
        batch_size: int = 100,
        progress_callback: Optional[ProgressCallback] = None,
        source_file: str = "",
    ) -> ImportResult:
        """
        Import rules into MongoDB.

        Args:
            rules: List of rule dictionaries (from transformer)
            deduplication_strategy: How to handle duplicates:
                - "skip_existing": Skip rules that exist
                - "update_existing": Update existing rules
                - "replace_all": Replace existing rules
            batch_size: Number of rules per batch
            progress_callback: Optional async callback for progress updates
            source_file: Source file path for tracking

        Returns:
            ImportResult with statistics and error details.

        Raises:
            ContentImportError: If import fails critically.
        """
        logger.info(
            "Starting import of %d rules (strategy: %s, batch_size: %d)",
            len(rules),
            deduplication_strategy,
            batch_size,
        )

        result = ImportResult(
            status="running",
            source_file=source_file,
        )

        try:
            # Initialize progress tracking
            self.progress = ImportProgress(total_rules=len(rules))
            self.progress.update(phase="importing")

            if progress_callback:
                await progress_callback(self.progress.to_dict())

            # Process rules in batches
            import_stats = await self._import_batched(
                rules=rules,
                deduplication_strategy=deduplication_strategy,
                batch_size=batch_size,
                progress_callback=progress_callback,
            )

            # Update result
            result.imported_count = import_stats["imported"]
            result.updated_count = import_stats["updated"]
            result.skipped_count = import_stats["skipped"]
            result.error_count = import_stats["errors"]
            result.errors = self.progress.errors.copy()
            result.warnings = self.progress.warnings.copy()
            result.status = "completed"
            result.end_time = datetime.utcnow()

            logger.info(
                "Import completed: imported=%d, updated=%d, skipped=%d, errors=%d",
                result.imported_count,
                result.updated_count,
                result.skipped_count,
                result.error_count,
            )

        except Exception as e:
            logger.error("Import failed: %s", str(e))
            result.status = "failed"
            result.errors.append({"type": "import_error", "message": str(e)})
            result.end_time = datetime.utcnow()

        return result

    async def _import_batched(
        self,
        rules: List[Dict[str, Any]],
        deduplication_strategy: str,
        batch_size: int,
        progress_callback: Optional[ProgressCallback],
    ) -> Dict[str, int]:
        """
        Import rules in batches with progress tracking.

        Args:
            rules: List of rules to import
            deduplication_strategy: How to handle duplicates
            batch_size: Number of rules per batch
            progress_callback: Optional progress callback

        Returns:
            Dictionary with import statistics.
        """
        stats = {"imported": 0, "updated": 0, "skipped": 0, "errors": 0}

        total_batches = (len(rules) + batch_size - 1) // batch_size

        for batch_num, i in enumerate(range(0, len(rules), batch_size)):
            batch = rules[i : i + batch_size]
            batch_stats = await self._process_batch(batch, deduplication_strategy)

            # Update statistics
            for key in stats:
                stats[key] += batch_stats[key]

            # Update progress
            if self.progress:
                self.progress.update(
                    processed=len(batch),
                    imported=batch_stats["imported"],
                    updated=batch_stats["updated"],
                    skipped=batch_stats["skipped"],
                    errors=batch_stats["errors"],
                    current_rule=f"Batch {batch_num + 1} of {total_batches}",
                )

                if progress_callback:
                    await progress_callback(self.progress.to_dict())

            logger.debug(
                "Processed batch %d/%d: %s",
                batch_num + 1,
                total_batches,
                batch_stats,
            )

        return stats

    async def _process_batch(
        self,
        batch: List[Dict[str, Any]],
        deduplication_strategy: str,
    ) -> Dict[str, int]:
        """
        Process a single batch of rules.

        Args:
            batch: List of rules in this batch
            deduplication_strategy: How to handle duplicates

        Returns:
            Dictionary with batch statistics.
        """
        stats = {"imported": 0, "updated": 0, "skipped": 0, "errors": 0}

        for rule_data in batch:
            try:
                result = await self._import_single_rule(
                    rule_data,
                    deduplication_strategy,
                )
                stats[result] += 1

            except Exception as e:
                rule_id = rule_data.get("rule_id", "unknown")
                logger.error("Failed to import rule %s: %s", rule_id, str(e))
                stats["errors"] += 1

                if self.progress:
                    self.progress.errors.append(
                        {
                            "rule_id": rule_id,
                            "error": str(e),
                        }
                    )

        return stats

    async def _import_single_rule(
        self,
        rule_data: Dict[str, Any],
        deduplication_strategy: str,
    ) -> str:
        """
        Import a single rule with deduplication.

        Args:
            rule_data: Rule data dictionary
            deduplication_strategy: How to handle if rule exists

        Returns:
            Result string: "imported", "updated", or "skipped"
        """
        rule_id = rule_data["rule_id"]

        # Check if rule exists
        existing_rule = await self._repository.find_one({"rule_id": rule_id})

        if existing_rule:
            if deduplication_strategy == "skip_existing":
                return "skipped"

            elif deduplication_strategy == "update_existing":
                await self._update_existing_rule(existing_rule, rule_data)
                return "updated"

            elif deduplication_strategy == "replace_all":
                await existing_rule.delete()
                await self._create_new_rule(rule_data)
                return "updated"

            else:
                # Unknown strategy, default to skip
                return "skipped"
        else:
            await self._create_new_rule(rule_data)
            return "imported"

    async def _create_new_rule(self, rule_data: Dict[str, Any]) -> None:
        """
        Create a new compliance rule.

        Args:
            rule_data: Rule data dictionary
        """
        rule = ComplianceRule(**rule_data)
        await rule.insert()

        # Create basic rule intelligence
        await self._create_rule_intelligence(rule_data)

    async def _update_existing_rule(
        self,
        existing_rule: ComplianceRule,
        rule_data: Dict[str, Any],
    ) -> None:
        """
        Update an existing compliance rule.

        Args:
            existing_rule: Existing rule document
            rule_data: New rule data
        """
        # Update fields that should be refreshed
        existing_rule.metadata = rule_data["metadata"]
        existing_rule.frameworks = rule_data["frameworks"]
        existing_rule.platform_implementations = rule_data["platform_implementations"]
        existing_rule.check_content = rule_data["check_content"]
        existing_rule.fix_content = rule_data["fix_content"]
        existing_rule.updated_at = datetime.utcnow()
        existing_rule.version = rule_data.get("version", "1.0.0")

        await existing_rule.replace()

    async def _create_rule_intelligence(self, rule_data: Dict[str, Any]) -> None:
        """
        Create basic rule intelligence record.

        Args:
            rule_data: Rule data dictionary
        """
        # Check if intelligence already exists
        existing_intel = await RuleIntelligence.find_one(
            RuleIntelligence.rule_id == rule_data["rule_id"]
        )

        if existing_intel:
            return  # Skip if already exists

        intelligence = RuleIntelligence(
            rule_id=rule_data["rule_id"],
            business_impact=self._generate_business_impact(rule_data),
            compliance_importance=self._assess_compliance_importance(rule_data),
            implementation_notes=rule_data.get("metadata", {}).get(
                "rationale",
                "No specific implementation notes available",
            ),
            testing_guidance=f"Verify the rule '{rule_data.get('metadata', {}).get('name', 'unknown')}' is properly configured",
            scan_duration_avg_ms=self._estimate_scan_duration(rule_data),
            resource_impact=rule_data.get("remediation_risk", "low"),
        )

        await intelligence.insert()

    def _generate_business_impact(self, rule_data: Dict[str, Any]) -> str:
        """Generate business impact description."""
        severity = rule_data.get("severity", "medium")
        category = rule_data.get("category", "system")

        impact_templates = {
            "critical": f"Critical {category} vulnerability that could lead to complete system compromise",
            "high": f"High-risk {category} issue that significantly impacts security posture",
            "medium": f"Moderate {category} concern that should be addressed to improve security",
            "low": f"Minor {category} improvement that enhances overall security baseline",
            "info": f"Informational {category} check that provides compliance visibility",
        }

        return impact_templates.get(
            severity,
            f"Standard {category} security configuration requirement",
        )

    def _assess_compliance_importance(self, rule_data: Dict[str, Any]) -> int:
        """Assess compliance importance on 1-10 scale."""
        severity = rule_data.get("severity", "medium")
        frameworks = rule_data.get("frameworks", {})

        # Base score from severity
        severity_scores = {
            "critical": 10,
            "high": 8,
            "medium": 5,
            "low": 3,
            "info": 1,
        }

        score = severity_scores.get(severity, 5)

        # Boost score if rule maps to multiple frameworks
        framework_count = sum(1 for fw in frameworks.values() if fw)
        if framework_count >= 3:
            score = min(10, score + 2)
        elif framework_count >= 2:
            score = min(10, score + 1)

        return score

    def _estimate_scan_duration(self, rule_data: Dict[str, Any]) -> int:
        """Estimate scan duration in milliseconds."""
        check_type = rule_data.get("check_type", "command")

        duration_map = {
            "file": 50,
            "command": 100,
            "service": 75,
            "package": 150,
            "script": 200,
            "oval": 300,
            "kernel": 100,
        }

        return duration_map.get(check_type, 100)

    async def get_import_status(self) -> Optional[Dict[str, Any]]:
        """
        Get current import progress status.

        Returns:
            Progress dictionary or None if no import in progress.
        """
        if not self.progress:
            return None
        return self.progress.to_dict()

    async def validate_import_integrity(
        self,
        source_hash: str,
    ) -> Dict[str, Any]:
        """
        Validate the integrity of imported rules.

        Args:
            source_hash: Hash of the source file

        Returns:
            Validation report dictionary.
        """
        # Count rules from this source
        rule_count = await self._repository.count({"source_hash": source_hash})

        # Get sample rules
        sample_rules = await self._repository.find_many(
            {"source_hash": source_hash},
            limit=5,
        )

        return {
            "source_hash": source_hash,
            "imported_rule_count": rule_count,
            "sample_rules": [
                {
                    "rule_id": rule.rule_id,
                    "name": rule.metadata.get("name", "unknown"),
                    "severity": rule.severity,
                    "category": rule.category,
                }
                for rule in sample_rules
            ],
            "validated_at": datetime.utcnow().isoformat(),
        }

    async def list_imported_files(self) -> List[Dict[str, Any]]:
        """
        List previously imported SCAP files.

        Uses MongoDB aggregation to group rules by source file and provides
        statistics about each imported file.

        Returns:
            List of file information dictionaries with:
            - source_file: Path to the source file
            - source_hash: SHA-256 hash of the source content
            - rule_count: Number of rules from this file
            - last_imported: Timestamp of most recent import
            - categories: List of rule categories
            - severities: List of severity levels
        """
        pipeline = [
            {
                "$group": {
                    "_id": {
                        "source_file": "$source_file",
                        "source_hash": "$source_hash",
                    },
                    "rule_count": {"$sum": 1},
                    "last_imported": {"$max": "$imported_at"},
                    "categories": {"$addToSet": "$category"},
                    "severities": {"$addToSet": "$severity"},
                }
            },
            {"$sort": {"last_imported": -1}},
        ]

        collection = ComplianceRule.get_motor_collection()
        cursor = collection.aggregate(pipeline)
        results = await cursor.to_list(length=None)

        files: List[Dict[str, Any]] = []
        for result in results:
            files.append(
                {
                    "source_file": result["_id"]["source_file"],
                    "source_hash": result["_id"]["source_hash"],
                    "rule_count": result["rule_count"],
                    "last_imported": result["last_imported"],
                    "categories": result["categories"],
                    "severities": result["severities"],
                }
            )

        return files

    async def validate_import_integrity_by_path(
        self,
        file_path: str,
        file_hash: str,
    ) -> Dict[str, Any]:
        """
        Validate the integrity of an imported SCAP file by path.

        Args:
            file_path: Path to the source file
            file_hash: SHA-256 hash of the file

        Returns:
            Validation report dictionary.
        """
        # Count rules from this file
        rule_count = await self._repository.count({"source_hash": file_hash})

        # Get sample rules
        sample_rules = await self._repository.find_many(
            {"source_hash": file_hash},
            limit=5,
        )

        return {
            "file_path": file_path,
            "file_hash": file_hash,
            "imported_rule_count": rule_count,
            "sample_rules": [
                {
                    "rule_id": rule.rule_id,
                    "name": rule.metadata.get("name", "unknown"),
                    "severity": rule.severity,
                    "category": rule.category,
                }
                for rule in sample_rules
            ],
            "validated_at": datetime.utcnow().isoformat(),
        }
