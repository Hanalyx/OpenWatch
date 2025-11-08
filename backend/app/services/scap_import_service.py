"""
SCAP Import Service for OpenWatch
Handles bulk import of SCAP rules into MongoDB with progress tracking and deduplication
"""

import asyncio
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, List, Optional

from backend.app.models.mongo_models import ComplianceRule, RemediationScript, RuleIntelligence
from backend.app.repositories import ComplianceRuleRepository
from backend.app.services.mongo_integration_service import MongoIntegrationService
from backend.app.services.scap_parser_service import SCAPParserService
from backend.app.services.scap_transformation_service import SCAPTransformationService

logger = logging.getLogger(__name__)


class ImportProgress:
    """Progress tracking for SCAP imports"""

    def __init__(self, total_rules: int):
        self.total_rules = total_rules
        self.processed_rules = 0
        self.imported_rules = 0
        self.updated_rules = 0
        self.skipped_rules = 0
        self.error_count = 0
        self.start_time = datetime.utcnow()
        self.current_phase = "initializing"
        self.current_rule = ""
        self.errors = []
        self.warnings = []

    def update(
        self,
        processed: int = 0,
        imported: int = 0,
        updated: int = 0,
        skipped: int = 0,
        errors: int = 0,
        phase: str = None,
        current_rule: str = None,
    ):
        """Update progress counters"""
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

    def get_status(self) -> Dict[str, Any]:
        """Get current status"""
        elapsed = (datetime.utcnow() - self.start_time).total_seconds()

        return {
            "total_rules": self.total_rules,
            "processed_rules": self.processed_rules,
            "imported_rules": self.imported_rules,
            "updated_rules": self.updated_rules,
            "skipped_rules": self.skipped_rules,
            "error_count": self.error_count,
            "progress_percentage": (
                (self.processed_rules / self.total_rules * 100) if self.total_rules > 0 else 0
            ),
            "current_phase": self.current_phase,
            "current_rule": self.current_rule,
            "elapsed_seconds": elapsed,
            "estimated_remaining": self._estimate_remaining(elapsed),
            "errors": self.errors[-10:],  # Last 10 errors
            "warnings": self.warnings[-10:],  # Last 10 warnings
        }

    def _estimate_remaining(self, elapsed: float) -> float:
        """Estimate remaining time"""
        if self.processed_rules == 0:
            return 0

        rate = self.processed_rules / elapsed
        remaining_rules = self.total_rules - self.processed_rules

        return remaining_rules / rate if rate > 0 else 0


class SCAPImportService:
    """Service for importing SCAP files into MongoDB"""

    def __init__(self, mongo_service: MongoIntegrationService):
        self.mongo_service = mongo_service
        self.parser = SCAPParserService()
        self.transformer = SCAPTransformationService()
        self.progress = None

    async def import_scap_file(
        self,
        file_path: str,
        progress_callback: Optional[callable] = None,
        deduplication_strategy: str = "skip_existing",
        batch_size: int = 100,
    ) -> Dict[str, Any]:
        """
        Import a SCAP file into MongoDB

        Args:
            file_path: Path to SCAP XML file
            progress_callback: Optional callback for progress updates
            deduplication_strategy: "skip_existing", "update_existing", or "replace_all"
            batch_size: Number of rules to process in each batch
        """
        logger.info(f"Starting SCAP import: {file_path}")

        result = {
            "file_path": file_path,
            "start_time": datetime.utcnow().isoformat(),
            "status": "running",
            "statistics": {},
            "errors": [],
            "warnings": [],
        }

        try:
            # Phase 1: Parse SCAP file
            logger.info("Phase 1: Parsing SCAP file")
            parsed_scap = self.parser.parse_scap_file(file_path)

            if parsed_scap["errors"]:
                result["errors"].extend(parsed_scap["errors"])
                logger.error(f"SCAP parsing failed with {len(parsed_scap['errors'])} errors")
                result["status"] = "failed"
                return result

            # Initialize progress tracking
            total_rules = len(parsed_scap["rules"])
            self.progress = ImportProgress(total_rules)

            if progress_callback:
                await progress_callback(self.progress.get_status())

            # Phase 2: Transform rules
            logger.info(f"Phase 2: Transforming {total_rules} rules")
            self.progress.update(phase="transforming")

            transformed_rules = self.transformer.transform_rules(parsed_scap)

            if self.transformer.errors:
                result["errors"].extend(self.transformer.errors)
                logger.warning(
                    f"Transformation completed with {len(self.transformer.errors)} errors"
                )

            # Phase 3: Import rules in batches
            logger.info(
                f"Phase 3: Importing {len(transformed_rules)} rules in batches of {batch_size}"
            )
            self.progress.update(phase="importing")

            import_stats = await self._import_rules_batched(
                transformed_rules, deduplication_strategy, batch_size, progress_callback
            )

            # Final statistics
            result["statistics"] = {
                "total_parsed": total_rules,
                "total_transformed": len(transformed_rules),
                "imported": import_stats["imported"],
                "updated": import_stats["updated"],
                "skipped": import_stats["skipped"],
                "errors": import_stats["errors"],
            }

            result["status"] = "completed"
            result["end_time"] = datetime.utcnow().isoformat()

            logger.info(f"SCAP import completed successfully: {result['statistics']}")

        except Exception as e:
            logger.error(f"SCAP import failed: {str(e)}")
            result["status"] = "failed"
            result["errors"].append({"type": "import_error", "message": str(e)})
            result["end_time"] = datetime.utcnow().isoformat()

        return result

    async def _import_rules_batched(
        self,
        rules: List[Dict[str, Any]],
        deduplication_strategy: str,
        batch_size: int,
        progress_callback: Optional[callable] = None,
    ) -> Dict[str, int]:
        """Import rules in batches with progress tracking"""
        stats = {"imported": 0, "updated": 0, "skipped": 0, "errors": 0}

        # Process rules in batches
        for i in range(0, len(rules), batch_size):
            batch = rules[i : i + batch_size]
            batch_stats = await self._process_rule_batch(batch, deduplication_strategy)

            # Update statistics
            for key in stats:
                stats[key] += batch_stats[key]

            # Update progress
            self.progress.update(
                processed=len(batch),
                imported=batch_stats["imported"],
                updated=batch_stats["updated"],
                skipped=batch_stats["skipped"],
                errors=batch_stats["errors"],
                current_rule=f"Batch {i//batch_size + 1} of {(len(rules) + batch_size - 1)//batch_size}",
            )

            # Call progress callback
            if progress_callback:
                await progress_callback(self.progress.get_status())

            logger.info(f"Processed batch {i//batch_size + 1}: {batch_stats}")

        return stats

    async def _process_rule_batch(
        self, batch: List[Dict[str, Any]], deduplication_strategy: str
    ) -> Dict[str, int]:
        """Process a single batch of rules"""
        stats = {"imported": 0, "updated": 0, "skipped": 0, "errors": 0}

        for rule_data in batch:
            try:
                result = await self._import_single_rule(rule_data, deduplication_strategy)
                stats[result] += 1

            except Exception as e:
                logger.error(f"Failed to import rule {rule_data.get('rule_id')}: {str(e)}")
                stats["errors"] += 1
                self.progress.errors.append({"rule_id": rule_data.get("rule_id"), "error": str(e)})

        return stats

    async def _import_single_rule(
        self, rule_data: Dict[str, Any], deduplication_strategy: str
    ) -> str:
        """
        Import a single rule with deduplication

        Returns: 'imported', 'updated', 'skipped', or 'error'
        """
        rule_id = rule_data["rule_id"]

        # Check if rule already exists
        # OW-REFACTOR-002: Repository Pattern (MANDATORY)
        repo = ComplianceRuleRepository()
        existing_rule = await repo.find_one({"rule_id": rule_id})

        if existing_rule:
            if deduplication_strategy == "skip_existing":
                return "skipped"
            elif deduplication_strategy == "update_existing":
                # Update existing rule
                await self._update_existing_rule(existing_rule, rule_data)
                return "updated"
            elif deduplication_strategy == "replace_all":
                # Delete and recreate
                await existing_rule.delete()
                await self._create_new_rule(rule_data)
                return "updated"
        else:
            # Create new rule
            await self._create_new_rule(rule_data)
            return "imported"

    async def _create_new_rule(self, rule_data: Dict[str, Any]):
        """Create a new compliance rule"""
        rule = ComplianceRule(**rule_data)
        await rule.insert()

        # Create basic rule intelligence
        await self._create_rule_intelligence(rule_data)

    async def _update_existing_rule(self, existing_rule: ComplianceRule, rule_data: Dict[str, Any]):
        """Update an existing compliance rule"""
        # Update fields that should be refreshed
        existing_rule.metadata = rule_data["metadata"]
        existing_rule.frameworks = rule_data["frameworks"]
        existing_rule.platform_implementations = rule_data["platform_implementations"]
        existing_rule.check_content = rule_data["check_content"]
        existing_rule.fix_content = rule_data["fix_content"]
        existing_rule.updated_at = datetime.utcnow()
        existing_rule.version = rule_data.get("version", "1.0.0")

        await existing_rule.replace()

    async def _create_rule_intelligence(self, rule_data: Dict[str, Any]):
        """Create basic rule intelligence record"""
        # Check if intelligence already exists
        existing_intel = await RuleIntelligence.find_one(
            RuleIntelligence.rule_id == rule_data["rule_id"]
        )

        if existing_intel:
            return  # Skip if already exists

        # Create basic intelligence
        intelligence = RuleIntelligence(
            rule_id=rule_data["rule_id"],
            business_impact=self._generate_business_impact(rule_data),
            compliance_importance=self._assess_compliance_importance(rule_data),
            implementation_notes=rule_data["metadata"].get(
                "rationale", "No specific implementation notes available"
            ),
            testing_guidance=f"Verify the rule '{rule_data['metadata']['name']}' is properly configured",
            scan_duration_avg_ms=self._estimate_scan_duration(rule_data),
            resource_impact=rule_data.get("remediation_risk", "low"),
        )

        await intelligence.insert()

    def _generate_business_impact(self, rule_data: Dict[str, Any]) -> str:
        """Generate business impact description"""
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
            severity, f"Standard {category} security configuration requirement"
        )

    def _assess_compliance_importance(self, rule_data: Dict[str, Any]) -> int:
        """Assess compliance importance (1-10 scale)"""
        severity = rule_data.get("severity", "medium")
        frameworks = rule_data.get("frameworks", {})

        # Base score from severity
        severity_scores = {"critical": 10, "high": 8, "medium": 5, "low": 3, "info": 1}

        score = severity_scores.get(severity, 5)

        # Boost score if rule maps to multiple frameworks
        framework_count = sum(1 for fw in frameworks.values() if fw)
        if framework_count >= 3:
            score = min(10, score + 2)
        elif framework_count >= 2:
            score = min(10, score + 1)

        return score

    def _estimate_scan_duration(self, rule_data: Dict[str, Any]) -> int:
        """Estimate scan duration in milliseconds"""
        check_type = rule_data.get("check_type", "command")

        # Estimates based on check type
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
        """Get current import progress status"""
        if not self.progress:
            return None

        return self.progress.get_status()

    async def list_imported_files(self) -> List[Dict[str, Any]]:
        """List previously imported SCAP files"""
        # Get unique source files from the database
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

        files = []
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

    async def validate_import_integrity(self, file_path: str) -> Dict[str, Any]:
        """Validate the integrity of an imported SCAP file"""
        file_hash = self.parser._calculate_file_hash(file_path)

        # Count rules from this file
        # OW-REFACTOR-002: Repository Pattern (MANDATORY)
        repo = ComplianceRuleRepository()
        rule_count = await repo.count({"source_hash": file_hash})

        # Get sample rules
        sample_rules = await repo.find_many({"source_hash": file_hash}, limit=5)

        return {
            "file_path": file_path,
            "file_hash": file_hash,
            "imported_rule_count": rule_count,
            "sample_rules": [
                {
                    "rule_id": rule.rule_id,
                    "name": rule.metadata["name"],
                    "severity": rule.severity,
                    "category": rule.category,
                }
                for rule in sample_rules
            ],
            "validated_at": datetime.utcnow().isoformat(),
        }
