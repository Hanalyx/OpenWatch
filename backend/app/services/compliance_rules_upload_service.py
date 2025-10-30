"""
Compliance Rules Upload Service
Main orchestrator for uploading compliance rule archives with BSON support,
smart deduplication, dependency-aware updates, and immutable versioning
"""
import uuid
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
import logging

from ..models.mongo_models import ComplianceRule, RuleIntelligence, UploadHistory
from .compliance_rules_bson_parser import BSONParserService
from .compliance_rules_security_service import ComplianceRulesSecurityService
from .compliance_rules_deduplication_service import (
    SmartDeduplicationService,
    DeduplicationStrategy
)
from .compliance_rules_dependency_service import (
    RuleDependencyGraph,
    InheritanceResolver
)
from .compliance_rules_versioning_service import RuleVersioningService

logger = logging.getLogger(__name__)


class ComplianceRulesUploadService:
    """
    Main orchestrator for compliance rules upload process

    Coordinates:
    - Security validation
    - BSON/JSON parsing
    - Dependency validation
    - Smart deduplication
    - Inheritance resolution
    - MongoDB import
    """

    def __init__(self):
        self.security_service = ComplianceRulesSecurityService()
        self.parser_service = BSONParserService()
        self.deduplication_service = SmartDeduplicationService()
        self.dependency_graph = RuleDependencyGraph()
        self.inheritance_resolver = None  # Initialized after graph is built
        self.versioning_service = RuleVersioningService()  # Immutable versioning

        self.upload_id = None
        self.current_phase = "initializing"
        self.progress = {
            'phase': 'initializing',
            'processed_rules': 0,
            'total_rules': 0,
            'percent_complete': 0
        }

    async def upload_rules_archive(
        self,
        archive_data: bytes,
        archive_filename: str,
        deduplication_strategy: str = DeduplicationStrategy.SKIP_UNCHANGED_UPDATE_CHANGED,
        user_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Main upload workflow

        Args:
            archive_data: Raw tar.gz archive bytes
            archive_filename: Original filename
            deduplication_strategy: How to handle duplicates
            user_id: User performing upload

        Returns:
            Detailed upload result with statistics and impact analysis
        """
        # Generate upload ID
        self.upload_id = str(uuid.uuid4())
        start_time = datetime.utcnow()

        logger.info(f"Starting upload {self.upload_id}: {archive_filename}")

        result = {
            'upload_id': self.upload_id,
            'filename': archive_filename,
            'start_time': start_time.isoformat(),
            'user_id': user_id,
            'success': False,
            'phase': 'initializing',
            'statistics': {},
            'security_validation': {},
            'dependency_validation': {},
            'inheritance_impact': {},
            'errors': [],
            'warnings': []
        }

        extracted_path = None

        try:
            # Phase 1: Security Validation
            logger.info(f"[{self.upload_id}] Phase 1: Security validation")
            self.current_phase = "security_validation"
            result['phase'] = 'security_validation'

            is_valid, security_checks, extracted_path = await self.security_service.validate_archive(
                archive_data
            )

            result['security_validation'] = self.security_service.get_security_summary(security_checks)
            result['file_hash'] = self.security_service.calculate_archive_hash(archive_data)

            if not is_valid:
                result['errors'].append({
                    'phase': 'security_validation',
                    'message': 'Security validation failed',
                    'details': [c.to_dict() for c in security_checks if not c.passed]
                })
                logger.error(f"[{self.upload_id}] Security validation failed")
                return result

            logger.info(f"[{self.upload_id}] Security validation passed")

            # Phase 2: Parse Archive
            logger.info(f"[{self.upload_id}] Phase 2: Parsing archive")
            self.current_phase = "parsing"
            result['phase'] = 'parsing'

            # Parse manifest
            manifest_bson = extracted_path / "manifest.bson"
            manifest_json = extracted_path / "manifest.json"

            if manifest_bson.exists():
                manifest = await self.parser_service.parse_manifest_bson(manifest_bson)
            elif manifest_json.exists():
                manifest = await self.parser_service.parse_manifest_json(manifest_json)
            else:
                raise ValueError("No manifest file found")

            result['manifest'] = {
                'name': manifest['name'],
                'version': manifest['version'],
                'rules_count': manifest['rules_count'],
                'created_at': manifest['created_at'].isoformat() if isinstance(manifest['created_at'], datetime) else manifest['created_at']
            }

            # Parse all rule files
            new_rules = await self.parser_service.parse_all_rule_files(
                extracted_path,
                max_rules=self.security_service.MAX_RULES_COUNT
            )

            parsing_stats = self.parser_service.get_parsing_statistics()
            if parsing_stats['parsing_errors']:
                result['warnings'].extend(parsing_stats['parsing_errors'])

            logger.info(
                f"[{self.upload_id}] Parsed {len(new_rules)} rules "
                f"({parsing_stats['parsing_errors_count']} errors)"
            )

            self.progress['total_rules'] = len(new_rules)

            # Phase 3: Dependency Validation
            logger.info(f"[{self.upload_id}] Phase 3: Dependency validation")
            self.current_phase = "dependency_validation"
            result['phase'] = 'dependency_validation'

            # Build dependency graph from existing DB rules
            await self.dependency_graph.build_from_database()

            # Validate new rules' dependencies
            dependency_validation = self.dependency_graph.validate_dependencies(
                new_rules,
                check_existing_db=True
            )

            result['dependency_validation'] = dependency_validation

            if not dependency_validation['valid']:
                result['errors'].append({
                    'phase': 'dependency_validation',
                    'message': 'Dependency validation failed',
                    'details': dependency_validation['errors']
                })
                logger.error(f"[{self.upload_id}] Dependency validation failed")
                return result

            if dependency_validation['warnings']:
                result['warnings'].extend(dependency_validation['warnings'])

            logger.info(f"[{self.upload_id}] Dependency validation passed")

            # Phase 4: Import Rules with Smart Deduplication
            logger.info(f"[{self.upload_id}] Phase 4: Importing rules")
            self.current_phase = "importing"
            result['phase'] = 'importing'

            # Reset deduplication statistics
            self.deduplication_service.reset_statistics()

            # Import rules
            import_results = await self._import_rules_batch(
                new_rules,
                archive_filename,
                result['file_hash'],
                deduplication_strategy
            )

            result['statistics'] = self.deduplication_service.get_statistics()

            logger.info(
                f"[{self.upload_id}] Import complete: "
                f"{result['statistics']['imported']} imported, "
                f"{result['statistics']['updated']} updated, "
                f"{result['statistics']['skipped']} skipped"
            )

            # Phase 5: Inheritance Impact Analysis
            logger.info(f"[{self.upload_id}] Phase 5: Inheritance impact analysis")
            self.current_phase = "inheritance_analysis"
            result['phase'] = 'inheritance_analysis'

            updated_rule_ids = [r['rule_id'] for r in import_results if r['action'] == 'updated']

            if updated_rule_ids:
                # Rebuild dependency graph with newly imported rules
                await self.dependency_graph.build_from_database()

                # Analyze impact
                impact = self.dependency_graph.get_impact_analysis(updated_rule_ids)
                result['inheritance_impact'] = impact

                # Initialize inheritance resolver
                self.inheritance_resolver = InheritanceResolver(self.dependency_graph)

                # Resolve inheritance updates (dry run first to report)
                inheritance_updates = []
                for updated_rule_id in updated_rule_ids:
                    # Get changes for this rule
                    updated_rule_result = next(
                        (r for r in import_results if r['rule_id'] == updated_rule_id),
                        None
                    )

                    if updated_rule_result and 'changes' in updated_rule_result:
                        updates = await self.inheritance_resolver.resolve_parent_update(
                            updated_rule_id,
                            updated_rule_result['changes'],
                            dry_run=False  # Apply updates
                        )
                        inheritance_updates.extend(updates)

                if inheritance_updates:
                    # Apply inheritance updates
                    apply_results = await self.inheritance_resolver.apply_inheritance_updates(
                        inheritance_updates
                    )

                    result['inheritance_impact']['applied_updates'] = apply_results
                    logger.info(
                        f"[{self.upload_id}] Applied {apply_results['applied']} "
                        f"inheritance updates"
                    )

            # Populate derived_rules (reverse index for inheritance)
            # This is a computed field that tracks which rules inherit from each parent
            await self._populate_derived_rules()

            # Success
            result['success'] = True
            result['phase'] = 'completed'
            result['end_time'] = datetime.utcnow().isoformat()
            result['processing_time_seconds'] = (
                datetime.utcnow() - start_time
            ).total_seconds()

            logger.info(
                f"[{self.upload_id}] Upload completed successfully in "
                f"{result['processing_time_seconds']:.2f}s"
            )

            return result

        except Exception as e:
            logger.error(f"[{self.upload_id}] Upload failed: {e}", exc_info=True)

            result['success'] = False
            result['end_time'] = datetime.utcnow().isoformat()
            result['errors'].append({
                'phase': result.get('phase', 'unknown'),
                'message': f"Upload failed: {str(e)}",
                'type': type(e).__name__
            })

            return result

        finally:
            # Save upload history for audit trail
            await self._save_upload_history(
                result=result,
                start_time=start_time,
                archive_filename=archive_filename,
                user_id=user_id
            )

            # Cleanup extracted files
            if extracted_path:
                self.security_service.cleanup_extracted_files(extracted_path)

    async def _populate_derived_rules(self) -> None:
        """
        Populate derived_rules field (reverse index for inheritance).

        This is a computed field that tracks which rules inherit from each parent rule.
        The bundle provides inherits_from (child→parent), OpenWatch computes derived_rules (parent→children).

        CRITICAL: derived_rules is excluded from content hash since it's computed, not source content.
        """
        from collections import defaultdict

        try:
            # Find all rules with inherits_from (child rules)
            child_rules = await ComplianceRule.find(
                {"inherits_from": {"$ne": None}, "is_latest": True}
            ).to_list()

            if not child_rules:
                logger.debug(f"[{self.upload_id}] No child rules found, skipping derived_rules population")
                return

            # Build reverse index: parent_id → [child_id1, child_id2, ...]
            inheritance_map = defaultdict(list)
            for child in child_rules:
                parent_id = child.inherits_from
                inheritance_map[parent_id].append(child.rule_id)

            # Update parent rules with derived_rules list
            update_count = 0
            for parent_id, child_ids in inheritance_map.items():
                result = await ComplianceRule.find_one(
                    {"rule_id": parent_id, "is_latest": True}
                ).update(
                    {"$set": {"derived_rules": sorted(child_ids)}}
                )
                if result:
                    update_count += 1

            logger.info(
                f"[{self.upload_id}] Populated derived_rules for {update_count} parent rules "
                f"({len(child_rules)} child rules processed)"
            )

        except Exception as e:
            # Non-fatal error - log and continue
            logger.warning(
                f"[{self.upload_id}] Failed to populate derived_rules: {e}. "
                f"This is a computed field and can be rebuilt later."
            )

    async def _import_rules_batch(
        self,
        new_rules: List[Dict[str, Any]],
        source_file: str,
        source_hash: str,
        strategy: str
    ) -> List[Dict[str, Any]]:
        """
        Import rules with smart deduplication

        Args:
            new_rules: List of parsed rule dictionaries
            source_file: Original archive filename
            source_hash: SHA-512 hash of archive
            strategy: Deduplication strategy

        Returns:
            List of import results per rule
        """
        results = []

        for idx, rule_data in enumerate(new_rules):
            try:
                # Update progress
                self.progress['processed_rules'] = idx + 1
                self.progress['percent_complete'] = (
                    (idx + 1) / len(new_rules) * 100
                )

                # Add provenance
                rule_data['source_file'] = source_file
                rule_data['source_hash'] = source_hash

                # CRITICAL: Clean empty framework fields BEFORE deduplication comparison
                # This ensures bundle data hashes identically to MongoDB data
                # Bug fix: OW-BUG-001 - Deduplication failing due to empty field differences
                rule_data = self._clean_empty_framework_fields(rule_data)

                # Check if latest version of rule exists (immutable versioning)
                rule_id = rule_data.get('rule_id')
                existing_rule = await ComplianceRule.find_one(
                    ComplianceRule.rule_id == rule_id,
                    ComplianceRule.is_latest == True
                )

                # Process with smart deduplication
                action, details = await self.deduplication_service.process_rule(
                    rule_data,
                    existing_rule
                )

                if action == 'imported':
                    # Create new rule (version 1)
                    await self._create_new_rule(
                        rule_data,
                        source_file,
                        source_hash
                    )

                elif action == 'updated':
                    # Create new version (immutable - never update existing)
                    await self._create_new_version(
                        existing_rule,
                        rule_data,
                        details.get('changes', {}),
                        source_file,
                        source_hash
                    )

                elif action == 'skipped':
                    # No action needed - rule unchanged
                    pass

                results.append(details)

            except Exception as e:
                import traceback
                logger.error(
                    f"Failed to import rule {rule_data.get('rule_id')}: {e}\n"
                    f"Exception type: {type(e).__name__}\n"
                    f"Traceback: {traceback.format_exc()}"
                )
                results.append({
                    'rule_id': rule_data.get('rule_id', 'unknown'),
                    'action': 'error',
                    'error': str(e)
                })

        return results

    def _clean_empty_framework_fields(self, rule_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Remove None/empty framework fields to prevent Pydantic from initializing them.
        CRITICAL for idempotency - prevents {'nist': None} vs {} hash mismatches.

        Args:
            rule_data: Rule dictionary

        Returns:
            Cleaned rule data with only populated framework fields
        """
        if 'frameworks' in rule_data and isinstance(rule_data['frameworks'], dict):
            # Remove None and empty dict values from frameworks
            cleaned_frameworks = {
                k: v for k, v in rule_data['frameworks'].items()
                if v is not None and v != {} and v != []
            }
            # Set to empty dict (not None) to match API schema expectations
            rule_data['frameworks'] = cleaned_frameworks if cleaned_frameworks else {}
        elif 'frameworks' not in rule_data:
            # Ensure frameworks field exists (API expects it)
            rule_data['frameworks'] = {}

        return rule_data

    async def _create_new_rule(
        self,
        rule_data: Dict[str, Any],
        source_file: str,
        source_hash: str
    ):
        """
        Create a new compliance rule in MongoDB (version 1)

        Args:
            rule_data: Rule dictionary
            source_file: Source bundle filename
            source_hash: SHA-512 hash of source bundle
        """
        # Remove _id field if present - MongoDB will auto-generate ObjectId
        if '_id' in rule_data:
            del rule_data['_id']

        # CRITICAL: Clean empty framework fields BEFORE Pydantic processing
        rule_data = self._clean_empty_framework_fields(rule_data)

        # Prepare version 1 with immutable versioning fields
        versioned_rule = self.versioning_service.prepare_new_version(
            rule_data=rule_data,
            previous_version=None,  # Version 1
            source_bundle=source_file,
            source_bundle_hash=source_hash,
            import_id=self.upload_id,
            created_by="bundle_import"
        )

        # Create ComplianceRule document
        rule = ComplianceRule(**versioned_rule)
        await rule.insert()

        logger.info(
            f"Created new rule: {rule.rule_id} v{rule.version} "
            f"(hash: {rule.version_hash[:16]}...)"
        )

        # Create basic rule intelligence (optional)
        await self._create_rule_intelligence(rule)

    async def _create_new_version(
        self,
        existing_rule: ComplianceRule,
        new_data: Dict[str, Any],
        changes: Dict[str, Any],
        source_file: str,
        source_hash: str
    ):
        """
        Create new immutable version of existing rule (NEVER updates existing document)

        Args:
            existing_rule: Latest version of existing rule
            new_data: New rule data
            changes: Detected changes
            source_file: Source bundle filename
            source_hash: SHA-512 hash of source bundle
        """
        now = datetime.utcnow()

        # Step 1: Mark existing version as superseded (update is_latest flag only)
        await ComplianceRule.find_one(
            ComplianceRule.id == existing_rule.id
        ).update({
            "$set": {
                "is_latest": False,
                "effective_until": now,
                "superseded_by": existing_rule.version + 1
            }
        })

        logger.debug(
            f"Marked rule {existing_rule.rule_id} v{existing_rule.version} "
            f"as superseded"
        )

        # Step 2: Prepare new version data
        # Remove _id to let MongoDB generate new one
        if '_id' in new_data:
            del new_data['_id']

        # CRITICAL: Clean empty framework fields BEFORE Pydantic processing
        new_data = self._clean_empty_framework_fields(new_data)

        # Convert existing_rule to dict for versioning service
        previous_version_dict = existing_rule.dict(by_alias=True)

        # Prepare new version
        versioned_rule = self.versioning_service.prepare_new_version(
            rule_data=new_data,
            previous_version=previous_version_dict,
            source_bundle=source_file,
            source_bundle_hash=source_hash,
            import_id=self.upload_id,
            created_by="bundle_import"
        )

        # Step 3: Insert new version (append-only)
        # CRITICAL: Defensive _id removal - MongoDB will auto-generate
        if '_id' in versioned_rule:
            logger.warning(
                f"BUG: versioned_rule contains _id field before insert! "
                f"rule_id={versioned_rule.get('rule_id')}, _id={versioned_rule['_id']}"
            )
            del versioned_rule['_id']

        new_rule = ComplianceRule(**versioned_rule)
        await new_rule.insert()

        logger.info(
            f"Created new version: {new_rule.rule_id} v{new_rule.version} "
            f"(hash: {new_rule.version_hash[:16]}..., "
            f"changes: {versioned_rule['change_summary']['change_count']}, "
            f"breaking: {versioned_rule['change_summary']['breaking_changes']})"
        )

    async def _create_rule_intelligence(self, rule: ComplianceRule):
        """
        Create basic rule intelligence record

        Args:
            rule: ComplianceRule document
        """
        # Check if intelligence already exists
        existing_intel = await RuleIntelligence.find_one(
            RuleIntelligence.rule_id == rule.rule_id
        )

        if existing_intel:
            return  # Skip if already exists

        # Create basic intelligence
        intelligence = RuleIntelligence(
            rule_id=rule.rule_id,
            business_impact=f"{rule.severity.capitalize()} {rule.category} compliance requirement",
            compliance_importance=self._assess_compliance_importance(rule),
            implementation_notes=rule.metadata.get('rationale', 'No implementation notes available'),
            testing_guidance=f"Verify {rule.metadata.get('name', 'rule')} is properly configured",
            scan_duration_avg_ms=100,  # Default estimate
            resource_impact='low'
        )

        await intelligence.insert()
        logger.debug(f"Created intelligence for rule: {rule.rule_id}")

    def _assess_compliance_importance(self, rule: ComplianceRule) -> int:
        """
        Assess compliance importance (1-10 scale)

        Args:
            rule: ComplianceRule document

        Returns:
            Importance score 1-10
        """
        severity_scores = {
            'critical': 10,
            'high': 8,
            'medium': 5,
            'low': 3,
            'info': 1,
            'unknown': 2
        }

        score = severity_scores.get(rule.severity, 5)

        # Boost score if rule maps to multiple frameworks
        if rule.frameworks:
            # Count frameworks that have non-empty mappings (generic, supports all frameworks)
            framework_count = sum(
                1 for fw_dict in rule.frameworks.values()
                if fw_dict and len(fw_dict) > 0
            )

            if framework_count >= 3:
                score = min(10, score + 2)
            elif framework_count >= 2:
                score = min(10, score + 1)

        return score

    async def _save_upload_history(
        self,
        result: Dict[str, Any],
        start_time: datetime,
        archive_filename: str,
        user_id: Optional[str]
    ) -> None:
        """
        Save upload history record to MongoDB for audit trail

        Args:
            result: Upload result dictionary
            start_time: Upload start timestamp
            archive_filename: Original bundle filename
            user_id: User ID who performed upload
        """
        try:
            # Extract username from various possible sources
            username = "unknown"
            if user_id:
                # In a real app, you'd look up username from user_id
                # For now, we'll use a placeholder
                username = f"user_{user_id}"

            history_record = UploadHistory(
                upload_id=self.upload_id,
                filename=archive_filename,
                file_hash=result.get('file_hash', ''),
                uploaded_at=start_time,
                uploaded_by=username,
                user_id=user_id,
                success=result.get('success', False),
                phase=result.get('phase', 'unknown'),
                statistics=result.get('statistics', {}),
                manifest=result.get('manifest'),
                processing_time_seconds=result.get('processing_time_seconds'),
                errors=result.get('errors', []),
                warnings=result.get('warnings', []),
                security_validation=result.get('security_validation'),
                dependency_validation=result.get('dependency_validation'),
                inheritance_impact=result.get('inheritance_impact')
            )

            await history_record.insert()
            logger.info(f"[{self.upload_id}] Upload history saved successfully")

            # Cleanup old history records (keep last 100)
            await self._cleanup_old_history()

        except Exception as e:
            # Don't fail the upload if history save fails - just log it
            logger.warning(f"[{self.upload_id}] Failed to save upload history: {e}")

    async def _cleanup_old_history(self) -> None:
        """
        Keep only the last 100 upload history records
        Automatically deletes older records to prevent unlimited growth
        """
        try:
            total_count = await UploadHistory.count()

            if total_count > 100:
                # Find records to delete (oldest ones beyond the 100 most recent)
                records_to_delete = total_count - 100

                # Get the 100th most recent record's timestamp
                records = await UploadHistory.find().sort("-uploaded_at").skip(99).limit(1).to_list()

                if records:
                    cutoff_date = records[0].uploaded_at

                    # Delete all records older than the cutoff
                    result = await UploadHistory.find(
                        UploadHistory.uploaded_at < cutoff_date
                    ).delete()

                    if result:
                        logger.info(f"Cleaned up {result.deleted_count} old upload history records")

        except Exception as e:
            logger.warning(f"Failed to cleanup old upload history: {e}")

    def get_upload_progress(self) -> Dict[str, Any]:
        """
        Get current upload progress

        Returns:
            Progress dictionary
        """
        return {
            'upload_id': self.upload_id,
            'phase': self.current_phase,
            'processed_rules': self.progress['processed_rules'],
            'total_rules': self.progress['total_rules'],
            'percent_complete': self.progress['percent_complete']
        }
