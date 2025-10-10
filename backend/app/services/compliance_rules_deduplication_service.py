"""
Smart Deduplication Service for Compliance Rules
Detects content changes and updates only modified rules
"""
import hashlib
import json
from typing import Dict, Any, Tuple, List, Union, Optional
from datetime import datetime
from collections import defaultdict
import logging

from ..models.mongo_models import ComplianceRule

logger = logging.getLogger(__name__)


class SmartDeduplicationService:
    """
    Intelligent deduplication with change detection

    Compares existing rules with new rules to determine:
    - If content actually changed (via hash comparison)
    - Which specific fields changed
    - Whether to skip or update
    """

    # Fields excluded from hash calculation (metadata that always changes)
    EXCLUDED_FROM_HASH = {
        'imported_at',
        'updated_at',
        'source_file',
        'source_hash',
        '_id'  # MongoDB internal ID
    }

    # Fields tracked for statistics (categorized)
    TRACKED_FIELD_CATEGORIES = {
        'metadata': ['metadata'],
        'frameworks': ['frameworks'],
        'platforms': ['platform_implementations'],
        'check_content': ['check_type', 'check_content'],
        'fix_content': ['fix_available', 'fix_content', 'manual_remediation'],
        'severity': ['severity', 'remediation_risk', 'remediation_complexity'],
        'inheritance': ['inherits_from', 'derived_rules', 'base_parameters', 'abstract'],
        'dependencies': ['dependencies'],
        'classification': ['category', 'tags', 'security_function']
    }

    def __init__(self):
        self.statistics = {
            'imported': 0,
            'updated': 0,
            'skipped': 0,
            'errors': 0,
            'field_changes': defaultdict(int)
        }

    async def process_rule(
        self,
        rule_data: Dict[str, Any],
        existing_rule: Optional[ComplianceRule] = None
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Process a single rule with smart deduplication

        Args:
            rule_data: New rule data from upload
            existing_rule: Existing rule from MongoDB (if exists)

        Returns:
            Tuple of (action, details) where:
                - action: 'imported' | 'updated' | 'skipped'
                - details: Dict with action details
        """
        rule_id = rule_data.get('rule_id', 'unknown')

        try:
            if not existing_rule:
                # New rule - import
                self.statistics['imported'] += 1
                return 'imported', {
                    'rule_id': rule_id,
                    'action': 'imported',
                    'reason': 'New rule'
                }

            # Calculate content hashes
            existing_hash = self.calculate_content_hash(existing_rule)
            new_hash = self.calculate_content_hash(rule_data)

            if existing_hash == new_hash:
                # No changes - skip
                self.statistics['skipped'] += 1
                return 'skipped', {
                    'rule_id': rule_id,
                    'action': 'skipped',
                    'reason': 'No content changes detected',
                    'content_hash': existing_hash
                }

            # Detect specific changes
            changes = self.detect_field_changes(existing_rule, rule_data)

            # Update field statistics
            for category in self.categorize_changes(changes):
                self.statistics['field_changes'][category] += 1

            # Content changed - update needed
            self.statistics['updated'] += 1
            return 'updated', {
                'rule_id': rule_id,
                'action': 'updated',
                'reason': 'Content changed',
                'changes': changes,
                'change_count': len(changes),
                'changed_categories': self.categorize_changes(changes),
                'old_hash': existing_hash,
                'new_hash': new_hash
            }

        except Exception as e:
            logger.error(f"Error processing rule {rule_id}: {e}")
            self.statistics['errors'] += 1
            return 'error', {
                'rule_id': rule_id,
                'action': 'error',
                'reason': f'Processing error: {str(e)}'
            }

    def calculate_content_hash(self, rule: Union[ComplianceRule, Dict[str, Any]]) -> str:
        """
        Calculate SHA-256 hash of rule content

        Excludes timestamp and provenance fields that change on every import.

        Args:
            rule: ComplianceRule model or dict

        Returns:
            Hex digest of content hash
        """
        try:
            # Convert to dict if Pydantic model
            if hasattr(rule, 'dict'):
                rule_dict = rule.dict()
            elif isinstance(rule, dict):
                rule_dict = dict(rule)
            else:
                raise ValueError(f"Cannot hash type: {type(rule)}")

            # Remove excluded fields
            normalized = {
                k: v for k, v in sorted(rule_dict.items())
                if k not in self.EXCLUDED_FROM_HASH
            }

            # Serialize to JSON with sorted keys for consistency
            content_json = json.dumps(normalized, sort_keys=True, default=str)

            # Calculate SHA-256 hash
            return hashlib.sha256(content_json.encode()).hexdigest()

        except Exception as e:
            logger.error(f"Error calculating hash: {e}")
            # Return empty hash on error
            return ""

    def detect_field_changes(
        self,
        existing_rule: ComplianceRule,
        new_data: Dict[str, Any]
    ) -> Dict[str, Dict[str, Any]]:
        """
        Detect which specific fields changed between existing and new rule

        Returns:
            {
                'field_name': {
                    'old': old_value,
                    'new': new_value,
                    'type': 'modified' | 'added' | 'removed'
                }
            }
        """
        changes = {}

        try:
            existing_dict = existing_rule.dict()

            # Check for modified/added fields in new data
            for field, new_value in new_data.items():
                # Skip excluded fields
                if field in self.EXCLUDED_FROM_HASH:
                    continue

                old_value = existing_dict.get(field)

                # Compare values
                if not self._values_equal(old_value, new_value):
                    if old_value is None:
                        change_type = 'added'
                    else:
                        change_type = 'modified'

                    changes[field] = {
                        'old': self._truncate_value(old_value),
                        'new': self._truncate_value(new_value),
                        'type': change_type
                    }

            # Check for removed fields (fields in existing but not in new)
            for field, old_value in existing_dict.items():
                # Skip excluded fields
                if field in self.EXCLUDED_FROM_HASH:
                    continue

                if field not in new_data and old_value is not None:
                    changes[field] = {
                        'old': self._truncate_value(old_value),
                        'new': None,
                        'type': 'removed'
                    }

        except Exception as e:
            logger.error(f"Error detecting changes: {e}")

        return changes

    def _values_equal(self, val1: Any, val2: Any) -> bool:
        """
        Compare two values for equality

        Handles nested dicts, lists, and type conversions
        """
        # Handle None cases
        if val1 is None and val2 is None:
            return True
        if val1 is None or val2 is None:
            return False

        # Convert both to comparable types
        try:
            # For dicts and lists, compare JSON representations
            if isinstance(val1, (dict, list)) or isinstance(val2, (dict, list)):
                json1 = json.dumps(val1, sort_keys=True, default=str)
                json2 = json.dumps(val2, sort_keys=True, default=str)
                return json1 == json2

            # Direct comparison for primitives
            return val1 == val2

        except Exception:
            # Fallback to string comparison
            return str(val1) == str(val2)

    def _truncate_value(self, value: Any, max_length: int = 100) -> Any:
        """
        Truncate long values for display in change reports

        Args:
            value: Value to truncate
            max_length: Maximum string length

        Returns:
            Truncated value
        """
        if value is None:
            return None

        # For strings, truncate if too long
        if isinstance(value, str):
            if len(value) > max_length:
                return value[:max_length] + '...'
            return value

        # For dicts/lists, convert to string and truncate
        if isinstance(value, (dict, list)):
            value_str = json.dumps(value, default=str)
            if len(value_str) > max_length:
                return value_str[:max_length] + '...'
            return value

        return value

    def categorize_changes(self, changes: Dict[str, Any]) -> List[str]:
        """
        Categorize changes into high-level categories

        Args:
            changes: Dict of field changes from detect_field_changes()

        Returns:
            List of categories that changed (e.g., ['metadata', 'frameworks'])
        """
        categories = set()

        for field in changes.keys():
            # Find which category this field belongs to
            for category, fields in self.TRACKED_FIELD_CATEGORIES.items():
                if field in fields:
                    categories.add(category)
                    break

        return sorted(list(categories))

    async def update_rule_with_changes(
        self,
        existing_rule: ComplianceRule,
        new_data: Dict[str, Any],
        changes: Dict[str, Dict[str, Any]]
    ) -> ComplianceRule:
        """
        Update existing rule with only changed fields

        Args:
            existing_rule: Existing ComplianceRule document
            new_data: New rule data from upload
            changes: Detected changes from detect_field_changes()

        Returns:
            Updated ComplianceRule (not yet saved to database)
        """
        try:
            # Update only changed fields
            for field, change in changes.items():
                new_value = change['new']
                setattr(existing_rule, field, new_value)
                logger.debug(
                    f"Updated {existing_rule.rule_id}.{field}: "
                    f"{change['type']} - {change.get('old')} → {new_value}"
                )

            # Always update these metadata fields
            existing_rule.updated_at = datetime.utcnow()

            # Update provenance if provided
            if 'source_file' in new_data:
                existing_rule.source_file = new_data['source_file']

            if 'source_hash' in new_data:
                existing_rule.source_hash = new_data['source_hash']

            if 'version' in new_data:
                existing_rule.version = new_data['version']

            return existing_rule

        except Exception as e:
            logger.error(f"Error updating rule {existing_rule.rule_id}: {e}")
            raise

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get deduplication statistics

        Returns:
            Statistics dictionary with counts and field changes
        """
        return {
            'imported': self.statistics['imported'],
            'updated': self.statistics['updated'],
            'skipped': self.statistics['skipped'],
            'errors': self.statistics['errors'],
            'field_changes': dict(self.statistics['field_changes'])
        }

    def reset_statistics(self):
        """Reset statistics for new upload"""
        self.statistics = {
            'imported': 0,
            'updated': 0,
            'skipped': 0,
            'errors': 0,
            'field_changes': defaultdict(int)
        }

    def generate_summary_report(self) -> Dict[str, Any]:
        """
        Generate human-readable summary report

        Returns:
            Summary report dictionary
        """
        stats = self.get_statistics()
        total_processed = stats['imported'] + stats['updated'] + stats['skipped']

        return {
            'total_processed': total_processed,
            'new_rules_imported': stats['imported'],
            'existing_rules_updated': stats['updated'],
            'unchanged_rules_skipped': stats['skipped'],
            'errors': stats['errors'],
            'update_efficiency': (
                f"{stats['updated']} updates vs {stats['skipped']} skipped "
                f"({stats['updated'] / max(total_processed, 1) * 100:.1f}% changed)"
                if total_processed > 0 else "N/A"
            ),
            'field_change_breakdown': stats['field_changes'],
            'most_changed_categories': sorted(
                stats['field_changes'].items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]  # Top 5 most changed categories
        }


class DeduplicationStrategy:
    """Enumeration of deduplication strategies"""

    SKIP_UNCHANGED_UPDATE_CHANGED = "skip_unchanged_update_changed"  # Smart deduplication (default)
    SKIP_EXISTING = "skip_existing"  # Never update existing rules
    UPDATE_ALL = "update_all"  # Always update existing rules
    FAIL_ON_DUPLICATE = "fail_on_duplicate"  # Reject upload if duplicates found

    @classmethod
    def all_strategies(cls) -> List[str]:
        """Get list of all valid strategies"""
        return [
            cls.SKIP_UNCHANGED_UPDATE_CHANGED,
            cls.SKIP_EXISTING,
            cls.UPDATE_ALL,
            cls.FAIL_ON_DUPLICATE
        ]

    @classmethod
    def is_valid(cls, strategy: str) -> bool:
        """Check if strategy is valid"""
        return strategy in cls.all_strategies()
