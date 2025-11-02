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

    # Fields excluded from hash calculation (metadata + versioning fields)
    # Must match RuleVersioningService.HASH_EXCLUDE_FIELDS for consistency
    EXCLUDED_FROM_HASH = {
        # Metadata that changes on every import
        "imported_at",
        "updated_at",
        "source_file",
        "source_hash",
        "source",  # Provenance metadata (upstream_id, source_type) - not compliance content
        "_id",
        "id",  # Beanie auto-generated alias for _id
        "revision_id",  # Beanie document revision tracking
        # Immutable versioning fields (added in Phase 5)
        "version",
        "version_hash",
        "is_latest",
        "supersedes_version",
        "superseded_by",
        "effective_from",
        "effective_until",
        "source_bundle",
        "source_bundle_hash",
        "import_id",
        "change_summary",
        "created_by",
        # Computed fields (OpenWatch-managed, not from bundle)
        "derived_rules",  # Auto-populated from other rules' inherits_from
        "parent_rule_id",  # Computed relationship field
        # Multi-platform merge metadata (tracking only, not content)
        "source_products",  # List of products that contributed to this merged rule
        "platform_implementations",  # Platform-specific implementation details - metadata, not core compliance logic
        "frameworks",  # Compliance framework mappings (NIST, CIS, STIG, etc.) - metadata about standards, not rule logic
        "stig",  # STIG-specific metadata (srg_requirement, vuldiscussion, checktext, fixtext) - documentation, not rule logic
    }

    # Fields tracked for statistics (categorized)
    TRACKED_FIELD_CATEGORIES = {
        "metadata": ["metadata"],
        "frameworks": ["frameworks"],
        "platforms": ["platform_implementations"],
        "check_content": ["check_type", "check_content"],
        "fix_content": ["fix_available", "fix_content", "manual_remediation"],
        "severity": ["severity", "remediation_risk", "remediation_complexity"],
        "inheritance": [
            "inherits_from",
            "derived_rules",
            "base_parameters",
            "abstract",
        ],
        "dependencies": ["dependencies"],
        "classification": ["category", "tags", "security_function"],
    }

    def __init__(self):
        self.statistics = {
            "imported": 0,
            "updated": 0,
            "skipped": 0,
            "errors": 0,
            "field_changes": defaultdict(int),
        }

    async def process_rule(
        self, rule_data: Dict[str, Any], existing_rule: Optional[ComplianceRule] = None
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
        rule_id = rule_data.get("rule_id", "unknown")

        try:
            if not existing_rule:
                # New rule - import
                self.statistics["imported"] += 1
                return "imported", {
                    "rule_id": rule_id,
                    "action": "imported",
                    "reason": "New rule",
                }

            # Calculate content hashes
            existing_hash = self.calculate_content_hash(existing_rule)
            new_hash = self.calculate_content_hash(rule_data)

            logger.debug(
                f"Hash comparison for {rule_id}: "
                f"existing={existing_hash[:16]}..., new={new_hash[:16]}..."
            )

            if existing_hash == new_hash:
                # No changes - skip
                self.statistics["skipped"] += 1
                logger.info(f"Skipping unchanged rule: {rule_id}")
                return "skipped", {
                    "rule_id": rule_id,
                    "action": "skipped",
                    "reason": "No content changes detected",
                    "content_hash": existing_hash,
                }

            # Detect specific changes
            changes = self.detect_field_changes(existing_rule, rule_data)

            # Debug: Log first change details
            if changes:
                first_field = list(changes.keys())[0]
                first_change = changes[first_field]
                logger.error(
                    f"Rule {rule_id} HASH MISMATCH - {len(changes)} fields changed. "
                    f"Example: {first_field} -> "
                    f"OLD type={type(first_change.get('old')).__name__} value={str(first_change.get('old'))[:50]}, "
                    f"NEW type={type(first_change.get('new')).__name__} value={str(first_change.get('new'))[:50]}"
                )

            logger.warning(
                f"Rule {rule_id} marked as updated - {len(changes)} fields changed: "
                f"{list(changes.keys())[:5]}"
            )

            # Update field statistics
            for category in self.categorize_changes(changes):
                self.statistics["field_changes"][category] += 1

            # Content changed - update needed
            self.statistics["updated"] += 1
            return "updated", {
                "rule_id": rule_id,
                "action": "updated",
                "reason": "Content changed",
                "changes": changes,
                "change_count": len(changes),
                "changed_categories": self.categorize_changes(changes),
                "old_hash": existing_hash,
                "new_hash": new_hash,
            }

        except Exception as e:
            logger.error(f"Error processing rule {rule_id}: {e}")
            self.statistics["errors"] += 1
            return "error", {
                "rule_id": rule_id,
                "action": "error",
                "reason": f"Processing error: {str(e)}",
            }

    def _apply_pydantic_defaults(self, rule_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply Pydantic model default values to a raw dict

        CRITICAL: This ensures that bundle data (raw dicts with missing fields)
        hashes identically to MongoDB data (Pydantic models with defaults populated).

        The bundle may have missing fields, but Pydantic will add defaults when
        creating ComplianceRule instances. We need to apply those same defaults
        to the bundle data BEFORE hashing.

        Args:
            rule_dict: Raw rule dict from bundle

        Returns:
            Dict with Pydantic defaults applied
        """
        result = dict(rule_dict)

        # Apply ALL defaults that match ComplianceRule model
        # CRITICAL: Apply defaults for both missing fields AND None values
        # This ensures bundle data with None values hashes identically to MongoDB data with defaults
        if result.get("abstract") is None:
            result["abstract"] = False

        if result.get("conditions") is None:
            result["conditions"] = []

        if result.get("parameter_resolution") is None:
            result["parameter_resolution"] = "most_restrictive"

        if result.get("dependencies") is None:
            result["dependencies"] = {"requires": [], "conflicts": [], "related": []}

        if result.get("check_type") is None:
            result["check_type"] = "custom"

        if result.get("fix_available") is None:
            result["fix_available"] = False

        if result.get("remediation_complexity") is None:
            result["remediation_complexity"] = "medium"

        if result.get("remediation_risk") is None:
            result["remediation_risk"] = "low"

        if result.get("deprecated") is None:
            result["deprecated"] = False

        if result.get("scanner_type") is None:
            result["scanner_type"] = "oscap"

        if result.get("platform_implementations") is None:
            result["platform_implementations"] = {}

        return result

    def calculate_content_hash(
        self, rule: Union[ComplianceRule, Dict[str, Any]]
    ) -> str:
        """
        Calculate SHA-256 hash of rule content

        Excludes timestamp, provenance, and computed fields that change on every import.
        Uses exclude_none=True to ensure None vs {} differences don't break idempotency.

        Args:
            rule: ComplianceRule model or dict

        Returns:
            Hex digest of content hash
        """
        try:
            # Convert to dict if Pydantic model
            if hasattr(rule, "dict"):
                # CRITICAL: Use exclude_none=True to remove None values
                # This ensures None and {} hash identically after normalization
                rule_dict = rule.dict(exclude_none=True)
                # CRITICAL: Also apply defaults to MongoDB data to fill in missing keys
                # This ensures both MongoDB and bundle data have the same keys with defaults
                rule_dict = self._apply_pydantic_defaults(rule_dict)
            elif isinstance(rule, dict):
                # CRITICAL: Apply Pydantic defaults to raw dict
                # This ensures bundle data hashes same as MongoDB data
                rule_dict = self._apply_pydantic_defaults(dict(rule))
            else:
                raise ValueError(f"Cannot hash type: {type(rule)}")

            # Remove excluded fields (metadata, versioning, computed)
            normalized = {
                k: v
                for k, v in sorted(rule_dict.items())
                if k not in self.EXCLUDED_FROM_HASH
            }

            # Remove merge-specific metadata from source field
            if "source" in normalized and isinstance(normalized["source"], dict):
                source_cleaned = dict(normalized["source"])
                # These fields are added by multi-platform merging and shouldn't affect hash
                source_cleaned.pop("merged_products", None)
                source_cleaned.pop("build_type", None)
                normalized["source"] = source_cleaned

            # Normalize empty nested structures (critical for idempotency)
            normalized = self._normalize_empty_values(normalized)

            # Debug: Log fields included in hash
            rule_id = rule_dict.get("rule_id", "unknown")
            included_fields = sorted(normalized.keys())
            logger.debug(
                f"Hash calculation for {rule_id}: "
                f"including {len(included_fields)} fields, "
                f"excluding {len(self.EXCLUDED_FROM_HASH)} fields"
            )

            # Serialize to JSON with sorted keys for consistency
            content_json = json.dumps(normalized, sort_keys=True, default=str)

            # Calculate SHA-256 hash
            return hashlib.sha256(content_json.encode()).hexdigest()

        except Exception as e:
            logger.error(f"Error calculating hash: {e}")
            # Return empty hash on error
            return ""

    def detect_field_changes(
        self, existing_rule: ComplianceRule, new_data: Dict[str, Any]
    ) -> Dict[str, Dict[str, Any]]:
        """
        Detect which specific fields changed between existing and new rule

        CRITICAL: Use exclude_none=True to ensure None vs {} comparisons work correctly.

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
            # CRITICAL: Use exclude_none=True to normalize None fields
            existing_dict = existing_rule.dict(exclude_none=True)

            # Normalize new_data to remove None values for consistent comparison
            new_data_normalized = {k: v for k, v in new_data.items() if v is not None}

            # Check for modified/added fields in new data
            for field, new_value in new_data_normalized.items():
                # Skip excluded fields
                if field in self.EXCLUDED_FROM_HASH:
                    continue

                old_value = existing_dict.get(field)

                # Compare values
                if not self._values_equal(old_value, new_value):
                    if old_value is None:
                        change_type = "added"
                    else:
                        change_type = "modified"

                    # DEBUG: Log comparison details for troubleshooting
                    logger.debug(
                        f"Field {field} mismatch: "
                        f"old={type(old_value).__name__}:{old_value!r}, "
                        f"new={type(new_value).__name__}:{new_value!r}"
                    )

                    changes[field] = {
                        "old": self._truncate_value(old_value),
                        "new": self._truncate_value(new_value),
                        "type": change_type,
                    }

            # Check for removed fields (fields in existing but not in new)
            for field, old_value in existing_dict.items():
                # Skip excluded fields
                if field in self.EXCLUDED_FROM_HASH:
                    continue

                if field not in new_data_normalized and old_value is not None:
                    changes[field] = {
                        "old": self._truncate_value(old_value),
                        "new": None,
                        "type": "removed",
                    }

        except Exception as e:
            logger.error(f"Error detecting changes: {e}")

        return changes

    def _normalize_empty_values(self, data: Any) -> Any:
        """
        Recursively normalize empty nested structures for consistent hashing

        CRITICAL FOR IDEMPOTENCY:
        - Converts None → {} for optional dict fields (identifiers, etc.)
        - Converts None → [] for optional list fields (derived_rules, etc.)
        - Removes empty nested structures from dicts

        This ensures that:
        - Bundle with `identifiers: None` hashes same as MongoDB `identifiers: {}`
        - Bundle with missing `derived_rules` hashes same as MongoDB `derived_rules: []`

        Args:
            data: Data structure to normalize

        Returns:
            Normalized data structure
        """
        if isinstance(data, dict):
            # Recursively normalize nested dicts
            normalized = {}
            for k, v in data.items():
                if v is None:
                    # Skip None values - they'll be normalized by Pydantic defaults
                    continue

                normalized_v = self._normalize_empty_values(v)

                # Skip empty nested structures
                if normalized_v == {} or normalized_v == []:
                    continue

                normalized[k] = normalized_v

            return normalized

        elif isinstance(data, list):
            # Recursively normalize list items
            normalized = [self._normalize_empty_values(item) for item in data]
            # Filter out None and empty items
            return [item for item in normalized if item not in (None, {}, [])]

        else:
            # Primitives pass through unchanged
            return data

    def _values_equal(self, val1: Any, val2: Any) -> bool:
        """
        Compare two values for equality

        CRITICAL: Treat None, {}, and [] as equivalent for idempotency.
        MongoDB may store fields as missing, None, or empty - all should hash identically.
        """

        # Normalize empty values: None, {}, [] are all treated as "empty"
        def is_empty(val):
            return val is None or val == {} or val == []

        # If both are empty (None/{}/[]), they're equal
        if is_empty(val1) and is_empty(val2):
            return True

        # If only one is empty, they're not equal
        if is_empty(val1) or is_empty(val2):
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
                return value[:max_length] + "..."
            return value

        # For dicts/lists, convert to string and truncate
        if isinstance(value, (dict, list)):
            value_str = json.dumps(value, default=str)
            if len(value_str) > max_length:
                return value_str[:max_length] + "..."
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
        changes: Dict[str, Dict[str, Any]],
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
                new_value = change["new"]
                setattr(existing_rule, field, new_value)
                logger.debug(
                    f"Updated {existing_rule.rule_id}.{field}: "
                    f"{change['type']} - {change.get('old')} → {new_value}"
                )

            # Always update these metadata fields
            existing_rule.updated_at = datetime.utcnow()

            # Update provenance if provided
            if "source_file" in new_data:
                existing_rule.source_file = new_data["source_file"]

            if "source_hash" in new_data:
                existing_rule.source_hash = new_data["source_hash"]

            if "version" in new_data:
                existing_rule.version = new_data["version"]

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
            "imported": self.statistics["imported"],
            "updated": self.statistics["updated"],
            "skipped": self.statistics["skipped"],
            "errors": self.statistics["errors"],
            "field_changes": dict(self.statistics["field_changes"]),
        }

    def reset_statistics(self):
        """Reset statistics for new upload"""
        self.statistics = {
            "imported": 0,
            "updated": 0,
            "skipped": 0,
            "errors": 0,
            "field_changes": defaultdict(int),
        }

    def generate_summary_report(self) -> Dict[str, Any]:
        """
        Generate human-readable summary report

        Returns:
            Summary report dictionary
        """
        stats = self.get_statistics()
        total_processed = stats["imported"] + stats["updated"] + stats["skipped"]

        return {
            "total_processed": total_processed,
            "new_rules_imported": stats["imported"],
            "existing_rules_updated": stats["updated"],
            "unchanged_rules_skipped": stats["skipped"],
            "errors": stats["errors"],
            "update_efficiency": (
                f"{stats['updated']} updates vs {stats['skipped']} skipped "
                f"({stats['updated'] / max(total_processed, 1) * 100:.1f}% changed)"
                if total_processed > 0
                else "N/A"
            ),
            "field_change_breakdown": stats["field_changes"],
            "most_changed_categories": sorted(
                stats["field_changes"].items(), key=lambda x: x[1], reverse=True
            )[
                :5
            ],  # Top 5 most changed categories
        }


class DeduplicationStrategy:
    """Enumeration of deduplication strategies"""

    SKIP_UNCHANGED_UPDATE_CHANGED = (
        "skip_unchanged_update_changed"  # Smart deduplication (default)
    )
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
            cls.FAIL_ON_DUPLICATE,
        ]

    @classmethod
    def is_valid(cls, strategy: str) -> bool:
        """Check if strategy is valid"""
        return strategy in cls.all_strategies()
