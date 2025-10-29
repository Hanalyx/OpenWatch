"""
Compliance Rules Versioning Service
Handles immutable versioning, content hashing, and change detection for FISMA/FedRAMP/HIPAA compliance
"""
import hashlib
import json
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class RuleVersioningService:
    """
    Service for immutable rule versioning with content-addressed integrity

    Supports:
    - Content hashing (SHA-256) for tamper detection
    - Change detection between rule versions
    - Breaking change analysis
    """

    # Fields to exclude from content hash (metadata fields)
    HASH_EXCLUDE_FIELDS = {
        '_id', 'id', 'revision_id',  # MongoDB/Beanie internal IDs
        'version', 'version_hash', 'is_latest', 'supersedes_version',
        'superseded_by', 'effective_from', 'effective_until', 'imported_at',
        'updated_at', 'created_by', 'source_bundle', 'source_bundle_hash',
        'import_id', 'change_summary'
    }

    # Fields that if changed, constitute a "breaking change" requiring re-scan
    BREAKING_CHANGE_FIELDS = {
        'check_content', 'check_type', 'severity', 'frameworks',
        'platform_implementations', 'dependencies.requires'
    }

    @staticmethod
    def calculate_content_hash(rule_data: Dict[str, Any]) -> str:
        """
        Calculate SHA-256 hash of rule content for integrity verification

        Args:
            rule_data: Rule dictionary

        Returns:
            SHA-256 hash as hex string with "sha256:" prefix
        """
        # Filter out metadata fields
        content_dict = {
            k: v for k, v in rule_data.items()
            if k not in RuleVersioningService.HASH_EXCLUDE_FIELDS
        }

        # Sort keys for deterministic hashing
        content_json = json.dumps(content_dict, sort_keys=True, default=str)

        # Calculate SHA-256
        hash_obj = hashlib.sha256(content_json.encode('utf-8'))
        hash_hex = hash_obj.hexdigest()

        return f"sha256:{hash_hex}"

    @staticmethod
    def detect_changes(
        old_rule: Dict[str, Any],
        new_rule: Dict[str, Any]
    ) -> Dict[str, Dict[str, Any]]:
        """
        Detect changes between two rule versions

        Args:
            old_rule: Previous version rule data
            new_rule: New version rule data

        Returns:
            Dictionary of changed fields with old/new values
            {
                'severity': {'old': 'medium', 'new': 'high'},
                'frameworks.nist': {'old': {...}, 'new': {...}}
            }
        """
        changes = {}

        # Compare top-level fields
        for field in new_rule.keys():
            if field in RuleVersioningService.HASH_EXCLUDE_FIELDS:
                continue

            old_value = old_rule.get(field)
            new_value = new_rule.get(field)

            # Deep comparison
            if not RuleVersioningService._values_equal(old_value, new_value):
                changes[field] = {
                    'old': old_value,
                    'new': new_value
                }

        # Check for removed fields
        for field in old_rule.keys():
            if field in RuleVersioningService.HASH_EXCLUDE_FIELDS:
                continue
            if field not in new_rule:
                changes[field] = {
                    'old': old_rule[field],
                    'new': None
                }

        return changes

    @staticmethod
    def _values_equal(val1: Any, val2: Any) -> bool:
        """
        Deep equality comparison for rule values

        Handles dicts, lists, and primitives
        """
        if type(val1) != type(val2):
            return False

        if isinstance(val1, dict):
            if set(val1.keys()) != set(val2.keys()):
                return False
            return all(
                RuleVersioningService._values_equal(val1[k], val2[k])
                for k in val1.keys()
            )

        if isinstance(val1, list):
            if len(val1) != len(val2):
                return False
            return all(
                RuleVersioningService._values_equal(v1, v2)
                for v1, v2 in zip(val1, val2)
            )

        return val1 == val2

    @staticmethod
    def has_breaking_changes(changes: Dict[str, Dict[str, Any]]) -> bool:
        """
        Determine if changes include breaking changes requiring re-scan

        Args:
            changes: Output from detect_changes()

        Returns:
            True if breaking changes detected
        """
        for changed_field in changes.keys():
            # Check top-level breaking fields
            if changed_field in RuleVersioningService.BREAKING_CHANGE_FIELDS:
                return True

            # Check nested breaking fields (e.g., "dependencies.requires")
            for breaking_field in RuleVersioningService.BREAKING_CHANGE_FIELDS:
                if '.' in breaking_field:
                    parent_field = breaking_field.split('.')[0]
                    if changed_field == parent_field:
                        # Could be more sophisticated - check actual nested change
                        return True

        return False

    @staticmethod
    def create_change_summary(
        changes: Dict[str, Dict[str, Any]],
        change_type: str = "updated",
        change_reason: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Create structured change summary for audit trail

        Args:
            changes: Output from detect_changes()
            change_type: "created", "updated", or "deprecated"
            change_reason: Optional reason for the change

        Returns:
            Change summary dictionary
        """
        return {
            "change_type": change_type,
            "changed_fields": list(changes.keys()),
            "change_reason": change_reason or "Automated bundle import",
            "breaking_changes": RuleVersioningService.has_breaking_changes(changes),
            "change_count": len(changes),
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

    @staticmethod
    def verify_content_hash(
        rule_data: Dict[str, Any],
        expected_hash: str
    ) -> bool:
        """
        Verify rule content integrity by comparing hashes

        Args:
            rule_data: Rule dictionary
            expected_hash: Expected SHA-256 hash (with "sha256:" prefix)

        Returns:
            True if hash matches
        """
        actual_hash = RuleVersioningService.calculate_content_hash(rule_data)
        return actual_hash == expected_hash

    @staticmethod
    def prepare_new_version(
        rule_data: Dict[str, Any],
        previous_version: Optional[Dict[str, Any]],
        source_bundle: str,
        source_bundle_hash: str,
        import_id: str,
        created_by: str = "system"
    ) -> Dict[str, Any]:
        """
        Prepare rule data for insertion as a new immutable version

        Args:
            rule_data: New rule data to insert
            previous_version: Previous version dict (None if v1)
            source_bundle: Source bundle filename
            source_bundle_hash: SHA-512 hash of source bundle
            import_id: UUID of import operation
            created_by: User or system that created this version

        Returns:
            Complete rule data ready for MongoDB insertion
        """
        now = datetime.utcnow()

        # Determine version number
        if previous_version:
            new_version = previous_version.get('version', 0) + 1
            supersedes_version = previous_version.get('version')
            change_type = "updated"

            # Detect changes
            changes = RuleVersioningService.detect_changes(
                previous_version,
                rule_data
            )
            change_summary = RuleVersioningService.create_change_summary(
                changes,
                change_type="updated"
            )
        else:
            new_version = 1
            supersedes_version = None
            change_summary = {
                "change_type": "created",
                "changed_fields": [],
                "change_reason": "Initial import",
                "breaking_changes": False,
                "change_count": 0,
                "timestamp": now.isoformat() + "Z"
            }

        # Calculate content hash
        content_hash = RuleVersioningService.calculate_content_hash(rule_data)

        # CRITICAL: Remove _id before spreading to prevent MongoDB duplicate key errors
        # Each version must have a unique _id generated by MongoDB
        clean_rule_data = {k: v for k, v in rule_data.items() if k != '_id'}

        # Prepare complete document
        versioned_rule = {
            **clean_rule_data,

            # Versioning
            "version": new_version,
            "version_hash": content_hash,
            "is_latest": True,
            "supersedes_version": supersedes_version,
            "superseded_by": None,

            # Temporal
            "effective_from": now,
            "effective_until": None,
            "imported_at": now,
            "updated_at": now,
            "created_by": created_by,

            # Source tracking
            "source_bundle": source_bundle,
            "source_bundle_hash": source_bundle_hash,
            "import_id": import_id,

            # Change metadata
            "change_summary": change_summary,
            "deprecated": False,
            "deprecation_reason": None,
            "replacement_rule_id": None
        }

        return versioned_rule


    @staticmethod
    def get_field_change_description(field_name: str, old_value: Any, new_value: Any) -> str:
        """
        Generate human-readable description of a field change

        Args:
            field_name: Name of changed field
            old_value: Previous value
            new_value: New value

        Returns:
            Human-readable description
        """
        if old_value is None:
            return f"Added {field_name}: {new_value}"
        elif new_value is None:
            return f"Removed {field_name}: {old_value}"
        else:
            return f"Changed {field_name}: {old_value} → {new_value}"
