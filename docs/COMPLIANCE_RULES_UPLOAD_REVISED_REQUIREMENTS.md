# Compliance Rules Upload - Revised Requirements Analysis

**Date:** 2025-10-09
**Purpose:** Assess revised requirements against current implementation
**Status:** Requirements clarified - Ready for implementation design

---

## User Requirements (Clarified)

### 1. Archive Format: BSON (Binary JSON) - **CRITICAL CHANGE**

**User Requirement:**
> "The compliance rules file will format to Binary JSON"

**Current Implementation:**
- ❌ Assessment assumed plain JSON files in tar.gz
- ❌ No BSON parsing/validation implemented
- ✅ MongoDB already uses BSON internally (pymongo 4.9.2, motor 3.6.0)
- ✅ Beanie ODM supports BSON natively

**Impact Analysis:**

#### What is BSON?
- **Binary JSON** - MongoDB's native storage format
- More efficient than text JSON (binary encoding)
- Supports additional data types (ObjectId, Binary, Decimal128, etc.)
- Smaller file sizes for large datasets
- Faster parsing than JSON

#### Archive Structure (Revised):

**Option A: BSON files in tar.gz** (Most likely)
```
compliance_rules_v1.0.0.tar.gz
├── manifest.bson                 # Archive metadata in BSON
├── ow-rhel9-001.bson            # Individual rule files in BSON
├── ow-rhel9-002.bson
├── ow-ubuntu2204-001.bson
└── checksums.sha512             # SHA-512 checksums
```

**Option B: Single BSON archive** (Alternative)
```
compliance_rules_v1.0.0.bson     # Single BSON file (not tar.gz)
```

**Recommendation:** Option A (BSON files in tar.gz) - Maintains granular file structure while using binary format.

#### Required Changes:

1. **BSON Parsing** (NEW)
   ```python
   import bson
   from bson import decode_all, decode_file_iter

   # Instead of json.load()
   with open('ow-rhel9-001.bson', 'rb') as f:
       rule_data = bson.decode(f.read())
   ```

2. **BSON Validation** (NEW)
   - Validate BSON structure before decoding
   - Handle BSON-specific types (ObjectId, Binary, etc.)
   - Convert BSON types to Pydantic-compatible types

3. **Archive Extraction** (Modified)
   ```python
   # Look for .bson files instead of .json
   bson_files = list(extracted_path.glob("**/*.bson"))
   ```

4. **Security Validation** (Enhanced)
   - Check for BSON bombs (malicious BSON that expands massively)
   - Validate BSON document size limits
   - Check for recursive BSON structures

**PyMongo BSON Support:**
```python
from bson import decode, encode, BSON
from bson.json_util import dumps, loads  # For JSON ↔ BSON conversion

# Decode BSON file
with open('rule.bson', 'rb') as f:
    bson_data = f.read()
    rule_dict = decode(bson_data)

# Validate against Pydantic model
rule = ComplianceRule(**rule_dict)
```

---

### 2. Deduplication Strategy: Smart Update - **ENHANCED LOGIC**

**User Requirement:**
> "No duplicates allowed. If rule_id already exists: 1) Skip if no changes, 2) Update if changed"

**Current Implementation:**
- ✅ `scap_import_service.py` has deduplication logic
- ❌ Only supports: `skip_existing`, `update_existing`, `replace_all`
- ❌ Does NOT detect if content actually changed

**Required Enhancement:**

#### Smart Deduplication Algorithm:

```python
async def smart_deduplication(existing_rule: ComplianceRule, new_rule_data: Dict) -> str:
    """
    Detect if rule content changed and update accordingly

    Returns: 'skipped' | 'updated'
    """

    # Step 1: Calculate content hash of existing rule
    existing_hash = calculate_rule_hash(existing_rule)

    # Step 2: Calculate content hash of new rule
    new_hash = calculate_rule_hash(new_rule_data)

    # Step 3: Compare hashes
    if existing_hash == new_hash:
        logger.info(f"Rule {existing_rule.rule_id}: No changes detected - SKIPPED")
        return 'skipped'

    # Step 4: Detect what changed
    changes = detect_changes(existing_rule, new_rule_data)
    logger.info(f"Rule {existing_rule.rule_id}: Changes detected - {changes}")

    # Step 5: Update only changed fields
    await update_rule_fields(existing_rule, new_rule_data, changes)

    return 'updated'


def calculate_rule_hash(rule: Union[ComplianceRule, Dict]) -> str:
    """
    Calculate SHA-256 hash of rule content (excluding timestamps)
    """
    import hashlib
    import json

    # Convert to dict if Pydantic model
    if isinstance(rule, ComplianceRule):
        rule_dict = rule.dict()
    else:
        rule_dict = rule

    # Exclude metadata that changes on every import
    exclude_fields = {'imported_at', 'updated_at', 'source_file', 'source_hash'}

    # Create normalized dict for hashing
    normalized = {
        k: v for k, v in sorted(rule_dict.items())
        if k not in exclude_fields
    }

    # Calculate hash
    content_json = json.dumps(normalized, sort_keys=True)
    return hashlib.sha256(content_json.encode()).hexdigest()


def detect_changes(existing: ComplianceRule, new_data: Dict) -> Dict[str, Any]:
    """
    Detect which fields changed between existing and new rule

    Returns: {
        'field_name': {'old': old_value, 'new': new_value}
    }
    """
    changes = {}

    exclude_fields = {'imported_at', 'updated_at', 'source_file', 'source_hash'}

    existing_dict = existing.dict()

    for field, new_value in new_data.items():
        if field in exclude_fields:
            continue

        old_value = existing_dict.get(field)

        if old_value != new_value:
            changes[field] = {
                'old': old_value,
                'new': new_value
            }

    return changes
```

**Statistics Tracking:**
```python
import_stats = {
    'imported': 0,      # New rules added
    'updated': 0,       # Existing rules modified
    'skipped': 0,       # No changes detected
    'errors': 0,        # Validation/import failures
    'details': {
        'metadata_updates': 0,
        'framework_updates': 0,
        'platform_updates': 0,
        'check_content_updates': 0,
        'fix_content_updates': 0
    }
}
```

---

### 3. Dependency-Aware Updates: Software Update Model - **NEW REQUIREMENT**

**User Requirement:**
> "The compliance rules will be like a software update. It only impacts what needs to be changed. Since the OpenWatch compliance rules approach have inheritance, support for multiple platforms, and cross framework mapping, like software we have to account for those dependencies."

**Current Implementation:**
- ✅ ComplianceRule model has `inherits_from`, `parent_rule_id`, `derived_rules`
- ✅ ComplianceRule model has `dependencies: {requires: [], conflicts: [], related: []}`
- ❌ No dependency validation during import
- ❌ No dependency graph traversal
- ❌ No impact analysis for rule updates

**Critical Requirements:**

#### 3.1 Dependency Graph Analysis

**Problem:** Updating a parent rule must trigger updates to derived rules

**Example Scenario:**
```
ow-base-password-policy (abstract rule)
    ├── ow-rhel9-password-policy (inherits_from: ow-base-password-policy)
    ├── ow-ubuntu2204-password-policy (inherits_from: ow-base-password-policy)
    └── ow-windows2022-password-policy (inherits_from: ow-base-password-policy)
```

**If** `ow-base-password-policy` is updated (e.g., minimum password length changed from 12 → 14):
- **Then** all derived rules must be evaluated
- Check if derived rules override the changed property
- If not overridden, derived rules inherit the new value
- Log impact: "3 rules affected by update to ow-base-password-policy"

**Required Implementation:**

```python
class DependencyGraph:
    """Manage rule dependency relationships"""

    def __init__(self):
        self.graph = {}  # rule_id → {parents: [], children: [], requires: [], conflicts: []}

    async def build_graph(self):
        """Build dependency graph from MongoDB"""
        all_rules = await ComplianceRule.find_all().to_list()

        for rule in all_rules:
            self.graph[rule.rule_id] = {
                'parents': [rule.inherits_from] if rule.inherits_from else [],
                'children': rule.derived_rules or [],
                'requires': rule.dependencies.get('requires', []),
                'conflicts': rule.dependencies.get('conflicts', []),
                'related': rule.dependencies.get('related', [])
            }

    def get_affected_rules(self, rule_id: str) -> Dict[str, List[str]]:
        """Get all rules affected by updating rule_id"""
        affected = {
            'direct_children': self.graph[rule_id]['children'],
            'transitive_children': self._get_transitive_children(rule_id),
            'dependent_rules': self._get_dependent_rules(rule_id),
            'conflicting_rules': self._get_conflicting_rules(rule_id)
        }
        return affected

    def _get_transitive_children(self, rule_id: str) -> List[str]:
        """Get all descendants (children, grandchildren, etc.)"""
        visited = set()
        queue = [rule_id]

        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)

            children = self.graph.get(current, {}).get('children', [])
            queue.extend(children)

        visited.discard(rule_id)  # Remove self
        return list(visited)


async def analyze_update_impact(updated_rules: List[str]) -> Dict[str, Any]:
    """
    Analyze impact of updating rules on entire rule set

    Returns impact analysis with affected rules and recommendations
    """
    graph = DependencyGraph()
    await graph.build_graph()

    impact = {
        'updated_rules_count': len(updated_rules),
        'affected_rules': {},
        'inheritance_chains': [],
        'dependency_warnings': [],
        'conflict_warnings': []
    }

    for rule_id in updated_rules:
        affected = graph.get_affected_rules(rule_id)

        impact['affected_rules'][rule_id] = affected

        # Check for inheritance impact
        if affected['direct_children']:
            impact['inheritance_chains'].append({
                'parent': rule_id,
                'children': affected['direct_children'],
                'transitive_count': len(affected['transitive_children'])
            })

        # Check for dependency warnings
        if affected['dependent_rules']:
            impact['dependency_warnings'].append({
                'rule': rule_id,
                'dependent_rules': affected['dependent_rules'],
                'message': f"{len(affected['dependent_rules'])} rules require {rule_id}"
            })

        # Check for conflicts
        if affected['conflicting_rules']:
            impact['conflict_warnings'].append({
                'rule': rule_id,
                'conflicting_rules': affected['conflicting_rules'],
                'message': f"Warning: {rule_id} conflicts with {len(affected['conflicting_rules'])} rules"
            })

    return impact
```

#### 3.2 Rule Inheritance Resolution

**Problem:** When parent rule updated, determine if child rules need updates

```python
async def resolve_inheritance_updates(
    parent_rule_id: str,
    parent_changes: Dict[str, Any],
    dry_run: bool = False
) -> List[Dict]:
    """
    Resolve inheritance when parent rule is updated

    Args:
        parent_rule_id: ID of updated parent rule
        parent_changes: Dict of changed fields
        dry_run: If True, only report what would change

    Returns:
        List of child rule updates needed
    """
    updates_needed = []

    # Find all derived rules
    derived_rules = await ComplianceRule.find(
        ComplianceRule.inherits_from == parent_rule_id
    ).to_list()

    for child_rule in derived_rules:
        child_updates = {}

        for field, change in parent_changes.items():
            # Check if child overrides this field
            if field in child_rule.parameter_overrides:
                # Child explicitly overrides - no inheritance
                logger.debug(f"{child_rule.rule_id} overrides {field} - skip inheritance")
                continue

            # Check if field is inheritable
            if field in INHERITABLE_FIELDS:
                child_updates[field] = change['new']

        if child_updates:
            updates_needed.append({
                'rule_id': child_rule.rule_id,
                'inherited_from': parent_rule_id,
                'updates': child_updates,
                'action': 'dry_run' if dry_run else 'update'
            })

    return updates_needed


INHERITABLE_FIELDS = {
    'severity',
    'remediation_complexity',
    'remediation_risk',
    'check_type',
    'frameworks',  # Can be inherited and extended
    'tags',        # Can be inherited and extended
    'base_parameters'  # Explicitly designed for inheritance
}

NON_INHERITABLE_FIELDS = {
    'rule_id',
    'scap_rule_id',
    'metadata',  # Child has own metadata
    'platform_implementations',  # Always platform-specific
    'check_content',  # Platform-specific
    'fix_content'     # Platform-specific
}
```

#### 3.3 Dependency Validation

**Problem:** Ensure required rules exist before importing dependent rules

```python
async def validate_dependencies(
    new_rules: List[Dict],
    existing_rules_in_db: bool = True
) -> Dict[str, Any]:
    """
    Validate all dependencies are satisfied

    Returns validation result with missing dependencies
    """
    validation = {
        'valid': True,
        'missing_dependencies': [],
        'circular_dependencies': [],
        'conflicts': []
    }

    # Build map of new rule IDs
    new_rule_ids = {rule['rule_id'] for rule in new_rules}

    for rule in new_rules:
        rule_id = rule['rule_id']

        # Check parent exists
        if rule.get('inherits_from'):
            parent_id = rule['inherits_from']

            # Check in new rules or existing DB
            parent_exists = (
                parent_id in new_rule_ids or
                (existing_rules_in_db and await rule_exists(parent_id))
            )

            if not parent_exists:
                validation['valid'] = False
                validation['missing_dependencies'].append({
                    'rule_id': rule_id,
                    'missing_parent': parent_id,
                    'type': 'inheritance'
                })

        # Check required dependencies
        for required_rule in rule.get('dependencies', {}).get('requires', []):
            required_exists = (
                required_rule in new_rule_ids or
                (existing_rules_in_db and await rule_exists(required_rule))
            )

            if not required_exists:
                validation['valid'] = False
                validation['missing_dependencies'].append({
                    'rule_id': rule_id,
                    'missing_required': required_rule,
                    'type': 'requires'
                })

        # Check for conflicts
        for conflict_rule in rule.get('dependencies', {}).get('conflicts', []):
            conflict_exists = (
                conflict_rule in new_rule_ids or
                (existing_rules_in_db and await rule_exists(conflict_rule))
            )

            if conflict_exists:
                validation['conflicts'].append({
                    'rule_id': rule_id,
                    'conflicts_with': conflict_rule
                })

    # Check for circular dependencies
    circular = detect_circular_dependencies(new_rules)
    if circular:
        validation['valid'] = False
        validation['circular_dependencies'] = circular

    return validation


async def rule_exists(rule_id: str) -> bool:
    """Check if rule exists in MongoDB"""
    count = await ComplianceRule.find(ComplianceRule.rule_id == rule_id).count()
    return count > 0


def detect_circular_dependencies(rules: List[Dict]) -> List[List[str]]:
    """Detect circular inheritance chains"""
    # Build inheritance graph
    graph = {rule['rule_id']: rule.get('inherits_from') for rule in rules}

    circular_chains = []

    for rule_id in graph:
        visited = set()
        current = rule_id

        while current:
            if current in visited:
                # Found circular dependency - trace the chain
                chain = [current]
                next_id = graph.get(current)
                while next_id != current:
                    chain.append(next_id)
                    next_id = graph.get(next_id)
                chain.append(current)

                circular_chains.append(chain)
                break

            visited.add(current)
            current = graph.get(current)

    return circular_chains
```

#### 3.4 Upload Process with Dependency Analysis

**Enhanced Upload Flow:**

```
1. Extract BSON archive
2. Parse manifest.bson
3. Parse all rule BSON files
4. Build dependency graph from new rules
5. Validate dependencies (missing parents, circular deps, conflicts)
6. Calculate content hashes for existing rules
7. For each new rule:
   a. Check if exists in DB
   b. If exists: Compare hash → Skip if unchanged, Update if changed
   c. If new: Validate dependencies → Import
   d. If updated: Analyze inheritance impact → Update derived rules if needed
8. Generate impact report
9. Commit to MongoDB (transaction for atomicity)
10. Return detailed results
```

**Impact Report Example:**
```json
{
  "upload_id": "uuid-1234",
  "success": true,
  "statistics": {
    "total_rules_in_archive": 1584,
    "imported": 42,
    "updated": 18,
    "skipped": 1524,
    "errors": 0
  },
  "dependency_impact": {
    "inheritance_chains_affected": 3,
    "total_derived_rules_updated": 12,
    "details": [
      {
        "parent_rule": "ow-base-password-policy",
        "change": "severity: medium → high",
        "affected_children": ["ow-rhel9-password-policy", "ow-ubuntu2204-password-policy"],
        "auto_updated": true
      }
    ]
  },
  "field_change_summary": {
    "metadata_updates": 5,
    "framework_updates": 8,
    "platform_updates": 3,
    "check_content_updates": 2,
    "severity_updates": 4
  }
}
```

---

### 4. Size Limits: Max 10,000 Rules - **CONFIRMED**

**User Requirement:**
> "Size limit: Max rules per upload: 10000"

**Current Implementation:**
- ❌ No limit enforced
- ✅ Batch processing exists (100 rules per batch in scap_import_service.py)

**Required Changes:**

```python
class ComplianceRulesSecurityService:
    MAX_RULES_COUNT = 10000  # User-specified limit

    async def _validate_archive_structure(self, extracted_path: Path) -> SecurityCheckResult:
        """Validate archive structure and rule count"""

        # Count BSON files (changed from JSON)
        bson_files = list(extracted_path.glob("**/*.bson"))
        bson_files = [f for f in bson_files if f.name != "manifest.bson"]

        if len(bson_files) > self.MAX_RULES_COUNT:
            return SecurityCheckResult(
                check_name="rule_count_limit",
                passed=False,
                severity="high",
                message=f"Archive contains {len(bson_files)} rules (max: {self.MAX_RULES_COUNT})"
            )

        return SecurityCheckResult(
            check_name="rule_count",
            passed=True,
            severity="info",
            message=f"Archive contains {len(bson_files)} rules"
        )
```

**No archive size limit specified** - Recommend still enforcing max archive size (e.g., 100MB for BSON) to prevent DoS attacks.

---

## Implementation Changes Required

### Summary of Changes:

| Component | Original Plan | Revised Requirement | Status |
|-----------|---------------|---------------------|--------|
| **Archive Format** | JSON files in tar.gz | **BSON files in tar.gz** | ⚠️ Change Required |
| **Deduplication** | Skip/Update/Replace all | **Smart: Skip unchanged, Update changed** | ⚠️ Enhancement Required |
| **Dependencies** | Basic validation | **Full dependency graph + inheritance resolution** | ⚠️ Major Addition |
| **Size Limit** | 50MB archive | **10,000 rules max** | ✅ Confirmed |

---

### 1. BSON Format Support - **NEW**

**Files to Create/Modify:**

#### `compliance_rules_bson_parser.py` (NEW)
```python
"""
BSON Parser for Compliance Rules
Handles Binary JSON parsing and validation
"""
import bson
from bson import decode, encode, BSON
from bson.errors import InvalidBSON
from pathlib import Path
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger(__name__)


class BSONParserService:
    """Parse and validate BSON compliance rule files"""

    MAX_BSON_SIZE = 16 * 1024 * 1024  # 16MB per BSON document (MongoDB limit)

    async def parse_bson_file(self, file_path: Path) -> Dict[str, Any]:
        """
        Parse a single BSON file

        Returns: Decoded dictionary
        Raises: InvalidBSON if parsing fails
        """
        try:
            # Check file size
            file_size = file_path.stat().st_size
            if file_size > self.MAX_BSON_SIZE:
                raise ValueError(f"BSON file too large: {file_size} bytes (max: {self.MAX_BSON_SIZE})")

            # Read and decode BSON
            with open(file_path, 'rb') as f:
                bson_data = f.read()

            # Decode BSON to Python dict
            decoded = bson.decode(bson_data)

            # Validate basic structure
            if not isinstance(decoded, dict):
                raise ValueError(f"BSON file did not decode to dictionary: {type(decoded)}")

            # Convert BSON-specific types to Python types
            normalized = self._normalize_bson_types(decoded)

            return normalized

        except InvalidBSON as e:
            logger.error(f"Invalid BSON in {file_path}: {e}")
            raise ValueError(f"Invalid BSON format: {str(e)}")
        except Exception as e:
            logger.error(f"Failed to parse BSON file {file_path}: {e}")
            raise

    async def parse_manifest_bson(self, manifest_path: Path) -> Dict[str, Any]:
        """Parse manifest.bson file"""
        manifest = await self.parse_bson_file(manifest_path)

        # Validate required manifest fields
        required_fields = ['name', 'version', 'rules_count', 'created_at']
        missing = [f for f in required_fields if f not in manifest]

        if missing:
            raise ValueError(f"Manifest missing required fields: {missing}")

        return manifest

    async def parse_all_rule_bson_files(self, extracted_path: Path) -> List[Dict[str, Any]]:
        """Parse all .bson rule files in directory"""
        bson_files = list(extracted_path.glob("**/*.bson"))

        # Exclude manifest
        bson_files = [f for f in bson_files if f.name != "manifest.bson"]

        rules = []
        errors = []

        for bson_file in bson_files:
            try:
                rule_data = await self.parse_bson_file(bson_file)
                rules.append(rule_data)
            except Exception as e:
                errors.append({
                    'file': str(bson_file),
                    'error': str(e)
                })

        if errors:
            logger.warning(f"Failed to parse {len(errors)} BSON files")

        return rules

    def _normalize_bson_types(self, data: Any) -> Any:
        """
        Normalize BSON-specific types to Python types

        Handles:
        - ObjectId → str
        - Binary → bytes
        - Decimal128 → float
        - datetime (already Python type)
        """
        from bson import ObjectId, Binary, Decimal128

        if isinstance(data, ObjectId):
            return str(data)

        elif isinstance(data, Binary):
            return data

        elif isinstance(data, Decimal128):
            return float(data.to_decimal())

        elif isinstance(data, dict):
            return {k: self._normalize_bson_types(v) for k, v in data.items()}

        elif isinstance(data, list):
            return [self._normalize_bson_types(item) for item in data]

        else:
            return data

    def validate_bson_structure(self, bson_data: bytes) -> bool:
        """
        Validate BSON structure without full parsing

        Returns True if valid BSON structure
        """
        try:
            # Quick validation - just check if decodable
            decoded = bson.decode(bson_data)
            return isinstance(decoded, dict)
        except InvalidBSON:
            return False
```

#### `compliance_rules_security_service.py` (MODIFIED)
```python
async def _validate_archive_structure(self, extracted_path: Path) -> SecurityCheckResult:
    """Validate archive has required structure (BSON files)"""

    # Check for manifest.bson (CHANGED from manifest.json)
    manifest_path = extracted_path / "manifest.bson"
    if not manifest_path.exists():
        # Fallback: check for manifest.json (backward compatibility)
        manifest_json = extracted_path / "manifest.json"
        if not manifest_json.exists():
            return SecurityCheckResult(
                check_name="archive_structure",
                passed=False,
                severity="critical",
                message="Archive missing required manifest.bson or manifest.json"
            )

    # Count BSON files (CHANGED from JSON files)
    bson_files = list(extracted_path.glob("**/*.bson"))
    bson_files = [f for f in bson_files if f.name != "manifest.bson"]

    # Also check for JSON files (backward compatibility)
    json_files = list(extracted_path.glob("**/*.json"))
    json_files = [f for f in json_files if f.name not in ["manifest.json", "checksums.sha512"]]

    total_rule_files = len(bson_files) + len(json_files)

    if total_rule_files == 0:
        return SecurityCheckResult(
            check_name="archive_structure",
            passed=False,
            severity="high",
            message="Archive contains no rule files (.bson or .json)"
        )

    if total_rule_files > self.MAX_RULES_COUNT:
        return SecurityCheckResult(
            check_name="rule_count_limit",
            passed=False,
            severity="high",
            message=f"Archive contains {total_rule_files} rules (max: {self.MAX_RULES_COUNT})"
        )

    return SecurityCheckResult(
        check_name="archive_structure",
        passed=True,
        severity="info",
        message=f"Archive structure valid ({len(bson_files)} BSON, {len(json_files)} JSON files)",
        details={
            "bson_files": len(bson_files),
            "json_files": len(json_files),
            "total_rules": total_rule_files
        }
    )
```

---

### 2. Smart Deduplication Service - **NEW**

#### `compliance_rules_deduplication_service.py` (NEW)
```python
"""
Smart Deduplication Service
Detects content changes and updates only modified rules
"""
import hashlib
import json
from typing import Dict, Any, Tuple, List
from datetime import datetime
import logging

from backend.app.models.mongo_models import ComplianceRule

logger = logging.getLogger(__name__)


class SmartDeduplicationService:
    """Intelligent deduplication with change detection"""

    # Fields excluded from hash calculation (metadata that always changes)
    EXCLUDED_FROM_HASH = {
        'imported_at',
        'updated_at',
        'source_file',
        'source_hash'
    }

    # Fields tracked for statistics
    TRACKED_FIELD_CATEGORIES = {
        'metadata': ['metadata'],
        'frameworks': ['frameworks'],
        'platforms': ['platform_implementations'],
        'check_content': ['check_type', 'check_content'],
        'fix_content': ['fix_available', 'fix_content', 'manual_remediation'],
        'severity': ['severity', 'remediation_risk', 'remediation_complexity'],
        'inheritance': ['inherits_from', 'derived_rules', 'base_parameters']
    }

    async def process_rule(
        self,
        rule_data: Dict[str, Any],
        existing_rule: ComplianceRule = None
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Process a single rule with smart deduplication

        Args:
            rule_data: New rule data from upload
            existing_rule: Existing rule from MongoDB (if exists)

        Returns:
            (action, details) where action is 'imported', 'updated', or 'skipped'
        """
        rule_id = rule_data['rule_id']

        if not existing_rule:
            # New rule - import
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
            return 'skipped', {
                'rule_id': rule_id,
                'action': 'skipped',
                'reason': 'No content changes detected',
                'content_hash': existing_hash
            }

        # Detect specific changes
        changes = self.detect_field_changes(existing_rule, rule_data)

        # Update rule
        return 'updated', {
            'rule_id': rule_id,
            'action': 'updated',
            'reason': 'Content changed',
            'changes': changes,
            'change_count': len(changes),
            'changed_categories': self.categorize_changes(changes)
        }

    def calculate_content_hash(self, rule: Any) -> str:
        """
        Calculate SHA-256 hash of rule content

        Args:
            rule: ComplianceRule model or dict

        Returns:
            Hex digest of content hash
        """
        # Convert to dict if Pydantic model
        if hasattr(rule, 'dict'):
            rule_dict = rule.dict()
        else:
            rule_dict = dict(rule)

        # Remove excluded fields
        normalized = {
            k: v for k, v in sorted(rule_dict.items())
            if k not in self.EXCLUDED_FROM_HASH
        }

        # Serialize to JSON (sorted keys for consistency)
        content_json = json.dumps(normalized, sort_keys=True, default=str)

        # Calculate SHA-256 hash
        return hashlib.sha256(content_json.encode()).hexdigest()

    def detect_field_changes(
        self,
        existing_rule: ComplianceRule,
        new_data: Dict[str, Any]
    ) -> Dict[str, Dict[str, Any]]:
        """
        Detect which specific fields changed

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

        existing_dict = existing_rule.dict()

        # Check for modified/added fields
        for field, new_value in new_data.items():
            if field in self.EXCLUDED_FROM_HASH:
                continue

            old_value = existing_dict.get(field)

            if old_value != new_value:
                if old_value is None:
                    change_type = 'added'
                else:
                    change_type = 'modified'

                changes[field] = {
                    'old': old_value,
                    'new': new_value,
                    'type': change_type
                }

        # Check for removed fields
        for field, old_value in existing_dict.items():
            if field in self.EXCLUDED_FROM_HASH:
                continue

            if field not in new_data and old_value is not None:
                changes[field] = {
                    'old': old_value,
                    'new': None,
                    'type': 'removed'
                }

        return changes

    def categorize_changes(self, changes: Dict[str, Any]) -> List[str]:
        """
        Categorize changes into high-level categories

        Returns:
            List of categories that changed (e.g., ['metadata', 'frameworks'])
        """
        categories = set()

        for field in changes.keys():
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
            Updated ComplianceRule (not yet saved)
        """
        # Update only changed fields
        for field, change in changes.items():
            setattr(existing_rule, field, change['new'])

        # Always update these metadata fields
        existing_rule.updated_at = datetime.utcnow()
        existing_rule.source_file = new_data.get('source_file', existing_rule.source_file)
        existing_rule.source_hash = new_data.get('source_hash', existing_rule.source_hash)
        existing_rule.version = new_data.get('version', existing_rule.version)

        return existing_rule
```

---

### 3. Dependency Management Service - **NEW**

#### `compliance_rules_dependency_service.py` (NEW)
```python
"""
Dependency Management Service
Handles rule dependencies, inheritance, and impact analysis
"""
from typing import Dict, List, Set, Any, Optional, Tuple
from collections import defaultdict, deque
import logging

from backend.app.models.mongo_models import ComplianceRule

logger = logging.getLogger(__name__)


class RuleDependencyGraph:
    """
    Manage rule dependency relationships

    Tracks:
    - Inheritance (parent → children via inherits_from)
    - Requirements (rule → required rules via dependencies.requires)
    - Conflicts (rule → conflicting rules via dependencies.conflicts)
    - Related rules (via dependencies.related)
    """

    def __init__(self):
        self.rules: Dict[str, ComplianceRule] = {}

        # Adjacency lists for different relationship types
        self.inheritance_parents: Dict[str, Optional[str]] = {}  # child → parent
        self.inheritance_children: Dict[str, List[str]] = defaultdict(list)  # parent → [children]

        self.requirements: Dict[str, List[str]] = defaultdict(list)  # rule → [required_rules]
        self.required_by: Dict[str, List[str]] = defaultdict(list)  # rule → [rules_that_require_this]

        self.conflicts: Dict[str, List[str]] = defaultdict(list)  # rule → [conflicting_rules]
        self.related: Dict[str, List[str]] = defaultdict(list)  # rule → [related_rules]

    async def build_from_database(self):
        """Build dependency graph from all rules in MongoDB"""
        logger.info("Building dependency graph from MongoDB...")

        all_rules = await ComplianceRule.find_all().to_list()

        for rule in all_rules:
            self.add_rule(rule)

        logger.info(f"Dependency graph built: {len(self.rules)} rules")

    def add_rule(self, rule: ComplianceRule):
        """Add a single rule to the dependency graph"""
        rule_id = rule.rule_id
        self.rules[rule_id] = rule

        # Inheritance relationships
        if rule.inherits_from:
            self.inheritance_parents[rule_id] = rule.inherits_from
            self.inheritance_children[rule.inherits_from].append(rule_id)

        # Requirement relationships
        if rule.dependencies:
            requires = rule.dependencies.get('requires', [])
            for required in requires:
                self.requirements[rule_id].append(required)
                self.required_by[required].append(rule_id)

            # Conflict relationships
            conflicts = rule.dependencies.get('conflicts', [])
            self.conflicts[rule_id] = conflicts

            # Related relationships
            related = rule.dependencies.get('related', [])
            self.related[rule_id] = related

    def get_descendants(self, rule_id: str) -> List[str]:
        """
        Get all descendants of a rule (children, grandchildren, etc.)

        Uses BFS to traverse inheritance tree
        """
        descendants = []
        visited = set()
        queue = deque([rule_id])

        while queue:
            current = queue.popleft()

            if current in visited or current == rule_id:
                continue

            visited.add(current)
            descendants.append(current)

            # Add children to queue
            children = self.inheritance_children.get(current, [])
            queue.extend(children)

        return descendants

    def get_ancestors(self, rule_id: str) -> List[str]:
        """
        Get all ancestors of a rule (parent, grandparent, etc.)
        """
        ancestors = []
        current = self.inheritance_parents.get(rule_id)

        while current:
            ancestors.append(current)
            current = self.inheritance_parents.get(current)

        return ancestors

    def get_impact_analysis(self, updated_rules: List[str]) -> Dict[str, Any]:
        """
        Analyze impact of updating specific rules

        Returns:
            Detailed impact analysis including affected rules
        """
        impact = {
            'updated_rules': updated_rules,
            'total_affected_rules': 0,
            'affected_by_rule': {},
            'inheritance_impacts': [],
            'dependency_impacts': [],
            'conflict_warnings': []
        }

        all_affected = set()

        for rule_id in updated_rules:
            affected = {
                'direct_children': self.inheritance_children.get(rule_id, []),
                'all_descendants': self.get_descendants(rule_id),
                'dependent_rules': self.required_by.get(rule_id, []),
                'conflicting_rules': self.conflicts.get(rule_id, [])
            }

            impact['affected_by_rule'][rule_id] = affected

            # Track inheritance impacts
            if affected['direct_children']:
                impact['inheritance_impacts'].append({
                    'parent_rule': rule_id,
                    'direct_children_count': len(affected['direct_children']),
                    'total_descendants_count': len(affected['all_descendants']),
                    'direct_children': affected['direct_children']
                })

                all_affected.update(affected['all_descendants'])

            # Track dependency impacts
            if affected['dependent_rules']:
                impact['dependency_impacts'].append({
                    'required_rule': rule_id,
                    'dependent_rules_count': len(affected['dependent_rules']),
                    'dependent_rules': affected['dependent_rules']
                })

                all_affected.update(affected['dependent_rules'])

            # Track conflicts
            if affected['conflicting_rules']:
                impact['conflict_warnings'].append({
                    'rule': rule_id,
                    'conflicts_with': affected['conflicting_rules'],
                    'severity': 'warning'
                })

        impact['total_affected_rules'] = len(all_affected)

        return impact

    def validate_dependencies(
        self,
        new_rules: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Validate that all dependencies are satisfied for new rules

        Returns:
            Validation result with missing/circular dependencies
        """
        validation = {
            'valid': True,
            'errors': [],
            'warnings': []
        }

        new_rule_ids = {rule['rule_id'] for rule in new_rules}

        for rule in new_rules:
            rule_id = rule['rule_id']

            # Validate parent exists
            parent = rule.get('inherits_from')
            if parent:
                parent_exists = (
                    parent in new_rule_ids or
                    parent in self.rules
                )

                if not parent_exists:
                    validation['valid'] = False
                    validation['errors'].append({
                        'rule_id': rule_id,
                        'type': 'missing_parent',
                        'message': f"Parent rule '{parent}' not found",
                        'severity': 'error'
                    })

            # Validate required dependencies exist
            requires = rule.get('dependencies', {}).get('requires', [])
            for required in requires:
                required_exists = (
                    required in new_rule_ids or
                    required in self.rules
                )

                if not required_exists:
                    validation['valid'] = False
                    validation['errors'].append({
                        'rule_id': rule_id,
                        'type': 'missing_dependency',
                        'message': f"Required rule '{required}' not found",
                        'severity': 'error'
                    })

            # Warn about conflicts
            conflicts = rule.get('dependencies', {}).get('conflicts', [])
            for conflict in conflicts:
                conflict_exists = (
                    conflict in new_rule_ids or
                    conflict in self.rules
                )

                if conflict_exists:
                    validation['warnings'].append({
                        'rule_id': rule_id,
                        'type': 'conflict',
                        'message': f"Rule conflicts with '{conflict}' which exists",
                        'severity': 'warning'
                    })

        # Check for circular dependencies
        circular = self._detect_circular_dependencies(new_rules)
        if circular:
            validation['valid'] = False
            for chain in circular:
                validation['errors'].append({
                    'type': 'circular_dependency',
                    'message': f"Circular dependency detected: {' → '.join(chain)}",
                    'chain': chain,
                    'severity': 'error'
                })

        return validation

    def _detect_circular_dependencies(
        self,
        new_rules: List[Dict[str, Any]]
    ) -> List[List[str]]:
        """Detect circular inheritance chains in new rules"""
        # Build temporary inheritance map
        inheritance = {}
        for rule in new_rules:
            rule_id = rule['rule_id']
            parent = rule.get('inherits_from')
            if parent:
                inheritance[rule_id] = parent

        circular_chains = []

        for rule_id in inheritance:
            visited = []
            current = rule_id

            while current in inheritance:
                if current in visited:
                    # Found circular dependency
                    cycle_start = visited.index(current)
                    chain = visited[cycle_start:] + [current]
                    circular_chains.append(chain)
                    break

                visited.append(current)
                current = inheritance[current]

        return circular_chains


# Inheritable field definitions
INHERITABLE_FIELDS = {
    'severity',
    'category',
    'tags',
    'frameworks',
    'remediation_complexity',
    'remediation_risk',
    'base_parameters',
    'inheritable_properties'
}

NON_INHERITABLE_FIELDS = {
    'rule_id',
    'scap_rule_id',
    'metadata',
    'platform_implementations',
    'check_type',
    'check_content',
    'fix_content',
    'source_file',
    'source_hash'
}


class InheritanceResolver:
    """Resolve inheritance when parent rules are updated"""

    def __init__(self, dependency_graph: RuleDependencyGraph):
        self.graph = dependency_graph

    async def resolve_parent_update(
        self,
        parent_rule_id: str,
        parent_changes: Dict[str, Any],
        dry_run: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Determine which child rules need updates when parent changes

        Args:
            parent_rule_id: ID of updated parent rule
            parent_changes: Dict of changed fields with old/new values
            dry_run: If True, only report what would change

        Returns:
            List of child rule updates needed
        """
        updates = []

        # Get all descendants
        descendants = self.graph.get_descendants(parent_rule_id)

        for child_id in descendants:
            child_rule = self.graph.rules.get(child_id)
            if not child_rule:
                continue

            child_updates = {}

            for field, change in parent_changes.items():
                # Skip if not inheritable
                if field not in INHERITABLE_FIELDS:
                    continue

                # Check if child explicitly overrides this field
                if self._child_overrides_field(child_rule, field):
                    logger.debug(f"{child_id} overrides {field} - skip inheritance")
                    continue

                # Child should inherit this change
                child_updates[field] = change['new']

            if child_updates:
                updates.append({
                    'rule_id': child_id,
                    'inherited_from': parent_rule_id,
                    'updates': child_updates,
                    'action': 'dry_run' if dry_run else 'update'
                })

        return updates

    def _child_overrides_field(self, child_rule: ComplianceRule, field: str) -> bool:
        """Check if child rule explicitly overrides a field"""
        # Check parameter_overrides
        if child_rule.parameter_overrides:
            if field in child_rule.parameter_overrides:
                return True

        # For certain fields, check if child has own value
        if field in ['metadata', 'platform_implementations', 'check_content']:
            child_value = getattr(child_rule, field, None)
            if child_value:
                return True

        return False
```

---

## Revised Implementation Plan

### Phase 1: BSON Support (Week 1, Days 1-3)
- ✅ Create `BSONParserService`
- ✅ Modify security service to handle BSON files
- ✅ Add BSON validation to upload flow
- ✅ Update archive structure validation
- ✅ Test BSON parsing with sample files

### Phase 2: Smart Deduplication (Week 1, Days 4-5)
- ✅ Create `SmartDeduplicationService`
- ✅ Implement content hash calculation
- ✅ Implement change detection logic
- ✅ Add field-level change tracking
- ✅ Test with real rule updates

### Phase 3: Dependency Management (Week 2, Days 1-4)
- ✅ Create `RuleDependencyGraph`
- ✅ Implement dependency validation
- ✅ Implement circular dependency detection
- ✅ Create `InheritanceResolver`
- ✅ Implement parent update propagation
- ✅ Test inheritance chains

### Phase 4: Upload Service Integration (Week 2, Day 5 - Week 3, Day 2)
- ✅ Create `ComplianceRulesUploadService`
- ✅ Integrate all validation services
- ✅ Implement upload workflow
- ✅ Add impact analysis reporting
- ✅ Add transaction support for atomicity

### Phase 5: API & Frontend (Week 3, Days 3-5)
- ✅ Create upload endpoint
- ✅ Update frontend to call real API
- ✅ Add detailed error reporting
- ✅ Add upload history

### Phase 6: Testing & Documentation (Week 4)
- ✅ Create test BSON archives
- ✅ Test all dependency scenarios
- ✅ Test inheritance propagation
- ✅ Write comprehensive documentation

---

## Critical Success Factors

### 1. BSON Format Handling
- ✅ Properly parse BSON files with pymongo
- ✅ Handle BSON-specific types (ObjectId, Binary, etc.)
- ✅ Validate BSON structure before import
- ✅ Support backward compatibility with JSON

### 2. Smart Deduplication
- ✅ Accurate content hash calculation
- ✅ Field-level change detection
- ✅ Update only what changed (no unnecessary writes)
- ✅ Track update statistics by field category

### 3. Dependency Management
- ✅ Build complete dependency graph
- ✅ Validate all dependencies before import
- ✅ Detect circular dependencies
- ✅ Propagate parent updates to children
- ✅ Respect child overrides

### 4. Software Update Model
- ✅ Atomic transactions (all-or-nothing)
- ✅ Impact analysis before commit
- ✅ Detailed update report
- ✅ Rollback on validation failure

---

## Next Steps

1. **Create Sample BSON Archives**
   - Generate test compliance rules in BSON format
   - Include inheritance chains
   - Include dependency relationships
   - Include conflict scenarios

2. **Implement Core Services** (in order)
   - BSONParserService
   - SmartDeduplicationService
   - RuleDependencyGraph
   - InheritanceResolver

3. **Integration Testing**
   - Test with real BSON archives
   - Test inheritance propagation
   - Test dependency validation
   - Test circular dependency detection

4. **Performance Optimization**
   - Batch processing for 10,000 rules
   - Efficient hash calculation
   - Optimized dependency graph traversal

---

**Last Updated:** 2025-10-09
**Status:** Requirements Finalized - Ready for Implementation
