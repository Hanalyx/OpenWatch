"""
Dependency Management Service for Compliance Rules
Handles rule dependencies, inheritance, and impact analysis
"""

import logging
from collections import defaultdict, deque
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from app.models.mongo_models import ComplianceRule
from app.repositories import ComplianceRuleRepository

logger = logging.getLogger(__name__)


class RuleDependencyGraph:
    """
    Manage rule dependency relationships

    Tracks:
    - Inheritance (parent -> children via inherits_from)
    - Requirements (rule -> required rules via dependencies.requires)
    - Conflicts (rule -> conflicting rules via dependencies.conflicts)
    - Related rules (via dependencies.related)
    """

    def __init__(self):
        # Core rule storage (can be ComplianceRule objects or dicts during validation)
        self.rules: Dict[str, Any] = {}

        # Inheritance relationships
        self.inheritance_parents: Dict[str, Optional[str]] = {}  # child -> parent
        self.inheritance_children: Dict[str, List[str]] = defaultdict(list)  # parent -> [children]

        # Dependency relationships
        self.requirements: Dict[str, List[str]] = defaultdict(list)  # rule -> [required_rules]
        self.required_by: Dict[str, List[str]] = defaultdict(list)  # rule -> [rules_that_require_this]

        # Conflict relationships
        self.conflicts: Dict[str, List[str]] = defaultdict(list)  # rule -> [conflicting_rules]

        # Related rules (informational only)
        self.related: Dict[str, List[str]] = defaultdict(list)  # rule -> [related_rules]

        # Repository Pattern: Centralized MongoDB access
        self._compliance_repo = ComplianceRuleRepository()

    async def build_from_database(self):
        """
        Build dependency graph from all rules in MongoDB

        Loads all ComplianceRule documents and builds relationship indexes
        """
        logger.info("Building dependency graph from MongoDB...")

        try:
            # OW-REFACTOR-002: Repository Pattern (MANDATORY)
            all_rules = await self._compliance_repo.find_many({})

            for rule in all_rules:
                self.add_rule(rule)

            logger.info(
                f"Dependency graph built: {len(self.rules)} rules, "
                f"{len(self.inheritance_parents)} inheritance relationships, "
                f"{sum(len(v) for v in self.requirements.values())} requirements"
            )

        except Exception as e:
            logger.error(f"Error building dependency graph: {e}")
            raise

    def add_rule(self, rule: ComplianceRule):
        """
        Add a single rule to the dependency graph

        Args:
            rule: ComplianceRule document to add
        """
        rule_id = rule.rule_id
        self.rules[rule_id] = rule

        # Build inheritance relationships
        if rule.inherits_from:
            self.inheritance_parents[rule_id] = rule.inherits_from
            self.inheritance_children[rule.inherits_from].append(rule_id)

        # Build requirement relationships
        if rule.dependencies:
            requires = rule.dependencies.get("requires", [])
            for required in requires:
                self.requirements[rule_id].append(required)
                self.required_by[required].append(rule_id)

            # Build conflict relationships
            conflicts = rule.dependencies.get("conflicts", [])
            self.conflicts[rule_id] = conflicts

            # Build related relationships
            related = rule.dependencies.get("related", [])
            self.related[rule_id] = related

    def add_rule_from_dict(self, rule_data: Dict[str, Any]):
        """
        Add a rule from dictionary (for new rules being uploaded)

        Args:
            rule_data: Rule dictionary with rule_id and relationships
        """
        rule_id = rule_data.get("rule_id")
        if not rule_id:
            return

        # Store basic info (not full ComplianceRule object)
        # This is used during upload validation before rules are created
        self.rules[rule_id] = rule_data

        # Build inheritance relationships
        parent = rule_data.get("inherits_from")
        if parent:
            self.inheritance_parents[rule_id] = parent
            self.inheritance_children[parent].append(rule_id)

        # Build dependency relationships
        dependencies = rule_data.get("dependencies", {})
        if dependencies:
            requires = dependencies.get("requires", [])
            for required in requires:
                self.requirements[rule_id].append(required)
                self.required_by[required].append(rule_id)

            conflicts = dependencies.get("conflicts", [])
            self.conflicts[rule_id] = conflicts

            related = dependencies.get("related", [])
            self.related[rule_id] = related

    def get_descendants(self, rule_id: str) -> List[str]:
        """
        Get all descendants of a rule (children, grandchildren, etc.)

        Uses BFS to traverse inheritance tree

        Args:
            rule_id: ID of parent rule

        Returns:
            List of all descendant rule IDs
        """
        descendants = []
        visited = set()
        queue = deque([rule_id])

        while queue:
            current = queue.popleft()

            # Skip if already visited or is the original rule
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

        Follows inheritance chain up to root

        Args:
            rule_id: ID of child rule

        Returns:
            List of all ancestor rule IDs (ordered from immediate parent to root)
        """
        ancestors = []
        current = self.inheritance_parents.get(rule_id)

        while current:
            ancestors.append(current)
            current = self.inheritance_parents.get(current)

        return ancestors

    def get_inheritance_depth(self, rule_id: str) -> int:
        """
        Get inheritance depth (distance from root)

        Args:
            rule_id: Rule ID

        Returns:
            Depth (0 for root rules, 1 for direct children, etc.)
        """
        return len(self.get_ancestors(rule_id))

    def get_impact_analysis(self, updated_rules: List[str]) -> Dict[str, Any]:
        """
        Analyze impact of updating specific rules

        Args:
            updated_rules: List of rule IDs being updated

        Returns:
            Detailed impact analysis including affected rules
        """
        impact: Dict[str, Any] = {
            "updated_rules": updated_rules,
            "updated_rules_count": len(updated_rules),
            "total_affected_rules": 0,
            "affected_by_rule": {},
            "inheritance_impacts": [],
            "dependency_impacts": [],
            "conflict_warnings": [],
        }

        all_affected = set()

        for rule_id in updated_rules:
            # Get all affected relationships
            affected = {
                "direct_children": self.inheritance_children.get(rule_id, []),
                "all_descendants": self.get_descendants(rule_id),
                "dependent_rules": self.required_by.get(rule_id, []),
                "conflicting_rules": self.conflicts.get(rule_id, []),
            }

            impact["affected_by_rule"][rule_id] = affected

            # Track inheritance impacts
            if affected["direct_children"]:
                impact["inheritance_impacts"].append(
                    {
                        "parent_rule": rule_id,
                        "direct_children_count": len(affected["direct_children"]),
                        "total_descendants_count": len(affected["all_descendants"]),
                        "direct_children": affected["direct_children"],
                        "severity": ("high" if len(affected["all_descendants"]) > 10 else "medium"),
                    }
                )

                all_affected.update(affected["all_descendants"])

            # Track dependency impacts
            if affected["dependent_rules"]:
                impact["dependency_impacts"].append(
                    {
                        "required_rule": rule_id,
                        "dependent_rules_count": len(affected["dependent_rules"]),
                        "dependent_rules": affected["dependent_rules"],
                        "severity": ("high" if len(affected["dependent_rules"]) > 5 else "medium"),
                    }
                )

                all_affected.update(affected["dependent_rules"])

            # Track conflicts
            if affected["conflicting_rules"]:
                impact["conflict_warnings"].append(
                    {
                        "rule": rule_id,
                        "conflicts_with": affected["conflicting_rules"],
                        "conflict_count": len(affected["conflicting_rules"]),
                        "severity": "warning",
                    }
                )

        impact["total_affected_rules"] = len(all_affected)

        return impact

    def validate_dependencies(self, new_rules: List[Dict[str, Any]], check_existing_db: bool = True) -> Dict[str, Any]:
        """
        Validate that all dependencies are satisfied for new rules

        Args:
            new_rules: List of new rule dictionaries being uploaded
            check_existing_db: Whether to check against existing DB rules

        Returns:
            Validation result with missing/circular dependencies
        """
        validation: Dict[str, Any] = {"valid": True, "errors": [], "warnings": []}

        # Build set of new rule IDs
        new_rule_ids = {rule.get("rule_id") for rule in new_rules if rule.get("rule_id")}

        for rule in new_rules:
            rule_id = rule.get("rule_id")
            if not rule_id:
                validation["errors"].append(
                    {
                        "type": "missing_rule_id",
                        "message": "Rule missing rule_id field",
                        "severity": "error",
                    }
                )
                validation["valid"] = False
                continue

            # Validate parent exists
            parent = rule.get("inherits_from")
            if parent:
                parent_exists = parent in new_rule_ids or (check_existing_db and parent in self.rules)

                if not parent_exists:
                    validation["valid"] = False
                    validation["errors"].append(
                        {
                            "rule_id": rule_id,
                            "type": "missing_parent",
                            "message": f"Parent rule '{parent}' not found",
                            "severity": "error",
                            "field": "inherits_from",
                        }
                    )

            # Validate required dependencies exist
            dependencies = rule.get("dependencies", {})
            requires = dependencies.get("requires", [])
            for required in requires:
                required_exists = required in new_rule_ids or (check_existing_db and required in self.rules)

                if not required_exists:
                    validation["valid"] = False
                    validation["errors"].append(
                        {
                            "rule_id": rule_id,
                            "type": "missing_dependency",
                            "message": f"Required rule '{required}' not found",
                            "severity": "error",
                            "field": "dependencies.requires",
                        }
                    )

            # Warn about conflicts
            conflicts = dependencies.get("conflicts", [])
            for conflict in conflicts:
                conflict_exists = conflict in new_rule_ids or (check_existing_db and conflict in self.rules)

                if conflict_exists:
                    validation["warnings"].append(
                        {
                            "rule_id": rule_id,
                            "type": "conflict",
                            "message": f"Rule conflicts with '{conflict}' which exists",
                            "severity": "warning",
                            "field": "dependencies.conflicts",
                        }
                    )

        # Check for circular dependencies
        circular = self._detect_circular_dependencies(new_rules)
        if circular:
            validation["valid"] = False
            for chain in circular:
                validation["errors"].append(
                    {
                        "type": "circular_dependency",
                        "message": f"Circular dependency detected: {' -> '.join(chain)}",
                        "chain": chain,
                        "severity": "error",
                    }
                )

        return validation

    def _detect_circular_dependencies(self, new_rules: List[Dict[str, Any]]) -> List[List[str]]:
        """
        Detect circular inheritance chains in new rules

        Args:
            new_rules: List of rule dictionaries

        Returns:
            List of circular dependency chains
        """
        # Build temporary inheritance map from new rules
        inheritance = {}
        for rule in new_rules:
            rule_id = rule.get("rule_id")
            parent = rule.get("inherits_from")
            if rule_id and parent:
                inheritance[rule_id] = parent

        circular_chains = []
        checked = set()

        for rule_id in inheritance:
            if rule_id in checked:
                continue

            visited: List[str] = []
            current = rule_id

            # Follow inheritance chain
            while current in inheritance:
                if current in visited:
                    # Found circular dependency
                    cycle_start = visited.index(current)
                    chain = visited[cycle_start:] + [current]
                    circular_chains.append(chain)
                    break

                visited.append(current)
                current = inheritance[current]

            # Mark all nodes in this path as checked
            checked.update(visited)

        return circular_chains

    def get_rule(self, rule_id: str) -> Optional[Union[ComplianceRule, Dict]]:
        """
        Get rule by ID

        Args:
            rule_id: Rule ID

        Returns:
            ComplianceRule object or dict, or None if not found
        """
        return self.rules.get(rule_id)

    def rule_exists(self, rule_id: str) -> bool:
        """
        Check if rule exists in graph

        Args:
            rule_id: Rule ID

        Returns:
            True if rule exists
        """
        return rule_id in self.rules

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get dependency graph statistics

        Returns:
            Statistics dictionary
        """
        return {
            "total_rules": len(self.rules),
            "rules_with_parents": len(self.inheritance_parents),
            "abstract_rules": sum(
                1 for rule in self.rules.values() if isinstance(rule, ComplianceRule) and rule.abstract
            ),
            "root_rules": len(self.rules) - len(self.inheritance_parents),
            "total_inheritance_relationships": len(self.inheritance_parents),
            "total_requirement_relationships": sum(len(v) for v in self.requirements.values()),
            "total_conflict_relationships": sum(len(v) for v in self.conflicts.values()),
            "max_inheritance_depth": max(
                (self.get_inheritance_depth(rule_id) for rule_id in self.rules),
                default=0,
            ),
            "rules_with_most_children": sorted(
                ((rule_id, len(children)) for rule_id, children in self.inheritance_children.items()),
                key=lambda x: x[1],
                reverse=True,
            )[:5],
        }


# Inheritable field definitions
INHERITABLE_FIELDS = {
    "severity",
    "category",
    "tags",
    "frameworks",
    "remediation_complexity",
    "remediation_risk",
    "base_parameters",
    "inheritable_properties",
    "security_function",
}

NON_INHERITABLE_FIELDS = {
    "rule_id",
    "scap_rule_id",
    "metadata",
    "platform_implementations",
    "check_type",
    "check_content",
    "fix_content",
    "source_file",
    "source_hash",
    "imported_at",
    "updated_at",
}


class InheritanceResolver:
    """
    Resolve inheritance when parent rules are updated

    Determines which child rules need updates when parent changes,
    respecting child overrides
    """

    def __init__(self, dependency_graph: RuleDependencyGraph):
        self.graph = dependency_graph

    async def resolve_parent_update(
        self, parent_rule_id: str, parent_changes: Dict[str, Any], dry_run: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Determine which child rules need updates when parent changes

        Args:
            parent_rule_id: ID of updated parent rule
            parent_changes: Dict of changed fields with old/new values
            dry_run: If True, only report what would change (don't apply)

        Returns:
            List of child rule updates needed
        """
        updates = []

        # Get all descendants (children, grandchildren, etc.)
        descendants = self.graph.get_descendants(parent_rule_id)

        logger.info(f"Analyzing inheritance impact: {parent_rule_id} has " f"{len(descendants)} descendants")

        for child_id in descendants:
            child_rule = self.graph.rules.get(child_id)
            if not child_rule:
                logger.warning(f"Descendant rule {child_id} not found in graph")
                continue

            # Only process ComplianceRule objects (not dicts)
            if not isinstance(child_rule, ComplianceRule):
                continue

            child_updates = {}

            # Check each changed field
            for field, change in parent_changes.items():
                # Skip if not inheritable
                if field not in INHERITABLE_FIELDS:
                    logger.debug(f"Field {field} not inheritable - skip")
                    continue

                # Check if child explicitly overrides this field
                if self._child_overrides_field(child_rule, field):
                    logger.debug(f"{child_id} overrides {field} - skip inheritance")
                    continue

                # Child should inherit this change
                child_updates[field] = change["new"]

            # If any updates needed, record them
            if child_updates:
                updates.append(
                    {
                        "rule_id": child_id,
                        "inherited_from": parent_rule_id,
                        "updates": child_updates,
                        "update_count": len(child_updates),
                        "action": "dry_run" if dry_run else "update",
                    }
                )

        logger.info(f"Inheritance resolution: {len(updates)} child rules need updates")

        return updates

    def _child_overrides_field(self, child_rule: ComplianceRule, field: str) -> bool:
        """
        Check if child rule explicitly overrides a field

        Args:
            child_rule: Child ComplianceRule
            field: Field name to check

        Returns:
            True if child overrides this field
        """
        # Check parameter_overrides dict
        if child_rule.parameter_overrides:
            if field in child_rule.parameter_overrides:
                return True

        # For specific fields, check if child has own non-default value
        if field == "metadata":
            # Child always has own metadata
            return True

        if field in ["platform_implementations", "check_content", "fix_content"]:
            # Platform-specific fields are never inherited
            return True

        # Check if child has explicit value different from default
        child_value = getattr(child_rule, field, None)

        # If child has a non-None value, consider it an override
        # (This is a simple heuristic - could be made more sophisticated)
        if child_value is not None:
            # Check if it's a non-empty collection
            if isinstance(child_value, (list, dict)):
                return len(child_value) > 0
            # Non-empty string
            if isinstance(child_value, str):
                return len(child_value) > 0
            # Any other non-None value
            return True

        return False

    async def apply_inheritance_updates(self, updates: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Apply inheritance updates to child rules

        Args:
            updates: List of updates from resolve_parent_update()

        Returns:
            Results with counts of applied updates
        """
        results: Dict[str, Any] = {"applied": 0, "failed": 0, "errors": []}

        for update_spec in updates:
            rule_id = update_spec["rule_id"]
            updates_dict = update_spec["updates"]

            try:
                # Get child rule from database
                # OW-REFACTOR-002: Repository Pattern (MANDATORY)
                child_rule = await self._compliance_repo.find_one({"rule_id": rule_id})

                if not child_rule:
                    results["failed"] += 1
                    results["errors"].append({"rule_id": rule_id, "error": "Rule not found in database"})
                    continue

                # Build update document
                update_fields = dict(updates_dict)
                update_fields["updated_at"] = datetime.utcnow()

                # Repository Pattern: Use update_one() for updates
                await self._compliance_repo.update_one(
                    {"rule_id": rule_id},
                    {"$set": update_fields},
                )

                results["applied"] += 1
                logger.info(f"Applied inheritance updates to {rule_id}")

            except Exception as e:
                results["failed"] += 1
                results["errors"].append({"rule_id": rule_id, "error": str(e)})
                logger.error(f"Failed to apply updates to {rule_id}: {e}")

        return results
