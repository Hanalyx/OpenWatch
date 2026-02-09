"""Rule dependency ordering and conflict detection.

This module provides topological sorting of rules based on dependency
relationships (depends_on, conflicts_with, supersedes).

Example:
    >>> from runner.ordering import order_rules, OrderingResult
    >>> result = order_rules(rules)
    >>> if result.cycles:
    ...     print(f"Circular dependencies: {result.cycles}")
    >>> for rule in result.ordered:
    ...     print(rule["id"])

"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class OrderingResult:
    """Result of rule ordering.

    Attributes:
        ordered: Rules in execution order (dependencies first).
        cycles: List of detected circular dependency chains.
        conflicts: List of (rule_id, conflicts_with_id) pairs both in set.
        superseded: Map of superseded_rule_id -> superseding_rule_id.
        skipped: Rule IDs skipped due to supersedes.

    """

    ordered: list[dict] = field(default_factory=list)
    cycles: list[list[str]] = field(default_factory=list)
    conflicts: list[tuple[str, str]] = field(default_factory=list)
    superseded: dict[str, str] = field(default_factory=dict)
    skipped: list[str] = field(default_factory=list)


def _detect_cycles(
    rule_ids: set[str],
    deps: dict[str, list[str]],
) -> list[list[str]]:
    """Detect cycles in dependency graph using DFS.

    Args:
        rule_ids: Set of all rule IDs.
        deps: Map of rule_id -> list of depends_on rule_ids.

    Returns:
        List of cycles, each cycle is a list of rule IDs forming the cycle.

    """
    WHITE, GRAY, BLACK = 0, 1, 2
    color = {rid: WHITE for rid in rule_ids}
    cycles = []

    def dfs(node: str, path: list[str]) -> None:
        if node not in color:
            return

        if color[node] == GRAY:
            # Found cycle - extract the cycle from path
            cycle_start = path.index(node)
            cycles.append(path[cycle_start:] + [node])
            return

        if color[node] == BLACK:
            return

        color[node] = GRAY
        path.append(node)

        for neighbor in deps.get(node, []):
            dfs(neighbor, path)

        path.pop()
        color[node] = BLACK

    for node in rule_ids:
        if color[node] == WHITE:
            dfs(node, [])

    return cycles


def _topological_sort(
    rule_ids: set[str],
    deps: dict[str, list[str]],
) -> list[str]:
    """Topological sort of rules based on dependencies.

    Args:
        rule_ids: Set of all rule IDs to sort.
        deps: Map of rule_id -> list of depends_on rule_ids.

    Returns:
        List of rule IDs in dependency order (dependencies first).

    """
    # Build in-degree counts
    in_degree = {rid: 0 for rid in rule_ids}
    for rid, dep_list in deps.items():
        if rid in in_degree:
            for dep in dep_list:
                if dep in in_degree:
                    in_degree[rid] += 1

    # Start with nodes that have no dependencies
    queue = [rid for rid, deg in in_degree.items() if deg == 0]
    result = []

    while queue:
        # Sort for deterministic ordering
        queue.sort()
        node = queue.pop(0)
        result.append(node)

        # Find nodes that depend on this one
        for rid, dep_list in deps.items():
            if node in dep_list and rid in in_degree:
                in_degree[rid] -= 1
                if in_degree[rid] == 0:
                    queue.append(rid)

    return result


def order_rules(rules: list[dict]) -> OrderingResult:
    """Order rules by dependencies and detect conflicts.

    Performs:
    1. Topological sort based on depends_on relationships
    2. Cycle detection for circular dependencies
    3. Conflict detection for conflicts_with relationships
    4. Supersedes handling (skip superseded rules when superseding rule present)

    Args:
        rules: List of rule dicts with id, depends_on, conflicts_with, supersedes.

    Returns:
        OrderingResult with ordered rules, detected issues, and skipped rules.

    """
    result = OrderingResult()

    if not rules:
        return result

    # Build maps
    rules_by_id = {r["id"]: r for r in rules}
    rule_ids = set(rules_by_id.keys())

    # Extract dependencies (only those referencing rules in this set)
    deps: dict[str, list[str]] = {}
    for rule in rules:
        rid = rule["id"]
        deps[rid] = [d for d in rule.get("depends_on", []) if d in rule_ids]

    # Detect cycles
    result.cycles = _detect_cycles(rule_ids, deps)

    # Handle supersedes
    for rule in rules:
        rid = rule["id"]
        for superseded_id in rule.get("supersedes", []):
            if superseded_id in rule_ids:
                result.superseded[superseded_id] = rid
                result.skipped.append(superseded_id)

    # Remove superseded rules from processing
    active_ids = rule_ids - set(result.skipped)

    # Check conflicts_with
    for rule in rules:
        rid = rule["id"]
        if rid not in active_ids:
            continue
        for conflict_id in rule.get("conflicts_with", []):
            if conflict_id in active_ids and (conflict_id, rid) not in result.conflicts:
                result.conflicts.append((rid, conflict_id))

    # Topological sort of active rules
    sorted_ids = _topological_sort(active_ids, deps)

    # Build ordered rule list
    result.ordered = [rules_by_id[rid] for rid in sorted_ids if rid in rules_by_id]

    return result


def get_dependency_failures(
    rule_id: str,
    rules: list[dict],
    failed_rules: set[str],
) -> list[str]:
    """Get list of failed dependencies for a rule.

    Args:
        rule_id: The rule to check.
        rules: All rules being processed.
        failed_rules: Set of rule IDs that have failed.

    Returns:
        List of failed dependency rule IDs.

    """
    rules_by_id = {r["id"]: r for r in rules}
    rule = rules_by_id.get(rule_id)
    if not rule:
        return []

    return [dep for dep in rule.get("depends_on", []) if dep in failed_rules]


def should_skip_rule(
    rule_id: str,
    rules: list[dict],
    failed_rules: set[str],
    transitive: bool = True,
) -> tuple[bool, str]:
    """Check if a rule should be skipped due to failed dependencies.

    Args:
        rule_id: The rule to check.
        rules: All rules being processed.
        failed_rules: Set of rule IDs that have failed.
        transitive: If True, check transitive dependencies.

    Returns:
        Tuple of (should_skip, reason).

    """
    rules_by_id = {r["id"]: r for r in rules}
    rule = rules_by_id.get(rule_id)
    if not rule:
        return False, ""

    # Check direct dependencies
    direct_deps = rule.get("depends_on", [])
    failed_direct = [d for d in direct_deps if d in failed_rules]
    if failed_direct:
        return True, f"dependency failed: {', '.join(failed_direct)}"

    if transitive:
        # Check transitive dependencies using DFS
        visited = set()
        to_check = list(direct_deps)

        while to_check:
            dep = to_check.pop()
            if dep in visited:
                continue
            visited.add(dep)

            if dep in failed_rules:
                return True, f"transitive dependency failed: {dep}"

            dep_rule = rules_by_id.get(dep)
            if dep_rule:
                to_check.extend(dep_rule.get("depends_on", []))

    return False, ""


def format_ordering_issues(result: OrderingResult) -> list[str]:
    """Format ordering issues for display.

    Args:
        result: OrderingResult from order_rules().

    Returns:
        List of formatted warning/error messages.

    """
    messages = []

    for cycle in result.cycles:
        cycle_str = " → ".join(cycle)
        messages.append(f"[ERROR] Circular dependency: {cycle_str}")

    for rid, conflict_id in result.conflicts:
        messages.append(f"[WARNING] Conflict: {rid} conflicts with {conflict_id} (both in active set)")

    for superseded, superseding in result.superseded.items():
        messages.append(f"[INFO] Skipping {superseded} (superseded by {superseding})")

    return messages
