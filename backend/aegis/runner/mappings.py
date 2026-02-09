"""Framework mapping layer for compliance standards.

This module provides a mapping layer that associates rules with framework
identifiers (CIS, STIG, NIST, etc.) without embedding mappings in rules.

Example:
    >>> from runner.mappings import load_mapping, rules_for_framework
    >>> mapping = load_mapping("mappings/cis/rhel9_v2.0.0.yaml")
    >>> filtered_rules = rules_for_framework(mapping, all_rules)

"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

import yaml


@dataclass
class MappingEntry:
    """A single mapping entry linking a framework section to a rule.

    Attributes:
        rule_id: Canonical rule ID this section maps to.
        title: Framework-specific title for this section.
        metadata: Additional metadata (level, type, severity, cci, etc.).

    """

    rule_id: str
    title: str
    metadata: dict = field(default_factory=dict)


@dataclass
class UnimplementedEntry:
    """A framework section that has no corresponding rule.

    Attributes:
        title: Framework-specific title for this section.
        reason: Why this section has no rule (manual, site-specific, etc.).
        entry_type: Type of entry (Manual, N/A, etc.).

    """

    title: str
    reason: str
    entry_type: str = "Manual"


@dataclass
class PlatformConstraint:
    """Platform constraint for a mapping.

    Attributes:
        family: OS family (rhel, debian, etc.).
        min_version: Minimum OS version.
        max_version: Maximum OS version.

    """

    family: str
    min_version: int | None = None
    max_version: int | None = None


@dataclass
class FrameworkMapping:
    """A complete framework mapping.

    Attributes:
        id: Unique mapping identifier (e.g., "cis-rhel9-v2.0.0").
        framework: Framework type (cis, stig, nist_800_53, pci_dss).
        title: Human-readable title.
        published: Publication date (optional).
        platform: Platform constraint (optional).
        controls: List of all control IDs that must be accounted for.
        sections: Map of section_id -> MappingEntry.
        unimplemented: Map of section_id -> UnimplementedEntry.

    """

    id: str
    framework: str
    title: str
    published: date | None = None
    platform: PlatformConstraint | None = None
    controls: list[str] = field(default_factory=list)
    sections: dict[str, MappingEntry] = field(default_factory=dict)
    unimplemented: dict[str, UnimplementedEntry] = field(default_factory=dict)

    @property
    def all_section_ids(self) -> set[str]:
        """All section IDs (implemented + unimplemented)."""
        return set(self.sections.keys()) | set(self.unimplemented.keys())

    @property
    def implemented_count(self) -> int:
        """Number of implemented sections."""
        return len(self.sections)

    @property
    def unimplemented_count(self) -> int:
        """Number of explicitly unimplemented sections."""
        return len(self.unimplemented)

    @property
    def rule_ids(self) -> set[str]:
        """Set of all rule IDs referenced by this mapping."""
        return {entry.rule_id for entry in self.sections.values()}

    @property
    def total_controls(self) -> int:
        """Total number of controls in the manifest."""
        return len(self.controls) if self.controls else 0

    @property
    def accounted_controls(self) -> set[str]:
        """Controls that are accounted for (in sections or unimplemented)."""
        return set(self.sections.keys()) | set(self.unimplemented.keys())

    @property
    def unaccounted_controls(self) -> list[str]:
        """Controls in manifest not yet accounted for."""
        if not self.controls:
            return []
        accounted = self.accounted_controls
        return [c for c in self.controls if c not in accounted]

    @property
    def is_complete(self) -> bool:
        """Whether all controls in the manifest are accounted for."""
        if not self.controls:
            # No manifest = can't determine completeness
            return True
        return len(self.unaccounted_controls) == 0


def _parse_platform(data: dict | None) -> PlatformConstraint | None:
    """Parse platform constraint from mapping data."""
    if data is None:
        return None
    return PlatformConstraint(
        family=data.get("family", ""),
        min_version=data.get("min_version"),
        max_version=data.get("max_version"),
    )


def _parse_sections(
    data: dict | None,
    section_key: str = "sections",
) -> dict[str, MappingEntry]:
    """Parse sections from mapping data.

    Handles both CIS-style (sections) and STIG-style (findings) formats.
    """
    if data is None:
        return {}

    sections = {}
    for section_id, entry in data.items():
        if not isinstance(entry, dict):
            continue

        rule_id = entry.get("rule", "")
        title = entry.get("title", "")

        # Collect all other fields as metadata
        metadata = {k: v for k, v in entry.items() if k not in ("rule", "title")}

        sections[str(section_id)] = MappingEntry(
            rule_id=rule_id,
            title=title,
            metadata=metadata,
        )

    return sections


def _parse_unimplemented(data: dict | None) -> dict[str, UnimplementedEntry]:
    """Parse unimplemented sections from mapping data."""
    if data is None:
        return {}

    unimplemented = {}
    for section_id, entry in data.items():
        if not isinstance(entry, dict):
            continue

        unimplemented[str(section_id)] = UnimplementedEntry(
            title=entry.get("title", ""),
            reason=entry.get("reason", ""),
            entry_type=entry.get("type", "Manual"),
        )

    return unimplemented


def _parse_nist_controls(data: dict | None) -> dict[str, MappingEntry]:
    """Parse NIST-style controls (many rules per control)."""
    if data is None:
        return {}

    sections = {}
    for control_id, entry in data.items():
        if not isinstance(entry, dict):
            continue

        title = entry.get("title", "")
        rules = entry.get("rules", [])

        # For NIST, we create one entry per control
        # The rule_id is a comma-separated list for display
        sections[str(control_id)] = MappingEntry(
            rule_id=",".join(rules) if rules else "",
            title=title,
            metadata={"rules": rules},
        )

    return sections


def load_mapping(path: str | Path) -> FrameworkMapping:
    """Load a framework mapping from YAML file.

    Args:
        path: Path to mapping YAML file.

    Returns:
        FrameworkMapping object.

    Raises:
        FileNotFoundError: If file doesn't exist.
        yaml.YAMLError: If YAML parsing fails.

    """
    path = Path(path)
    data = yaml.safe_load(path.read_text())

    if not isinstance(data, dict):
        raise ValueError(f"Mapping file must contain a YAML mapping: {path}")

    # Parse published date
    published = None
    if "published" in data:
        pub_val = data["published"]
        if isinstance(pub_val, date):
            published = pub_val
        elif isinstance(pub_val, str):
            published = date.fromisoformat(pub_val)

    # Determine section format based on framework type
    framework = data.get("framework", "")
    if framework == "nist_800_53":
        sections = _parse_nist_controls(data.get("controls"))
    elif framework == "stig":
        sections = _parse_sections(data.get("findings"))
    else:
        sections = _parse_sections(data.get("sections"))

    # Parse control_ids manifest (list of all control IDs that must be accounted for)
    control_ids = data.get("control_ids", [])
    if not isinstance(control_ids, list):
        control_ids = []
    controls = [str(c) for c in control_ids]

    return FrameworkMapping(
        id=data.get("id", ""),
        framework=framework,
        title=data.get("title", ""),
        published=published,
        platform=_parse_platform(data.get("platform")),
        controls=controls,
        sections=sections,
        unimplemented=_parse_unimplemented(data.get("unimplemented")),
    )


def load_all_mappings(
    mappings_dir: str | Path = "mappings/",
) -> dict[str, FrameworkMapping]:
    """Load all mappings from a directory.

    Args:
        mappings_dir: Directory containing mapping files.

    Returns:
        Dict mapping ID to FrameworkMapping.

    """
    mappings_dir = Path(mappings_dir)
    if not mappings_dir.exists():
        return {}

    mappings = {}
    for path in mappings_dir.rglob("*.yaml"):
        try:
            mapping = load_mapping(path)
            mappings[mapping.id] = mapping
        except (yaml.YAMLError, ValueError):
            continue

    for path in mappings_dir.rglob("*.yml"):
        try:
            mapping = load_mapping(path)
            mappings[mapping.id] = mapping
        except (yaml.YAMLError, ValueError):
            continue

    return mappings


def get_applicable_mappings(
    mappings: dict[str, FrameworkMapping],
    family: str,
    version: int,
) -> list[FrameworkMapping]:
    """Get mappings applicable to a platform.

    Args:
        mappings: Dict of all loaded mappings.
        family: OS family (rhel, debian, etc.).
        version: OS major version.

    Returns:
        List of applicable mappings.

    """
    applicable = []
    for mapping in mappings.values():
        if mapping.platform is None:
            # No platform constraint = applies to all
            applicable.append(mapping)
            continue

        if mapping.platform.family != family:
            continue

        min_v = mapping.platform.min_version or 0
        max_v = mapping.platform.max_version or 99

        if min_v <= version <= max_v:
            applicable.append(mapping)

    return applicable


def rules_for_framework(
    mapping: FrameworkMapping,
    rules: list[dict],
) -> list[dict]:
    """Filter rules to those in a framework mapping.

    Args:
        mapping: FrameworkMapping to filter by.
        rules: List of all rule dicts.

    Returns:
        List of rules that appear in the mapping.

    """
    rule_ids = mapping.rule_ids
    return [r for r in rules if r.get("id") in rule_ids]


def build_rule_to_section_map(mapping: FrameworkMapping) -> dict[str, str]:
    """Build reverse lookup from rule_id to section_id.

    This enables including framework control IDs in check output
    when filtering by a specific framework.

    Args:
        mapping: FrameworkMapping to build lookup from.

    Returns:
        Dict mapping rule_id to section_id (e.g., {"ssh-root-login": "5.1.20"}).

    """
    return {entry.rule_id: section_id for section_id, entry in mapping.sections.items() if entry.rule_id}


def order_by_framework(
    mapping: FrameworkMapping,
    rules: list[dict],
) -> list[tuple[str, dict]]:
    """Order rules by framework section.

    Args:
        mapping: FrameworkMapping defining the order.
        rules: List of rule dicts.

    Returns:
        List of (section_id, rule_dict) tuples in framework order.

    """
    rules_by_id = {r["id"]: r for r in rules}
    result = []

    # Sort section IDs for consistent ordering
    for section_id in sorted(mapping.sections.keys()):
        entry = mapping.sections[section_id]
        rule = rules_by_id.get(entry.rule_id)
        if rule:
            result.append((section_id, rule))

    return result


def _parse_section_key(section: str | None) -> tuple:
    """Parse a section ID into a sortable tuple.

    Handles numeric and alphanumeric section IDs like "1.1.1", "5.2.3", "V-257947".

    Args:
        section: Section ID string or None.

    Returns:
        Tuple for sorting. None sections sort last.

    """
    if section is None:
        # Return a tuple that sorts after any valid section
        # (2, ...) sorts after (0, ...) numeric and (1, ...) alpha
        return ((2, ""),)

    parts: list[tuple[int, int | str]] = []
    for part in section.replace("-", ".").split("."):
        # Try to parse as int for numeric sorting
        try:
            parts.append((0, int(part)))  # Numeric parts sort first
        except ValueError:
            parts.append((1, part))  # Alpha parts sort after numerics
    return tuple(parts)


def order_results_by_section(
    results: list,
    rule_to_section: dict[str, str] | None = None,
) -> list:
    """Order RuleResult objects by framework section.

    Args:
        results: List of RuleResult objects.
        rule_to_section: Optional mapping of rule_id to section_id.
            If not provided, uses result.framework_section.

    Returns:
        New list of results sorted by section (1.1.1 < 1.1.2 < 5.2.3).
        Results without sections are sorted to the end.

    Example:
        >>> from runner.mappings import order_results_by_section
        >>> sorted_results = order_results_by_section(results)

    """
    rule_to_section = rule_to_section or {}

    def section_key(result) -> tuple:
        # Use provided mapping or fall back to result's framework_section
        section = rule_to_section.get(result.rule_id) or result.framework_section
        return _parse_section_key(section)

    return sorted(results, key=section_key)


@dataclass
class CoverageReport:
    """Coverage report for a framework mapping.

    Attributes:
        mapping_id: Framework mapping ID.
        total_controls: Total controls in framework (from manifest).
        implemented: Number of controls mapped to rules.
        unimplemented: Number of explicitly unimplemented controls.
        unaccounted: Controls not yet accounted for (need mapping).
        missing_rules: Rule IDs in mapping that don't exist.
        has_manifest: Whether a control manifest was provided.

    """

    mapping_id: str
    total_controls: int
    implemented: int
    unimplemented: int
    unaccounted: list[str]
    missing_rules: list[str]
    has_manifest: bool = True

    # Backward compatibility aliases
    @property
    def total_sections(self) -> int:
        """Alias for total_controls (backward compatibility)."""
        return self.total_controls

    @property
    def missing(self) -> list[str]:
        """Alias for unaccounted (backward compatibility)."""
        return self.unaccounted

    @property
    def coverage_percent(self) -> float:
        """Percentage of controls mapped to rules (implemented/total)."""
        if self.total_controls == 0:
            return 0.0
        return (self.implemented / self.total_controls) * 100

    @property
    def accounted_percent(self) -> float:
        """Percentage of controls accounted for (implemented+unimplemented/total)."""
        if self.total_controls == 0:
            return 0.0
        return ((self.implemented + self.unimplemented) / self.total_controls) * 100

    @property
    def is_complete(self) -> bool:
        """Whether all controls are accounted for."""
        return len(self.unaccounted) == 0


def check_coverage(
    mapping: FrameworkMapping,
    available_rules: set[str],
) -> CoverageReport:
    """Check coverage of a mapping against available rules.

    Args:
        mapping: FrameworkMapping to check.
        available_rules: Set of available rule IDs.

    Returns:
        CoverageReport with coverage details.

    """
    # Find missing rules (referenced but don't exist)
    # Handle both NIST-style (rules in metadata) and CIS/STIG-style (single rule_id)
    missing_rules = []
    for entry in mapping.sections.values():
        rule_list = entry.metadata.get("rules", [])
        if rule_list:
            # NIST format: check each rule in the list
            for rule_id in rule_list:
                if rule_id and rule_id not in available_rules:
                    missing_rules.append(rule_id)
        elif entry.rule_id and entry.rule_id not in available_rules:
            # CIS/STIG format: single rule_id
            missing_rules.append(entry.rule_id)

    # Deduplicate missing rules
    missing_rules = sorted(set(missing_rules))

    # Determine totals based on whether a manifest exists
    has_manifest = bool(mapping.controls)
    if has_manifest:
        total = len(mapping.controls)
        unaccounted = mapping.unaccounted_controls
    else:
        # Fallback: use sections + unimplemented as total
        total = len(mapping.sections) + len(mapping.unimplemented)
        unaccounted = []

    return CoverageReport(
        mapping_id=mapping.id,
        total_controls=total,
        implemented=len(mapping.sections),
        unimplemented=len(mapping.unimplemented),
        unaccounted=unaccounted,
        missing_rules=missing_rules,
        has_manifest=has_manifest,
    )


# ── Cross-reference index ────────────────────────────────────────────────────


@dataclass
class FrameworkReference:
    """A reference from a framework to a rule.

    Attributes:
        mapping_id: Framework mapping ID (e.g., "cis-rhel9-v2.0.0").
        mapping_title: Human-readable framework title.
        section_id: Section/control ID within the framework.
        title: Section title from the framework.
        metadata: Additional metadata (level, type, severity, etc.).

    """

    mapping_id: str
    mapping_title: str
    section_id: str
    title: str
    metadata: dict = field(default_factory=dict)


@dataclass
class FrameworkIndex:
    """Cross-reference index for framework mappings.

    Provides fast lookups for:
    - Which frameworks reference a rule
    - Which rules implement a control

    Example:
        >>> mappings = load_all_mappings()
        >>> index = FrameworkIndex.build(mappings)
        >>> refs = index.query_by_rule("ssh-disable-root-login")
        >>> for ref in refs:
        ...     print(f"{ref.mapping_id}: {ref.section_id}")

    """

    # rule_id -> list of FrameworkReference
    rules_to_frameworks: dict[str, list[FrameworkReference]]

    # "mapping_id:section_id" -> list of rule_ids
    controls_to_rules: dict[str, list[str]]

    # All loaded mappings for metadata lookups
    mappings: dict[str, FrameworkMapping]

    @classmethod
    def build(cls, mappings: dict[str, FrameworkMapping]) -> FrameworkIndex:
        """Build cross-reference index from all mappings.

        Args:
            mappings: Dict of mapping_id -> FrameworkMapping.

        Returns:
            Populated FrameworkIndex.

        """
        rules_to_frameworks: dict[str, list[FrameworkReference]] = {}
        controls_to_rules: dict[str, list[str]] = {}

        for mapping_id, mapping in mappings.items():
            for section_id, entry in mapping.sections.items():
                # Build rule -> frameworks index
                ref = FrameworkReference(
                    mapping_id=mapping_id,
                    mapping_title=mapping.title,
                    section_id=section_id,
                    title=entry.title,
                    metadata=entry.metadata,
                )

                # Handle NIST-style many-to-many (rules in metadata)
                # vs CIS/STIG-style one-to-one (single rule_id)
                rule_list = entry.metadata.get("rules", [])
                if rule_list:
                    # NIST format: multiple rules per control
                    for rule_id in rule_list:
                        rules_to_frameworks.setdefault(rule_id, []).append(ref)
                    control_key = f"{mapping_id}:{section_id}"
                    controls_to_rules.setdefault(control_key, []).extend(rule_list)
                elif entry.rule_id:
                    # CIS/STIG format: single rule per section
                    rules_to_frameworks.setdefault(entry.rule_id, []).append(ref)
                    control_key = f"{mapping_id}:{section_id}"
                    controls_to_rules.setdefault(control_key, []).append(entry.rule_id)

        return cls(
            rules_to_frameworks=rules_to_frameworks,
            controls_to_rules=controls_to_rules,
            mappings=mappings,
        )

    def query_by_rule(self, rule_id: str) -> list[FrameworkReference]:
        """Find all framework references for a rule.

        Args:
            rule_id: Canonical rule ID.

        Returns:
            List of FrameworkReference objects, or empty list if not found.

        """
        return self.rules_to_frameworks.get(rule_id, [])

    def query_by_control(self, control_spec: str, *, prefix_match: bool = False) -> list[str]:
        """Find rules implementing a control.

        Args:
            control_spec: Control specification in format "mapping_id:section_id"
                or just "section_id" to search all mappings.
            prefix_match: If True, match control_spec as a prefix
                (e.g., "5.1" matches "5.1.1", "5.1.2", etc.).

        Returns:
            List of rule IDs implementing the control(s).

        """
        if ":" in control_spec:
            # Exact or prefix match for "mapping_id:section_id"
            if prefix_match:
                results = []
                for key, rules in self.controls_to_rules.items():
                    if key.startswith(control_spec) or key.startswith(control_spec + "."):
                        results.extend(rules)
                return list(set(results))
            return self.controls_to_rules.get(control_spec, [])

        # Search all mappings for section_id
        results = []
        for key, rules in self.controls_to_rules.items():
            _, section = key.split(":", 1)
            if prefix_match:
                if section.startswith(control_spec) or section.startswith(control_spec + "."):
                    results.extend(rules)
            elif section == control_spec:
                results.extend(rules)
        return list(set(results))

    def list_controls(self, mapping_id: str | None = None) -> list[tuple[str, str, int]]:
        """List all controls with rule counts.

        Args:
            mapping_id: Optional filter by mapping ID.

        Returns:
            List of (mapping_id, section_id, rule_count) tuples, sorted.

        """
        results = []
        for key, rules in self.controls_to_rules.items():
            mid, section = key.split(":", 1)
            if mapping_id is None or mid == mapping_id:
                results.append((mid, section, len(rules)))

        # Sort by mapping_id, then section_id
        return sorted(results, key=lambda x: (x[0], _parse_section_key(x[1])))
