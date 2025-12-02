"""
Content Module Shared Models and Types

This module defines the core data structures used across the content management
subsystem, including parsed content representations, import progress tracking,
and content format definitions.

These models are used by:
- Content parsers (SCAP, CIS, STIG, custom formats)
- Content transformers (to MongoDB format)
- Content importers (bulk import operations)
- Content validators (dependency resolution, validation)

Design Principles:
- Immutable where possible (frozen dataclasses)
- Type-safe with explicit type hints
- Framework-agnostic (no MongoDB/SQL dependencies)
- Serializable to JSON for API responses
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class ContentFormat(str, Enum):
    """
    Supported content formats for compliance rules.

    Each format represents a different source of compliance content that
    OpenWatch can parse and import. The format determines which parser
    will be used for content processing.

    Attributes:
        SCAP_DATASTREAM: SCAP 1.3 datastream format (bundled XCCDF + OVAL)
        XCCDF: Standalone XCCDF benchmark files
        OVAL: Standalone OVAL definition files
        CIS_BENCHMARK: CIS Benchmark format (future)
        STIG: DISA STIG format (future)
        CUSTOM_JSON: Custom JSON policy format (future)
        CUSTOM_YAML: Custom YAML policy format (future)
    """

    SCAP_DATASTREAM = "scap_datastream"
    XCCDF = "xccdf"
    OVAL = "oval"
    CIS_BENCHMARK = "cis_benchmark"
    STIG = "stig"
    CUSTOM_JSON = "custom_json"
    CUSTOM_YAML = "custom_yaml"


class ContentSeverity(str, Enum):
    """
    Standardized severity levels for compliance rules.

    These severity levels are normalized from various source formats
    (SCAP severity, CIS impact, STIG CAT levels) into a common scale.

    Attributes:
        CRITICAL: Immediate remediation required (STIG CAT I equivalent)
        HIGH: High priority remediation (STIG CAT II equivalent)
        MEDIUM: Medium priority remediation (STIG CAT III equivalent)
        LOW: Low priority, address when convenient
        INFO: Informational only, no action required
        UNKNOWN: Severity could not be determined
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class ImportStage(str, Enum):
    """
    Stages of the content import process.

    Used to track progress during bulk import operations and provide
    meaningful status updates to users.

    Attributes:
        INITIALIZING: Setting up import operation
        PARSING: Parsing source content file
        VALIDATING: Validating parsed content
        TRANSFORMING: Transforming to MongoDB format
        RESOLVING_DEPENDENCIES: Resolving rule dependencies
        IMPORTING: Inserting rules into database
        FINALIZING: Completing import, updating indexes
        COMPLETED: Import finished successfully
        FAILED: Import failed with errors
    """

    INITIALIZING = "initializing"
    PARSING = "parsing"
    VALIDATING = "validating"
    TRANSFORMING = "transforming"
    RESOLVING_DEPENDENCIES = "resolving_dependencies"
    IMPORTING = "importing"
    FINALIZING = "finalizing"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(frozen=True)
class ParsedRule:
    """
    Represents a single parsed compliance rule.

    This is the normalized representation of a rule from any source format.
    It contains all the information needed to create a MongoDB ComplianceRule
    document.

    Attributes:
        rule_id: Unique identifier for the rule (e.g., xccdf_org.ssgproject...)
        title: Human-readable rule title
        description: Detailed rule description
        severity: Normalized severity level
        rationale: Why this rule is important
        check_content: The actual check definition (OVAL ID, script, etc.)
        fix_content: Remediation instructions or script
        references: External references (CCE, CVE, NIST controls, etc.)
        platforms: List of applicable platforms (RHEL8, Ubuntu20.04, etc.)
        metadata: Additional metadata from source format
    """

    rule_id: str
    title: str
    description: str
    severity: ContentSeverity
    rationale: str = ""
    check_content: str = ""
    fix_content: str = ""
    references: Dict[str, List[str]] = field(default_factory=dict)
    platforms: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert rule to dictionary for JSON serialization.

        Returns:
            Dictionary representation of the rule.
        """
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "rationale": self.rationale,
            "check_content": self.check_content,
            "fix_content": self.fix_content,
            "references": self.references,
            "platforms": self.platforms,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class ParsedProfile:
    """
    Represents a parsed compliance profile.

    A profile is a collection of rules selected for a specific use case
    (e.g., STIG, CIS Level 1, PCI-DSS).

    Attributes:
        profile_id: Unique identifier for the profile
        title: Human-readable profile title
        description: Detailed profile description
        selected_rules: List of rule IDs selected in this profile
        extends: Profile ID this profile extends (inheritance)
        metadata: Additional profile metadata
    """

    profile_id: str
    title: str
    description: str = ""
    selected_rules: List[str] = field(default_factory=list)
    extends: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert profile to dictionary for JSON serialization.

        Returns:
            Dictionary representation of the profile.
        """
        return {
            "profile_id": self.profile_id,
            "title": self.title,
            "description": self.description,
            "selected_rules": self.selected_rules,
            "extends": self.extends,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class ParsedOVALDefinition:
    """
    Represents a parsed OVAL definition.

    OVAL definitions contain the actual check logic for compliance rules.

    Attributes:
        definition_id: Unique OVAL definition ID
        title: Definition title
        description: What this definition checks
        definition_class: OVAL class (compliance, vulnerability, inventory, etc.)
        criteria: The check criteria tree
        metadata: Additional OVAL metadata
    """

    definition_id: str
    title: str
    description: str = ""
    definition_class: str = "compliance"
    criteria: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert OVAL definition to dictionary for JSON serialization.

        Returns:
            Dictionary representation of the OVAL definition.
        """
        return {
            "definition_id": self.definition_id,
            "title": self.title,
            "description": self.description,
            "definition_class": self.definition_class,
            "criteria": self.criteria,
            "metadata": self.metadata,
        }


@dataclass
class ParsedContent:
    """
    Unified representation of parsed security content.

    This is the output of any content parser, containing all extracted
    rules, profiles, and OVAL definitions in a normalized format.

    Attributes:
        format: The source content format
        rules: List of parsed compliance rules
        profiles: List of parsed profiles
        oval_definitions: List of parsed OVAL definitions
        metadata: Content-level metadata (benchmark info, version, etc.)
        source_file: Path to the source content file
        parse_warnings: Non-fatal warnings encountered during parsing
        parse_timestamp: When the content was parsed
    """

    format: ContentFormat
    rules: List[ParsedRule] = field(default_factory=list)
    profiles: List[ParsedProfile] = field(default_factory=list)
    oval_definitions: List[ParsedOVALDefinition] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    source_file: str = ""
    parse_warnings: List[str] = field(default_factory=list)
    parse_timestamp: datetime = field(default_factory=datetime.utcnow)

    @property
    def rule_count(self) -> int:
        """Get the total number of parsed rules."""
        return len(self.rules)

    @property
    def profile_count(self) -> int:
        """Get the total number of parsed profiles."""
        return len(self.profiles)

    @property
    def oval_count(self) -> int:
        """Get the total number of OVAL definitions."""
        return len(self.oval_definitions)

    def get_rule_by_id(self, rule_id: str) -> Optional[ParsedRule]:
        """
        Find a rule by its ID.

        Args:
            rule_id: The rule ID to search for.

        Returns:
            The matching ParsedRule or None if not found.
        """
        for rule in self.rules:
            if rule.rule_id == rule_id:
                return rule
        return None

    def get_profile_by_id(self, profile_id: str) -> Optional[ParsedProfile]:
        """
        Find a profile by its ID.

        Args:
            profile_id: The profile ID to search for.

        Returns:
            The matching ParsedProfile or None if not found.
        """
        for profile in self.profiles:
            if profile.profile_id == profile_id:
                return profile
        return None

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert parsed content to dictionary for JSON serialization.

        Returns:
            Dictionary representation of the parsed content.
        """
        return {
            "format": self.format.value,
            "rules": [r.to_dict() for r in self.rules],
            "profiles": [p.to_dict() for p in self.profiles],
            "oval_definitions": [o.to_dict() for o in self.oval_definitions],
            "metadata": self.metadata,
            "source_file": self.source_file,
            "parse_warnings": self.parse_warnings,
            "parse_timestamp": self.parse_timestamp.isoformat(),
            "rule_count": self.rule_count,
            "profile_count": self.profile_count,
            "oval_count": self.oval_count,
        }


@dataclass
class ImportProgress:
    """
    Track bulk import progress.

    Used to provide real-time status updates during content import
    operations, which may take several minutes for large content bundles.

    Attributes:
        total_rules: Total number of rules to import
        imported_rules: Number of rules successfully imported
        skipped_rules: Number of rules skipped (duplicates, etc.)
        failed_rules: Number of rules that failed to import
        current_stage: Current import stage
        stage_progress: Progress within current stage (0-100)
        errors: List of error messages encountered
        warnings: List of warning messages encountered
        start_time: When the import started
        estimated_remaining_seconds: Estimated time to completion
    """

    total_rules: int = 0
    imported_rules: int = 0
    skipped_rules: int = 0
    failed_rules: int = 0
    current_stage: ImportStage = ImportStage.INITIALIZING
    stage_progress: float = 0.0
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    start_time: datetime = field(default_factory=datetime.utcnow)
    estimated_remaining_seconds: Optional[int] = None

    @property
    def progress_percent(self) -> float:
        """
        Calculate overall import progress as a percentage.

        Returns:
            Progress percentage (0.0 to 100.0).
        """
        if self.total_rules == 0:
            return 0.0
        processed = self.imported_rules + self.skipped_rules + self.failed_rules
        return (processed / self.total_rules) * 100.0

    @property
    def is_complete(self) -> bool:
        """Check if import is complete (success or failure)."""
        return self.current_stage in (ImportStage.COMPLETED, ImportStage.FAILED)

    @property
    def success_rate(self) -> float:
        """
        Calculate import success rate as a percentage.

        Returns:
            Success rate percentage (0.0 to 100.0).
        """
        processed = self.imported_rules + self.skipped_rules + self.failed_rules
        if processed == 0:
            return 0.0
        return (self.imported_rules / processed) * 100.0

    @property
    def elapsed_seconds(self) -> float:
        """Calculate elapsed time since import started."""
        return (datetime.utcnow() - self.start_time).total_seconds()

    def add_error(self, error: str) -> None:
        """
        Add an error message to the progress tracker.

        Args:
            error: The error message to add.
        """
        self.errors.append(error)

    def add_warning(self, warning: str) -> None:
        """
        Add a warning message to the progress tracker.

        Args:
            warning: The warning message to add.
        """
        self.warnings.append(warning)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert import progress to dictionary for JSON serialization.

        Returns:
            Dictionary representation of the import progress.
        """
        return {
            "total_rules": self.total_rules,
            "imported_rules": self.imported_rules,
            "skipped_rules": self.skipped_rules,
            "failed_rules": self.failed_rules,
            "current_stage": self.current_stage.value,
            "stage_progress": self.stage_progress,
            "progress_percent": self.progress_percent,
            "success_rate": self.success_rate,
            "is_complete": self.is_complete,
            "errors": self.errors,
            "warnings": self.warnings,
            "start_time": self.start_time.isoformat(),
            "elapsed_seconds": self.elapsed_seconds,
            "estimated_remaining_seconds": self.estimated_remaining_seconds,
        }


@dataclass(frozen=True)
class ContentValidationResult:
    """
    Result of content validation.

    Used by validators to report the outcome of content validation
    including any issues found.

    Attributes:
        is_valid: Whether the content passed validation
        errors: List of validation errors (fatal issues)
        warnings: List of validation warnings (non-fatal issues)
        metadata: Additional validation metadata
    """

    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert validation result to dictionary for JSON serialization.

        Returns:
            Dictionary representation of the validation result.
        """
        return {
            "is_valid": self.is_valid,
            "errors": self.errors,
            "warnings": self.warnings,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class DependencyResolution:
    """
    Result of dependency resolution for a rule.

    Used to track which dependencies a rule has and whether they
    are satisfied.

    Attributes:
        rule_id: The rule being resolved
        dependencies: List of dependency rule IDs
        satisfied: List of satisfied dependency rule IDs
        missing: List of missing dependency rule IDs
        circular: List of circular dependency chains detected
        is_resolved: Whether all dependencies are satisfied
    """

    rule_id: str
    dependencies: List[str] = field(default_factory=list)
    satisfied: List[str] = field(default_factory=list)
    missing: List[str] = field(default_factory=list)
    circular: List[List[str]] = field(default_factory=list)

    @property
    def is_resolved(self) -> bool:
        """Check if all dependencies are satisfied."""
        return len(self.missing) == 0 and len(self.circular) == 0

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert dependency resolution to dictionary for JSON serialization.

        Returns:
            Dictionary representation of the dependency resolution.
        """
        return {
            "rule_id": self.rule_id,
            "dependencies": self.dependencies,
            "satisfied": self.satisfied,
            "missing": self.missing,
            "circular": self.circular,
            "is_resolved": self.is_resolved,
        }
