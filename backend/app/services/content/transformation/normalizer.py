"""
Content Normalizer - Cross-format content normalization

This module provides normalization services that convert compliance content from
various source formats into a unified internal representation. It ensures consistent
data structures regardless of the original content format (SCAP, CIS, STIG, etc.).

Design Philosophy:
    - Format-Agnostic: Handles any source format with consistent output
    - Non-Destructive: Preserves original data in metadata fields
    - Deterministic: Same input always produces same normalized output
    - Extensible: Easy to add normalization rules for new formats

Architecture:
    The normalizer operates as a pipeline with these stages:
    1. Severity Normalization: Map format-specific severities to standard levels
    2. Reference Normalization: Extract and standardize external references
    3. Platform Normalization: Standardize platform identifiers
    4. Metadata Normalization: Ensure consistent metadata structure
    5. Text Normalization: Clean and standardize text fields

Thread Safety:
    All normalizer methods are stateless and thread-safe.

Security Notes:
    - Input validation prevents injection of malformed data
    - Text normalization removes potentially dangerous content
    - Maximum field lengths enforced to prevent DoS

Usage:
    from backend.app.services.content.transformation.normalizer import (
        ContentNormalizer,
        normalize_severity,
        normalize_platform,
    )

    # Normalize a single rule
    normalizer = ContentNormalizer()
    normalized_rule = normalizer.normalize_rule(parsed_rule)

    # Normalize entire parsed content
    normalized_content = normalizer.normalize_content(parsed_content)

    # Use standalone functions
    severity = normalize_severity("CAT I", source_format=ContentFormat.STIG)
    platform = normalize_platform("Red Hat Enterprise Linux 8")

Related Modules:
    - content.models: ParsedRule, ParsedContent data structures
    - content.parsers: Content parsing that produces input for normalization
    - content.transformation.transformer: MongoDB transformation using normalized data
"""

import hashlib
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from ..models import ContentFormat, ContentSeverity, ParsedContent, ParsedProfile, ParsedRule

logger = logging.getLogger(__name__)

# Maximum field lengths to prevent DoS attacks from oversized content
MAX_TITLE_LENGTH = 500
MAX_DESCRIPTION_LENGTH = 10000
MAX_RATIONALE_LENGTH = 5000
MAX_FIX_CONTENT_LENGTH = 50000
MAX_CHECK_CONTENT_LENGTH = 50000

# Severity mapping from various formats to standardized ContentSeverity
# SCAP uses: high, medium, low, unknown
# STIG uses: CAT I (critical), CAT II (high), CAT III (medium)
# CIS uses: Level 1 (medium), Level 2 (high), scored/not scored
SEVERITY_MAPPINGS: Dict[str, Dict[str, ContentSeverity]] = {
    # SCAP/XCCDF severity mappings
    "scap": {
        "critical": ContentSeverity.CRITICAL,
        "high": ContentSeverity.HIGH,
        "medium": ContentSeverity.MEDIUM,
        "low": ContentSeverity.LOW,
        "info": ContentSeverity.INFO,
        "informational": ContentSeverity.INFO,
        "unknown": ContentSeverity.UNKNOWN,
    },
    # DISA STIG CAT mappings
    "stig": {
        "cat i": ContentSeverity.CRITICAL,
        "cat ii": ContentSeverity.HIGH,
        "cat iii": ContentSeverity.MEDIUM,
        "category i": ContentSeverity.CRITICAL,
        "category ii": ContentSeverity.HIGH,
        "category iii": ContentSeverity.MEDIUM,
    },
    # CIS Benchmark level mappings
    "cis": {
        "level 1": ContentSeverity.MEDIUM,
        "level 2": ContentSeverity.HIGH,
        "level 3": ContentSeverity.CRITICAL,
        "scored": ContentSeverity.MEDIUM,
        "not scored": ContentSeverity.INFO,
    },
    # CVSS-based severity mappings
    "cvss": {
        "critical": ContentSeverity.CRITICAL,
        "high": ContentSeverity.HIGH,
        "medium": ContentSeverity.MEDIUM,
        "low": ContentSeverity.LOW,
        "none": ContentSeverity.INFO,
    },
}

# Platform name normalization patterns
# Maps various platform names/patterns to canonical form
PLATFORM_NORMALIZATIONS: List[Tuple[str, str]] = [
    # Red Hat Enterprise Linux variants
    (r"(?i)red\s*hat\s*enterprise\s*linux\s*(\d+)", r"rhel\1"),
    (r"(?i)rhel\s*(\d+)", r"rhel\1"),
    (r"(?i)redhat\s*(\d+)", r"rhel\1"),
    # CentOS variants
    (r"(?i)centos\s*(\d+)", r"centos\1"),
    (r"(?i)centos\s*stream\s*(\d+)", r"centos-stream\1"),
    # Ubuntu variants
    (r"(?i)ubuntu\s*(\d+)\.(\d+)", r"ubuntu\1.\2"),
    (r"(?i)ubuntu\s*(\d+)", r"ubuntu\1"),
    # Debian variants
    (r"(?i)debian\s*(\d+)", r"debian\1"),
    # SUSE variants
    (r"(?i)suse\s*linux\s*enterprise\s*server\s*(\d+)", r"sles\1"),
    (r"(?i)sles\s*(\d+)", r"sles\1"),
    (r"(?i)opensuse\s*leap\s*(\d+\.?\d*)", r"opensuse-leap\1"),
    # Oracle Linux variants
    (r"(?i)oracle\s*linux\s*(\d+)", r"ol\1"),
    (r"(?i)ol\s*(\d+)", r"ol\1"),
    # Amazon Linux variants
    (r"(?i)amazon\s*linux\s*(\d+)", r"amazon-linux\1"),
    (r"(?i)amzn\s*(\d+)", r"amazon-linux\1"),
    # Windows variants (for future support)
    (r"(?i)windows\s*server\s*(\d+)", r"windows-server\1"),
    (r"(?i)windows\s*(\d+)", r"windows\1"),
]

# Reference type normalization
# Maps various reference identifier patterns to standard types
REFERENCE_TYPE_PATTERNS: Dict[str, str] = {
    r"^CCE-\d+-\d+$": "CCE",
    r"^CVE-\d{4}-\d+$": "CVE",
    r"^CWE-\d+$": "CWE",
    r"^NIST\s*SP\s*800-53": "NIST_800_53",
    r"^AC-\d+|AU-\d+|CA-\d+|CM-\d+|CP-\d+|IA-\d+|IR-\d+|MA-\d+|MP-\d+|PE-\d+|PL-\d+|PM-\d+|PS-\d+|PT-\d+|RA-\d+|SA-\d+|SC-\d+|SI-\d+|SR-\d+": "NIST_800_53",  # noqa: E501
    r"^CIS\s+\d+\.\d+": "CIS",
    r"^\d+\.\d+\.\d+": "CIS",  # CIS control numbers like 1.1.1
    r"^V-\d+$": "STIG",
    r"^SV-\d+$": "STIG",
    r"^RHEL-\d+-\d+": "RHEL_STIG",
    r"^PCI\s*DSS": "PCI_DSS",
    r"^HIPAA": "HIPAA",
    r"^SOC\s*2": "SOC2",
}


@dataclass
class NormalizationStats:
    """
    Statistics about normalization operations.

    Tracks what was normalized to help with debugging and auditing.

    Attributes:
        rules_processed: Total rules processed.
        severities_normalized: Count of severity normalizations.
        platforms_normalized: Count of platform normalizations.
        references_extracted: Total references extracted.
        text_fields_cleaned: Count of text fields cleaned.
        warnings: Non-fatal warnings during normalization.
    """

    rules_processed: int = 0
    severities_normalized: int = 0
    platforms_normalized: int = 0
    references_extracted: int = 0
    text_fields_cleaned: int = 0
    warnings: List[str] = field(default_factory=list)


def normalize_severity(
    severity_value: str,
    source_format: Optional[ContentFormat] = None,
) -> ContentSeverity:
    """
    Normalize a severity value to standard ContentSeverity enum.

    Maps format-specific severity values (STIG CAT levels, CIS levels, etc.)
    to the unified ContentSeverity enumeration.

    Args:
        severity_value: The severity string from source content.
        source_format: Optional hint about source format for better mapping.

    Returns:
        Normalized ContentSeverity enum value.

    Examples:
        >>> normalize_severity("CAT I", ContentFormat.STIG)
        ContentSeverity.CRITICAL
        >>> normalize_severity("high")
        ContentSeverity.HIGH
        >>> normalize_severity("Level 2", ContentFormat.CIS_BENCHMARK)
        ContentSeverity.HIGH
    """
    if not severity_value:
        return ContentSeverity.UNKNOWN

    # Normalize input for matching
    normalized_input = severity_value.lower().strip()

    # If already a ContentSeverity, return it
    if isinstance(severity_value, ContentSeverity):
        return severity_value

    # Try format-specific mapping first if format is known
    if source_format:
        format_key = _get_format_mapping_key(source_format)
        if format_key in SEVERITY_MAPPINGS:
            format_map = SEVERITY_MAPPINGS[format_key]
            if normalized_input in format_map:
                return format_map[normalized_input]

    # Fall back to checking all mappings
    for format_map in SEVERITY_MAPPINGS.values():
        if normalized_input in format_map:
            return format_map[normalized_input]

    # Check for direct ContentSeverity value match
    try:
        return ContentSeverity(normalized_input)
    except ValueError:
        pass

    # Log unknown severity for debugging
    logger.debug("Unknown severity value '%s', defaulting to UNKNOWN", severity_value)
    return ContentSeverity.UNKNOWN


def _get_format_mapping_key(content_format: ContentFormat) -> str:
    """
    Get the mapping key for a content format.

    Args:
        content_format: The ContentFormat enum value.

    Returns:
        String key for SEVERITY_MAPPINGS lookup.
    """
    format_to_key = {
        ContentFormat.SCAP_DATASTREAM: "scap",
        ContentFormat.XCCDF: "scap",
        ContentFormat.OVAL: "scap",
        ContentFormat.STIG: "stig",
        ContentFormat.CIS_BENCHMARK: "cis",
    }
    return format_to_key.get(content_format, "scap")


def normalize_platform(platform_name: str) -> str:
    """
    Normalize a platform name to canonical form.

    Converts various platform name formats to a consistent, lowercase
    identifier suitable for database queries and matching.

    Args:
        platform_name: Raw platform name from content.

    Returns:
        Normalized platform identifier.

    Examples:
        >>> normalize_platform("Red Hat Enterprise Linux 8")
        'rhel8'
        >>> normalize_platform("Ubuntu 20.04")
        'ubuntu20.04'
        >>> normalize_platform("CentOS Stream 9")
        'centos-stream9'
    """
    if not platform_name:
        return "unknown"

    # Clean input
    cleaned = platform_name.strip()

    # Apply normalization patterns
    for pattern, replacement in PLATFORM_NORMALIZATIONS:
        match = re.match(pattern, cleaned)
        if match:
            # Use re.sub with the pattern to get the normalized form
            normalized = re.sub(pattern, replacement, cleaned, flags=re.IGNORECASE)
            return normalized.lower().strip()

    # If no pattern matched, return cleaned lowercase version
    # Remove special characters and normalize spaces
    normalized = re.sub(r"[^a-zA-Z0-9.-]", "-", cleaned.lower())
    normalized = re.sub(r"-+", "-", normalized)  # Collapse multiple dashes
    return normalized.strip("-")


def normalize_reference(
    ref_id: str,
    ref_type: Optional[str] = None,
) -> Tuple[str, str]:
    """
    Normalize a reference identifier and determine its type.

    Identifies the reference type (CCE, CVE, NIST control, etc.) and
    normalizes the identifier format.

    Args:
        ref_id: The reference identifier.
        ref_type: Optional explicit type (overrides auto-detection).

    Returns:
        Tuple of (normalized_id, reference_type).

    Examples:
        >>> normalize_reference("CCE-80171-3")
        ('CCE-80171-3', 'CCE')
        >>> normalize_reference("cve-2021-44228")
        ('CVE-2021-44228', 'CVE')
        >>> normalize_reference("AC-2", "NIST")
        ('AC-2', 'NIST_800_53')
    """
    if not ref_id:
        return ("", "UNKNOWN")

    # Clean and uppercase for matching
    cleaned_id = ref_id.strip().upper()

    # Use explicit type if provided
    if ref_type:
        normalized_type = ref_type.upper().replace(" ", "_").replace("-", "_")
        return (cleaned_id, normalized_type)

    # Auto-detect type from pattern
    for pattern, detected_type in REFERENCE_TYPE_PATTERNS.items():
        if re.match(pattern, cleaned_id, re.IGNORECASE):
            return (cleaned_id, detected_type)

    # Unknown type, return as-is
    return (cleaned_id, "UNKNOWN")


def clean_text(
    text: str,
    max_length: Optional[int] = None,
    preserve_formatting: bool = False,
) -> str:
    """
    Clean and normalize text content.

    Removes or normalizes problematic content while preserving semantic meaning.
    Optionally truncates to maximum length.

    Args:
        text: Raw text to clean.
        max_length: Optional maximum length (truncates with ellipsis).
        preserve_formatting: If True, preserves newlines and indentation.

    Returns:
        Cleaned text string.

    Security:
        - Removes null bytes and control characters
        - Normalizes Unicode to prevent homograph attacks
        - Strips leading/trailing whitespace
    """
    if not text:
        return ""

    # Remove null bytes and most control characters (keep newline, tab if preserving)
    if preserve_formatting:
        # Keep newlines and tabs
        cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    else:
        # Remove all control characters including newlines
        cleaned = re.sub(r"[\x00-\x1f\x7f]", " ", text)
        # Collapse multiple whitespace to single space
        cleaned = re.sub(r"\s+", " ", cleaned)

    # Strip leading/trailing whitespace
    cleaned = cleaned.strip()

    # Truncate if needed
    if max_length and len(cleaned) > max_length:
        cleaned = cleaned[: max_length - 3] + "..."

    return cleaned


def generate_normalized_id(
    rule_id: str,
    source_format: ContentFormat,
    source_file: str,
) -> str:
    """
    Generate a normalized, consistent identifier for a rule.

    Creates a deterministic identifier that can be used to track rules
    across different imports of the same content.

    Args:
        rule_id: Original rule identifier.
        source_format: Content format for namespacing.
        source_file: Source file path for disambiguation.

    Returns:
        Normalized identifier string.

    Note:
        Uses SHA-256 hash truncated to 12 characters for uniqueness.
    """
    if not rule_id:
        # Generate from source file if no rule_id
        hash_input = f"{source_format.value}:{source_file}"
        hash_value = hashlib.sha256(hash_input.encode()).hexdigest()[:12]
        return f"ow-{source_format.value}-{hash_value}"

    # Clean the rule_id
    cleaned_id = rule_id.strip()

    # If it already looks like an XCCDF ID, preserve it
    if cleaned_id.startswith("xccdf_"):
        return cleaned_id

    # Otherwise, create a normalized ID
    # Replace problematic characters
    normalized = re.sub(r"[^a-zA-Z0-9_.-]", "_", cleaned_id)
    normalized = re.sub(r"_+", "_", normalized)  # Collapse multiple underscores

    return normalized


class ContentNormalizer:
    """
    Normalizes compliance content to a unified internal format.

    This class provides methods to normalize individual rules, profiles,
    or entire parsed content structures. It ensures consistent data
    regardless of the source format.

    Normalization includes:
    - Severity level standardization
    - Platform name canonicalization
    - Reference extraction and typing
    - Text field cleaning
    - Metadata structure normalization

    Thread Safety:
        Instances are stateless and can be used concurrently.

    Attributes:
        stats: NormalizationStats tracking normalization operations.

    Example:
        >>> normalizer = ContentNormalizer()
        >>> normalized_content = normalizer.normalize_content(parsed_content)
        >>> print(f"Processed {normalizer.stats.rules_processed} rules")
    """

    def __init__(self) -> None:
        """Initialize the normalizer with fresh statistics."""
        self.stats = NormalizationStats()

    def reset_stats(self) -> None:
        """Reset normalization statistics."""
        self.stats = NormalizationStats()

    def normalize_content(
        self,
        content: ParsedContent,
        source_format: Optional[ContentFormat] = None,
    ) -> ParsedContent:
        """
        Normalize all rules and profiles in parsed content.

        Creates a new ParsedContent instance with normalized data.
        The original content is not modified.

        Args:
            content: ParsedContent to normalize.
            source_format: Override format detection for normalization.

        Returns:
            New ParsedContent with normalized data.

        Example:
            >>> normalizer = ContentNormalizer()
            >>> normalized = normalizer.normalize_content(parsed_content)
            >>> print(f"Normalized {len(normalized.rules)} rules")
        """
        effective_format = source_format or content.format

        # Normalize all rules
        normalized_rules = [self.normalize_rule(rule, effective_format) for rule in content.rules]

        # Normalize all profiles
        normalized_profiles = [self.normalize_profile(profile) for profile in content.profiles]

        # Normalize metadata
        normalized_metadata = self._normalize_metadata(content.metadata)

        # Create new ParsedContent with normalized data
        return ParsedContent(
            format=content.format,
            rules=normalized_rules,
            profiles=normalized_profiles,
            oval_definitions=content.oval_definitions,  # OVAL defs don't need normalization
            metadata=normalized_metadata,
            source_file=content.source_file,
            parse_warnings=content.parse_warnings + self.stats.warnings,
            parse_timestamp=content.parse_timestamp,
        )

    def normalize_rule(
        self,
        rule: ParsedRule,
        source_format: Optional[ContentFormat] = None,
    ) -> ParsedRule:
        """
        Normalize a single parsed rule.

        Creates a new ParsedRule instance with normalized fields.
        The original rule is not modified.

        Args:
            rule: ParsedRule to normalize.
            source_format: Content format for format-specific normalization.

        Returns:
            New ParsedRule with normalized data.

        Note:
            Since ParsedRule is frozen, this creates a new instance.
        """
        self.stats.rules_processed += 1

        # Normalize severity
        normalized_severity = self._normalize_rule_severity(rule.severity, source_format)

        # Normalize platforms
        normalized_platforms = self._normalize_platforms(rule.platforms)

        # Normalize references
        normalized_references = self._normalize_references(rule.references)

        # Clean text fields
        normalized_title = clean_text(rule.title, MAX_TITLE_LENGTH)
        normalized_description = clean_text(rule.description, MAX_DESCRIPTION_LENGTH, preserve_formatting=True)
        normalized_rationale = clean_text(rule.rationale, MAX_RATIONALE_LENGTH, preserve_formatting=True)
        normalized_fix = clean_text(rule.fix_content, MAX_FIX_CONTENT_LENGTH, preserve_formatting=True)
        normalized_check = clean_text(rule.check_content, MAX_CHECK_CONTENT_LENGTH, preserve_formatting=True)

        self.stats.text_fields_cleaned += 5

        # Normalize metadata
        normalized_metadata = self._normalize_metadata(rule.metadata)

        # Create new normalized rule
        return ParsedRule(
            rule_id=rule.rule_id,
            title=normalized_title,
            description=normalized_description,
            severity=normalized_severity,
            rationale=normalized_rationale,
            check_content=normalized_check,
            fix_content=normalized_fix,
            references=normalized_references,
            platforms=normalized_platforms,
            metadata=normalized_metadata,
        )

    def normalize_profile(self, profile: ParsedProfile) -> ParsedProfile:
        """
        Normalize a parsed profile.

        Args:
            profile: ParsedProfile to normalize.

        Returns:
            New ParsedProfile with normalized data.
        """
        # Clean text fields
        normalized_title = clean_text(profile.title, MAX_TITLE_LENGTH)
        normalized_description = clean_text(profile.description, MAX_DESCRIPTION_LENGTH, preserve_formatting=True)

        # Normalize metadata
        normalized_metadata = self._normalize_metadata(profile.metadata)

        return ParsedProfile(
            profile_id=profile.profile_id,
            title=normalized_title,
            description=normalized_description,
            selected_rules=profile.selected_rules,  # Rule IDs don't need normalization
            extends=profile.extends,
            metadata=normalized_metadata,
        )

    def _normalize_rule_severity(
        self,
        severity: ContentSeverity,
        source_format: Optional[ContentFormat],
    ) -> ContentSeverity:
        """
        Normalize a rule's severity value.

        Args:
            severity: Current severity (may be enum or string).
            source_format: Source format for context.

        Returns:
            Normalized ContentSeverity enum.
        """
        self.stats.severities_normalized += 1

        # If already a ContentSeverity, it's normalized
        if isinstance(severity, ContentSeverity):
            return severity

        # Convert string to ContentSeverity
        return normalize_severity(str(severity), source_format)

    def _normalize_platforms(self, platforms: List[str]) -> List[str]:
        """
        Normalize a list of platform identifiers.

        Args:
            platforms: List of platform names.

        Returns:
            List of normalized platform identifiers.
        """
        normalized: List[str] = []
        seen: Set[str] = set()

        for platform in platforms:
            norm_platform = normalize_platform(platform)
            if norm_platform and norm_platform not in seen:
                normalized.append(norm_platform)
                seen.add(norm_platform)
                self.stats.platforms_normalized += 1

        return normalized

    def _normalize_references(
        self,
        references: Dict[str, List[str]],
    ) -> Dict[str, List[str]]:
        """
        Normalize and consolidate references.

        Processes references to ensure consistent typing and format,
        and consolidates duplicates.

        Args:
            references: Dictionary of reference type -> list of IDs.

        Returns:
            Normalized references dictionary.
        """
        normalized: Dict[str, List[str]] = {}

        for ref_type, ref_ids in references.items():
            for ref_id in ref_ids:
                norm_id, detected_type = normalize_reference(ref_id, ref_type)
                if norm_id:
                    if detected_type not in normalized:
                        normalized[detected_type] = []
                    if norm_id not in normalized[detected_type]:
                        normalized[detected_type].append(norm_id)
                        self.stats.references_extracted += 1

        return normalized

    def _normalize_metadata(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize metadata structure.

        Ensures consistent key naming and cleans string values.

        Args:
            metadata: Raw metadata dictionary.

        Returns:
            Normalized metadata dictionary.
        """
        if not metadata:
            return {}

        normalized: Dict[str, Any] = {}

        for key, value in metadata.items():
            # Normalize key name (lowercase, underscores)
            norm_key = key.lower().replace("-", "_").replace(" ", "_")

            # Clean string values
            if isinstance(value, str):
                normalized[norm_key] = clean_text(value, max_length=1000)
            elif isinstance(value, dict):
                # Recursively normalize nested dicts
                normalized[norm_key] = self._normalize_metadata(value)
            elif isinstance(value, list):
                # Clean list items if strings
                normalized[norm_key] = [
                    clean_text(item, max_length=500) if isinstance(item, str) else item for item in value
                ]
            else:
                normalized[norm_key] = value

        return normalized


# Convenience function for simple normalization
def normalize_content(
    content: ParsedContent,
    source_format: Optional[ContentFormat] = None,
) -> ParsedContent:
    """
    Convenience function to normalize parsed content.

    Creates a normalizer instance and normalizes the content.
    For batch operations, create a ContentNormalizer instance directly.

    Args:
        content: ParsedContent to normalize.
        source_format: Optional format override.

    Returns:
        Normalized ParsedContent.

    Example:
        >>> from backend.app.services.content.transformation import normalize_content
        >>> normalized = normalize_content(parsed_content)
    """
    normalizer = ContentNormalizer()
    return normalizer.normalize_content(content, source_format)
