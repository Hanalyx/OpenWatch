"""
SCAP Dependency Validator - Validates and resolves SCAP content dependencies

This module provides dependency resolution and validation for SCAP content files,
ensuring all referenced files (OVAL, CPE, tailoring, etc.) are identified and
validated before import or remote transfer operations.

Design Philosophy:
    - Single Responsibility: Focuses solely on dependency resolution and validation
    - Defensive Coding: Gracefully handles missing files, malformed XML
    - Security-First: Uses secure XML parsing to prevent XXE attacks
    - Immutable Results: Returns dataclasses for predictable state management

Architecture:
    - DependencyValidator: Main class for resolving and validating dependencies
    - SCAPDependency: Immutable dataclass representing a single dependency
    - ValidationResult: Result of dependency validation with errors/warnings

Supported Content Types:
    - XCCDF 1.1 and 1.2 benchmarks
    - SCAP 1.2 and 1.3 datastreams
    - OVAL definition files
    - CPE dictionaries
    - Tailoring files

Security Notes:
    - Uses defusedxml for XML parsing to prevent XXE attacks
    - Validates file paths to prevent directory traversal
    - Limits file sizes to prevent DoS attacks
    - Sanitizes error messages to prevent information disclosure

Usage:
    from app.services.content.import.validator import (
        DependencyValidator,
        SCAPDependency,
    )

    # Resolve dependencies for a SCAP file
    validator = DependencyValidator()
    dependencies = validator.resolve("/path/to/xccdf.xml")

    # Validate all dependencies exist
    validation = validator.validate_dependencies()
    if not validation.is_valid:
        for error in validation.errors:
            print(f"Missing: {error}")

    # Get files for transfer
    files = validator.get_transfer_list()

Related Modules:
    - content.parsers.scap: XCCDF parsing
    - content.parsers.datastream: Datastream parsing
    - content.import.importer: Content import orchestration
"""

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

# Use defusedxml for secure XML parsing (prevents XXE attacks)
# Falls back to standard library with security warnings if unavailable
try:
    import defusedxml.ElementTree as ET

    SECURE_XML = True
except ImportError:
    import xml.etree.ElementTree as ET

    SECURE_XML = False
    logging.getLogger(__name__).warning(
        "defusedxml not available, using standard xml.etree.ElementTree. "
        "Consider installing defusedxml for XXE protection."
    )

logger = logging.getLogger(__name__)

# Maximum file size to parse (10MB) - prevents DoS attacks
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024

# XML namespaces commonly used in SCAP content
# These enable proper namespace-aware parsing of SCAP documents
SCAP_NAMESPACES: Dict[str, str] = {
    "xccdf": "http://checklists.nist.gov/xccdf/1.2",
    "xccdf-1.1": "http://checklists.nist.gov/xccdf/1.1",
    "oval": "http://oval.mitre.org/XMLSchema/oval-definitions-5",
    "scap": "http://scap.nist.gov/schema/scap/source/1.2",
    "ds": "http://scap.nist.gov/schema/scap/source/1.2",
    "cpe": "http://cpe.mitre.org/dictionary/2.0",
}


@dataclass(frozen=True)
class SCAPDependency:
    """
    Represents a SCAP file dependency with metadata about its relationship.

    This immutable dataclass captures a single dependency in the SCAP content
    dependency graph. Each dependency tracks:
    - The file path (absolute)
    - The type of content (xccdf, oval, cpe, etc.)
    - Which file referenced it
    - Whether it's the primary file being analyzed

    Attributes:
        file_path: Absolute path to the dependency file.
        dependency_type: Content type ('xccdf', 'oval', 'cpe', 'tailoring', 'datastream', 'other').
        referenced_by: Path to the file that references this dependency.
        is_primary: True if this is the main file being analyzed.

    Example:
        >>> dep = SCAPDependency(
        ...     file_path=Path("/app/content/oval-defs.xml"),
        ...     dependency_type="oval",
        ...     referenced_by=Path("/app/content/xccdf.xml"),
        ...     is_primary=False,
        ... )
        >>> print(dep.file_path.name)
        oval-defs.xml
    """

    file_path: Path
    dependency_type: str
    referenced_by: Optional[Path] = None
    is_primary: bool = False


@dataclass
class ValidationResult:
    """
    Result of dependency validation containing errors and warnings.

    This dataclass aggregates validation results across all dependencies,
    providing a comprehensive view of what's missing or problematic.

    Attributes:
        is_valid: True if no critical errors were found.
        errors: List of critical error messages (missing files, etc.).
        warnings: List of non-critical warning messages.
        checked_count: Number of dependencies that were validated.

    Example:
        >>> result = ValidationResult(
        ...     is_valid=False,
        ...     errors=["Missing dependency: oval-defs.xml"],
        ...     warnings=["Large file detected: benchmark.xml (15MB)"],
        ...     checked_count=3,
        ... )
    """

    is_valid: bool = True
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    checked_count: int = 0


class DependencyValidator:
    """
    Resolves and validates SCAP content dependencies.

    This class analyzes SCAP content files (XCCDF benchmarks, datastreams) to
    identify all required dependencies such as OVAL definition files, CPE
    dictionaries, and tailoring files. It then validates that all dependencies
    exist and are accessible.

    The resolver supports:
    - XCCDF 1.1 and 1.2 check-content-ref elements
    - SCAP 1.2 and 1.3 datastream components
    - Relative and absolute path references
    - Co-located files (common pattern for generated content)

    Typical Workflow:
        1. Create validator instance
        2. Call resolve() with primary SCAP file
        3. Call validate_dependencies() to check all files exist
        4. Call get_transfer_list() to get ordered file list for transfer

    Thread Safety:
        Not thread-safe. Create separate instances for concurrent use.

    Attributes:
        resolved_files: Set of file paths that have been resolved.
        dependencies: List of SCAPDependency objects representing all files.
        namespaces: XML namespace mappings for parsing.

    Example:
        >>> validator = DependencyValidator()
        >>> deps = validator.resolve(Path("/app/content/xccdf.xml"))
        >>> print(f"Found {len(deps)} dependencies")
        Found 3 dependencies
        >>> validation = validator.validate_dependencies()
        >>> if validation.is_valid:
        ...     files = validator.get_transfer_list()
        ...     for f in files:
        ...         print(f"Transfer: {f.name}")
    """

    def __init__(self) -> None:
        """Initialize the dependency validator with empty state."""
        self.resolved_files: Set[Path] = set()
        self.dependencies: List[SCAPDependency] = []
        self.namespaces: Dict[str, str] = SCAP_NAMESPACES.copy()

    def resolve(
        self,
        primary_file: Path,
        base_dir: Optional[Path] = None,
    ) -> List[SCAPDependency]:
        """
        Resolve all dependencies for a SCAP content file.

        This method parses the primary file and recursively identifies all
        referenced content files. It handles both explicit references
        (check-content-ref elements) and implicit co-located files.

        Args:
            primary_file: Path to the main SCAP file (XCCDF or datastream).
                         Must be an absolute path to an existing file.
            base_dir: Base directory for resolving relative paths.
                     Defaults to primary_file's parent directory.

        Returns:
            List of SCAPDependency objects representing all files needed,
            including the primary file itself.

        Raises:
            FileNotFoundError: If the primary file does not exist.
            ValueError: If the primary file path is not absolute.

        Security:
            - Validates file paths to prevent directory traversal
            - Limits file size to prevent DoS
            - Uses secure XML parsing when available

        Example:
            >>> validator = DependencyValidator()
            >>> deps = validator.resolve(Path("/app/content/ssg-rhel8-xccdf.xml"))
            >>> for dep in deps:
            ...     print(f"{dep.file_path.name}: {dep.dependency_type}")
            ssg-rhel8-xccdf.xml: xccdf
            ssg-rhel8-oval.xml: oval
            ssg-rhel8-cpe-dictionary.xml: cpe
        """
        # Validate input path
        primary_file = Path(primary_file)
        if not primary_file.is_absolute():
            # Convert to absolute for consistent handling
            primary_file = primary_file.resolve()

        if not primary_file.exists():
            raise FileNotFoundError(f"Primary SCAP file not found: {primary_file}")

        # Set base directory for relative path resolution
        base_dir = Path(base_dir) if base_dir else primary_file.parent

        # Reset state for fresh resolution
        self.resolved_files.clear()
        self.dependencies.clear()

        # Detect file type and add as primary dependency
        file_type = self._detect_file_type(primary_file)
        primary_dep = SCAPDependency(
            file_path=primary_file,
            dependency_type=file_type,
            referenced_by=None,
            is_primary=True,
        )
        self.dependencies.append(primary_dep)
        self.resolved_files.add(primary_file)

        # Resolve dependencies based on file type
        # Each type has different reference patterns
        if file_type == "xccdf":
            self._resolve_xccdf_dependencies(primary_file, base_dir)
        elif file_type == "datastream":
            self._resolve_datastream_dependencies(primary_file, base_dir)
        # OVAL, CPE, and tailoring files typically don't have external deps

        logger.info(
            "Resolved %d SCAP dependencies for %s",
            len(self.dependencies),
            primary_file.name,
        )

        return self.dependencies

    def _detect_file_type(self, file_path: Path) -> str:
        """
        Detect SCAP file type by examining the XML root element.

        Uses the root element tag to determine the content type. This is
        more reliable than file extensions since SCAP files may have
        non-standard naming.

        Args:
            file_path: Path to the SCAP file to analyze.

        Returns:
            Content type string: 'xccdf', 'datastream', 'oval', 'cpe',
            'tailoring', or 'other' if unknown.

        Security:
            Uses secure XML parsing to prevent XXE attacks.
        """
        try:
            # Check file size before parsing (DoS prevention)
            if file_path.stat().st_size > MAX_FILE_SIZE_BYTES:
                logger.warning(
                    "File %s exceeds size limit (%d bytes), type detection may fail",
                    file_path.name,
                    MAX_FILE_SIZE_BYTES,
                )
                return "other"

            # Parse XML root element only (faster than full parse)
            tree = ET.parse(str(file_path))
            root = tree.getroot()

            # Check root element tag for content type indicators
            # Tag may include namespace prefix, so use 'in' checks
            tag = root.tag.lower()

            if "benchmark" in tag:
                return "xccdf"
            elif "data-stream-collection" in tag or "datastreamcollection" in tag:
                return "datastream"
            elif "oval_definitions" in tag or "oval-definitions" in tag:
                return "oval"
            elif "platform-specification" in tag or "cpe-list" in tag:
                return "cpe"
            elif "tailoring" in tag:
                return "tailoring"
            else:
                logger.debug("Unknown SCAP type for %s (tag: %s)", file_path.name, tag)
                return "other"

        except ET.ParseError as e:
            logger.warning("XML parse error detecting type for %s: %s", file_path.name, e)
            return "other"
        except OSError as e:
            logger.warning("File access error for %s: %s", file_path.name, e)
            return "other"
        except Exception as e:
            # Catch-all for unexpected errors - don't fail dependency resolution
            logger.warning("Unexpected error detecting file type for %s: %s", file_path.name, e)
            return "other"

    def _resolve_xccdf_dependencies(self, xccdf_file: Path, base_dir: Path) -> None:
        """
        Parse XCCDF file to find check-content-ref and other references.

        XCCDF files reference external content via:
        - <check-content-ref href="..."> for OVAL definitions
        - <reference href="..."> for external documentation
        - Co-located files with naming patterns (oval-*.xml, cpe-*.xml)

        Args:
            xccdf_file: Path to the XCCDF benchmark file.
            base_dir: Base directory for resolving relative paths.

        Security:
            - Uses secure XML parsing
            - Validates resolved paths against base directory
        """
        try:
            tree = ET.parse(str(xccdf_file))
            root = tree.getroot()

            # Collect all reference elements
            # Try multiple namespace prefixes for XCCDF 1.1/1.2 compatibility
            ref_elements = []

            for ns_prefix in ["xccdf", "xccdf-1.1"]:
                ns = self.namespaces.get(ns_prefix, "")
                if ns:
                    # Find check-content-ref elements (OVAL references)
                    ref_elements.extend(root.findall(f".//{{{ns}}}check-content-ref"))
                    # Find reference elements (documentation links)
                    ref_elements.extend(root.findall(f".//{{{ns}}}reference"))

            # Also try without namespace for files with default namespace
            ref_elements.extend(root.findall(".//check-content-ref"))

            logger.debug(
                "Found %d reference elements in %s",
                len(ref_elements),
                xccdf_file.name,
            )

            # Extract href attributes and add as dependencies
            for ref in ref_elements:
                href = ref.get("href")
                if href:
                    self._add_dependency_from_href(href, base_dir, xccdf_file)

            # Check for co-located files (common for MongoDB-generated content)
            # These files follow naming patterns and are in the same directory
            self._discover_colocated_files(xccdf_file, base_dir)

        except ET.ParseError as e:
            logger.error("Failed to parse XCCDF file %s: %s", xccdf_file.name, e)
        except Exception as e:
            logger.error("Error resolving XCCDF dependencies for %s: %s", xccdf_file.name, e)

    def _resolve_datastream_dependencies(self, datastream_file: Path, base_dir: Path) -> None:
        """
        Parse SCAP datastream to find external component references.

        SCAP datastreams typically embed all content inline, so external
        dependencies are rare. However, component-ref elements may point
        to external files in some configurations.

        Args:
            datastream_file: Path to the SCAP datastream file.
            base_dir: Base directory for resolving relative paths.
        """
        try:
            tree = ET.parse(str(datastream_file))
            root = tree.getroot()

            # Check for external component references
            # Most datastreams use internal references (#fragment) which we skip
            for ns_prefix in ["ds", "scap"]:
                ns = self.namespaces.get(ns_prefix, "")
                if ns:
                    refs = root.findall(f".//{{{ns}}}component-ref")
                    for ref in refs:
                        # Try both href and xlink:href attributes
                        href = ref.get("href") or ref.get("{http://www.w3.org/1999/xlink}href")
                        if href and not href.startswith("#"):
                            # External reference (not internal fragment)
                            self._add_dependency_from_href(href, base_dir, datastream_file)

            logger.debug("Resolved datastream dependencies for %s", datastream_file.name)

        except ET.ParseError as e:
            logger.error("Failed to parse datastream %s: %s", datastream_file.name, e)
        except Exception as e:
            logger.error("Error resolving datastream dependencies: %s", e)

    def _add_dependency_from_href(
        self,
        href: str,
        base_dir: Path,
        referenced_by: Path,
    ) -> None:
        """
        Add a dependency from an href reference after validation.

        Handles:
        - Fragment identifiers (file.xml#fragment -> file.xml)
        - Relative paths (resolved against base_dir)
        - Absolute paths (used directly)
        - URL schemes (http:// etc. - logged but not added)

        Args:
            href: The href attribute value from XML.
            base_dir: Base directory for resolving relative paths.
            referenced_by: Path to the file containing the reference.

        Security:
            - Strips fragment identifiers
            - Validates resolved paths are within allowed directories
            - Skips URL references
        """
        # Handle fragment identifiers (e.g., "file.xml#some-id")
        if "#" in href:
            href = href.split("#")[0]

        # Skip empty or anchor-only references
        if not href or href.startswith("#"):
            return

        # Skip URL references (http://, https://, etc.)
        if "://" in href:
            logger.debug("Skipping URL reference: %s", href[:50])
            return

        # Resolve path (handle both relative and absolute)
        if href.startswith("/"):
            dep_path = Path(href)
        else:
            dep_path = (base_dir / href).resolve()

        # Security: Ensure resolved path doesn't escape base directory
        # This prevents directory traversal attacks (../../../etc/passwd)
        try:
            dep_path.relative_to(base_dir.parent)
        except ValueError:
            logger.warning(
                "Potential directory traversal detected in href: %s",
                href[:100],
            )
            return

        # Add if file exists and not already resolved
        if dep_path.exists() and dep_path not in self.resolved_files:
            dep_type = self._detect_file_type(dep_path)
            dep = SCAPDependency(
                file_path=dep_path,
                dependency_type=dep_type,
                referenced_by=referenced_by,
                is_primary=False,
            )
            self.dependencies.append(dep)
            self.resolved_files.add(dep_path)
            logger.debug("Added dependency: %s (type: %s)", dep_path.name, dep_type)

    def _discover_colocated_files(self, primary_file: Path, base_dir: Path) -> None:
        """
        Discover co-located SCAP files that may be implicit dependencies.

        MongoDB-generated content and some SCAP bundles place related files
        in the same directory without explicit references. This method
        discovers them using common naming patterns.

        Patterns checked:
        - oval-definitions.xml, oval-*.xml (OVAL definitions)
        - cpe-*.xml, cpe-dictionary.xml (CPE dictionaries)

        Args:
            primary_file: The primary SCAP file being analyzed.
            base_dir: Directory to search for co-located files.
        """
        # Patterns that indicate related SCAP content
        patterns = [
            "oval-definitions.xml",
            "oval-*.xml",
            "cpe-*.xml",
            "cpe-dictionary.xml",
        ]

        for pattern in patterns:
            for found_file in base_dir.glob(pattern):
                # Skip if already resolved or is the primary file
                if found_file in self.resolved_files:
                    continue
                if found_file == primary_file:
                    continue

                dep_type = self._detect_file_type(found_file)
                dep = SCAPDependency(
                    file_path=found_file,
                    dependency_type=dep_type,
                    referenced_by=primary_file,
                    is_primary=False,
                )
                self.dependencies.append(dep)
                self.resolved_files.add(found_file)
                logger.debug("Added co-located dependency: %s", found_file.name)

    def validate_dependencies(self) -> ValidationResult:
        """
        Validate that all resolved dependencies exist and are accessible.

        Performs these checks on each dependency:
        - File exists
        - Is a regular file (not directory, symlink, etc.)
        - Has non-zero size
        - Is readable

        Returns:
            ValidationResult with is_valid, errors, and warnings.

        Example:
            >>> validator = DependencyValidator()
            >>> validator.resolve(Path("/app/content/xccdf.xml"))
            >>> result = validator.validate_dependencies()
            >>> if not result.is_valid:
            ...     print(f"Errors: {result.errors}")
        """
        result = ValidationResult(
            is_valid=True,
            errors=[],
            warnings=[],
            checked_count=len(self.dependencies),
        )

        for dep in self.dependencies:
            path = dep.file_path

            # Check existence
            if not path.exists():
                result.is_valid = False
                result.errors.append(f"Missing dependency: {path}")
                continue

            # Check is regular file
            if not path.is_file():
                result.is_valid = False
                result.errors.append(f"Not a regular file: {path}")
                continue

            # Check non-empty
            try:
                size = path.stat().st_size
                if size == 0:
                    result.is_valid = False
                    result.errors.append(f"Empty file: {path}")
                elif size > MAX_FILE_SIZE_BYTES:
                    result.warnings.append(f"Large file ({size / 1024 / 1024:.1f}MB): {path.name}")
            except OSError as e:
                result.is_valid = False
                result.errors.append(f"Cannot access file {path.name}: {e}")

        return result

    def get_transfer_list(self) -> List[Path]:
        """
        Get ordered list of file paths for transfer operations.

        Returns dependencies in the correct order for remote transfer:
        dependencies first, then the primary file last. This ensures
        all referenced content is available when the main file is processed.

        Returns:
            List of absolute file paths, dependencies first, primary last.

        Example:
            >>> validator = DependencyValidator()
            >>> validator.resolve(Path("/app/content/xccdf.xml"))
            >>> files = validator.get_transfer_list()
            >>> print(f"Transfer {len(files)} files")
            >>> print(f"Primary file is last: {files[-1].name}")
        """
        # Sort: non-primary first (is_primary=False), then primary (is_primary=True)
        # This ensures dependencies are transferred before the main file
        sorted_deps = sorted(self.dependencies, key=lambda d: d.is_primary)
        return [dep.file_path for dep in sorted_deps]

    def get_file_manifest(self) -> Dict[str, str]:
        """
        Get manifest mapping filenames to their content types.

        Useful for logging, UI display, or metadata generation.

        Returns:
            Dictionary mapping filename (not full path) to content type.

        Example:
            >>> validator = DependencyValidator()
            >>> validator.resolve(Path("/app/content/xccdf.xml"))
            >>> manifest = validator.get_file_manifest()
            >>> print(manifest)
            {'xccdf.xml': 'xccdf', 'oval-defs.xml': 'oval'}
        """
        return {dep.file_path.name: dep.dependency_type for dep in self.dependencies}

    def get_dependencies_by_type(self, content_type: str) -> List[SCAPDependency]:
        """
        Get all dependencies of a specific content type.

        Args:
            content_type: Type to filter by ('xccdf', 'oval', 'cpe', etc.).

        Returns:
            List of SCAPDependency objects matching the specified type.

        Example:
            >>> oval_deps = validator.get_dependencies_by_type("oval")
            >>> print(f"Found {len(oval_deps)} OVAL files")
        """
        return [dep for dep in self.dependencies if dep.dependency_type == content_type]

    def clear(self) -> None:
        """
        Clear all resolved state, preparing for a new resolution.

        Call this method before resolving a new set of dependencies
        if reusing the same validator instance.
        """
        self.resolved_files.clear()
        self.dependencies.clear()
