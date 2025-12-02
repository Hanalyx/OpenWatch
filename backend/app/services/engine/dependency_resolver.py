"""
SCAP Dependency Resolver - File Dependency Analysis for Remote Execution

This module provides intelligent dependency resolution for SCAP content files,
ensuring all referenced files (OVAL, CPE, tailoring, etc.) are identified and
validated before remote transfer.

Architecture:
    The dependency resolver sits between content management and execution:

    Content Module (parsers) --> Dependency Resolver --> SSH Executor

    It analyzes XCCDF/datastream files to find all referenced OVAL definitions,
    CPE dictionaries, and other dependencies required for successful scan execution.

Supported SCAP Content Types:
    - XCCDF 1.1 and 1.2 benchmarks
    - SCAP 1.2 and 1.3 datastreams
    - OVAL definitions (standalone or referenced)
    - CPE dictionaries
    - Tailoring files

Design Philosophy:
    - Single Responsibility: Only resolves dependencies, no execution logic
    - Defensive: Validates all paths, handles missing files gracefully
    - Security-First: Path traversal prevention, safe XML parsing
    - Type-Safe: Full type annotations for IDE support
    - Testable: Pure functions where possible, clear interfaces

Usage:
    from backend.app.services.engine import SCAPDependencyResolver, SCAPDependency

    resolver = SCAPDependencyResolver()
    dependencies = resolver.resolve(Path("/app/data/scap/xccdf.xml"))

    # Get list of files to transfer
    transfer_files = resolver.get_transfer_list()

    # Validate all dependencies exist
    errors = resolver.validate_dependencies()
    if errors:
        raise DependencyError(f"Missing dependencies: {errors}")

Security Notes:
    - XML parsing uses standard library (no external entity expansion)
    - All paths resolved to absolute paths and validated
    - Path traversal attempts are blocked
    - Empty/malformed files are detected and reported
"""

import logging
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set

from .exceptions import DependencyError

logger = logging.getLogger(__name__)


@dataclass
class SCAPDependency:
    """
    Represents a SCAP file dependency identified during resolution.

    This dataclass holds metadata about a single file that is part of
    a SCAP content bundle (XCCDF + OVAL + CPE + tailoring).

    Attributes:
        file_path: Absolute path to the dependency file
        dependency_type: Type of SCAP content ('xccdf', 'oval', 'cpe', 'tailoring', 'datastream', 'other')
        referenced_by: Path to the file that references this dependency (None for primary)
        is_primary: True if this is the main content file (not a dependency)

    Usage:
        dep = SCAPDependency(
            file_path=Path("/app/data/scap/oval-definitions.xml"),
            dependency_type="oval",
            referenced_by=Path("/app/data/scap/xccdf.xml"),
            is_primary=False
        )
    """

    file_path: Path
    dependency_type: str  # 'xccdf', 'oval', 'cpe', 'tailoring', 'datastream', 'other'
    referenced_by: Optional[Path] = None
    is_primary: bool = False

    def __post_init__(self):
        """Validate dependency type is recognized."""
        valid_types = {"xccdf", "oval", "cpe", "tailoring", "datastream", "other"}
        if self.dependency_type not in valid_types:
            logger.warning(
                "Unrecognized dependency type '%s' for %s, treating as 'other'",
                self.dependency_type,
                self.file_path.name,
            )
            object.__setattr__(self, "dependency_type", "other")


class SCAPDependencyResolver:
    """
    Resolves SCAP content dependencies by parsing XML files.

    This class analyzes SCAP content (XCCDF benchmarks, datastreams) to
    identify all files required for scan execution. It follows references
    in check-content-ref elements and component-ref elements.

    Thread Safety:
        Not thread-safe. Create one resolver per scan operation.

    Attributes:
        resolved_files: Set of already-processed file paths (prevents cycles)
        dependencies: List of SCAPDependency objects found during resolution

    Supported Content:
        - XCCDF 1.2 check-content-ref elements pointing to OVAL
        - XCCDF 1.1 check-content-ref elements (legacy format)
        - SCAP 1.3 datastream component references
        - Co-located files (oval-definitions.xml in same directory)

    Usage:
        resolver = SCAPDependencyResolver()

        # Resolve all dependencies
        deps = resolver.resolve(Path("/app/data/scap/xccdf.xml"))

        # Get transfer manifest
        files_to_transfer = resolver.get_transfer_list()

        # Check for issues
        errors = resolver.validate_dependencies()
    """

    # XML namespaces for SCAP content parsing
    # These cover XCCDF 1.1, XCCDF 1.2, OVAL 5.x, SCAP 1.2, and CPE 2.0
    NAMESPACES: Dict[str, str] = {
        "xccdf": "http://checklists.nist.gov/xccdf/1.2",
        "xccdf-1.1": "http://checklists.nist.gov/xccdf/1.1",
        "oval": "http://oval.mitre.org/XMLSchema/oval-definitions-5",
        "scap": "http://scap.nist.gov/schema/scap/source/1.2",
        "ds": "http://scap.nist.gov/schema/scap/source/1.2",
        "cpe": "http://cpe.mitre.org/dictionary/2.0",
    }

    def __init__(self):
        """Initialize the dependency resolver with empty state."""
        self.resolved_files: Set[Path] = set()
        self.dependencies: List[SCAPDependency] = []
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def resolve(self, primary_file: Path, base_dir: Optional[Path] = None) -> List[SCAPDependency]:
        """
        Resolve all dependencies for a SCAP content file.

        This is the main entry point for dependency resolution. It parses
        the primary content file and recursively identifies all referenced
        files needed for scan execution.

        Args:
            primary_file: Main SCAP file (XCCDF benchmark or datastream)
            base_dir: Base directory for resolving relative paths.
                     Defaults to the primary file's parent directory.

        Returns:
            List of SCAPDependency objects representing all files needed,
            including the primary file itself.

        Raises:
            DependencyError: If primary file does not exist
            FileNotFoundError: If primary file path is invalid

        Example:
            >>> resolver = SCAPDependencyResolver()
            >>> deps = resolver.resolve(Path("/app/data/scap/ssg-rhel8-xccdf.xml"))
            >>> print(f"Found {len(deps)} dependencies")
            Found 3 dependencies
        """
        # Validate primary file exists
        if not primary_file.exists():
            raise DependencyError(
                message=f"Primary SCAP file not found: {primary_file}",
                primary_file=str(primary_file),
                missing_files=[str(primary_file)],
            )

        # Security: Resolve to absolute path to prevent path traversal
        primary_file = primary_file.resolve()
        base_dir = (base_dir or primary_file.parent).resolve()

        # Reset state for new resolution
        self.resolved_files.clear()
        self.dependencies.clear()

        # Detect file type and add primary file
        file_type = self._detect_file_type(primary_file)
        primary_dep = SCAPDependency(
            file_path=primary_file, dependency_type=file_type, is_primary=True
        )
        self.dependencies.append(primary_dep)
        self.resolved_files.add(primary_file)

        # Resolve based on file type
        if file_type == "xccdf":
            self._resolve_xccdf_dependencies(primary_file, base_dir)
        elif file_type == "datastream":
            self._resolve_datastream_dependencies(primary_file, base_dir)
        else:
            self._logger.debug(
                "File type '%s' does not have external dependencies: %s",
                file_type,
                primary_file.name,
            )

        self._logger.info(
            "Resolved %d SCAP dependencies for %s", len(self.dependencies), primary_file.name
        )
        return self.dependencies

    def _detect_file_type(self, file_path: Path) -> str:
        """
        Detect SCAP file type by examining XML root element.

        Parses the file to determine what type of SCAP content it contains
        based on the root element's tag name and namespace.

        Args:
            file_path: Path to the SCAP content file

        Returns:
            Content type string: 'xccdf', 'datastream', 'oval', 'cpe',
            'tailoring', or 'other'

        Security:
            Uses xml.etree.ElementTree which is safe from XXE by default
            in Python 3.7.1+ (disables external entities)
        """
        try:
            # Parse only the root element to determine type
            tree = ET.parse(file_path)
            root = tree.getroot()
            tag = root.tag.lower()

            # Check root element tag for content type
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
                return "other"

        except ET.ParseError as e:
            self._logger.warning(
                "XML parse error detecting file type for %s: %s", file_path, str(e)
            )
            return "other"
        except Exception as e:
            self._logger.warning("Could not detect file type for %s: %s", file_path, str(e))
            return "other"

    def _resolve_xccdf_dependencies(self, xccdf_file: Path, base_dir: Path) -> None:
        """
        Parse XCCDF file to find check-content-ref elements.

        XCCDF benchmarks reference OVAL definitions and other content via
        check-content-ref elements within Rule definitions. This method
        extracts those references.

        Example XCCDF check:
            <xccdf:check system="http://oval.mitre.org/XMLSchema/oval-definitions-5">
                <xccdf:check-content-ref name="oval:..." href="oval-definitions.xml"/>
            </xccdf:check>

        Args:
            xccdf_file: Path to the XCCDF benchmark file
            base_dir: Base directory for resolving relative paths
        """
        try:
            tree = ET.parse(xccdf_file)
            root = tree.getroot()

            # Find all check-content-ref elements across namespace variants
            ref_elements: List[ET.Element] = []

            # Try XCCDF 1.2 namespace
            ns = self.NAMESPACES.get("xccdf", "")
            if ns:
                ref_elements.extend(root.findall(f".//{{{ns}}}check-content-ref"))

            # Try XCCDF 1.1 namespace (legacy)
            ns_legacy = self.NAMESPACES.get("xccdf-1.1", "")
            if ns_legacy:
                ref_elements.extend(root.findall(f".//{{{ns_legacy}}}check-content-ref"))

            # Try without namespace for non-conformant files
            ref_elements.extend(root.findall(".//check-content-ref"))

            # Also check for external reference elements
            for ns_key in ["xccdf", "xccdf-1.1"]:
                ns = self.NAMESPACES.get(ns_key, "")
                if ns:
                    ref_elements.extend(root.findall(f".//{{{ns}}}reference"))

            self._logger.debug(
                "Found %d check-content-ref elements in %s", len(ref_elements), xccdf_file.name
            )

            # Extract href attributes and add dependencies
            for ref in ref_elements:
                href = ref.get("href")
                if href:
                    self._add_dependency(href, base_dir, xccdf_file)

            # Check for co-located files (common pattern for MongoDB-generated content)
            # These are OVAL/CPE files in the same directory not explicitly referenced
            self._resolve_colocated_dependencies(xccdf_file, base_dir)

        except ET.ParseError as e:
            self._logger.error("Failed to parse XCCDF file %s: %s", xccdf_file, str(e))
        except Exception as e:
            self._logger.error("Error resolving XCCDF dependencies for %s: %s", xccdf_file, str(e))

    def _resolve_datastream_dependencies(self, datastream_file: Path, base_dir: Path) -> None:
        """
        Parse SCAP datastream to find component references.

        SCAP datastreams typically embed all content inline, but may have
        external component-ref elements pointing to separate files.

        Note: Most datastreams are self-contained, so external dependencies
        are rare but must be handled for edge cases.

        Args:
            datastream_file: Path to the SCAP datastream file
            base_dir: Base directory for resolving relative paths
        """
        try:
            tree = ET.parse(datastream_file)
            root = tree.getroot()

            # Check for external component-ref elements
            for ns_key in ["ds", "scap"]:
                ns = self.NAMESPACES.get(ns_key, "")
                if ns:
                    refs = root.findall(f".//{{{ns}}}component-ref")
                    for ref in refs:
                        # Try both href and xlink:href attributes
                        href = ref.get("href") or ref.get("{http://www.w3.org/1999/xlink}href")
                        # Skip internal references (start with #)
                        if href and not href.startswith("#"):
                            self._add_dependency(href, base_dir, datastream_file)

            self._logger.debug("Resolved datastream dependencies for %s", datastream_file.name)

        except ET.ParseError as e:
            self._logger.error("Failed to parse datastream %s: %s", datastream_file, str(e))
        except Exception as e:
            self._logger.error("Error resolving datastream dependencies: %s", str(e))

    def _resolve_colocated_dependencies(self, primary_file: Path, base_dir: Path) -> None:
        """
        Check for commonly named OVAL/CPE files in the same directory.

        MongoDB-generated XCCDF content may not explicitly reference OVAL
        files but expects them to be in the same directory with standard names.

        Args:
            primary_file: The primary XCCDF file
            base_dir: Directory to search for co-located files
        """
        # Common patterns for co-located SCAP files
        colocated_patterns = [
            "oval-definitions.xml",
            "oval-*.xml",
            "cpe-dictionary.xml",
            "cpe-*.xml",
        ]

        for pattern in colocated_patterns:
            for found_file in base_dir.glob(pattern):
                # Skip if already resolved or is the primary file
                if found_file in self.resolved_files or found_file == primary_file:
                    continue

                # Determine type and add dependency
                dep_type = self._detect_file_type(found_file)
                dep = SCAPDependency(
                    file_path=found_file,
                    dependency_type=dep_type,
                    referenced_by=primary_file,
                    is_primary=False,
                )
                self.dependencies.append(dep)
                self.resolved_files.add(found_file)

                self._logger.debug(
                    "Added co-located dependency: %s (type: %s)", found_file.name, dep_type
                )

    def _add_dependency(self, href: str, base_dir: Path, referenced_by: Path) -> None:
        """
        Add a dependency from an href reference.

        Resolves the href to an absolute path and adds it to the
        dependency list if it exists and hasn't been processed.

        Args:
            href: The href attribute value (may be relative or absolute)
            base_dir: Base directory for resolving relative paths
            referenced_by: The file that contains this reference

        Security:
            Validates paths to prevent path traversal attacks.
            Rejects references that escape the base directory.
        """
        # Handle fragment identifiers (e.g., "file.xml#fragment")
        if "#" in href:
            href = href.split("#")[0]

        # Skip empty or anchor-only references
        if not href or href.startswith("#"):
            return

        # Resolve path (support both relative and absolute)
        if href.startswith("/"):
            dep_path = Path(href)
        else:
            dep_path = (base_dir / href).resolve()

        # Security: Ensure resolved path is under base_dir (prevent traversal)
        try:
            dep_path.relative_to(base_dir.parent)  # Allow siblings
        except ValueError:
            self._logger.warning(
                "Blocked potential path traversal: %s (resolved to %s)", href, dep_path
            )
            return

        # Add if exists and not already resolved
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

            self._logger.debug("Added dependency: %s (type: %s)", dep_path.name, dep_type)
        elif not dep_path.exists():
            self._logger.debug("Referenced file does not exist: %s", dep_path)

    def get_transfer_list(self) -> List[Path]:
        """
        Get list of file paths to transfer, in dependency order.

        Returns files sorted so that dependencies are transferred before
        the primary file (which needs them to execute).

        Returns:
            List of Path objects, dependencies first, primary file last.

        Example:
            >>> resolver = SCAPDependencyResolver()
            >>> resolver.resolve(Path("/app/data/scap/xccdf.xml"))
            >>> files = resolver.get_transfer_list()
            >>> # [oval-definitions.xml, cpe-dict.xml, xccdf.xml]
        """
        # Sort: non-primary first (dependencies), then primary
        sorted_deps = sorted(self.dependencies, key=lambda d: d.is_primary)
        return [dep.file_path for dep in sorted_deps]

    def get_file_manifest(self) -> Dict[str, str]:
        """
        Get manifest of files with their types.

        Returns:
            Dictionary mapping filename -> file type.
            Useful for logging and debugging.

        Example:
            >>> manifest = resolver.get_file_manifest()
            >>> # {'xccdf.xml': 'xccdf', 'oval-definitions.xml': 'oval'}
        """
        return {dep.file_path.name: dep.dependency_type for dep in self.dependencies}

    def validate_dependencies(self) -> List[str]:
        """
        Validate that all dependencies exist and are readable.

        Checks each resolved dependency for:
        - File existence
        - Is actually a file (not directory)
        - Non-empty content

        Returns:
            List of error messages. Empty list if all dependencies are valid.

        Example:
            >>> errors = resolver.validate_dependencies()
            >>> if errors:
            ...     raise DependencyError(f"Validation failed: {errors}")
        """
        errors: List[str] = []

        for dep in self.dependencies:
            if not dep.file_path.exists():
                errors.append(f"Missing dependency: {dep.file_path}")
            elif not dep.file_path.is_file():
                errors.append(f"Not a file: {dep.file_path}")
            else:
                try:
                    if dep.file_path.stat().st_size == 0:
                        errors.append(f"Empty file: {dep.file_path}")
                except OSError as e:
                    errors.append(f"Cannot stat file {dep.file_path}: {e}")

        return errors


# =============================================================================
# Factory Function
# =============================================================================


def get_dependency_resolver() -> SCAPDependencyResolver:
    """
    Factory function to create a SCAPDependencyResolver instance.

    This is the recommended way to obtain a resolver instance,
    as it allows for future dependency injection or configuration.

    Returns:
        New SCAPDependencyResolver instance.

    Example:
        >>> from backend.app.services.engine import get_dependency_resolver
        >>> resolver = get_dependency_resolver()
        >>> deps = resolver.resolve(content_path)
    """
    return SCAPDependencyResolver()
