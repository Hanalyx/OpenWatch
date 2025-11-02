"""
SCAP Dependency Resolver - Analyzes SCAP content files to find all dependencies

This module provides intelligent dependency resolution for SCAP content, ensuring
all referenced files (OVAL, CPE, tailoring, etc.) are identified for remote transfer.

Designed to support:
- MongoDB-generated XCCDF profiles
- Standard SCAP datastreams
- Custom OWScan content (future)
"""

import logging
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Set, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class SCAPDependency:
    """Represents a SCAP file dependency"""

    file_path: Path
    dependency_type: str  # 'xccdf', 'oval', 'cpe', 'tailoring', 'other'
    referenced_by: Optional[Path] = None
    is_primary: bool = False


class SCAPDependencyResolver:
    """
    Resolves SCAP content dependencies by parsing XML files.

    Supports:
    - XCCDF 1.2 check-content-ref elements
    - SCAP 1.3 datastream components
    - Relative and absolute path references
    - Nested dependencies (future)
    """

    # XML namespaces commonly used in SCAP content
    NAMESPACES = {
        "xccdf": "http://checklists.nist.gov/xccdf/1.2",
        "xccdf-1.1": "http://checklists.nist.gov/xccdf/1.1",
        "oval": "http://oval.mitre.org/XMLSchema/oval-definitions-5",
        "scap": "http://scap.nist.gov/schema/scap/source/1.2",
        "ds": "http://scap.nist.gov/schema/scap/source/1.2",
        "cpe": "http://cpe.mitre.org/dictionary/2.0",
    }

    def __init__(self):
        self.resolved_files: Set[Path] = set()
        self.dependencies: List[SCAPDependency] = []

    def resolve(
        self, primary_file: Path, base_dir: Optional[Path] = None
    ) -> List[SCAPDependency]:
        """
        Resolve all dependencies for a SCAP content file.

        Args:
            primary_file: Main SCAP file (XCCDF or datastream)
            base_dir: Base directory for resolving relative paths (defaults to primary_file parent)

        Returns:
            List of SCAPDependency objects representing all files needed
        """
        if not primary_file.exists():
            raise FileNotFoundError(f"Primary SCAP file not found: {primary_file}")

        base_dir = base_dir or primary_file.parent
        self.resolved_files.clear()
        self.dependencies.clear()

        # Add primary file
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

        logger.info(
            f"Resolved {len(self.dependencies)} SCAP dependencies for {primary_file.name}"
        )
        return self.dependencies

    def _detect_file_type(self, file_path: Path) -> str:
        """Detect SCAP file type by examining XML root element"""
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()

            # Check root element tag
            if "Benchmark" in root.tag:
                return "xccdf"
            elif (
                "data-stream-collection" in root.tag
                or "DataStreamCollection" in root.tag
            ):
                return "datastream"
            elif "oval_definitions" in root.tag:
                return "oval"
            elif "platform-specification" in root.tag or "cpe-list" in root.tag:
                return "cpe"
            elif "Tailoring" in root.tag:
                return "tailoring"
            else:
                return "other"
        except Exception as e:
            logger.warning(f"Could not detect file type for {file_path}: {e}")
            return "other"

    def _resolve_xccdf_dependencies(self, xccdf_file: Path, base_dir: Path):
        """
        Parse XCCDF file to find check-content-ref elements.

        Example XCCDF check:
        <xccdf:check system="http://oval.mitre.org/XMLSchema/oval-definitions-5">
            <xccdf:check-content-ref name="oval:..." href="oval-definitions.xml"/>
        </xccdf:check>
        """
        try:
            tree = ET.parse(xccdf_file)
            root = tree.getroot()

            # Find all check-content-ref elements
            # Try multiple namespace prefixes for compatibility
            ref_elements = []
            for ns_prefix in ["xccdf", "xccdf-1.1", ""]:
                ns = self.NAMESPACES.get(ns_prefix, "")
                if ns:
                    ref_elements.extend(root.findall(f".//{{{ns}}}check-content-ref"))
                else:
                    # Try without namespace for files without proper namespaces
                    ref_elements.extend(root.findall(".//check-content-ref"))

            # Also check for external references
            for ns_prefix in ["xccdf", "xccdf-1.1", ""]:
                ns = self.NAMESPACES.get(ns_prefix, "")
                if ns:
                    ref_elements.extend(root.findall(f".//{{{ns}}}reference"))

            logger.debug(
                f"Found {len(ref_elements)} check-content-ref elements in {xccdf_file.name}"
            )

            # Extract href attributes
            for ref in ref_elements:
                href = ref.get("href")
                if href:
                    self._add_dependency(href, base_dir, xccdf_file)

            # Look for same directory files (common pattern for MongoDB-generated content)
            # Check if there's an oval-definitions.xml in the same directory
            for pattern in ["oval-definitions.xml", "oval-*.xml", "cpe-*.xml"]:
                for oval_file in base_dir.glob(pattern):
                    if oval_file not in self.resolved_files and oval_file != xccdf_file:
                        dep_type = self._detect_file_type(oval_file)
                        dep = SCAPDependency(
                            file_path=oval_file,
                            dependency_type=dep_type,
                            referenced_by=xccdf_file,
                            is_primary=False,
                        )
                        self.dependencies.append(dep)
                        self.resolved_files.add(oval_file)
                        logger.debug(f"Added co-located dependency: {oval_file.name}")

        except ET.ParseError as e:
            logger.error(f"Failed to parse XCCDF file {xccdf_file}: {e}")
        except Exception as e:
            logger.error(f"Error resolving XCCDF dependencies: {e}")

    def _resolve_datastream_dependencies(self, datastream_file: Path, base_dir: Path):
        """
        Parse SCAP datastream to find component references.

        Note: Datastreams typically embed all content, so external dependencies are rare.
        """
        try:
            tree = ET.parse(datastream_file)
            root = tree.getroot()

            # Datastreams usually have everything embedded
            # Check for any external component-ref elements
            for ns_prefix in ["ds", "scap"]:
                ns = self.NAMESPACES.get(ns_prefix, "")
                if ns:
                    refs = root.findall(f".//{{{ns}}}component-ref")
                    for ref in refs:
                        href = ref.get("href") or ref.get("xlink:href")
                        if href and not href.startswith("#"):
                            # External reference
                            self._add_dependency(href, base_dir, datastream_file)

            logger.debug(f"Resolved datastream dependencies for {datastream_file.name}")

        except Exception as e:
            logger.error(f"Error resolving datastream dependencies: {e}")

    def _add_dependency(self, href: str, base_dir: Path, referenced_by: Path):
        """Add a dependency from an href reference"""
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
            logger.debug(f"Added dependency: {dep_path.name} (type: {dep_type})")

    def get_transfer_list(self) -> List[Path]:
        """Get list of file paths to transfer, in dependency order"""
        # Primary file should be transferred last (after dependencies)
        # Sort: non-primary first, then primary
        sorted_deps = sorted(self.dependencies, key=lambda d: d.is_primary)
        return [dep.file_path for dep in sorted_deps]

    def get_file_manifest(self) -> Dict[str, str]:
        """
        Get manifest of files with their types.

        Returns:
            Dict mapping filename -> file type
        """
        return {dep.file_path.name: dep.dependency_type for dep in self.dependencies}

    def validate_dependencies(self) -> List[str]:
        """
        Validate that all dependencies exist and are readable.

        Returns:
            List of error messages (empty if all valid)
        """
        errors = []
        for dep in self.dependencies:
            if not dep.file_path.exists():
                errors.append(f"Missing dependency: {dep.file_path}")
            elif not dep.file_path.is_file():
                errors.append(f"Not a file: {dep.file_path}")
            elif not dep.file_path.stat().st_size > 0:
                errors.append(f"Empty file: {dep.file_path}")

        return errors
