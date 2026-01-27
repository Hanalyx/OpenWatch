"""
Base Scanner Abstract Class

This module defines the abstract base class for all compliance scanners.
Scanners are responsible for content validation, profile extraction,
command building, and result parsing.

Design Philosophy:
- Single Responsibility: Scanners handle content operations, not execution
- Interface Segregation: Clear, minimal interface for implementations
- Stateless Design: No persistent state between operations
- Security First: Content validation prevents injection attacks

Scanner vs Executor Responsibilities:
    Scanner: Content validation, profile extraction, command building, result parsing
    Executor: Connection management, file transfer, command execution, result retrieval

Implementation Requirements:
- All abstract methods must be implemented
- Content validation must prevent XXE and injection attacks
- Result parsing must handle malformed output gracefully
- Capabilities must accurately reflect scanner features
"""

import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..exceptions import ContentValidationError  # noqa: F401
from ..models import ScannerCapabilities, ScanProvider, ScanType

logger = logging.getLogger(__name__)


class BaseScanner(ABC):
    """
    Abstract base class for compliance scanners.

    Scanners handle content-related operations for compliance scanning:
    - Content validation and format detection
    - Profile extraction from benchmarks
    - Command line building for execution
    - Result file parsing and normalization

    Subclasses must implement:
    - provider: Return the scanner's provider type
    - capabilities: Return scanner capability metadata
    - validate_content(): Validate SCAP content
    - extract_profiles(): Extract available profiles
    - parse_results(): Parse scan result files

    Usage:
        class MyScanner(BaseScanner):
            @property
            def provider(self):
                return ScanProvider.CUSTOM

            def validate_content(self, content_path):
                # Validation logic
                pass

        scanner = MyScanner()
        if scanner.validate_content(path):
            profiles = scanner.extract_profiles(path)
    """

    def __init__(self, name: str = "BaseScanner"):
        """
        Initialize the base scanner.

        Args:
            name: Human-readable name for logging and debugging.
        """
        self.name = name
        self._logger = logging.getLogger(f"{__name__}.{name}")

    @property
    @abstractmethod
    def provider(self) -> ScanProvider:
        """
        Return the scanner's provider type.

        Returns:
            The ScanProvider enum value for this scanner.
        """

    @property
    @abstractmethod
    def capabilities(self) -> ScannerCapabilities:
        """
        Return the scanner's capabilities.

        Returns:
            ScannerCapabilities describing what this scanner supports.
        """

    @abstractmethod
    def validate_content(self, content_path: Path) -> bool:
        """
        Validate SCAP content file.

        Checks that the content file:
        - Exists and is readable
        - Has valid format (XML, proper structure)
        - Contains required elements for scanning
        - Is free from security issues (XXE, etc.)

        Args:
            content_path: Path to the SCAP content file.

        Returns:
            True if content is valid and usable.

        Raises:
            ContentValidationError: If validation fails with details.

        Note:
            This method should be called before any scan execution
            to ensure content is safe and properly formatted.
        """

    @abstractmethod
    def extract_profiles(self, content_path: Path) -> List[Dict[str, Any]]:
        """
        Extract available profiles from SCAP content.

        Parses the content file to identify all XCCDF profiles
        that can be used for scanning.

        Args:
            content_path: Path to the SCAP content file.

        Returns:
            List of profile dictionaries with:
            - id: Profile ID for scan commands
            - title: Human-readable profile title
            - description: Profile description (optional)

        Raises:
            ContentValidationError: If content cannot be parsed.

        Usage:
            >>> profiles = scanner.extract_profiles(content_path)
            >>> for p in profiles:
            ...     print(f"{p['id']}: {p['title']}")
        """

    @abstractmethod
    def parse_results(self, result_path: Path, result_format: str = "xccdf") -> Dict[str, Any]:
        """
        Parse scan result file into normalized format.

        Reads and parses the result file produced by scan execution,
        extracting findings, statistics, and metadata.

        Args:
            result_path: Path to the result file.
            result_format: Format of results (xccdf, arf, oval).

        Returns:
            Dictionary with normalized results including:
            - pass_count: Number of passing rules
            - fail_count: Number of failing rules
            - error_count: Number of errors
            - findings: List of individual rule results
            - metadata: Scan metadata

        Raises:
            ResultParseError: If result file cannot be parsed.

        Note:
            Result parsing should be lenient - partial results are
            better than complete failure for troubleshooting.
        """

    def can_handle_content(self, content_path: str) -> bool:
        """
        Check if this scanner can handle the given content.

        Quick check to determine if this scanner is appropriate
        for the given content file. Does not do full validation.

        Args:
            content_path: Path to the content file.

        Returns:
            True if scanner can likely handle this content.
        """
        try:
            path = Path(content_path)

            # Basic checks
            if not path.exists():
                return False

            if not path.suffix.lower() in [".xml", ".xccdf", ".oval", ".ds"]:
                return False

            return True

        except Exception:
            return False

    def get_content_info(self, content_path: Path) -> Dict[str, Any]:
        """
        Get metadata about SCAP content file.

        Extracts basic information about the content without
        full validation. Useful for display and selection.

        Args:
            content_path: Path to the SCAP content file.

        Returns:
            Dictionary with content metadata:
            - type: Content type (xccdf, oval, datastream)
            - title: Content title if available
            - version: Content version if available
            - profiles: Number of profiles (for XCCDF)
        """
        # Default implementation - subclasses should override
        return {
            "type": "unknown",
            "title": content_path.stem,
            "version": "unknown",
            "path": str(content_path),
        }

    def build_scan_command(
        self,
        content_path: str,
        profile_id: str,
        result_xml: str,
        result_html: Optional[str] = None,
        result_arf: Optional[str] = None,
        rule_id: Optional[str] = None,
        **kwargs: Any,
    ) -> List[str]:
        """
        Build the command line for scan execution.

        Creates a properly formatted command with all required
        and optional arguments for the scanner.

        Args:
            content_path: Path to SCAP content file.
            profile_id: XCCDF profile ID to evaluate.
            result_xml: Path for XCCDF result output.
            result_html: Optional path for HTML report.
            result_arf: Optional path for ARF result.
            rule_id: Optional rule ID for single-rule scan.
            **kwargs: Scanner-specific options.

        Returns:
            List of command arguments.

        Note:
            This is a template method. Subclasses should override
            for scanner-specific command formats.
        """
        # Default implementation for OSCAP-like scanners
        cmd = ["oscap", "xccdf", "eval", "--profile", profile_id]

        if result_xml:
            cmd.extend(["--results", result_xml])

        if result_html:
            cmd.extend(["--report", result_html])

        if result_arf:
            cmd.extend(["--results-arf", result_arf])

        if rule_id:
            cmd.extend(["--rule", rule_id])

        cmd.append(content_path)

        return cmd

    def get_supported_formats(self) -> List[str]:
        """
        Get list of content formats this scanner supports.

        Returns:
            List of format identifiers (e.g., ["xccdf", "oval", "datastream"]).
        """
        return self.capabilities.supported_formats

    def get_supported_scan_types(self) -> List[ScanType]:
        """
        Get list of scan types this scanner supports.

        Returns:
            List of ScanType enum values.
        """
        return self.capabilities.supported_scan_types

    def log_validation_result(self, content_path: Path, is_valid: bool, details: Optional[str] = None) -> None:
        """
        Log content validation result.

        Standardized logging for validation operations.

        Args:
            content_path: Path to validated content.
            is_valid: Whether validation passed.
            details: Optional details about validation.
        """
        if is_valid:
            self._logger.info("Content validation passed: %s", content_path.name)
        else:
            self._logger.warning(
                "Content validation failed: %s - %s",
                content_path.name,
                details or "Unknown reason",
            )
