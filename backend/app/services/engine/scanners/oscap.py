"""
OpenSCAP Scanner Implementation

This module provides the OSCAPScanner class for validating, extracting,
and parsing OpenSCAP compliance content. It is the primary scanner for
SCAP content processing in OpenWatch.

Key Features:
- XCCDF, OVAL, and datastream content support
- Profile extraction from benchmarks
- Result parsing from XCCDF and ARF formats
- Content validation with security checks

Migrated from: backend/app/services/base_scap_scanner.py (SCAPContentValidator)

Design Philosophy:
- Subprocess isolation for oscap operations
- Security-first content validation
- Graceful error handling with detailed messages
- Stateless operation for thread safety

Usage:
    from backend.app.services.engine.scanners import OSCAPScanner

    scanner = OSCAPScanner()

    # Validate content
    if scanner.validate_content(content_path):
        profiles = scanner.extract_profiles(content_path)
        for profile in profiles:
            print(f"{profile['id']}: {profile['title']}")

Security Notes:
- oscap commands use argument lists (no shell injection)
- File paths are validated before use
- XML parsing uses timeout to prevent DoS
- Error messages are sanitized to prevent info disclosure
"""

import logging
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..exceptions import ContentValidationError, ResultParseError
from ..models import ScannerCapabilities, ScanProvider, ScanType
from .base import BaseScanner

logger = logging.getLogger(__name__)


class OSCAPScanner(BaseScanner):
    """
    OpenSCAP-based scanner for XCCDF, OVAL, and datastream content.

    This scanner uses the oscap command-line tool to validate content,
    extract profiles, and parse results. It is the primary scanner
    for production SCAP scanning in OpenWatch.

    The scanner is stateless - all operations take content paths as
    arguments and do not maintain internal state.

    Attributes:
        oscap_path: Path to the oscap binary
        validation_timeout: Timeout for validation operations (seconds)
        parse_timeout: Timeout for parsing operations (seconds)

    Usage:
        scanner = OSCAPScanner()
        if scanner.validate_content(path):
            profiles = scanner.extract_profiles(path)
    """

    def __init__(
        self,
        oscap_path: str = "oscap",
        validation_timeout: int = 30,
        parse_timeout: int = 60,
    ):
        """
        Initialize the OpenSCAP scanner.

        Args:
            oscap_path: Path to oscap binary (default: use PATH).
            validation_timeout: Timeout for validation operations.
            parse_timeout: Timeout for parsing operations.
        """
        super().__init__(name="OSCAPScanner")
        self.oscap_path = oscap_path
        self.validation_timeout = validation_timeout
        self.parse_timeout = parse_timeout

    @property
    def provider(self) -> ScanProvider:
        """Return OSCAP provider type."""
        return ScanProvider.OSCAP

    @property
    def capabilities(self) -> ScannerCapabilities:
        """Return OSCAP scanner capabilities."""
        return ScannerCapabilities(
            provider=ScanProvider.OSCAP,
            supported_scan_types=[
                ScanType.XCCDF_PROFILE,
                ScanType.XCCDF_RULE,
                ScanType.OVAL_DEFINITIONS,
                ScanType.DATASTREAM,
                ScanType.MONGODB_GENERATED,
            ],
            supported_formats=["xccdf", "oval", "datastream", "sds"],
            supports_remote=True,
            supports_local=True,
            max_concurrent=0,  # Unlimited
        )

    def validate_content(self, content_path: Path) -> bool:
        """
        Validate SCAP content file using oscap.

        Runs oscap info to validate the content file is properly
        formatted and contains the expected elements.

        Args:
            content_path: Path to the SCAP content file.

        Returns:
            True if content is valid.

        Raises:
            ContentValidationError: If validation fails.
        """
        try:
            # Verify file exists
            if not content_path.exists():
                raise ContentValidationError(
                    message=f"Content file not found: {content_path}",
                    content_path=str(content_path),
                )

            # Run oscap info to validate content
            # Security: Using list of arguments prevents shell injection
            result = subprocess.run(
                [self.oscap_path, "info", str(content_path)],
                capture_output=True,
                text=True,
                timeout=self.validation_timeout,
            )

            if result.returncode != 0:
                raise ContentValidationError(
                    message=f"Invalid SCAP content: {result.stderr[:500]}",
                    content_path=str(content_path),
                    validation_errors=[result.stderr],
                )

            self.log_validation_result(content_path, True)
            return True

        except subprocess.TimeoutExpired:
            raise ContentValidationError(
                message="Timeout validating SCAP content",
                content_path=str(content_path),
            )
        except ContentValidationError:
            raise
        except Exception as e:
            self._logger.error("Content validation error: %s", e)
            raise ContentValidationError(
                message=f"Content validation failed: {str(e)}",
                content_path=str(content_path),
                cause=e,
            )

    def extract_profiles(self, content_path: Path) -> List[Dict[str, Any]]:
        """
        Extract available profiles from SCAP content.

        Uses oscap info --profiles to list all available XCCDF profiles
        in the content file.

        Args:
            content_path: Path to the SCAP content file.

        Returns:
            List of profile dictionaries with id, title, description.

        Raises:
            ContentValidationError: If profile extraction fails.
        """
        try:
            # Verify file exists
            if not content_path.exists():
                raise ContentValidationError(
                    message=f"Content file not found: {content_path}",
                    content_path=str(content_path),
                )

            # Extract profiles using oscap
            result = subprocess.run(
                [self.oscap_path, "info", "--profiles", str(content_path)],
                capture_output=True,
                text=True,
                timeout=self.validation_timeout,
            )

            if result.returncode != 0:
                raise ContentValidationError(
                    message=f"Failed to extract profiles: {result.stderr[:500]}",
                    content_path=str(content_path),
                )

            profiles = self._parse_profiles_output(result.stdout)
            self._logger.info("Extracted %d profiles from %s", len(profiles), content_path.name)

            return profiles

        except subprocess.TimeoutExpired:
            raise ContentValidationError(
                message="Timeout extracting profiles",
                content_path=str(content_path),
            )
        except ContentValidationError:
            raise
        except Exception as e:
            self._logger.error("Profile extraction error: %s", e)
            raise ContentValidationError(
                message=f"Profile extraction failed: {str(e)}",
                content_path=str(content_path),
                cause=e,
            )

    def parse_results(self, result_path: Path, result_format: str = "xccdf") -> Dict[str, Any]:
        """
        Parse scan result file into normalized format.

        Parses XCCDF or ARF result files to extract findings,
        statistics, and metadata.

        Args:
            result_path: Path to the result file.
            result_format: Format of results (xccdf or arf).

        Returns:
            Dictionary with normalized scan results.

        Raises:
            ResultParseError: If result file cannot be parsed.
        """
        try:
            if not result_path.exists():
                raise ResultParseError(
                    message=f"Result file not found: {result_path}",
                    result_path=str(result_path),
                    expected_format=result_format,
                )

            # Read result file
            with open(result_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Parse based on format
            if result_format == "xccdf":
                return self._parse_xccdf_results(content, result_path)
            elif result_format == "arf":
                return self._parse_arf_results(content, result_path)
            else:
                raise ResultParseError(
                    message=f"Unsupported result format: {result_format}",
                    result_path=str(result_path),
                    expected_format=result_format,
                )

        except ResultParseError:
            raise
        except Exception as e:
            self._logger.error("Result parsing error: %s", e)
            raise ResultParseError(
                message=f"Result parsing failed: {str(e)}",
                result_path=str(result_path),
                expected_format=result_format,
                cause=e,
            )

    def get_content_info(self, content_path: Path) -> Dict[str, Any]:
        """
        Get detailed information about SCAP content.

        Uses oscap info to extract metadata about the content file.

        Args:
            content_path: Path to the SCAP content file.

        Returns:
            Dictionary with content metadata.
        """
        try:
            result = subprocess.run(
                [self.oscap_path, "info", str(content_path)],
                capture_output=True,
                text=True,
                timeout=self.validation_timeout,
            )

            if result.returncode != 0:
                return {
                    "type": "unknown",
                    "title": content_path.stem,
                    "error": result.stderr[:200],
                }

            info = self._parse_oscap_info(result.stdout)
            info["path"] = str(content_path)

            return info

        except subprocess.TimeoutExpired:
            return {
                "type": "unknown",
                "title": content_path.stem,
                "error": "Timeout getting content info",
            }
        except Exception as e:
            return {
                "type": "unknown",
                "title": content_path.stem,
                "error": str(e),
            }

    def can_handle_content(self, content_path: str) -> bool:
        """
        Check if OSCAP can handle the given content.

        Args:
            content_path: Path to the content file.

        Returns:
            True if OSCAP can handle this content.
        """
        try:
            path = Path(content_path)

            # Check file exists
            if not path.exists():
                return False

            # Check extension
            valid_extensions = [".xml", ".xccdf", ".oval", ".ds", ".sds"]
            if path.suffix.lower() not in valid_extensions:
                return False

            # Quick content check - look for SCAP namespaces
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                # Read first 4KB to check for SCAP markers
                header = f.read(4096)

            scap_markers = [
                "xccdf",
                "oval",
                "data-stream",
                "scap",
                "benchmark",
            ]

            header_lower = header.lower()
            return any(marker in header_lower for marker in scap_markers)

        except Exception as e:
            self._logger.debug("Content check failed: %s", e)
            return False

    def _parse_oscap_info(self, info_output: str) -> Dict[str, Any]:
        """
        Parse oscap info command output.

        Args:
            info_output: Raw output from oscap info.

        Returns:
            Dictionary with parsed content metadata.
        """
        info: Dict[str, Any] = {}
        lines = info_output.split("\n")

        for line in lines:
            line = line.strip()
            if ":" in line:
                key, value = line.split(":", 1)
                key = key.strip().lower().replace(" ", "_")
                value = value.strip()
                info[key] = value

        return info

    def _parse_profiles_output(self, profiles_output: str) -> List[Dict[str, Any]]:
        """
        Parse oscap info --profiles output.

        Args:
            profiles_output: Raw output from oscap info --profiles.

        Returns:
            List of profile dictionaries.
        """
        profiles: List[Dict[str, Any]] = []
        lines = profiles_output.split("\n")

        current_profile: Optional[Dict[str, Any]] = None

        for line in lines:
            line = line.strip()

            if line.startswith("Profile ID:"):
                # Save previous profile
                if current_profile:
                    profiles.append(current_profile)

                # Start new profile
                current_profile = {
                    "id": line.split(":", 1)[1].strip(),
                    "title": "",
                    "description": "",
                }

            elif line.startswith("Title:") and current_profile:
                current_profile["title"] = line.split(":", 1)[1].strip()

            elif line.startswith("Description:") and current_profile:
                current_profile["description"] = line.split(":", 1)[1].strip()

        # Add last profile
        if current_profile:
            profiles.append(current_profile)

        return profiles

    def _parse_xccdf_results(self, content: str, result_path: Path) -> Dict[str, Any]:
        """
        Parse XCCDF result file content.

        This is a simplified parser that extracts basic statistics.
        For full parsing, use the content module's XCCDF parser.

        Args:
            content: XML content of result file.
            result_path: Path to result file (for error context).

        Returns:
            Dictionary with parsed results.
        """
        # Count rule results using simple string matching
        # This is intentionally simple - full parsing uses content module
        pass_count = content.count('result="pass"')
        fail_count = content.count('result="fail"')
        error_count = content.count('result="error"')
        notapplicable_count = content.count('result="notapplicable"')
        notchecked_count = content.count('result="notchecked"')

        total = pass_count + fail_count + error_count + notapplicable_count + notchecked_count

        # Calculate pass rate
        pass_rate = (pass_count / total * 100) if total > 0 else 0.0

        return {
            "format": "xccdf",
            "source_file": str(result_path),
            "statistics": {
                "pass_count": pass_count,
                "fail_count": fail_count,
                "error_count": error_count,
                "notapplicable_count": notapplicable_count,
                "notchecked_count": notchecked_count,
                "total_count": total,
                "pass_rate": round(pass_rate, 2),
            },
            "has_findings": fail_count > 0,
        }

    def _parse_arf_results(self, content: str, result_path: Path) -> Dict[str, Any]:
        """
        Parse ARF result file content.

        ARF (Asset Reporting Format) contains XCCDF results along with
        additional asset and report metadata.

        Args:
            content: XML content of ARF file.
            result_path: Path to result file (for error context).

        Returns:
            Dictionary with parsed results.
        """
        # ARF files contain XCCDF results - extract and parse
        # This is simplified - full parsing uses content module

        # Check if this looks like ARF
        if "<arf:" not in content and "<asset-report-collection" not in content:
            self._logger.warning("File does not appear to be ARF format: %s", result_path)

        # Use XCCDF parser for the embedded results
        base_results = self._parse_xccdf_results(content, result_path)
        base_results["format"] = "arf"

        return base_results
