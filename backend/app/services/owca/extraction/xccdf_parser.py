"""
OWCA Extraction Layer - XCCDF Parser

Provides secure extraction of native XCCDF scores from SCAP scan result files.
Uses lxml.etree with XXE protection (resolve_entities=False, no_network=True).

This module is part of OWCA Layer 0 (Extraction Layer):
- Extracts TestResult/score elements from XCCDF/ARF files
- Validates file paths to prevent path traversal attacks
- Enforces file size limits (10MB maximum)
- Provides comprehensive audit logging

Security Controls:
- OWASP A03:2021 - Injection Prevention (XXE protection)
- Path traversal validation (no ../ sequences)
- File size limits (DoS prevention)
- Input validation via Pydantic models

Example:
    >>> from app.services.owca import get_owca_service
    >>> owca = get_owca_service(db)
    >>> result = await owca.extract_xccdf_score("/app/data/results/scan_123_xccdf.xml")
    >>> print(f"Score: {result.xccdf_score}/{result.xccdf_score_max}")
"""

import logging
from pathlib import Path
from typing import Optional

import lxml.etree as etree  # nosec B410 - Using secure parser (resolve_entities=False, no_network=True)
from pydantic import BaseModel, Field, validator

logger = logging.getLogger(__name__)
audit_logger = logging.getLogger("openwatch.audit")


class XCCDFScoreResult(BaseModel):
    """
    Pydantic model for XCCDF score extraction results.

    Attributes:
        xccdf_score: Actual score value (0.0-100.0 typically)
        xccdf_score_system: Scoring system URN (e.g., 'urn:xccdf:scoring:default')
        xccdf_score_max: Maximum possible score (usually 100.0)
        found: Whether score element was found in XML
        error: Error message if extraction failed
    """

    xccdf_score: Optional[float] = Field(None, ge=0.0, description="Actual XCCDF score")
    xccdf_score_system: Optional[str] = Field(None, max_length=255, description="Scoring system URN")
    xccdf_score_max: Optional[float] = Field(None, ge=0.0, description="Maximum possible score")
    found: bool = Field(False, description="Whether score was found in XML")
    error: Optional[str] = Field(None, max_length=500, description="Error message if extraction failed")

    @validator("xccdf_score", "xccdf_score_max")
    def validate_score_range(cls, v):
        """Validate score is within reasonable range (0-1000)"""
        if v is not None and v > 1000.0:
            raise ValueError("Score exceeds reasonable maximum (1000.0)")
        return v


class XCCDFParser:
    """
    Parser for extracting XCCDF native scores with comprehensive security controls.

    Part of OWCA Extraction Layer (Layer 0).

    Security Features:
    - XXE prevention via lxml parser configuration
    - Path traversal validation
    - File size limits (10MB)
    - Comprehensive audit logging

    XCCDF Namespace Support:
    - XCCDF 1.2: http://checklists.nist.gov/xccdf/1.2
    - XCCDF 1.1: http://checklists.nist.gov/xccdf/1.1
    - ARF: http://scap.nist.gov/schema/asset-reporting-format/1.1
    """

    # Security limits
    MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB

    # XCCDF namespaces
    NAMESPACES = {
        "xccdf": "http://checklists.nist.gov/xccdf/1.2",
        "xccdf-1.1": "http://checklists.nist.gov/xccdf/1.1",
        "arf": "http://scap.nist.gov/schema/asset-reporting-format/1.1",
    }

    def __init__(self):
        """Initialize XCCDF parser with secure XML parser configuration."""
        # Secure XML parser configuration (prevents XXE attacks)
        self.parser = etree.XMLParser(
            resolve_entities=False,  # Prevents XXE attacks
            no_network=True,  # Prevents SSRF via external entities
            remove_comments=True,  # Remove XML comments
            remove_pis=True,  # Remove processing instructions
        )

    def extract_native_score(self, result_file: str, user_id: Optional[str] = None) -> XCCDFScoreResult:
        """
        Extract XCCDF native score from result file with security validation.

        This method:
        1. Validates file path (no path traversal)
        2. Checks file size (max 10MB)
        3. Parses XML with XXE protection
        4. Extracts TestResult/score element
        5. Logs audit trail

        Args:
            result_file: Absolute path to XCCDF/ARF result file
            user_id: Optional user ID for audit logging

        Returns:
            XCCDFScoreResult with extracted score data or error information

        Security:
            - Path traversal prevention (rejects ../ sequences)
            - File size limit enforcement (10MB)
            - XXE attack prevention (secure parser)
            - Comprehensive audit logging

        Example:
            >>> parser = XCCDFParser()
            >>> result = parser.extract_native_score("/app/data/results/scan_123.xml")
            >>> if result.found:
            ...     print(f"Score: {result.xccdf_score}/{result.xccdf_score_max}")
        """
        try:
            # Security: Validate file path (prevent path traversal)
            if not self._is_safe_path(result_file):
                error = "Invalid file path (path traversal detected): {}".format(result_file)
                logger.warning(error)
                audit_logger.warning(
                    "SECURITY: Path traversal attempt blocked",
                    extra={
                        "event_type": "PATH_TRAVERSAL_BLOCKED",
                        "user_id": user_id,
                        "file_path": result_file,
                    },
                )
                return XCCDFScoreResult(found=False, error=error)

            # Security: Check file exists
            file_path = Path(result_file)
            if not file_path.exists():
                error = "Result file not found: {}".format(result_file)
                logger.warning(error)
                return XCCDFScoreResult(found=False, error=error)

            # Security: Enforce file size limit (prevent DoS)
            file_size = file_path.stat().st_size
            if file_size > self.MAX_FILE_SIZE_BYTES:
                error = "File too large: {} bytes (max {})".format(file_size, self.MAX_FILE_SIZE_BYTES)
                logger.warning(error)
                audit_logger.warning(
                    "SECURITY: File size limit exceeded",
                    extra={
                        "event_type": "FILE_SIZE_LIMIT_EXCEEDED",
                        "user_id": user_id,
                        "file_path": result_file,
                        "file_size": file_size,
                        "limit": self.MAX_FILE_SIZE_BYTES,
                    },
                )
                return XCCDFScoreResult(found=False, error=error)

            # Parse XML with secure parser (XXE protection)
            tree = etree.parse(str(file_path), self.parser)  # nosec B320
            root = tree.getroot()

            # Try to extract score from TestResult element
            score_result = self._extract_from_test_result(root)

            # Audit log successful extraction
            if score_result.found:
                audit_logger.info(
                    "XCCDF score extracted successfully",
                    extra={
                        "event_type": "XCCDF_SCORE_EXTRACTED",
                        "user_id": user_id,
                        "file_path": result_file,
                        "score": score_result.xccdf_score,
                        "score_max": score_result.xccdf_score_max,
                        "score_system": score_result.xccdf_score_system,
                    },
                )
            else:
                logger.info("No XCCDF score found in {}".format(result_file))

            return score_result

        except etree.XMLSyntaxError as e:
            error = "XML parsing error: {}".format(str(e))
            logger.error(error)
            return XCCDFScoreResult(found=False, error=error)

        except Exception as e:
            error = "Unexpected error extracting XCCDF score: {}".format(str(e))
            logger.error(error, exc_info=True)
            return XCCDFScoreResult(found=False, error=error)

    def _extract_from_test_result(self, root: etree._Element) -> XCCDFScoreResult:
        """
        Extract score from XCCDF TestResult element.

        XCCDF score element structure:
        <TestResult>
            <score system="urn:xccdf:scoring:default" maximum="100.0">87.5</score>
        </TestResult>

        Args:
            root: XML root element (may be TestResult itself or contain TestResult)

        Returns:
            XCCDFScoreResult with extracted data
        """
        score_elem = None

        # Check if root IS TestResult (common case)
        if "TestResult" in root.tag:
            # Root is TestResult, look for score as direct child
            score_elem = root.find("xccdf:score", self.NAMESPACES)
            if score_elem is None:
                score_elem = root.find("xccdf-1.1:score", self.NAMESPACES)
            if score_elem is None:
                score_elem = root.find("score")  # No namespace

        # If not found yet, try searching for TestResult/score deeper in tree
        if score_elem is None:
            # Try XCCDF 1.2 namespace
            score_elem = root.find(".//xccdf:TestResult/xccdf:score", self.NAMESPACES)

        # Fallback to XCCDF 1.1 namespace
        if score_elem is None:
            score_elem = root.find(".//xccdf-1.1:TestResult/xccdf-1.1:score", self.NAMESPACES)

        # Fallback to no namespace (some files don't use namespaces)
        if score_elem is None:
            score_elem = root.find(".//TestResult/score")

        # No score element found
        if score_elem is None:
            return XCCDFScoreResult(found=False)

        # Extract score value
        try:
            score_value = float(score_elem.text.strip()) if score_elem.text else None
        except (ValueError, AttributeError):
            logger.warning("Invalid score value: {}".format(score_elem.text))
            return XCCDFScoreResult(found=False, error="Invalid score value")

        # Extract score attributes
        score_system = score_elem.get("system")
        score_max_str = score_elem.get("maximum")

        # Parse maximum score
        score_max = None
        if score_max_str:
            try:
                score_max = float(score_max_str)
            except ValueError:
                logger.warning("Invalid maximum score: {}".format(score_max_str))

        return XCCDFScoreResult(
            xccdf_score=score_value,
            xccdf_score_system=score_system,
            xccdf_score_max=score_max,
            found=True,
        )

    def _is_safe_path(self, file_path: str) -> bool:
        """
        Validate file path to prevent path traversal attacks.

        Security Check: Rejects paths containing ../ sequences or absolute paths
        outside allowed directories.

        Args:
            file_path: File path to validate

        Returns:
            True if path is safe, False otherwise

        Example:
            >>> parser._is_safe_path("/app/data/results/scan.xml")  # Safe
            True
            >>> parser._is_safe_path("../../../etc/passwd")  # Unsafe
            False
        """
        # Reject paths with ../ (path traversal)
        if ".." in file_path:
            return False

        # Resolve to absolute path
        try:
            resolved = Path(file_path).resolve()
        except Exception:
            return False

        # Only allow paths within /app/data/ (OpenWatch data directory)
        allowed_base = Path("/app/data").resolve()
        try:
            resolved.relative_to(allowed_base)
            return True
        except ValueError:
            # Path is outside /app/data/
            return False
