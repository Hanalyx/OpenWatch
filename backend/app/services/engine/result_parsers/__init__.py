"""
Engine Result Parsers Module

This module provides specialized parsers for SCAP scan result files.
Each parser handles a specific result format (XCCDF, ARF, OVAL) and
produces normalized output for storage and analysis.

Parsers are responsible for:
- Reading and validating result file structure
- Extracting rule results with pass/fail/error status
- Normalizing data formats across different SCAP versions
- Providing statistics and summary information

Available Parsers:
- BaseResultParser: Abstract base class defining the parser interface
- XCCDFResultParser: Parser for XCCDF result files (most common format)
- ARFResultParser: Parser for Asset Reporting Format result files

Architecture Notes:
- Parsers are stateless (result paths passed to methods)
- Parsers do NOT handle storage (that's the repository's job)
- Parsers focus on extraction and normalization
- All parsers produce consistent output format

Usage:
    from app.services.engine.result_parsers import (
        XCCDFResultParser,
        ARFResultParser,
        get_parser_for_file,
    )

    # Get parser based on file format
    parser = get_parser_for_file("/app/data/results/scan_123_xccdf.xml")

    # Parse results
    if parser.can_parse(result_path):
        results = parser.parse(result_path)
        print(f"Pass rate: {results.statistics.pass_rate}%")

Security Notes:
- XML parsing uses defused parsers to prevent XXE attacks
- File paths validated before access
- Large files handled with streaming where possible
- Error messages sanitized to prevent info disclosure
"""

import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Import parser implementations (re-exported for public API)
# ARFResultParser and XCCDFResultParser removed (SCAP-era dead code)
from .base import BaseResultParser, ParsedResults, ResultStatistics, RuleResult  # noqa: F401, E402


def get_parser_for_file(file_path: str) -> Optional[BaseResultParser]:
    """
    Auto-detect and return appropriate parser based on file content.

    Examines the result file to determine which parser can handle it.
    Detection is based on file content, not just extension.

    Args:
        file_path: Path to scan result file.

    Returns:
        Parser instance that can handle the file, or None if
        no suitable parser is found.

    Usage:
        >>> parser = get_parser_for_file("/app/data/results/scan_123.xml")
        >>> if parser:
        ...     results = parser.parse(Path(file_path))
    """
    path = Path(file_path)

    if not path.exists():
        logger.warning("Result file does not exist: %s", file_path)
        return None

    # ARF and XCCDF parsers removed (SCAP-era, replaced by Kensa)
    # Kensa results are stored directly in scan_findings table, no file parsing needed
    logger.warning("No parser found for result file: %s (legacy SCAP parsers removed)", file_path)
    return None


def get_parser(format_type: str) -> BaseResultParser:
    """
    Get a parser for the specified format type.

    Args:
        format_type: Format type ('xccdf', 'arf', 'oval').

    Returns:
        Configured parser instance.

    Raises:
        ValueError: If format type is not supported.

    Usage:
        >>> parser = get_parser("xccdf")
        >>> results = parser.parse(result_path)
    """
    # Legacy SCAP parsers removed — Kensa stores results directly in scan_findings
    raise ValueError(
        f"Unsupported result format: {format_type}. "
        "SCAP parsers (XCCDF, ARF, OVAL) have been removed. "
        "Kensa compliance results are stored directly in scan_findings."
    )


# Public API exports
__all__ = [
    # Base classes and models
    "BaseResultParser",
    "ParsedResults",
    "ResultStatistics",
    "RuleResult",
    # Parser implementations
    "XCCDFResultParser",
    "ARFResultParser",
    # Factory functions
    "get_parser_for_file",
    "get_parser",
]
