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
    from backend.app.services.engine.result_parsers import (
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
from .arf import ARFResultParser  # noqa: F401, E402
from .base import BaseResultParser, ParsedResults, ResultStatistics, RuleResult  # noqa: F401, E402
from .xccdf import XCCDFResultParser  # noqa: F401, E402


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

    # Try ARF parser first (ARF contains XCCDF, so more specific match)
    arf_parser = ARFResultParser()
    try:
        if arf_parser.can_parse(path):
            logger.debug("Using ARF parser for: %s", path.name)
            return arf_parser
    except Exception as e:
        logger.debug("ARF parser cannot handle file: %s", e)

    # Try XCCDF parser (most common format)
    xccdf_parser = XCCDFResultParser()
    try:
        if xccdf_parser.can_parse(path):
            logger.debug("Using XCCDF parser for: %s", path.name)
            return xccdf_parser
    except Exception as e:
        logger.debug("XCCDF parser cannot handle file: %s", e)

    # No suitable parser found
    logger.warning("No parser found for result file: %s", file_path)
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
    format_lower = format_type.lower()

    if format_lower == "xccdf":
        return XCCDFResultParser()

    elif format_lower == "arf":
        return ARFResultParser()

    elif format_lower == "oval":
        # OVAL result parsing is handled by XCCDF parser
        # since OVAL results are typically embedded in XCCDF
        logger.info("Using XCCDF parser for OVAL results (embedded format)")
        return XCCDFResultParser()

    else:
        raise ValueError(f"Unsupported result format: {format_type}")


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
