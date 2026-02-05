"""
Compliance Rules Parsing Submodule

Handles BSON and JSON parsing for compliance rule uploads.
"""

import logging

from .bson_parser import BSONParserService, BSONParsingError, detect_file_format

logger = logging.getLogger(__name__)

__all__ = [
    "BSONParserService",
    "BSONParsingError",
    "detect_file_format",
]

logger.debug("Compliance rules parsing submodule initialized")
