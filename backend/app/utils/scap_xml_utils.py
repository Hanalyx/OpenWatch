"""
SCAP XML Utility Functions
Shared utilities for XML processing across SCAP services
"""

import logging
import re
from typing import Dict, Optional

from lxml import etree

logger = logging.getLogger(__name__)


def extract_text_content(element) -> str:
    """
    Extract clean text content from XML element, handling HTML tags

    This function was extracted from duplicate implementations in:
    - scap_scanner.py
    - scap_datastream_processor.py

    Args:
        element: XML element to extract text from

    Returns:
        str: Clean text content with normalized whitespace
    """
    if element is None:
        return ""

    # Get text content and clean up HTML tags
    text = etree.tostring(element, method="text", encoding="unicode").strip()

    # Clean up extra whitespace
    text = re.sub(r"\s+", " ", text).strip()

    return text


def parse_oscap_info_basic(info_output: str) -> Dict:
    """
    Basic oscap info command output parser

    Extracts key-value pairs from oscap info output with basic normalization.
    For enhanced parsing with special case handling, use the specific
    implementations in scap_datastream_processor.py

    Args:
        info_output: Raw output from oscap info command

    Returns:
        Dict: Parsed key-value pairs with normalized keys
    """
    info = {}
    lines = info_output.split("\n")

    for line in lines:
        line = line.strip()
        if ":" in line:
            key, value = line.split(":", 1)
            key = key.strip().lower().replace(" ", "_")
            value = value.strip()
            info[key] = value

    return info


# Common XML namespaces used across SCAP processing
SCAP_NAMESPACES = {
    "ds": "http://scap.nist.gov/schema/scap/source/1.2",
    "xccdf": "http://checklists.nist.gov/xccdf/1.2",
    "oval": "http://oval.mitre.org/XMLSchema/oval-definitions-5",
    "oval-res": "http://oval.mitre.org/XMLSchema/oval-results-5",
    "arf": "http://scap.nist.gov/schema/asset-reporting-format/1.1",
    "cpe": "http://cpe.mitre.org/XMLSchema/cpe/2.3",
    "dc": "http://purl.org/dc/elements/1.1/",
}


def safe_xml_find(root, xpath: str, namespaces: Optional[Dict] = None) -> Optional[any]:
    """
    Safe XML element finder with error handling

    Args:
        root: XML root element
        xpath: XPath expression
        namespaces: Optional namespace dict (defaults to SCAP_NAMESPACES)

    Returns:
        Element if found, None if not found or on error
    """
    try:
        if namespaces is None:
            namespaces = SCAP_NAMESPACES
        return root.find(xpath, namespaces)
    except Exception as e:
        logger.debug(f"XML find error for xpath '{xpath}': {e}")
        return None


def safe_xml_findall(root, xpath: str, namespaces: Optional[Dict] = None) -> list:
    """
    Safe XML elements finder with error handling

    Args:
        root: XML root element
        xpath: XPath expression
        namespaces: Optional namespace dict (defaults to SCAP_NAMESPACES)

    Returns:
        List of elements (empty list if none found or on error)
    """
    try:
        if namespaces is None:
            namespaces = SCAP_NAMESPACES
        return root.findall(xpath, namespaces)
    except Exception as e:
        logger.debug(f"XML findall error for xpath '{xpath}': {e}")
        return []
