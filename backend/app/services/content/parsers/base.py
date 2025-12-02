"""
Abstract Base Parser for Content Module

This module defines the abstract base class that all content parsers must
implement. It establishes the contract for parsing compliance content from
various formats (SCAP, CIS, STIG, custom) into a normalized representation.

Design Principles:
- Abstract methods enforce consistent interface across all parsers
- Template method pattern for common parsing workflow
- Extensible for new content formats without modifying existing code
- Security-first: XML parsing with XXE prevention built-in
"""

import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import BinaryIO, List, Optional, Union

from ..exceptions import ContentParseError, UnsupportedFormatError
from ..models import ContentFormat, ParsedContent

logger = logging.getLogger(__name__)


class BaseContentParser(ABC):
    """
    Abstract base class for all content parsers.

    Each content format (SCAP, CIS, STIG, etc.) must implement a parser
    that inherits from this class. The parser is responsible for reading
    the source content and producing a normalized ParsedContent object.

    Subclasses must implement:
    - supported_formats: List of ContentFormat values this parser handles
    - _parse_file_impl: Core parsing logic for file paths
    - _parse_bytes_impl: Core parsing logic for byte streams

    Optional overrides:
    - validate_content: Additional validation after parsing
    - detect_format: Format detection from content

    Security Considerations:
    - All XML parsing must use defusedxml or lxml with XXE prevention
    - File size limits should be enforced (default 100MB)
    - Path traversal prevention for file operations

    Example:
        class SCAPParser(BaseContentParser):
            @property
            def supported_formats(self) -> List[ContentFormat]:
                return [ContentFormat.SCAP_DATASTREAM, ContentFormat.XCCDF]

            def _parse_file_impl(self, file_path: Path) -> ParsedContent:
                # SCAP-specific parsing logic
                pass
    """

    # Maximum file size to parse (100MB default, can be overridden)
    MAX_FILE_SIZE_BYTES: int = 100 * 1024 * 1024

    @property
    @abstractmethod
    def supported_formats(self) -> List[ContentFormat]:
        """
        Return list of content formats this parser supports.

        Returns:
            List of ContentFormat enum values supported by this parser.
        """
        pass

    @property
    def parser_name(self) -> str:
        """
        Return a human-readable name for this parser.

        Returns:
            Parser name string (defaults to class name).
        """
        return self.__class__.__name__

    def supports_format(self, content_format: ContentFormat) -> bool:
        """
        Check if this parser supports a given content format.

        Args:
            content_format: The ContentFormat to check.

        Returns:
            True if this parser supports the format, False otherwise.
        """
        return content_format in self.supported_formats

    def parse(
        self,
        source: Union[str, Path, BinaryIO, bytes],
        content_format: Optional[ContentFormat] = None,
    ) -> ParsedContent:
        """
        Parse content from various source types.

        This is the main entry point for parsing content. It handles
        different source types and delegates to the appropriate
        implementation method.

        Args:
            source: Content source - can be a file path (str/Path),
                   binary file object, or raw bytes.
            content_format: Optional format hint. If not provided,
                           format detection will be attempted.

        Returns:
            ParsedContent object containing all parsed rules, profiles, etc.

        Raises:
            ContentParseError: If parsing fails.
            UnsupportedFormatError: If content format is not supported.
            FileNotFoundError: If source file doesn't exist.
            ValueError: If source type is not supported.
        """
        logger.info(
            "Starting content parse with %s (format: %s)",
            self.parser_name,
            content_format.value if content_format else "auto-detect",
        )

        try:
            # Determine source type and parse accordingly
            if isinstance(source, (str, Path)):
                file_path = Path(source)
                return self._parse_from_file(file_path, content_format)
            elif isinstance(source, bytes):
                return self._parse_from_bytes(source, content_format)
            elif hasattr(source, "read"):
                # File-like object
                content_bytes = source.read()
                return self._parse_from_bytes(content_bytes, content_format)
            else:
                raise ValueError(
                    f"Unsupported source type: {type(source).__name__}. "
                    "Expected str, Path, bytes, or file-like object."
                )
        except ContentParseError:
            # Re-raise content errors as-is
            raise
        except UnsupportedFormatError:
            # Re-raise format errors as-is
            raise
        except Exception as e:
            # Wrap unexpected errors
            logger.error("Unexpected error during parsing: %s", str(e))
            raise ContentParseError(
                message=f"Unexpected parsing error: {str(e)}",
                details={"parser": self.parser_name, "error_type": type(e).__name__},
            ) from e

    def _parse_from_file(
        self,
        file_path: Path,
        content_format: Optional[ContentFormat] = None,
    ) -> ParsedContent:
        """
        Parse content from a file path.

        Args:
            file_path: Path to the content file.
            content_format: Optional format hint.

        Returns:
            ParsedContent object.

        Raises:
            ContentParseError: If parsing fails.
            FileNotFoundError: If file doesn't exist.
        """
        # Security: Resolve to absolute path and validate
        file_path = file_path.resolve()

        if not file_path.exists():
            raise FileNotFoundError(f"Content file not found: {file_path}")

        if not file_path.is_file():
            raise ContentParseError(
                message=f"Path is not a file: {file_path}",
                source_file=str(file_path),
            )

        # Security: Check file size before reading
        file_size = file_path.stat().st_size
        if file_size > self.MAX_FILE_SIZE_BYTES:
            raise ContentParseError(
                message=f"File exceeds maximum size limit ({self.MAX_FILE_SIZE_BYTES} bytes)",
                source_file=str(file_path),
                details={"file_size": file_size, "max_size": self.MAX_FILE_SIZE_BYTES},
            )

        # Detect format if not provided
        if content_format is None:
            content_format = self.detect_format_from_file(file_path)

        # Validate format is supported
        if not self.supports_format(content_format):
            raise UnsupportedFormatError(
                message=f"Parser {self.parser_name} does not support format {content_format.value}",
                source_file=str(file_path),
                detected_format=content_format.value,
                supported_formats=[f.value for f in self.supported_formats],
            )

        logger.debug("Parsing file: %s (format: %s)", file_path, content_format.value)

        # Delegate to implementation
        result = self._parse_file_impl(file_path, content_format)
        result.source_file = str(file_path)

        # Post-parse validation
        self._validate_parsed_content(result)

        logger.info(
            "Successfully parsed %d rules, %d profiles from %s",
            result.rule_count,
            result.profile_count,
            file_path,
        )

        return result

    def _parse_from_bytes(
        self,
        content_bytes: bytes,
        content_format: Optional[ContentFormat] = None,
    ) -> ParsedContent:
        """
        Parse content from raw bytes.

        Args:
            content_bytes: Raw content bytes.
            content_format: Optional format hint.

        Returns:
            ParsedContent object.

        Raises:
            ContentParseError: If parsing fails.
        """
        # Security: Check content size
        if len(content_bytes) > self.MAX_FILE_SIZE_BYTES:
            raise ContentParseError(
                message=f"Content exceeds maximum size limit ({self.MAX_FILE_SIZE_BYTES} bytes)",
                details={
                    "content_size": len(content_bytes),
                    "max_size": self.MAX_FILE_SIZE_BYTES,
                },
            )

        # Detect format if not provided
        if content_format is None:
            content_format = self.detect_format_from_bytes(content_bytes)

        # Validate format is supported
        if not self.supports_format(content_format):
            raise UnsupportedFormatError(
                message=f"Parser {self.parser_name} does not support format {content_format.value}",
                detected_format=content_format.value,
                supported_formats=[f.value for f in self.supported_formats],
            )

        logger.debug(
            "Parsing bytes content (size: %d, format: %s)",
            len(content_bytes),
            content_format.value,
        )

        # Delegate to implementation
        result = self._parse_bytes_impl(content_bytes, content_format)

        # Post-parse validation
        self._validate_parsed_content(result)

        logger.info(
            "Successfully parsed %d rules, %d profiles from bytes",
            result.rule_count,
            result.profile_count,
        )

        return result

    @abstractmethod
    def _parse_file_impl(
        self,
        file_path: Path,
        content_format: ContentFormat,
    ) -> ParsedContent:
        """
        Implementation-specific file parsing logic.

        Subclasses must implement this method to perform the actual
        parsing of content from a file.

        Args:
            file_path: Path to the content file (validated to exist).
            content_format: The content format (validated to be supported).

        Returns:
            ParsedContent object with parsed rules, profiles, etc.

        Raises:
            ContentParseError: If parsing fails.
        """
        pass

    @abstractmethod
    def _parse_bytes_impl(
        self,
        content_bytes: bytes,
        content_format: ContentFormat,
    ) -> ParsedContent:
        """
        Implementation-specific bytes parsing logic.

        Subclasses must implement this method to perform the actual
        parsing of content from raw bytes.

        Args:
            content_bytes: Raw content bytes (validated for size).
            content_format: The content format (validated to be supported).

        Returns:
            ParsedContent object with parsed rules, profiles, etc.

        Raises:
            ContentParseError: If parsing fails.
        """
        pass

    def detect_format_from_file(self, file_path: Path) -> ContentFormat:
        """
        Detect content format from a file.

        Default implementation uses file extension and magic bytes.
        Subclasses can override for more sophisticated detection.

        Args:
            file_path: Path to the content file.

        Returns:
            Detected ContentFormat.

        Raises:
            UnsupportedFormatError: If format cannot be detected.
        """
        # Try extension-based detection first
        extension = file_path.suffix.lower()
        extension_map = {
            ".xml": ContentFormat.XCCDF,  # Default XML to XCCDF
            ".json": ContentFormat.CUSTOM_JSON,
            ".yaml": ContentFormat.CUSTOM_YAML,
            ".yml": ContentFormat.CUSTOM_YAML,
        }

        if extension in extension_map:
            # For XML files, peek at content to distinguish SCAP datastream
            if extension == ".xml":
                try:
                    with open(file_path, "rb") as f:
                        header = f.read(4096)
                        return self.detect_format_from_bytes(header)
                except Exception:
                    return ContentFormat.XCCDF

            return extension_map[extension]

        raise UnsupportedFormatError(
            message=f"Cannot detect content format from file: {file_path}",
            source_file=str(file_path),
            supported_formats=[f.value for f in self.supported_formats],
        )

    def detect_format_from_bytes(self, content_bytes: bytes) -> ContentFormat:
        """
        Detect content format from raw bytes.

        Default implementation checks for common format signatures.
        Subclasses can override for format-specific detection.

        Args:
            content_bytes: Raw content bytes (may be partial).

        Returns:
            Detected ContentFormat.

        Raises:
            UnsupportedFormatError: If format cannot be detected.
        """
        # Decode header for text-based format detection
        try:
            header = content_bytes[:4096].decode("utf-8", errors="ignore").lower()
        except Exception:
            header = ""

        # Check for SCAP datastream indicators
        if "data-stream-collection" in header or "scap:data-stream" in header:
            return ContentFormat.SCAP_DATASTREAM

        # Check for XCCDF benchmark
        if "benchmark" in header and ("xccdf" in header or "xmlns" in header):
            return ContentFormat.XCCDF

        # Check for OVAL definitions
        if "oval_definitions" in header or "oval:definitions" in header:
            return ContentFormat.OVAL

        # Check for JSON
        if header.strip().startswith("{") or header.strip().startswith("["):
            return ContentFormat.CUSTOM_JSON

        # Check for YAML
        if header.strip().startswith("---") or ":" in header.split("\n")[0]:
            return ContentFormat.CUSTOM_YAML

        raise UnsupportedFormatError(
            message="Cannot detect content format from bytes",
            supported_formats=[f.value for f in self.supported_formats],
        )

    def _validate_parsed_content(self, content: ParsedContent) -> None:
        """
        Validate parsed content after parsing.

        Default implementation performs basic sanity checks.
        Subclasses can override to add format-specific validation.

        Args:
            content: The ParsedContent to validate.

        Raises:
            ContentParseError: If validation fails.
        """
        # Basic sanity checks
        if content.rule_count == 0 and content.profile_count == 0:
            logger.warning("Parsed content contains no rules or profiles - file may be empty or invalid")
            content.parse_warnings.append("Parsed content contains no rules or profiles")

        # Check for duplicate rule IDs
        rule_ids = [r.rule_id for r in content.rules]
        duplicate_ids = set(rid for rid in rule_ids if rule_ids.count(rid) > 1)
        if duplicate_ids:
            logger.warning(
                "Duplicate rule IDs found: %s",
                ", ".join(list(duplicate_ids)[:5]),
            )
            content.parse_warnings.append(f"Found {len(duplicate_ids)} duplicate rule IDs")

        # Check for duplicate profile IDs
        profile_ids = [p.profile_id for p in content.profiles]
        duplicate_profile_ids = set(pid for pid in profile_ids if profile_ids.count(pid) > 1)
        if duplicate_profile_ids:
            logger.warning(
                "Duplicate profile IDs found: %s",
                ", ".join(list(duplicate_profile_ids)[:5]),
            )
            content.parse_warnings.append(f"Found {len(duplicate_profile_ids)} duplicate profile IDs")
