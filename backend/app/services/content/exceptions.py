"""
Content Module Exceptions

This module defines exception classes specific to content management operations
including parsing, transformation, validation, and import errors.

Exception Hierarchy:
- ContentError (base)
  - ContentParseError (parsing failures)
  - ContentValidationError (validation failures)
  - ContentTransformationError (transformation failures)
  - ContentImportError (import failures)
  - DependencyResolutionError (dependency issues)

Design Principles:
- Clear exception hierarchy for targeted exception handling
- Rich context information for debugging
- Serializable to JSON for API error responses
- No sensitive data in exception messages
"""

from typing import Any, Dict, List, Optional


class ContentError(Exception):
    """
    Base exception for all content module errors.

    All content-related exceptions inherit from this class, allowing
    callers to catch all content errors with a single except clause
    when appropriate.

    Attributes:
        message: Human-readable error description
        details: Additional context information
        source_file: Path to the content file that caused the error (if applicable)
    """

    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        source_file: Optional[str] = None,
    ) -> None:
        """
        Initialize a ContentError.

        Args:
            message: Human-readable error description.
            details: Additional context information for debugging.
            source_file: Path to the content file that caused the error.
        """
        self.message = message
        self.details = details or {}
        self.source_file = source_file
        super().__init__(message)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert exception to dictionary for JSON serialization.

        Returns:
            Dictionary representation of the exception.
        """
        return {
            "error_type": self.__class__.__name__,
            "message": self.message,
            "details": self.details,
            "source_file": self.source_file,
        }


class ContentParseError(ContentError):
    """
    Raised when content parsing fails.

    This exception indicates that the content file could not be parsed
    due to format issues, missing required elements, or XML/JSON syntax errors.

    Common causes:
    - Malformed XML/JSON syntax
    - Missing required elements (benchmark, rules, profiles)
    - Unsupported content format version
    - Character encoding issues

    Attributes:
        message: Human-readable error description
        details: Additional context (line number, element name, etc.)
        source_file: Path to the content file
        line_number: Line number where error occurred (if applicable)
        element: XML/JSON element that caused the error (if applicable)
    """

    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        source_file: Optional[str] = None,
        line_number: Optional[int] = None,
        element: Optional[str] = None,
    ) -> None:
        """
        Initialize a ContentParseError.

        Args:
            message: Human-readable error description.
            details: Additional context information.
            source_file: Path to the content file.
            line_number: Line number where error occurred.
            element: XML/JSON element that caused the error.
        """
        self.line_number = line_number
        self.element = element

        # Enhance details with specific parse error info
        enhanced_details = details or {}
        if line_number is not None:
            enhanced_details["line_number"] = line_number
        if element is not None:
            enhanced_details["element"] = element

        super().__init__(message, enhanced_details, source_file)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert exception to dictionary for JSON serialization.

        Returns:
            Dictionary representation of the exception.
        """
        result = super().to_dict()
        result["line_number"] = self.line_number
        result["element"] = self.element
        return result


class ContentValidationError(ContentError):
    """
    Raised when content validation fails.

    This exception indicates that the content was parsed successfully
    but failed validation checks (semantic validation, required fields,
    format compliance).

    Common causes:
    - Missing required rule attributes
    - Invalid severity values
    - Invalid platform identifiers
    - Schema validation failures

    Attributes:
        message: Human-readable error description
        details: Additional context
        source_file: Path to the content file
        validation_errors: List of specific validation error messages
        rule_id: Rule ID that failed validation (if applicable)
    """

    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        source_file: Optional[str] = None,
        validation_errors: Optional[List[str]] = None,
        rule_id: Optional[str] = None,
    ) -> None:
        """
        Initialize a ContentValidationError.

        Args:
            message: Human-readable error description.
            details: Additional context information.
            source_file: Path to the content file.
            validation_errors: List of specific validation error messages.
            rule_id: Rule ID that failed validation.
        """
        self.validation_errors = validation_errors or []
        self.rule_id = rule_id

        # Enhance details with validation-specific info
        enhanced_details = details or {}
        if validation_errors:
            enhanced_details["validation_errors"] = validation_errors
        if rule_id:
            enhanced_details["rule_id"] = rule_id

        super().__init__(message, enhanced_details, source_file)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert exception to dictionary for JSON serialization.

        Returns:
            Dictionary representation of the exception.
        """
        result = super().to_dict()
        result["validation_errors"] = self.validation_errors
        result["rule_id"] = self.rule_id
        return result


class ContentTransformationError(ContentError):
    """
    Raised when content transformation fails.

    This exception indicates that parsed content could not be transformed
    to the target format (usually MongoDB document format).

    Common causes:
    - Unsupported source format features
    - Data type conversion failures
    - Missing required mapping information

    Attributes:
        message: Human-readable error description
        details: Additional context
        source_file: Path to the content file
        source_format: Format being transformed from
        target_format: Format being transformed to
        rule_id: Rule ID that failed transformation (if applicable)
    """

    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        source_file: Optional[str] = None,
        source_format: Optional[str] = None,
        target_format: Optional[str] = None,
        rule_id: Optional[str] = None,
    ) -> None:
        """
        Initialize a ContentTransformationError.

        Args:
            message: Human-readable error description.
            details: Additional context information.
            source_file: Path to the content file.
            source_format: Format being transformed from.
            target_format: Format being transformed to.
            rule_id: Rule ID that failed transformation.
        """
        self.source_format = source_format
        self.target_format = target_format
        self.rule_id = rule_id

        # Enhance details with transformation-specific info
        enhanced_details = details or {}
        if source_format:
            enhanced_details["source_format"] = source_format
        if target_format:
            enhanced_details["target_format"] = target_format
        if rule_id:
            enhanced_details["rule_id"] = rule_id

        super().__init__(message, enhanced_details, source_file)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert exception to dictionary for JSON serialization.

        Returns:
            Dictionary representation of the exception.
        """
        result = super().to_dict()
        result["source_format"] = self.source_format
        result["target_format"] = self.target_format
        result["rule_id"] = self.rule_id
        return result


class ContentImportError(ContentError):
    """
    Raised when content import fails.

    This exception indicates that transformed content could not be
    imported into the database.

    Common causes:
    - Database connection failures
    - Duplicate rule IDs (unique constraint violations)
    - Transaction rollback
    - Bulk insert failures

    Attributes:
        message: Human-readable error description
        details: Additional context
        source_file: Path to the content file
        imported_count: Number of rules successfully imported before failure
        failed_rule_ids: List of rule IDs that failed to import
    """

    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        source_file: Optional[str] = None,
        imported_count: int = 0,
        failed_rule_ids: Optional[List[str]] = None,
    ) -> None:
        """
        Initialize a ContentImportError.

        Args:
            message: Human-readable error description.
            details: Additional context information.
            source_file: Path to the content file.
            imported_count: Number of rules successfully imported.
            failed_rule_ids: List of rule IDs that failed to import.
        """
        self.imported_count = imported_count
        self.failed_rule_ids = failed_rule_ids or []

        # Enhance details with import-specific info
        enhanced_details = details or {}
        enhanced_details["imported_count"] = imported_count
        if failed_rule_ids:
            enhanced_details["failed_rule_ids"] = failed_rule_ids

        super().__init__(message, enhanced_details, source_file)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert exception to dictionary for JSON serialization.

        Returns:
            Dictionary representation of the exception.
        """
        result = super().to_dict()
        result["imported_count"] = self.imported_count
        result["failed_rule_ids"] = self.failed_rule_ids
        return result


class DependencyResolutionError(ContentError):
    """
    Raised when dependency resolution fails.

    This exception indicates that rule dependencies could not be
    resolved, usually due to missing or circular dependencies.

    Common causes:
    - Missing dependency rules (rule A depends on rule B which doesn't exist)
    - Circular dependencies (rule A -> rule B -> rule A)
    - Version conflicts between dependencies

    Attributes:
        message: Human-readable error description
        details: Additional context
        source_file: Path to the content file
        rule_id: Rule ID with dependency issues
        missing_dependencies: List of missing dependency rule IDs
        circular_dependencies: List of circular dependency chains
    """

    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        source_file: Optional[str] = None,
        rule_id: Optional[str] = None,
        missing_dependencies: Optional[List[str]] = None,
        circular_dependencies: Optional[List[List[str]]] = None,
    ) -> None:
        """
        Initialize a DependencyResolutionError.

        Args:
            message: Human-readable error description.
            details: Additional context information.
            source_file: Path to the content file.
            rule_id: Rule ID with dependency issues.
            missing_dependencies: List of missing dependency rule IDs.
            circular_dependencies: List of circular dependency chains.
        """
        self.rule_id = rule_id
        self.missing_dependencies = missing_dependencies or []
        self.circular_dependencies = circular_dependencies or []

        # Enhance details with dependency-specific info
        enhanced_details = details or {}
        if rule_id:
            enhanced_details["rule_id"] = rule_id
        if missing_dependencies:
            enhanced_details["missing_dependencies"] = missing_dependencies
        if circular_dependencies:
            enhanced_details["circular_dependencies"] = circular_dependencies

        super().__init__(message, enhanced_details, source_file)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert exception to dictionary for JSON serialization.

        Returns:
            Dictionary representation of the exception.
        """
        result = super().to_dict()
        result["rule_id"] = self.rule_id
        result["missing_dependencies"] = self.missing_dependencies
        result["circular_dependencies"] = self.circular_dependencies
        return result


class UnsupportedFormatError(ContentError):
    """
    Raised when an unsupported content format is encountered.

    This exception indicates that the content format is not supported
    by any available parser.

    Attributes:
        message: Human-readable error description
        details: Additional context
        source_file: Path to the content file
        detected_format: The format that was detected (if any)
        supported_formats: List of supported formats
    """

    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        source_file: Optional[str] = None,
        detected_format: Optional[str] = None,
        supported_formats: Optional[List[str]] = None,
    ) -> None:
        """
        Initialize an UnsupportedFormatError.

        Args:
            message: Human-readable error description.
            details: Additional context information.
            source_file: Path to the content file.
            detected_format: The format that was detected.
            supported_formats: List of supported formats.
        """
        self.detected_format = detected_format
        self.supported_formats = supported_formats or []

        # Enhance details with format-specific info
        enhanced_details = details or {}
        if detected_format:
            enhanced_details["detected_format"] = detected_format
        if supported_formats:
            enhanced_details["supported_formats"] = supported_formats

        super().__init__(message, enhanced_details, source_file)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert exception to dictionary for JSON serialization.

        Returns:
            Dictionary representation of the exception.
        """
        result = super().to_dict()
        result["detected_format"] = self.detected_format
        result["supported_formats"] = self.supported_formats
        return result
