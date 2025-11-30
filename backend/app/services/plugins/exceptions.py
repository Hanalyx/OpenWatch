"""
Plugin System Exceptions

Centralized exception hierarchy for all plugin-related errors. These exceptions
provide specific error types for different failure scenarios in the plugin
system, enabling precise error handling and informative error messages.

Exception Hierarchy:
    PluginError (base)
    +-- PluginNotFoundError: Plugin does not exist
    +-- PluginImportError: Failed to import plugin
    +-- PluginSecurityError: Security validation failed
    +-- PluginExecutionError: Plugin execution failed
    +-- PluginValidationError: Plugin validation failed
    +-- PluginRegistryError: Registry operation failed
    +-- PluginSignatureError: Signature verification failed

Usage:
    from backend.app.services.plugins.exceptions import (
        PluginError,
        PluginNotFoundError,
        PluginSecurityError,
    )

    try:
        plugin = await registry.get_plugin(plugin_id)
        if not plugin:
            raise PluginNotFoundError(plugin_id)
    except PluginError as e:
        logger.error(f"Plugin operation failed: {e}")
"""

from typing import Any, Dict, List, Optional


class PluginError(Exception):
    """
    Base exception for all plugin-related errors.

    All plugin exceptions inherit from this class, allowing callers to catch
    any plugin error with a single except clause while still enabling
    specific error handling when needed.

    Attributes:
        message: Human-readable error description.
        details: Additional context about the error (optional).
    """

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize the plugin error.

        Args:
            message: Human-readable error description.
            details: Additional context about the error.
        """
        self.message = message
        self.details = details or {}
        super().__init__(self.message)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert exception to dictionary for API responses.

        Returns:
            Dictionary containing error type, message, and details.
        """
        return {
            "error_type": self.__class__.__name__,
            "message": self.message,
            "details": self.details,
        }


class PluginNotFoundError(PluginError):
    """
    Raised when a requested plugin does not exist.

    This exception is raised when attempting to access, execute, or modify
    a plugin that is not registered in the system.

    Attributes:
        plugin_id: The ID of the plugin that was not found.
    """

    def __init__(self, plugin_id: str, message: Optional[str] = None) -> None:
        """
        Initialize the not found error.

        Args:
            plugin_id: The ID of the plugin that was not found.
            message: Custom error message (optional).
        """
        self.plugin_id = plugin_id
        default_message = f"Plugin not found: {plugin_id}"
        super().__init__(
            message=message or default_message,
            details={"plugin_id": plugin_id},
        )


class PluginImportError(PluginError):
    """
    Raised when plugin import fails.

    This exception covers various import failure scenarios including
    invalid package format, missing manifest, or failed extraction.

    Attributes:
        stage: The import stage where failure occurred.
        source: The source of the import (file, URL, registry).
    """

    def __init__(
        self,
        message: str,
        stage: str = "unknown",
        source: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Initialize the import error.

        Args:
            message: Description of the import failure.
            stage: The import stage where failure occurred
                   (extraction, validation, security_scan, registration).
            source: The source of the import attempt.
            details: Additional context about the failure.
        """
        self.stage = stage
        self.source = source
        error_details = details or {}
        error_details.update({"stage": stage, "source": source})
        super().__init__(message=message, details=error_details)


class PluginSecurityError(PluginError):
    """
    Raised when plugin fails security validation.

    This exception is raised when a plugin contains dangerous patterns,
    forbidden file access attempts, or other security violations.

    Attributes:
        severity: Severity level of the security issue (critical, high, medium, low).
        checks_failed: List of security checks that failed.
    """

    def __init__(
        self,
        message: str,
        severity: str = "critical",
        checks_failed: Optional[List[str]] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Initialize the security error.

        Args:
            message: Description of the security violation.
            severity: Severity level (critical, high, medium, low).
            checks_failed: List of failed security check names.
            details: Additional context about the violation.
        """
        self.severity = severity
        self.checks_failed = checks_failed or []
        error_details = details or {}
        error_details.update(
            {
                "severity": severity,
                "checks_failed": self.checks_failed,
            }
        )
        super().__init__(message=message, details=error_details)


class PluginExecutionError(PluginError):
    """
    Raised when plugin execution fails.

    This exception covers runtime failures during plugin execution,
    including timeouts, resource limits, and execution errors.

    Attributes:
        plugin_id: The ID of the plugin that failed.
        execution_id: Unique identifier for the failed execution.
        exit_code: Exit code from the executed process (if applicable).
    """

    def __init__(
        self,
        message: str,
        plugin_id: str,
        execution_id: Optional[str] = None,
        exit_code: Optional[int] = None,
        stdout: Optional[str] = None,
        stderr: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Initialize the execution error.

        Args:
            message: Description of the execution failure.
            plugin_id: The ID of the plugin that failed.
            execution_id: Unique identifier for this execution.
            exit_code: Exit code from the process.
            stdout: Standard output from the process.
            stderr: Standard error from the process.
            details: Additional context about the failure.
        """
        self.plugin_id = plugin_id
        self.execution_id = execution_id
        self.exit_code = exit_code
        error_details = details or {}
        error_details.update(
            {
                "plugin_id": plugin_id,
                "execution_id": execution_id,
                "exit_code": exit_code,
                "stdout": stdout,
                "stderr": stderr,
            }
        )
        super().__init__(message=message, details=error_details)


class PluginValidationError(PluginError):
    """
    Raised when plugin validation fails.

    This exception is raised when a plugin's manifest, executors,
    or other components fail validation checks.

    Attributes:
        validation_errors: List of specific validation errors.
    """

    def __init__(
        self,
        message: str,
        validation_errors: Optional[List[str]] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Initialize the validation error.

        Args:
            message: Description of the validation failure.
            validation_errors: List of specific validation error messages.
            details: Additional context about the failure.
        """
        self.validation_errors = validation_errors or []
        error_details = details or {}
        error_details.update({"validation_errors": self.validation_errors})
        super().__init__(message=message, details=error_details)


class PluginRegistryError(PluginError):
    """
    Raised when registry operations fail.

    This exception covers failures in plugin registration, unregistration,
    and other registry management operations.

    Attributes:
        operation: The registry operation that failed.
        plugin_id: The plugin ID involved in the operation (if applicable).
    """

    def __init__(
        self,
        message: str,
        operation: str,
        plugin_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Initialize the registry error.

        Args:
            message: Description of the registry failure.
            operation: The operation that failed (register, unregister, update).
            plugin_id: The plugin ID involved.
            details: Additional context about the failure.
        """
        self.operation = operation
        self.plugin_id = plugin_id
        error_details = details or {}
        error_details.update(
            {
                "operation": operation,
                "plugin_id": plugin_id,
            }
        )
        super().__init__(message=message, details=error_details)


class PluginSignatureError(PluginError):
    """
    Raised when signature verification fails.

    This exception is raised when a plugin's cryptographic signature
    cannot be verified or is invalid.

    Attributes:
        signer: The claimed signer of the plugin (if available).
        key_id: The public key ID used for verification (if available).
    """

    def __init__(
        self,
        message: str,
        signer: Optional[str] = None,
        key_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Initialize the signature error.

        Args:
            message: Description of the signature failure.
            signer: The claimed signer identity.
            key_id: The public key ID used for verification.
            details: Additional context about the failure.
        """
        self.signer = signer
        self.key_id = key_id
        error_details = details or {}
        error_details.update(
            {
                "signer": signer,
                "key_id": key_id,
            }
        )
        super().__init__(message=message, details=error_details)


class PluginDependencyError(PluginError):
    """
    Raised when plugin dependency resolution fails.

    This exception is raised when a plugin has unmet dependencies
    or circular dependency issues.

    Attributes:
        plugin_id: The plugin with dependency issues.
        missing_dependencies: List of unmet dependencies.
        circular_dependencies: List of circular dependency chains.
    """

    def __init__(
        self,
        message: str,
        plugin_id: str,
        missing_dependencies: Optional[List[str]] = None,
        circular_dependencies: Optional[List[str]] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Initialize the dependency error.

        Args:
            message: Description of the dependency issue.
            plugin_id: The plugin with dependency issues.
            missing_dependencies: List of unmet dependency names.
            circular_dependencies: List of circular dependency chains.
            details: Additional context about the issue.
        """
        self.plugin_id = plugin_id
        self.missing_dependencies = missing_dependencies or []
        self.circular_dependencies = circular_dependencies or []
        error_details = details or {}
        error_details.update(
            {
                "plugin_id": plugin_id,
                "missing_dependencies": self.missing_dependencies,
                "circular_dependencies": self.circular_dependencies,
            }
        )
        super().__init__(message=message, details=error_details)
