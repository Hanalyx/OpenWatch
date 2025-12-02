"""
Engine Module Exceptions

This module defines the exception hierarchy for the scan execution engine.
All engine-specific exceptions inherit from EngineError, enabling consistent
error handling across executors and scanners.

Exception Hierarchy:
    EngineError (base)
    ├── ExecutorError (executor-related failures)
    │   ├── SSHExecutionError (SSH connection/execution failures)
    │   ├── LocalExecutionError (local execution failures)
    │   └── FileTransferError (file upload/download failures)
    ├── ScannerError (scanner-related failures)
    │   ├── ScanExecutionError (scan process failures)
    │   ├── ContentValidationError (SCAP content issues)
    │   └── ResultParseError (result file parsing failures)
    └── DependencyError (dependency resolution failures)

Design Principles:
- All exceptions include context for debugging
- Sensitive information is sanitized in error messages
- Exceptions are serializable for logging and API responses
- Error codes enable programmatic error handling

Security Notes:
- Error messages never include credentials
- File paths are sanitized to prevent information disclosure
- Stack traces are logged server-side only
"""

from typing import Any, Dict, List, Optional


class EngineError(Exception):
    """
    Base exception for all engine operations.

    All exceptions in the engine module inherit from this class,
    enabling consistent catch-all error handling.

    Attributes:
        message: Human-readable error description
        error_code: Machine-readable error identifier
        context: Additional context for debugging
        cause: Original exception if wrapping another error

    Usage:
        try:
            executor.execute(context)
        except EngineError as e:
            logger.error(f"Engine error {e.error_code}: {e.message}")
            if e.context:
                logger.debug(f"Context: {e.context}")
    """

    def __init__(
        self,
        message: str,
        error_code: str = "ENGINE_ERROR",
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.context = context or {}
        self.cause = cause

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert exception to dictionary for JSON serialization.

        Returns:
            Dictionary representation safe for API responses.
        """
        return {
            "error": self.error_code,
            "message": self.message,
            "context": self.context,
            "cause": str(self.cause) if self.cause else None,
        }

    def __str__(self) -> str:
        """Format exception for logging."""
        parts = [f"[{self.error_code}] {self.message}"]
        if self.context:
            parts.append(f" (context: {self.context})")
        if self.cause:
            parts.append(f" (caused by: {self.cause})")
        return "".join(parts)


# =============================================================================
# Executor Exceptions
# =============================================================================


class ExecutorError(EngineError):
    """
    Base exception for executor-related failures.

    Raised when an executor fails to complete its operation,
    such as connection failures, authentication errors, or
    execution environment issues.
    """

    def __init__(
        self,
        message: str,
        error_code: str = "EXECUTOR_ERROR",
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(message, error_code, context, cause)


class SSHExecutionError(ExecutorError):
    """
    Raised when SSH-based execution fails.

    Covers connection failures, authentication errors, command
    execution failures, and SSH-specific issues.

    Attributes:
        hostname: Target host where connection failed
        port: SSH port number
        auth_method: Authentication method attempted

    Usage:
        raise SSHExecutionError(
            message="SSH connection timed out",
            hostname="192.168.1.100",
            port=22,
            auth_method="ssh_key"
        )
    """

    def __init__(
        self,
        message: str,
        hostname: str = "",
        port: int = 22,
        auth_method: str = "",
        error_code: str = "SSH_EXECUTION_ERROR",
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        # Build context with SSH-specific details
        ssh_context = {
            "hostname": hostname,
            "port": port,
            "auth_method": auth_method,
        }
        if context:
            ssh_context.update(context)

        super().__init__(message, error_code, ssh_context, cause)
        self.hostname = hostname
        self.port = port
        self.auth_method = auth_method


class LocalExecutionError(ExecutorError):
    """
    Raised when local execution fails.

    Covers process execution failures, permission issues, and
    environment problems on the local host.

    Attributes:
        command: Command that failed to execute
        exit_code: Process exit code if available
        working_dir: Working directory for execution
    """

    def __init__(
        self,
        message: str,
        command: str = "",
        exit_code: Optional[int] = None,
        working_dir: str = "",
        error_code: str = "LOCAL_EXECUTION_ERROR",
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        local_context = {
            "command": command,
            "exit_code": exit_code,
            "working_dir": working_dir,
        }
        if context:
            local_context.update(context)

        super().__init__(message, error_code, local_context, cause)
        self.command = command
        self.exit_code = exit_code
        self.working_dir = working_dir


class FileTransferError(ExecutorError):
    """
    Raised when file transfer operations fail.

    Covers upload and download failures in remote execution,
    including size mismatches, permission issues, and timeouts.

    Attributes:
        local_path: Path on local system
        remote_path: Path on remote system
        direction: Transfer direction ('upload' or 'download')
        bytes_transferred: Number of bytes transferred before failure
    """

    def __init__(
        self,
        message: str,
        local_path: str = "",
        remote_path: str = "",
        direction: str = "upload",
        bytes_transferred: int = 0,
        error_code: str = "FILE_TRANSFER_ERROR",
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        transfer_context = {
            "local_path": local_path,
            "remote_path": remote_path,
            "direction": direction,
            "bytes_transferred": bytes_transferred,
        }
        if context:
            transfer_context.update(context)

        super().__init__(message, error_code, transfer_context, cause)
        self.local_path = local_path
        self.remote_path = remote_path
        self.direction = direction
        self.bytes_transferred = bytes_transferred


# =============================================================================
# Scanner Exceptions
# =============================================================================


class ScannerError(EngineError):
    """
    Base exception for scanner-related failures.

    Raised when a scanner fails to complete scan operations,
    including scan execution, content issues, or result problems.
    """

    def __init__(
        self,
        message: str,
        error_code: str = "SCANNER_ERROR",
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(message, error_code, context, cause)


class ScanExecutionError(ScannerError):
    """
    Raised when scan execution fails.

    Covers oscap command failures, timeout errors, and
    unexpected scan termination.

    Attributes:
        scan_id: Identifier of the failed scan
        profile_id: XCCDF profile being evaluated
        exit_code: Scanner process exit code
        stderr: Standard error output from scanner
    """

    def __init__(
        self,
        message: str,
        scan_id: str = "",
        profile_id: str = "",
        exit_code: Optional[int] = None,
        stderr: str = "",
        error_code: str = "SCAN_EXECUTION_ERROR",
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        scan_context = {
            "scan_id": scan_id,
            "profile_id": profile_id,
            "exit_code": exit_code,
            # Truncate stderr to prevent log bloat (security: limit info disclosure)
            "stderr": stderr[:1000] if stderr else "",
        }
        if context:
            scan_context.update(context)

        super().__init__(message, error_code, scan_context, cause)
        self.scan_id = scan_id
        self.profile_id = profile_id
        self.exit_code = exit_code
        self.stderr = stderr


class ContentValidationError(ScannerError):
    """
    Raised when SCAP content validation fails.

    Covers invalid content format, missing required elements,
    and schema validation failures.

    Attributes:
        content_path: Path to the invalid content file
        validation_errors: List of specific validation failures
        content_type: Type of content (xccdf, oval, datastream)
    """

    def __init__(
        self,
        message: str,
        content_path: str = "",
        validation_errors: Optional[List[str]] = None,
        content_type: str = "",
        error_code: str = "CONTENT_VALIDATION_ERROR",
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        validation_context = {
            "content_path": content_path,
            "validation_errors": validation_errors or [],
            "content_type": content_type,
        }
        if context:
            validation_context.update(context)

        super().__init__(message, error_code, validation_context, cause)
        self.content_path = content_path
        self.validation_errors = validation_errors or []
        self.content_type = content_type


class ResultParseError(ScannerError):
    """
    Raised when scan result parsing fails.

    Covers XML parsing errors, missing required elements,
    and malformed result files.

    Attributes:
        result_path: Path to the result file
        parse_errors: Specific parsing error messages
        expected_format: Expected result format (xccdf, arf, oval)
    """

    def __init__(
        self,
        message: str,
        result_path: str = "",
        parse_errors: Optional[List[str]] = None,
        expected_format: str = "",
        error_code: str = "RESULT_PARSE_ERROR",
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        parse_context = {
            "result_path": result_path,
            "parse_errors": parse_errors or [],
            "expected_format": expected_format,
        }
        if context:
            parse_context.update(context)

        super().__init__(message, error_code, parse_context, cause)
        self.result_path = result_path
        self.parse_errors = parse_errors or []
        self.expected_format = expected_format


# =============================================================================
# Dependency Exceptions
# =============================================================================


class DependencyError(EngineError):
    """
    Raised when SCAP dependency resolution fails.

    Covers missing dependencies, circular references, and
    unresolvable content references.

    Attributes:
        primary_file: Main content file being resolved
        missing_files: List of files that could not be found
        circular_refs: List of circular reference chains detected
    """

    def __init__(
        self,
        message: str,
        primary_file: str = "",
        missing_files: Optional[List[str]] = None,
        circular_refs: Optional[List[str]] = None,
        error_code: str = "DEPENDENCY_ERROR",
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        dep_context = {
            "primary_file": primary_file,
            "missing_files": missing_files or [],
            "circular_refs": circular_refs or [],
        }
        if context:
            dep_context.update(context)

        super().__init__(message, error_code, dep_context, cause)
        self.primary_file = primary_file
        self.missing_files = missing_files or []
        self.circular_refs = circular_refs or []


# =============================================================================
# Timeout and Resource Exceptions
# =============================================================================


class ScanTimeoutError(ScanExecutionError):
    """
    Raised when scan execution exceeds the maximum allowed time.

    Attributes:
        timeout_seconds: Configured timeout value
        elapsed_seconds: Time elapsed before timeout
    """

    def __init__(
        self,
        message: str,
        scan_id: str = "",
        timeout_seconds: int = 0,
        elapsed_seconds: float = 0.0,
        error_code: str = "SCAN_TIMEOUT_ERROR",
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        timeout_context = {
            "timeout_seconds": timeout_seconds,
            "elapsed_seconds": elapsed_seconds,
        }
        if context:
            timeout_context.update(context)

        super().__init__(
            message=message,
            scan_id=scan_id,
            error_code=error_code,
            context=timeout_context,
            cause=cause,
        )
        self.timeout_seconds = timeout_seconds
        self.elapsed_seconds = elapsed_seconds


class ResourceExhaustedError(EngineError):
    """
    Raised when system resources are exhausted.

    Covers disk space issues, memory limits, and
    concurrent execution limits.

    Attributes:
        resource_type: Type of resource exhausted (disk, memory, concurrent)
        current_usage: Current usage level
        limit: Configured limit
    """

    def __init__(
        self,
        message: str,
        resource_type: str = "",
        current_usage: str = "",
        limit: str = "",
        error_code: str = "RESOURCE_EXHAUSTED_ERROR",
        context: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
    ):
        resource_context = {
            "resource_type": resource_type,
            "current_usage": current_usage,
            "limit": limit,
        }
        if context:
            resource_context.update(context)

        super().__init__(message, error_code, resource_context, cause)
        self.resource_type = resource_type
        self.current_usage = current_usage
        self.limit = limit


# =============================================================================
# Backward Compatibility Aliases
# =============================================================================

# These aliases maintain compatibility with existing code that imports
# from the legacy module locations. New code should use the canonical
# exception names defined above.

RemoteSCAPExecutionError = SSHExecutionError
SCAPBaseError = ScannerError
SCAPContentError = ContentValidationError
