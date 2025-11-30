"""
SSH Exceptions

Custom exception classes for SSH-related errors with detailed context
for debugging and error handling. These exceptions provide structured
error information that can be logged and presented to users safely.

This module defines:
- SSHKeyError: Errors related to SSH key parsing and validation
- SSHConnectionError: Errors during SSH connection establishment
- SSHConfigurationError: Errors in SSH configuration and policies
- SSHCommandError: Errors during command execution

Security Considerations:
- Exception messages should never contain sensitive data (keys, passwords)
- Error context is designed for logging without information leakage
- All exceptions inherit from base Exception for proper error handling

Usage:
    from backend.app.services.ssh.exceptions import SSHKeyError, SSHConnectionError

    try:
        key = parse_ssh_key(key_content)
    except SSHKeyError as e:
        logger.error(f"Key parsing failed: {e}")
        raise HTTPException(status_code=400, detail="Invalid SSH key format")
"""

from typing import Optional


class SSHKeyError(Exception):
    """
    Custom exception for SSH key related errors.

    Raised when SSH key operations fail, including:
    - Key parsing failures (invalid format, unsupported algorithm)
    - Key validation failures (encrypted without passphrase)
    - Key security assessment failures

    Attributes:
        message: Human-readable error description
        key_type: The detected or expected key type (if known)
        details: Additional error context for debugging

    Example:
        >>> try:
        ...     key = parse_ssh_key(invalid_content)
        ... except SSHKeyError as e:
        ...     logger.error(f"Key error: {e}")
        ...     # Handle gracefully without exposing key content
    """

    def __init__(
        self,
        message: str,
        key_type: Optional[str] = None,
        details: Optional[str] = None,
    ) -> None:
        """
        Initialize SSH key error.

        Args:
            message: Human-readable error description
            key_type: The key type involved (rsa, ed25519, etc.)
            details: Additional context for debugging
        """
        self.message = message
        self.key_type = key_type
        self.details = details
        super().__init__(self.message)

    def __str__(self) -> str:
        """Return string representation of the error."""
        if self.key_type:
            return f"{self.message} (key_type: {self.key_type})"
        return self.message

    def __repr__(self) -> str:
        """Return detailed representation for debugging."""
        return f"SSHKeyError(message={self.message!r}, " f"key_type={self.key_type!r}, details={self.details!r})"


class SSHConnectionError(Exception):
    """
    Custom exception for SSH connection errors.

    Raised when SSH connection operations fail, including:
    - Network connectivity issues (timeout, refused, unreachable)
    - Authentication failures (wrong credentials, key rejected)
    - SSH protocol errors (banner, key exchange, version mismatch)

    Attributes:
        message: Human-readable error description
        hostname: Target hostname or IP address
        port: Target SSH port
        error_type: Categorized error type for handling

    Error Types:
        - auth_failed: Authentication credentials rejected
        - timeout: Connection timed out
        - refused: Connection actively refused
        - unreachable: Network path not available
        - protocol_error: SSH protocol negotiation failed

    Example:
        >>> try:
        ...     result = ssh_service.connect(host)
        ... except SSHConnectionError as e:
        ...     if e.error_type == "timeout":
        ...         # Retry with longer timeout
        ...     else:
        ...         logger.error(f"Connection failed: {e}")
    """

    def __init__(
        self,
        message: str,
        hostname: Optional[str] = None,
        port: Optional[int] = None,
        error_type: Optional[str] = None,
    ) -> None:
        """
        Initialize SSH connection error.

        Args:
            message: Human-readable error description
            hostname: Target hostname or IP
            port: Target SSH port (default 22)
            error_type: Categorized error type
        """
        self.message = message
        self.hostname = hostname
        self.port = port
        self.error_type = error_type
        super().__init__(self.message)

    def __str__(self) -> str:
        """Return string representation of the error."""
        if self.hostname:
            target = f"{self.hostname}:{self.port or 22}"
            return f"{self.message} (target: {target})"
        return self.message

    def __repr__(self) -> str:
        """Return detailed representation for debugging."""
        return (
            f"SSHConnectionError(message={self.message!r}, "
            f"hostname={self.hostname!r}, port={self.port!r}, "
            f"error_type={self.error_type!r})"
        )


class SSHConfigurationError(Exception):
    """
    Custom exception for SSH configuration errors.

    Raised when SSH configuration operations fail, including:
    - Invalid policy settings
    - Malformed trusted network ranges
    - Database persistence failures for settings

    Attributes:
        message: Human-readable error description
        setting_key: The configuration setting involved
        setting_value: The invalid value (sanitized)

    Example:
        >>> try:
        ...     ssh_service.set_ssh_policy("invalid_policy")
        ... except SSHConfigurationError as e:
        ...     logger.warning(f"Invalid configuration: {e}")
    """

    def __init__(
        self,
        message: str,
        setting_key: Optional[str] = None,
        setting_value: Optional[str] = None,
    ) -> None:
        """
        Initialize SSH configuration error.

        Args:
            message: Human-readable error description
            setting_key: The configuration key involved
            setting_value: The value that caused the error
        """
        self.message = message
        self.setting_key = setting_key
        self.setting_value = setting_value
        super().__init__(self.message)

    def __str__(self) -> str:
        """Return string representation of the error."""
        if self.setting_key:
            return f"{self.message} (setting: {self.setting_key})"
        return self.message

    def __repr__(self) -> str:
        """Return detailed representation for debugging."""
        return f"SSHConfigurationError(message={self.message!r}, " f"setting_key={self.setting_key!r})"


class SSHCommandError(Exception):
    """
    Custom exception for SSH command execution errors.

    Raised when command execution over SSH fails, including:
    - Command timeout
    - Channel errors
    - Execution failures (non-zero exit code is NOT an error)

    Note: A command returning non-zero exit code is NOT an error.
    This exception is for execution infrastructure failures only.

    Attributes:
        message: Human-readable error description
        command: The command that failed (truncated for security)
        hostname: Target host where command was executed
        duration: How long before failure occurred

    Example:
        >>> try:
        ...     result = ssh_service.execute_command("long_running_cmd", timeout=10)
        ... except SSHCommandError as e:
        ...     if "timeout" in str(e).lower():
        ...         logger.warning(f"Command timed out: {e}")
    """

    def __init__(
        self,
        message: str,
        command: Optional[str] = None,
        hostname: Optional[str] = None,
        duration: Optional[float] = None,
    ) -> None:
        """
        Initialize SSH command error.

        Args:
            message: Human-readable error description
            command: The command that failed (will be truncated)
            hostname: Target host
            duration: Execution time before failure
        """
        self.message = message
        # Truncate command to prevent log injection and sensitive data exposure
        self.command = command[:100] + "..." if command and len(command) > 100 else command
        self.hostname = hostname
        self.duration = duration
        super().__init__(self.message)

    def __str__(self) -> str:
        """Return string representation of the error."""
        parts = [self.message]
        if self.hostname:
            parts.append(f"host: {self.hostname}")
        if self.duration is not None:
            parts.append(f"duration: {self.duration:.2f}s")
        return " | ".join(parts)

    def __repr__(self) -> str:
        """Return detailed representation for debugging."""
        return f"SSHCommandError(message={self.message!r}, " f"hostname={self.hostname!r}, duration={self.duration!r})"


__all__ = [
    "SSHKeyError",
    "SSHConnectionError",
    "SSHConfigurationError",
    "SSHCommandError",
]
