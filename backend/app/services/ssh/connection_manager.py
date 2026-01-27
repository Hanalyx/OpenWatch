"""
SSH Connection Manager Module

Provides centralized SSH connection management with multiple authentication
methods, comprehensive error handling, and audit logging.

This module handles:
- SSH connection establishment (password, key, agent, combined auth)
- Command execution over SSH with timeout handling
- Connection state management and cleanup
- Detailed error categorization for troubleshooting

Authentication Methods:
    - password: Username/password authentication
    - key/ssh_key/ssh-key: Private key authentication
    - agent: SSH agent forwarding
    - both: Try SSH key first, fallback to password

Connection Flow:
    1. Create SSHClient with configured host key policy
    2. Load system and user known hosts
    3. Attempt authentication with specified method
    4. Return connection result with fingerprint and status
    5. Execute commands and handle results
    6. Clean up connection on completion or error

Usage:
    from app.services.ssh.connection_manager import SSHConnectionManager

    manager = SSHConnectionManager(db)

    # Connect with password
    result = manager.connect_with_credentials(
        hostname="server.example.com",
        port=22,
        username="admin",
        auth_method="password",
        credential="secret123",
        service_name="scan_service"
    )

    if result.success:
        cmd_result = manager.execute_command_advanced(
            result.connection,
            "oscap --version",
            timeout=30
        )
        print(cmd_result.stdout)
        result.connection.close()

Security Notes:
    - Credentials are never logged (only auth method and success/failure)
    - Host key verification follows configured security policy
    - Connection timeouts prevent hanging on unreachable hosts
    - All operations logged for audit compliance

References:
    - OpenSSH Protocol: RFC 4252 (Authentication Protocol)
    - NIST SP 800-53 IA-2: Identification and Authentication
"""

import asyncio
import errno
import io
import logging
import socket
from datetime import datetime
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, Dict, Optional

import paramiko
from paramiko import SSHClient

from .exceptions import SSHKeyError
from .key_parser import parse_ssh_key
from .models import SSHCommandResult, SSHConnectionResult

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


class SSHConnectionManager:
    """
    Manages SSH connections with multiple authentication methods.

    This class provides a high-level interface for establishing SSH
    connections with various authentication methods and executing
    commands. It integrates with the configuration manager for
    security policies and the known hosts manager for host verification.

    The manager supports:
    - Multiple authentication methods with automatic fallback
    - Configurable timeouts for connection and commands
    - Detailed error categorization for troubleshooting
    - Debug mode for paramiko logging
    - Async command execution for non-blocking operations

    Attributes:
        db: SQLAlchemy database session for configuration access
        client: Currently active SSHClient (for stateful connections)
        current_host: Currently connected host (for stateful connections)
        _debug_mode: Whether paramiko debug logging is enabled

    Example:
        >>> from app.services.ssh.connection_manager import SSHConnectionManager
        >>> manager = SSHConnectionManager(db)
        >>>
        >>> # Connect with SSH key
        >>> result = manager.connect_with_credentials(
        ...     hostname="192.168.1.100",
        ...     port=22,
        ...     username="root",
        ...     auth_method="ssh_key",
        ...     credential=private_key_content,
        ...     service_name="compliance_scan"
        ... )
        >>>
        >>> if result.success:
        ...     print(f"Connected! Fingerprint: {result.host_key_fingerprint}")
        ...     result.connection.close()
    """

    # Supported authentication methods
    # Maps various spellings to canonical internal method
    # NOTE: These are method identifiers, not actual secrets
    SUPPORTED_AUTH_METHODS = {
        "password": "password",  # pragma: allowlist secret
        "key": "private_key",
        "ssh_key": "private_key",
        "ssh-key": "private_key",
        "agent": "ssh_agent",
        "both": "both",
    }

    def __init__(self, db: Optional["Session"] = None) -> None:
        """
        Initialize the SSH connection manager.

        Args:
            db: Optional SQLAlchemy session for configuration access.
                If not provided, default security settings are used.
        """
        self.db = db
        self.client: Optional[SSHClient] = None
        self.current_host: Optional[Any] = None
        self._debug_mode = False
        self._config_manager = None

    def _get_config_manager(self) -> Any:
        """
        Lazy-load configuration manager to avoid circular imports.

        Returns:
            SSHConfigManager instance
        """
        if self._config_manager is None:
            from .config_manager import SSHConfigManager

            self._config_manager = SSHConfigManager(self.db)
        return self._config_manager

    def enable_debug_mode(self) -> None:
        """
        Enable detailed paramiko SSH debugging.

        When enabled, paramiko writes detailed debug logs to
        /tmp/paramiko_debug.log. This is useful for troubleshooting
        connection issues but should not be enabled in production.
        """
        self._debug_mode = True
        # Enable paramiko debug logging to file
        paramiko.util.log_to_file("/tmp/paramiko_debug.log")
        logger.info("SSH debug mode enabled - detailed logs will be written " "to /tmp/paramiko_debug.log")

    def disable_debug_mode(self) -> None:
        """Disable SSH debugging."""
        self._debug_mode = False
        logger.info("SSH debug mode disabled")

    def connect_with_credentials(
        self,
        hostname: str,
        port: int,
        username: str,
        auth_method: str,
        credential: str,
        service_name: str,
        timeout: Optional[int] = None,
        password: Optional[str] = None,
    ) -> SSHConnectionResult:
        """
        Establish SSH connection with specified authentication method.

        This is the primary method for establishing SSH connections. It
        supports multiple authentication methods and provides detailed
        error information for troubleshooting.

        Args:
            hostname: Target hostname or IP address
            port: SSH port (typically 22)
            username: Username for authentication
            auth_method: Authentication method to use. One of:
                - "password": Use password authentication
                - "key", "ssh_key", "ssh-key": Use private key authentication
                - "agent": Use SSH agent for authentication
                - "both": Try key first, fallback to password
            credential: Authentication credential:
                - For "password": The password string
                - For "key"/"ssh_key": Private key content (PEM format)
                - For "agent": Not used (can be empty)
                - For "both": Private key content
            service_name: Name of calling service (for logging)
            timeout: Connection timeout in seconds (default: 30)
            password: Additional password for "both" auth method fallback

        Returns:
            SSHConnectionResult containing:
                - success: Whether connection succeeded
                - connection: Active SSHClient if successful
                - host_key_fingerprint: Remote host's key fingerprint
                - auth_method_used: Actual auth method that succeeded
                - error_message: Description if connection failed
                - error_type: Category of error if failed

        Error Types:
            - auth_failed: Authentication credentials rejected
            - key_error: Private key parsing failed
            - ssh_error: SSH protocol error
            - timeout: Connection timed out
            - connection_error: Network/socket error

        Example:
            >>> # Password authentication  # pragma: allowlist secret
            >>> result = manager.connect_with_credentials(
            ...     hostname="server.example.com",
            ...     port=22,
            ...     username="admin",
            ...     auth_method="password",
            ...     credential="secretpass",  # pragma: allowlist secret
            ...     service_name="discovery"
            ... )
            >>>
            >>> # SSH key with password fallback  # pragma: allowlist secret
            >>> result = manager.connect_with_credentials(
            ...     hostname="server.example.com",
            ...     port=22,
            ...     username="admin",
            ...     auth_method="both",
            ...     credential=private_key_content,
            ...     password="backup_password",  # pragma: allowlist secret
            ...     service_name="scan"
            ... )
        """
        start_time = datetime.utcnow()
        client = None
        auth_method_used = None

        try:
            client = SSHClient()
            config_manager = self._get_config_manager()
            config_manager.configure_ssh_client(client, hostname)

            # Set connection timeout
            connect_timeout = timeout or 30

            if self._debug_mode:
                logger.info("[DEBUG] SSH connection attempt to %s:%d as %s", hostname, port, username)
                logger.info("[DEBUG] Auth method: %s, Timeout: %ds", auth_method, connect_timeout)
                logger.info("[DEBUG] Service: %s", service_name)

            # Handle different authentication methods
            if auth_method == "both":
                # Try SSH key first, fallback to password
                client, auth_method_used = self._connect_with_both(
                    client=client,
                    hostname=hostname,
                    port=port,
                    username=username,
                    private_key=credential,
                    password=password,
                    timeout=connect_timeout,
                )
                if client is None:
                    return SSHConnectionResult(
                        success=False,
                        error_message=("Both SSH key and password authentication " f"failed for {username}@{hostname}"),
                        error_type="auth_failed",
                    )

            elif auth_method == "password":
                client.connect(
                    hostname=hostname,
                    port=port,
                    username=username,
                    password=credential,
                    timeout=connect_timeout,
                    allow_agent=False,
                    look_for_keys=False,
                )
                auth_method_used = "password"

            elif auth_method in ["key", "ssh_key", "ssh-key"]:
                # Parse and use private key
                try:
                    pkey = parse_ssh_key(credential)
                    logger.debug(
                        "SSH key parsed successfully - Type: %s, Bits: %d",
                        pkey.get_name(),
                        pkey.get_bits(),
                    )

                    client.connect(
                        hostname=hostname,
                        port=port,
                        username=username,
                        pkey=pkey,
                        timeout=connect_timeout,
                        allow_agent=False,
                        look_for_keys=False,
                    )
                    auth_method_used = "private_key"

                except SSHKeyError as e:
                    logger.error("SSH key parsing failed: %s", e)
                    return SSHConnectionResult(
                        success=False,
                        error_message=f"Invalid private key: {e}",
                        error_type="key_error",
                    )

            elif auth_method == "agent":
                client.connect(
                    hostname=hostname,
                    port=port,
                    username=username,
                    timeout=connect_timeout,
                    allow_agent=True,
                    look_for_keys=True,
                )
                auth_method_used = "ssh_agent"

            else:
                return SSHConnectionResult(
                    success=False,
                    error_message=(
                        f"Unsupported authentication method: {auth_method}. "
                        "Supported: password, key, ssh_key, ssh-key, agent, both"
                    ),
                    error_type="auth_error",
                )

            # Extract host key fingerprint for audit/verification
            transport = client.get_transport()
            host_key = transport.get_remote_server_key()
            host_key_fingerprint = host_key.get_fingerprint().hex() if host_key else None

            # Log successful connection (without credentials)
            duration = (datetime.utcnow() - start_time).total_seconds()
            logger.info(
                "SSH connection successful: %s -> %s@%s:%d " "(auth: %s, duration: %.2fs)",
                service_name,
                username,
                hostname,
                port,
                auth_method_used,
                duration,
            )

            return SSHConnectionResult(
                success=True,
                connection=client,
                host_key_fingerprint=host_key_fingerprint,
                auth_method_used=auth_method_used,
            )

        except paramiko.AuthenticationException as e:
            if client:
                client.close()
            return self._handle_auth_exception(e, username, hostname, port, auth_method)

        except paramiko.SSHException as e:
            if client:
                client.close()
            return self._handle_ssh_exception(e, hostname, port)

        except socket.timeout:
            if client:
                client.close()
            logger.warning("SSH connection timeout to %s:%d after %ds", hostname, port, connect_timeout)
            return SSHConnectionResult(
                success=False,
                error_message=(f"Connection timeout to {hostname}:{port} " f"after {connect_timeout}s"),
                error_type="timeout",
            )

        except socket.error as e:
            if client:
                client.close()
            return self._handle_socket_error(e, hostname, port)

        except Exception as e:
            if client:
                client.close()
            logger.error("Unexpected SSH connection error: %s: %s", type(e).__name__, e)
            logger.debug("Full exception details:", exc_info=True)
            return SSHConnectionResult(
                success=False,
                error_message=f"Connection failed: {type(e).__name__}: {e}",
                error_type="connection_error",
            )

    def _connect_with_both(
        self,
        client: SSHClient,
        hostname: str,
        port: int,
        username: str,
        private_key: Optional[str],
        password: Optional[str],
        timeout: int,
    ) -> tuple:
        """
        Attempt connection with SSH key first, fallback to password.

        Args:
            client: Configured SSHClient
            hostname: Target hostname
            port: SSH port
            username: Username
            private_key: Private key content (optional)
            password: Password for fallback (optional)
            timeout: Connection timeout

        Returns:
            Tuple of (connected_client or None, auth_method_used or None)
        """
        logger.info(
            "Credential has 'both' auth method, attempting SSH key first " "for %s@%s",
            username,
            hostname,
        )

        # Try SSH key first (faster, more secure)
        if private_key:
            try:
                pkey = parse_ssh_key(private_key)
                logger.debug(
                    "SSH key parsed successfully - Type: %s, Bits: %d",
                    pkey.get_name(),
                    pkey.get_bits(),
                )

                try:
                    client.connect(
                        hostname=hostname,
                        port=port,
                        username=username,
                        pkey=pkey,
                        timeout=timeout,
                        allow_agent=False,
                        look_for_keys=False,
                    )
                    logger.info(
                        "SSH key authentication successful for %s@%s (both method)",
                        username,
                        hostname,
                    )
                    return client, "private_key"

                except paramiko.AuthenticationException as e:
                    logger.warning("SSH key authentication failed for %s@%s: %s", username, hostname, e)
                    # Close failed connection before retry
                    if client:
                        client.close()
                        client = None

            except SSHKeyError as e:
                logger.warning("SSH key parsing failed for %s@%s: %s", username, hostname, e)
                # Will try password below

        # Fallback to password if SSH key didn't succeed
        if not client or not client.get_transport() or not client.get_transport().is_active():
            if password:
                logger.info("Falling back to password authentication for %s@%s", username, hostname)
                if not client:
                    client = SSHClient()
                    config_manager = self._get_config_manager()
                    config_manager.configure_ssh_client(client, hostname)

                try:
                    client.connect(
                        hostname=hostname,
                        port=port,
                        username=username,
                        password=password,
                        timeout=timeout,
                        allow_agent=False,
                        look_for_keys=False,
                    )
                    logger.info(
                        "Password authentication successful for %s@%s " "(both method fallback)",
                        username,
                        hostname,
                    )
                    return client, "password"

                except paramiko.AuthenticationException:
                    if client:
                        client.close()
                    logger.error(
                        "Both SSH key and password authentication failed " "for %s@%s",
                        username,
                        hostname,
                    )
                    return None, None
            else:
                if client:
                    client.close()
                logger.error("SSH key authentication failed and no password provided " "for fallback (both method)")
                return None, None

        return client, None

    def _handle_auth_exception(
        self,
        exception: paramiko.AuthenticationException,
        username: str,
        hostname: str,
        port: int,
        auth_method: str,
    ) -> SSHConnectionResult:
        """
        Handle authentication exception with detailed error message.

        Args:
            exception: The authentication exception
            username: Username that failed
            hostname: Target hostname
            port: SSH port
            auth_method: Auth method that was attempted

        Returns:
            SSHConnectionResult with error details
        """
        logger.error(
            "SSH authentication failed for %s@%s:%d using %s auth",
            username,
            hostname,
            port,
            auth_method,
        )
        logger.debug("AuthenticationException details: %s", exception)

        # Determine specific authentication failure reason
        error_details = str(exception).lower()
        if "no authentication methods available" in error_details:
            specific_error = "No authentication methods accepted by server"
        elif "authentication failed" in error_details:
            specific_error = "Invalid credentials or key not accepted"
        elif "permission denied" in error_details:
            specific_error = "Permission denied (check username/key permissions)"
        else:
            specific_error = "Authentication failed"

        return SSHConnectionResult(
            success=False,
            error_message=f"{specific_error} for {username}@{hostname}",
            error_type="auth_failed",
        )

    def _handle_ssh_exception(
        self,
        exception: paramiko.SSHException,
        hostname: str,
        port: int,
    ) -> SSHConnectionResult:
        """
        Handle SSH protocol exception with detailed error message.

        Args:
            exception: The SSH exception
            hostname: Target hostname
            port: SSH port

        Returns:
            SSHConnectionResult with error details
        """
        logger.error("SSH connection error to %s:%d: %s", hostname, port, exception)

        # Provide more specific SSH error messages
        error_details = str(exception).lower()
        if "unable to connect" in error_details:
            specific_error = "Unable to establish SSH connection"
        elif "host key" in error_details:
            specific_error = "Host key verification failed"
        elif "banner" in error_details:
            specific_error = "SSH banner exchange failed"
        else:
            specific_error = f"SSH protocol error: {exception}"

        return SSHConnectionResult(
            success=False,
            error_message=specific_error,
            error_type="ssh_error",
        )

    def _handle_socket_error(
        self,
        exception: socket.error,
        hostname: str,
        port: int,
    ) -> SSHConnectionResult:
        """
        Handle socket error with detailed error message.

        Args:
            exception: The socket error
            hostname: Target hostname
            port: SSH port

        Returns:
            SSHConnectionResult with error details
        """
        logger.error("Socket error connecting to %s:%d: %s", hostname, port, exception)

        # Provide specific socket error messages
        if hasattr(exception, "errno"):
            if exception.errno == errno.ECONNREFUSED:
                specific_error = "Connection refused (SSH service may not be running)"
            elif exception.errno == errno.EHOSTUNREACH:
                specific_error = "No route to host (network unreachable)"
            elif exception.errno == errno.ETIMEDOUT:
                specific_error = "Connection timed out"
            else:
                specific_error = f"Network error (errno {exception.errno}): {exception}"
        else:
            specific_error = f"Network error: {exception}"

        return SSHConnectionResult(
            success=False,
            error_message=specific_error,
            error_type="connection_error",
        )

    def execute_command_advanced(
        self,
        ssh_connection: SSHClient,
        command: str,
        timeout: Optional[int] = None,
    ) -> SSHCommandResult:
        """
        Execute command with advanced result handling.

        Executes a command on an established SSH connection and returns
        detailed results including stdout, stderr, exit code, and duration.

        Args:
            ssh_connection: Active paramiko SSHClient connection
            command: Command string to execute
            timeout: Command timeout in seconds (default: 300/5 minutes)

        Returns:
            SSHCommandResult containing:
                - success: True if exit_code == 0
                - stdout: Command standard output
                - stderr: Command standard error
                - exit_code: Process exit code
                - duration: Execution time in seconds
                - error_message: Description if execution failed

        Example:
            >>> result = manager.execute_command_advanced(
            ...     connection,
            ...     "oscap --version",
            ...     timeout=30
            ... )
            >>> if result.success:
            ...     print(f"OSCAP version: {result.stdout}")
        """
        start_time = datetime.utcnow()
        command_timeout = timeout or 300  # 5 minute default for long operations

        try:
            # Execute command with timeout
            stdin, stdout, stderr = ssh_connection.exec_command(command, timeout=command_timeout)

            # Read output with error handling for encoding issues
            stdout_data = stdout.read().decode("utf-8", errors="replace").strip()
            stderr_data = stderr.read().decode("utf-8", errors="replace").strip()
            exit_code = stdout.channel.recv_exit_status()

            duration = (datetime.utcnow() - start_time).total_seconds()

            return SSHCommandResult(
                success=exit_code == 0,
                stdout=stdout_data,
                stderr=stderr_data,
                exit_code=exit_code,
                duration=duration,
            )

        except socket.timeout:
            return SSHCommandResult(
                success=False,
                error_message=f"Command timed out after {command_timeout} seconds",
            )
        except Exception as e:
            return SSHCommandResult(
                success=False,
                error_message=f"Command execution failed: {e}",
            )

    async def execute_command_async(
        self,
        host: Any,
        credentials: Any,
        command: str,
        timeout: int = 30,
    ) -> Any:
        """
        Async wrapper for SSH command execution.

        Creates a temporary SSH connection, executes command, and returns
        result. This is a compatibility layer for async code paths like
        readiness check modules.

        Args:
            host: Host model instance with hostname/ip_address
            credentials: CredentialData from AuthService with auth details
            command: Command to execute
            timeout: Command timeout in seconds

        Returns:
            SimpleNamespace with exit_code, stdout, stderr, success attributes

        Note:
            This method runs synchronous SSH operations in a thread pool
            executor to avoid blocking the async event loop.
        """

        def _execute_sync() -> Any:
            """Synchronous SSH execution in thread pool."""
            temp_client = paramiko.SSHClient()
            temp_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            try:
                # Build connection parameters
                hostname = getattr(host, "ip_address", None) or host.hostname
                port = getattr(host, "port", 22) or 22

                # Handle both enum and string values for auth_method
                auth_method_str = (
                    credentials.auth_method
                    if isinstance(credentials.auth_method, str)
                    else credentials.auth_method.value
                )

                if auth_method_str == "ssh_key" and credentials.private_key:
                    # Use SSH key authentication
                    key_file = io.StringIO(credentials.private_key)

                    # Try to determine key type and load
                    pkey = self._load_private_key(key_file)
                    if pkey is None:
                        return SimpleNamespace(exit_code=-1, stdout="", stderr="Failed to parse SSH key", success=False)

                    temp_client.connect(
                        hostname=hostname,
                        port=port,
                        username=credentials.username,
                        pkey=pkey,
                        timeout=timeout,
                        look_for_keys=False,
                        allow_agent=False,
                    )
                else:
                    # Use password authentication
                    temp_client.connect(
                        hostname=hostname,
                        port=port,
                        username=credentials.username,
                        password=credentials.password,
                        timeout=timeout,
                        look_for_keys=False,
                        allow_agent=False,
                    )

                # Execute command
                stdin, stdout, stderr = temp_client.exec_command(command, timeout=timeout)

                # Read output
                stdout_data = stdout.read().decode("utf-8", errors="ignore")
                stderr_data = stderr.read().decode("utf-8", errors="ignore")
                exit_code = stdout.channel.recv_exit_status()

                return SimpleNamespace(
                    exit_code=exit_code,
                    stdout=stdout_data,
                    stderr=stderr_data,
                    success=(exit_code == 0),
                )

            except Exception as e:
                logger.error("SSH command execution failed: %s", e)
                return SimpleNamespace(exit_code=-1, stdout="", stderr=str(e), success=False)
            finally:
                if temp_client:
                    temp_client.close()

        # Run synchronous SSH in thread pool to avoid blocking
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, _execute_sync)
        return result

    def _load_private_key(self, key_file: io.StringIO) -> Optional[paramiko.PKey]:
        """
        Attempt to load private key trying different key types.

        Args:
            key_file: StringIO containing private key content

        Returns:
            Loaded PKey or None if parsing fails
        """
        # Try RSA first (most common)
        try:
            return paramiko.RSAKey.from_private_key(key_file)
        except Exception:
            key_file.seek(0)

        # Try Ed25519 (modern, recommended)
        try:
            return paramiko.Ed25519Key.from_private_key(key_file)
        except Exception:
            key_file.seek(0)

        # Try ECDSA
        try:
            return paramiko.ECDSAKey.from_private_key(key_file)
        except Exception:
            key_file.seek(0)

        # Note: DSA keys are not supported (deprecated, insecure)
        return None

    def execute_minimal_system_check(
        self,
        hostname: str,
        port: int,
        username: str,
        auth_method: str,
        credential: str,
        service_name: str,
    ) -> Dict[str, Any]:
        """
        Execute minimal system discovery for SCAP scanning.

        Performs just 2 essential checks (reduced from 7) to minimize
        reconnaissance footprint while gathering required information
        for SCAP compliance scanning.

        Args:
            hostname: Target hostname or IP address
            port: SSH port
            username: SSH username
            auth_method: Authentication method
            credential: Password or SSH key
            service_name: Name of calling service

        Returns:
            Dict containing:
                - os_family: Operating system family (redhat, debian, unknown)
                - oscap_available: Whether oscap command is available
                - error: Error message if connection failed
                - error_type: Error category if connection failed

        Essential Checks:
            1. os_family: Determines which SCAP content to use
            2. oscap_available: Verifies scanning is possible
        """
        # Essential commands for SCAP scanning (reduced from 7 to 2)
        essential_commands = {
            "os_family": (
                "[ -f /etc/redhat-release ] && echo 'redhat' || "
                "([ -f /etc/debian_version ] && echo 'debian' || echo 'unknown')"
            ),
            "oscap_available": ("command -v oscap >/dev/null 2>&1 && echo 'yes' || echo 'no'"),
        }

        # Establish connection
        connection_result = self.connect_with_credentials(
            hostname=hostname,
            port=port,
            username=username,
            auth_method=auth_method,
            credential=credential,
            service_name=service_name,
        )

        if not connection_result.success:
            return {
                "error": connection_result.error_message,
                "error_type": connection_result.error_type,
                "commands_attempted": list(essential_commands.keys()),
            }

        # Execute essential commands
        results: Dict[str, Any] = {}
        ssh = connection_result.connection

        try:
            for key, command in essential_commands.items():
                logger.debug("Executing minimal discovery command '%s': %s", key, command)

                command_result = self.execute_command_advanced(ssh, command)

                if command_result.success:
                    results[key] = command_result.stdout
                    logger.debug("Command '%s' result: %s", key, command_result.stdout)
                else:
                    results[key] = "unknown"
                    logger.warning("Command '%s' failed: %s", key, command_result.error_message)

            # Log successful minimal discovery
            logger.info("Minimal system discovery completed for %s: %s", hostname, results)

        except Exception as e:
            logger.error("Error during minimal system discovery for %s: %s", hostname, e)
            results["error"] = str(e)

        finally:
            # Always close the SSH connection
            try:
                ssh.close()
            except Exception as e:
                logger.debug("Error closing SSH connection to %s: %s", hostname, e)

        return results


__all__ = [
    "SSHConnectionManager",
]
