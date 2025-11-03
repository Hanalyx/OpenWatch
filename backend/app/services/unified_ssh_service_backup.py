"""
Unified SSH Service for OpenWatch

Provides centralized SSH connection management across all OpenWatch services
with consistent security policies, comprehensive audit logging, and
automation-friendly host key handling.
"""

import json
import logging
import os
import socket
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import paramiko
from paramiko import SSHClient, SSHException

from .ssh_utils import SSHKeyError, SSHKeyValidationResult, format_validation_message, parse_ssh_key, validate_ssh_key

logger = logging.getLogger(__name__)


class SecurityWarningPolicy(paramiko.MissingHostKeyPolicy):
    """
    Secure middle-ground SSH host key policy for automation environments.

    Logs security warnings for unknown hosts but allows connections to proceed.
    This balances security (full audit trail) with operational requirements
    (automation doesn't fail on new hosts).

    Follows industry best practices similar to Ansible's approach.
    """

    def __init__(self, audit_callback=None):
        """
        Initialize policy with optional audit callback.

        Args:
            audit_callback: Optional function to call for audit logging
        """
        self.audit_callback = audit_callback

    def missing_host_key(self, client: SSHClient, hostname: str, key: paramiko.PKey) -> None:
        """
        Handle missing host key by logging warning and storing key.

        Args:
            client: SSH client instance
            hostname: Target hostname
            key: SSH host key
        """
        # Get key fingerprint for logging (with safe fallback)
        try:
            fingerprint = key.get_fingerprint().hex()
            key_type = key.get_name()
        except Exception:
            fingerprint = "unknown"
            key_type = "unknown"

        # Log security warning (safe logging)
        try:
            logger.warning(
                f"SSH_SECURITY_WARNING: Unknown host key for {hostname} "
                f"(type: {key_type}, fingerprint: {fingerprint}). "
                f"Connection allowed but logged for audit."
            )
        except Exception:
            # Even logging can fail in some environments, ensure connection continues
            pass

        # Store key for this session (safe operation)
        try:
            client.get_host_keys().add(hostname, key.get_name(), key)
        except Exception:
            # Don't let host key storage errors prevent connections
            pass


@dataclass
class SSHConnectionResult:
    """Result of SSH connection attempt with detailed information."""

    success: bool
    connection: Optional[SSHClient] = None
    error_message: Optional[str] = None
    error_type: Optional[str] = None
    host_key_fingerprint: Optional[str] = None
    auth_method_used: Optional[str] = None


@dataclass
class SSHCommandResult:
    """Result of SSH command execution."""

    success: bool
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    error_message: Optional[str] = None


class UnifiedSSHService:
    """
    Unified SSH service providing consistent connection handling across
    all OpenWatch services with comprehensive security and audit features.
    """

    def __init__(self, settings=None):
        """
        Initialize unified SSH service.

        Args:
            settings: Application settings object (optional)
        """
        self.settings = settings

        # Detect SSH strict mode from FIPS setting or environment
        self.ssh_strict_mode = self._detect_ssh_strict_mode()

        # SSH connection defaults
        self.default_timeout = 30
        self.default_banner_timeout = 30
        self.max_retries = 3 if not self.ssh_strict_mode else 1

        # Container-aware known_hosts path
        self.container_known_hosts_path = Path("/app/security/known_hosts")

        # Ensure SSH directory exists in container environment
        self._ensure_ssh_directory()

        logger.info(f"UnifiedSSHService initialized with ssh_strict_mode={self.ssh_strict_mode}")

    def _detect_ssh_strict_mode(self) -> bool:
        """
        Detect SSH strict mode based on FIPS setting and environment variables.

        Returns:
            bool: True if strict mode should be enabled
        """
        # Check FIPS mode from settings
        if self.settings and hasattr(self.settings, "fips_mode") and self.settings.fips_mode:
            logger.info("SSH strict mode enabled due to FIPS mode")
            return True

        # Check environment variable
        if os.getenv("OPENWATCH_SSH_STRICT_MODE", "false").lower() == "true":
            logger.info("SSH strict mode enabled via OPENWATCH_SSH_STRICT_MODE")
            return True

        return False

    def _ensure_ssh_directory(self) -> None:
        """
        Ensure SSH directories exist in container environment to prevent file not found errors.
        """
        try:
            # Ensure user SSH directory exists
            ssh_dir = Path.home() / ".ssh"
            ssh_dir.mkdir(parents=True, exist_ok=True)

            # Create empty known_hosts if it doesn't exist
            known_hosts_file = ssh_dir / "known_hosts"
            if not known_hosts_file.exists():
                known_hosts_file.touch()
                logger.debug(f"Created empty known_hosts file: {known_hosts_file}")

            # Ensure container security directory exists
            security_dir = Path("/app/security")
            security_dir.mkdir(parents=True, exist_ok=True)

            # Create container known_hosts if it doesn't exist
            if not self.container_known_hosts_path.exists():
                self.container_known_hosts_path.touch()
                logger.debug(f"Created empty container known_hosts: {self.container_known_hosts_path}")

        except Exception as e:
            logger.debug(f"Could not ensure SSH directory setup (non-critical): {e}")

    def _get_host_key_policy(self) -> paramiko.MissingHostKeyPolicy:
        """
        Get appropriate host key policy based on environment configuration.

        Returns:
            paramiko.MissingHostKeyPolicy: Policy instance
        """
        # Check for explicit environment overrides
        if os.getenv("OPENWATCH_STRICT_SSH", "false").lower() == "true":
            logger.info("Using RejectPolicy due to OPENWATCH_STRICT_SSH")
            return paramiko.RejectPolicy()

        if os.getenv("OPENWATCH_PERMISSIVE_SSH", "false").lower() == "true":
            logger.info("Using AutoAddPolicy due to OPENWATCH_PERMISSIVE_SSH")
            return paramiko.AutoAddPolicy()

        # Use SecurityWarningPolicy as default (automation-friendly)
        logger.debug("Using SecurityWarningPolicy (default automation-friendly)")
        return SecurityWarningPolicy(audit_callback=self._audit_host_key_event)

    def _load_container_host_keys(self, ssh_client: SSHClient) -> None:
        """
        Load host keys from container-persistent storage.

        Args:
            ssh_client: SSH client to load keys into
        """
        keys_loaded = False

        # Skip loading host keys entirely when not in strict mode
        # This prevents file not found errors when ssh_strict_mode is false
        if not self.ssh_strict_mode:
            logger.debug("SSH strict mode disabled - skipping host key loading")
            return

        # Try to load system host keys if available
        try:
            ssh_client.load_system_host_keys()
            keys_loaded = True
            logger.debug("Loaded system host keys")
        except Exception as e:
            logger.debug(f"Could not load system host keys: {e}")

        # Try to load user host keys if available (only if file exists)
        try:
            user_known_hosts = os.path.expanduser("~/.ssh/known_hosts")
            if os.path.exists(user_known_hosts):
                ssh_client.load_host_keys(user_known_hosts)
                keys_loaded = True
                logger.debug("Loaded user known_hosts")
            else:
                logger.debug("User known_hosts file does not exist")
        except Exception as e:
            logger.debug(f"Could not load user host keys: {e}")

        # Try to load container-persistent host keys if available
        try:
            if self.container_known_hosts_path.exists():
                ssh_client.load_host_keys(str(self.container_known_hosts_path))
                keys_loaded = True
                logger.debug(f"Loaded container host keys from {self.container_known_hosts_path}")
            else:
                logger.debug("Container known_hosts file does not exist yet")
        except Exception as e:
            logger.debug(f"Could not load container host keys: {e}")

        if not keys_loaded:
            logger.info("No known_hosts files found - will accept new host keys")

    def _audit_host_key_event(self, hostname: str, event_type: str, details: Dict[str, Any]) -> None:
        """
        Audit host key events for compliance logging.

        Args:
            hostname: Target hostname
            event_type: Type of event (e.g., 'unknown_host_key')
            details: Additional event details
        """
        audit_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "ssh_host_key_event",
            "hostname": hostname,
            "ssh_strict_mode": self.ssh_strict_mode,
            "host_key_event_type": event_type,
            "details": details,
        }
        logger.info(f"SSH_HOST_KEY_AUDIT: {json.dumps(audit_entry)}")

    def audit_ssh_connection(
        self,
        hostname: str,
        username: str,
        service_name: str,
        success: bool,
        error_message: Optional[str] = None,
        auth_method: Optional[str] = None,
        additional_info: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log SSH connection attempts for compliance and audit purposes.

        Args:
            hostname: Target hostname
            username: SSH username
            service_name: Name of calling service
            success: Whether connection succeeded
            error_message: Error message if failed
            auth_method: Authentication method used
            additional_info: Additional information to log
        """
        audit_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": "ssh_connection",
            "service": service_name,
            "target_host": hostname,
            "username": username,
            "success": success,
            "error": error_message,
            "auth_method": auth_method,
            "ssh_strict_mode": self.ssh_strict_mode,
        }

        # Add additional info if provided
        if additional_info:
            audit_entry.update(additional_info)

        logger.info(f"SSH_AUDIT: {json.dumps(audit_entry)}")

    def connect_with_credentials(
        self,
        hostname: str,
        port: int,
        username: str,
        auth_method: str,
        credential: str,
        service_name: str,
        timeout: Optional[int] = None,
    ) -> SSHConnectionResult:
        """
        Establish SSH connection using specified credentials and authentication method.

        Args:
            hostname: Target hostname or IP address
            port: SSH port (typically 22)
            username: SSH username
            auth_method: Authentication method ('password', 'ssh-key', 'ssh_key')
            credential: Password or SSH private key content
            service_name: Name of calling service for audit logging
            timeout: Connection timeout (uses default if None)

        Returns:
            SSHConnectionResult: Connection result with details
        """
        connection_timeout = timeout or self.default_timeout

        # Validate inputs
        if not hostname or not username or not credential:
            error_msg = "Missing required connection parameters"
            self.audit_ssh_connection(
                hostname=hostname or "unknown",
                username=username or "unknown",
                service_name=service_name,
                success=False,
                error_message=error_msg,
                auth_method=auth_method,
            )
            return SSHConnectionResult(success=False, error_message=error_msg, error_type="invalid_parameters")

        # Validate SSH key if using key authentication
        if auth_method in ["ssh-key", "ssh_key"]:
            validation_result = validate_ssh_key(credential)
            if not validation_result.is_valid:
                error_msg = f"Invalid SSH key: {validation_result.error_message}"
                self.audit_ssh_connection(
                    hostname=hostname,
                    username=username,
                    service_name=service_name,
                    success=False,
                    error_message=error_msg,
                    auth_method=auth_method,
                )
                return SSHConnectionResult(success=False, error_message=error_msg, error_type="invalid_ssh_key")

        # Attempt connection with retries
        last_error = None
        for attempt in range(self.max_retries):
            try:
                # Create SSH client
                ssh = SSHClient()

                # Set host key policy
                ssh.set_missing_host_key_policy(self._get_host_key_policy())

                # Load host keys
                self._load_container_host_keys(ssh)

                # Connection parameters
                connect_kwargs = {
                    "hostname": hostname,
                    "port": port,
                    "username": username,
                    "timeout": connection_timeout,
                    "banner_timeout": self.default_banner_timeout,
                }

                # Add authentication-specific parameters
                if auth_method == "password":
                    connect_kwargs["password"] = credential
                elif auth_method in ["ssh-key", "ssh_key"]:
                    # Parse SSH key using unified parser
                    try:
                        pkey = parse_ssh_key(credential)
                        connect_kwargs["pkey"] = pkey
                    except SSHKeyError as e:
                        error_msg = f"SSH key parsing failed: {str(e)}"
                        self.audit_ssh_connection(
                            hostname=hostname,
                            username=username,
                            service_name=service_name,
                            success=False,
                            error_message=error_msg,
                            auth_method=auth_method,
                        )
                        return SSHConnectionResult(
                            success=False,
                            error_message=error_msg,
                            error_type="ssh_key_parse_error",
                        )
                else:
                    error_msg = f"Unsupported authentication method: {auth_method}"
                    self.audit_ssh_connection(
                        hostname=hostname,
                        username=username,
                        service_name=service_name,
                        success=False,
                        error_message=error_msg,
                        auth_method=auth_method,
                    )
                    return SSHConnectionResult(
                        success=False,
                        error_message=error_msg,
                        error_type="unsupported_auth_method",
                    )

                # Establish connection
                ssh.connect(**connect_kwargs)

                # Get host key fingerprint for logging
                host_key_fingerprint = None
                try:
                    transport = ssh.get_transport()
                    if transport:
                        remote_server_key = transport.get_remote_server_key()
                        if remote_server_key:
                            host_key_fingerprint = remote_server_key.get_fingerprint().hex()
                except Exception as e:
                    logger.debug(f"Could not get host key fingerprint: {e}")

                # Log successful connection
                self.audit_ssh_connection(
                    hostname=hostname,
                    username=username,
                    service_name=service_name,
                    success=True,
                    auth_method=auth_method,
                    additional_info={
                        "host_key_fingerprint": host_key_fingerprint,
                        "attempt": attempt + 1,
                    },
                )

                return SSHConnectionResult(
                    success=True,
                    connection=ssh,
                    host_key_fingerprint=host_key_fingerprint,
                    auth_method_used=auth_method,
                )

            except paramiko.AuthenticationException as e:
                last_error = f"SSH authentication failed: {str(e)}"
                error_type = "authentication_failed"

            except paramiko.SSHException as e:
                last_error = f"SSH connection error: {str(e)}"
                error_type = "ssh_error"

            except socket.timeout:
                last_error = f"SSH connection timeout after {connection_timeout}s"
                error_type = "timeout"

            except ConnectionRefusedError:
                last_error = f"SSH connection refused to {hostname}:{port}"
                error_type = "connection_refused"

            except Exception as e:
                last_error = f"Unexpected SSH error: {str(e)}"
                error_type = "unexpected_error"

            # Log retry attempt if not the last one
            if attempt < self.max_retries - 1:
                logger.debug(f"SSH connection attempt {attempt + 1} failed for {hostname}: {last_error}. Retrying...")

        # Log final failure
        self.audit_ssh_connection(
            hostname=hostname,
            username=username,
            service_name=service_name,
            success=False,
            error_message=last_error,
            auth_method=auth_method,
            additional_info={"total_attempts": self.max_retries},
        )

        return SSHConnectionResult(success=False, error_message=last_error, error_type=error_type)

    def execute_command(
        self, ssh_connection: SSHClient, command: str, timeout: Optional[int] = None
    ) -> SSHCommandResult:
        """
        Execute a single command via SSH connection.

        Args:
            ssh_connection: Established SSH connection
            command: Command to execute
            timeout: Command timeout (uses default if None)

        Returns:
            SSHCommandResult: Command execution result
        """
        command_timeout = timeout or self.default_timeout

        try:
            # Execute command
            stdin, stdout, stderr = ssh_connection.exec_command(command, timeout=command_timeout)

            # Get output
            stdout_data = stdout.read().decode("utf-8", errors="replace").strip()
            stderr_data = stderr.read().decode("utf-8", errors="replace").strip()
            exit_code = stdout.channel.recv_exit_status()

            return SSHCommandResult(
                success=(exit_code == 0),
                stdout=stdout_data,
                stderr=stderr_data,
                exit_code=exit_code,
            )

        except socket.timeout:
            return SSHCommandResult(
                success=False,
                error_message=f"Command timeout after {command_timeout}s",
                exit_code=-1,
            )
        except Exception as e:
            return SSHCommandResult(
                success=False,
                error_message=f"Command execution error: {str(e)}",
                exit_code=-1,
            )

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
        Execute minimal system discovery commands to reduce reconnaissance footprint.

        This replaces the original 7-command system discovery with just 2 essential
        checks that are required for SCAP compliance scanning.

        Args:
            hostname: Target hostname or IP address
            port: SSH port
            username: SSH username
            auth_method: Authentication method
            credential: Password or SSH key
            service_name: Name of calling service

        Returns:
            Dict containing essential system information
        """
        # Essential commands for SCAP scanning (reduced from 7 to 2)
        essential_commands = {
            "os_family": (
                "[ -f /etc/redhat-release ] && echo 'redhat' || "
                "([ -f /etc/debian_version ] && echo 'debian' || echo 'unknown')"
            ),
            "oscap_available": "command -v oscap >/dev/null 2>&1 && echo 'yes' || echo 'no'",
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
        results = {}
        ssh = connection_result.connection

        try:
            for key, command in essential_commands.items():
                logger.debug(f"Executing minimal discovery command '{key}': {command}")

                command_result = self.execute_command(ssh, command)

                if command_result.success:
                    results[key] = command_result.stdout
                    logger.debug(f"Command '{key}' result: {command_result.stdout}")
                else:
                    results[key] = "unknown"
                    logger.warning(f"Command '{key}' failed: {command_result.error_message}")

            # Log successful minimal discovery
            logger.info(f"Minimal system discovery completed for {hostname}: {results}")

        except Exception as e:
            logger.error(f"Error during minimal system discovery for {hostname}: {e}")
            results["error"] = str(e)

        finally:
            # Always close the SSH connection
            try:
                ssh.close()
            except Exception as e:
                logger.debug(f"Error closing SSH connection to {hostname}: {e}")

        return results


# Global instance for service usage
unified_ssh_service = UnifiedSSHService()
