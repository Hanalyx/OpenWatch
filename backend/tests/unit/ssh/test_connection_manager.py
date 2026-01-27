"""
Unit Tests for SSHConnectionManager

Tests the SSH connection management functionality including:
- Connection establishment with various authentication methods
- Command execution with timeout handling
- Error handling and categorization
- Debug mode functionality

These tests use mocked paramiko clients to isolate unit testing
from actual SSH connections.

Test Categories:
- Initialization tests: Verify proper setup
- connect_with_credentials tests: Authentication and connection
- execute_command_advanced tests: Command execution
- Error handling tests: Exception categorization
- Debug mode tests: Logging configuration

CLAUDE.md Compliance:
- Comprehensive docstrings on all test functions
- Type hints where applicable
- Defensive error handling verification
- Security-focused test cases
- No emojis in code

References:
- OpenSSH Protocol: RFC 4252 (Authentication Protocol)
- NIST SP 800-53 IA-2: Identification and Authentication
"""

import errno
import io
import socket
from datetime import datetime
from types import SimpleNamespace
from typing import Any, Optional
from unittest.mock import MagicMock, Mock, patch, PropertyMock

import paramiko
import pytest

# Import the class and models under test
from app.services.ssh.connection_manager import SSHConnectionManager
from app.services.ssh.models import SSHConnectionResult, SSHCommandResult


# =============================================================================
# Test Data Constants
# =============================================================================

# Sample SSH private key for testing (NOT a real key - for testing only)
SAMPLE_RSA_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7PcqK0cP4HRXAZ0UL
fake_key_content_for_testing_only_do_not_use
-----END RSA PRIVATE KEY-----"""

SAMPLE_ED25519_PRIVATE_KEY = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz
fake_key_content_for_testing_only_do_not_use
-----END OPENSSH PRIVATE KEY-----"""


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def mock_db_session() -> MagicMock:
    """
    Create a mock database session for isolated unit testing.

    Returns:
        MagicMock configured to behave like a SQLAlchemy Session
    """
    return MagicMock()


@pytest.fixture
def connection_manager(mock_db_session: MagicMock) -> SSHConnectionManager:
    """
    Create an SSHConnectionManager instance with mocked database.

    Args:
        mock_db_session: Mocked SQLAlchemy session

    Returns:
        SSHConnectionManager instance ready for testing
    """
    return SSHConnectionManager(db=mock_db_session)


@pytest.fixture
def connection_manager_no_db() -> SSHConnectionManager:
    """
    Create an SSHConnectionManager instance without a database session.

    Returns:
        SSHConnectionManager instance with db=None
    """
    return SSHConnectionManager(db=None)


@pytest.fixture
def mock_ssh_client() -> MagicMock:
    """
    Create a mock paramiko SSHClient.

    Returns:
        MagicMock configured to behave like paramiko.SSHClient
    """
    mock_client = MagicMock(spec=paramiko.SSHClient)
    mock_transport = MagicMock()
    mock_host_key = MagicMock()
    mock_host_key.get_fingerprint.return_value = b"abcdef1234567890"

    mock_transport.get_remote_server_key.return_value = mock_host_key
    mock_transport.is_active.return_value = True
    mock_client.get_transport.return_value = mock_transport

    return mock_client


# =============================================================================
# Initialization Tests
# =============================================================================


class TestSSHConnectionManagerInit:
    """Tests for SSHConnectionManager initialization."""

    def test_init_with_db_session(self, mock_db_session: MagicMock) -> None:
        """
        Verify manager initializes correctly with a database session.
        """
        manager = SSHConnectionManager(db=mock_db_session)

        assert manager.db is mock_db_session
        assert manager.client is None
        assert manager.current_host is None
        assert manager._debug_mode is False

    def test_init_without_db_session(self) -> None:
        """
        Verify manager initializes correctly without a database session.
        """
        manager = SSHConnectionManager(db=None)

        assert manager.db is None
        assert manager.client is None
        assert manager._debug_mode is False

    def test_supported_auth_methods_defined(self) -> None:
        """
        Verify SUPPORTED_AUTH_METHODS contains expected mappings.
        """
        expected_methods = {
            "password": "password",
            "key": "private_key",
            "ssh_key": "private_key",
            "ssh-key": "private_key",
            "agent": "ssh_agent",
            "both": "both",
        }

        assert SSHConnectionManager.SUPPORTED_AUTH_METHODS == expected_methods


# =============================================================================
# Debug Mode Tests
# =============================================================================


class TestDebugMode:
    """Tests for debug mode functionality."""

    @patch("backend.app.services.ssh.connection_manager.paramiko.util.log_to_file")
    def test_enable_debug_mode(
        self,
        mock_log_to_file: MagicMock,
        connection_manager: SSHConnectionManager,
    ) -> None:
        """
        Verify enable_debug_mode sets flag and enables paramiko logging.
        """
        connection_manager.enable_debug_mode()

        assert connection_manager._debug_mode is True
        mock_log_to_file.assert_called_once_with("/tmp/paramiko_debug.log")

    def test_disable_debug_mode(
        self, connection_manager: SSHConnectionManager
    ) -> None:
        """
        Verify disable_debug_mode clears the debug flag.
        """
        connection_manager._debug_mode = True
        connection_manager.disable_debug_mode()

        assert connection_manager._debug_mode is False


# =============================================================================
# connect_with_credentials Tests - Password Auth
# =============================================================================


class TestConnectWithPassword:
    """Tests for password authentication."""

    @patch("backend.app.services.ssh.connection_manager.SSHClient")
    @patch("backend.app.services.ssh.connection_manager.SSHConnectionManager._get_config_manager")
    def test_connect_password_success(
        self,
        mock_get_config: MagicMock,
        mock_ssh_class: MagicMock,
        connection_manager: SSHConnectionManager,
    ) -> None:
        """
        Verify successful password authentication returns correct result.
        """
        # Setup mocks
        mock_client = MagicMock()
        mock_ssh_class.return_value = mock_client

        mock_transport = MagicMock()
        mock_host_key = MagicMock()
        mock_host_key.get_fingerprint.return_value = b"fingerprint123"
        mock_transport.get_remote_server_key.return_value = mock_host_key
        mock_client.get_transport.return_value = mock_transport

        mock_config = MagicMock()
        mock_get_config.return_value = mock_config

        result = connection_manager.connect_with_credentials(
            hostname="server.example.com",
            port=22,
            username="admin",
            auth_method="password",
            credential="secret123",
            service_name="test_service",
        )

        assert result.success is True
        assert result.auth_method_used == "password"
        assert result.connection is mock_client
        mock_client.connect.assert_called_once()

    @patch("backend.app.services.ssh.connection_manager.SSHClient")
    @patch("backend.app.services.ssh.connection_manager.SSHConnectionManager._get_config_manager")
    def test_connect_password_auth_failed(
        self,
        mock_get_config: MagicMock,
        mock_ssh_class: MagicMock,
        connection_manager: SSHConnectionManager,
    ) -> None:
        """
        Verify authentication failure returns appropriate error.
        """
        mock_client = MagicMock()
        mock_ssh_class.return_value = mock_client
        mock_client.connect.side_effect = paramiko.AuthenticationException(
            "Authentication failed"
        )

        mock_config = MagicMock()
        mock_get_config.return_value = mock_config

        result = connection_manager.connect_with_credentials(
            hostname="server.example.com",
            port=22,
            username="admin",
            auth_method="password",
            credential="wrongpass",
            service_name="test_service",
        )

        assert result.success is False
        assert result.error_type == "auth_failed"
        mock_client.close.assert_called_once()


# =============================================================================
# connect_with_credentials Tests - SSH Key Auth
# =============================================================================


class TestConnectWithSSHKey:
    """Tests for SSH key authentication."""

    @patch("backend.app.services.ssh.connection_manager.SSHClient")
    @patch("backend.app.services.ssh.connection_manager.SSHConnectionManager._get_config_manager")
    @patch("backend.app.services.ssh.connection_manager.parse_ssh_key")
    def test_connect_ssh_key_success(
        self,
        mock_parse_key: MagicMock,
        mock_get_config: MagicMock,
        mock_ssh_class: MagicMock,
        connection_manager: SSHConnectionManager,
    ) -> None:
        """
        Verify successful SSH key authentication.
        """
        # Setup mocks
        mock_client = MagicMock()
        mock_ssh_class.return_value = mock_client

        mock_pkey = MagicMock()
        mock_pkey.get_name.return_value = "ssh-rsa"
        mock_pkey.get_bits.return_value = 4096
        mock_parse_key.return_value = mock_pkey

        mock_transport = MagicMock()
        mock_host_key = MagicMock()
        mock_host_key.get_fingerprint.return_value = b"fingerprint123"
        mock_transport.get_remote_server_key.return_value = mock_host_key
        mock_client.get_transport.return_value = mock_transport

        mock_config = MagicMock()
        mock_get_config.return_value = mock_config

        result = connection_manager.connect_with_credentials(
            hostname="server.example.com",
            port=22,
            username="admin",
            auth_method="ssh_key",
            credential=SAMPLE_RSA_PRIVATE_KEY,
            service_name="test_service",
        )

        assert result.success is True
        assert result.auth_method_used == "private_key"
        mock_parse_key.assert_called_once_with(SAMPLE_RSA_PRIVATE_KEY)

    @patch("backend.app.services.ssh.connection_manager.SSHClient")
    @patch("backend.app.services.ssh.connection_manager.SSHConnectionManager._get_config_manager")
    @patch("backend.app.services.ssh.connection_manager.parse_ssh_key")
    def test_connect_ssh_key_parse_error(
        self,
        mock_parse_key: MagicMock,
        mock_get_config: MagicMock,
        mock_ssh_class: MagicMock,
        connection_manager: SSHConnectionManager,
    ) -> None:
        """
        Verify SSH key parsing error returns appropriate result.
        """
        from app.services.ssh.exceptions import SSHKeyError

        mock_client = MagicMock()
        mock_ssh_class.return_value = mock_client
        mock_parse_key.side_effect = SSHKeyError("Invalid key format")

        mock_config = MagicMock()
        mock_get_config.return_value = mock_config

        result = connection_manager.connect_with_credentials(
            hostname="server.example.com",
            port=22,
            username="admin",
            auth_method="key",
            credential="invalid_key_content",
            service_name="test_service",
        )

        assert result.success is False
        assert result.error_type == "key_error"
        assert "Invalid private key" in result.error_message

    def test_connect_all_key_auth_aliases(
        self, connection_manager: SSHConnectionManager
    ) -> None:
        """
        Verify all SSH key authentication method aliases work.

        Methods: key, ssh_key, ssh-key should all use private_key auth.
        """
        key_methods = ["key", "ssh_key", "ssh-key"]

        for method in key_methods:
            canonical = SSHConnectionManager.SUPPORTED_AUTH_METHODS.get(method)
            assert canonical == "private_key", f"Method '{method}' should map to private_key"


# =============================================================================
# connect_with_credentials Tests - Agent Auth
# =============================================================================


class TestConnectWithAgent:
    """Tests for SSH agent authentication."""

    @patch("backend.app.services.ssh.connection_manager.SSHClient")
    @patch("backend.app.services.ssh.connection_manager.SSHConnectionManager._get_config_manager")
    def test_connect_agent_success(
        self,
        mock_get_config: MagicMock,
        mock_ssh_class: MagicMock,
        connection_manager: SSHConnectionManager,
    ) -> None:
        """
        Verify successful SSH agent authentication.
        """
        mock_client = MagicMock()
        mock_ssh_class.return_value = mock_client

        mock_transport = MagicMock()
        mock_host_key = MagicMock()
        mock_host_key.get_fingerprint.return_value = b"fingerprint123"
        mock_transport.get_remote_server_key.return_value = mock_host_key
        mock_client.get_transport.return_value = mock_transport

        mock_config = MagicMock()
        mock_get_config.return_value = mock_config

        result = connection_manager.connect_with_credentials(
            hostname="server.example.com",
            port=22,
            username="admin",
            auth_method="agent",
            credential="",  # Not used for agent auth
            service_name="test_service",
        )

        assert result.success is True
        assert result.auth_method_used == "ssh_agent"

        # Verify agent-specific connect options
        call_kwargs = mock_client.connect.call_args[1]
        assert call_kwargs["allow_agent"] is True
        assert call_kwargs["look_for_keys"] is True


# =============================================================================
# connect_with_credentials Tests - Both Auth Method
# =============================================================================


class TestConnectWithBoth:
    """Tests for 'both' authentication method (key + password fallback)."""

    @patch("backend.app.services.ssh.connection_manager.SSHClient")
    @patch("backend.app.services.ssh.connection_manager.SSHConnectionManager._get_config_manager")
    @patch("backend.app.services.ssh.connection_manager.parse_ssh_key")
    def test_connect_both_key_succeeds(
        self,
        mock_parse_key: MagicMock,
        mock_get_config: MagicMock,
        mock_ssh_class: MagicMock,
        connection_manager: SSHConnectionManager,
    ) -> None:
        """
        Verify 'both' method uses SSH key when it succeeds.
        """
        mock_client = MagicMock()
        mock_ssh_class.return_value = mock_client

        mock_pkey = MagicMock()
        mock_pkey.get_name.return_value = "ssh-ed25519"
        mock_pkey.get_bits.return_value = 256
        mock_parse_key.return_value = mock_pkey

        mock_transport = MagicMock()
        mock_host_key = MagicMock()
        mock_host_key.get_fingerprint.return_value = b"fingerprint123"
        mock_transport.get_remote_server_key.return_value = mock_host_key
        mock_transport.is_active.return_value = True
        mock_client.get_transport.return_value = mock_transport

        mock_config = MagicMock()
        mock_get_config.return_value = mock_config

        result = connection_manager.connect_with_credentials(
            hostname="server.example.com",
            port=22,
            username="admin",
            auth_method="both",
            credential=SAMPLE_ED25519_PRIVATE_KEY,
            password="backup_password",
            service_name="test_service",
        )

        assert result.success is True
        assert result.auth_method_used == "private_key"

    @patch("backend.app.services.ssh.connection_manager.SSHClient")
    @patch("backend.app.services.ssh.connection_manager.SSHConnectionManager._get_config_manager")
    @patch("backend.app.services.ssh.connection_manager.parse_ssh_key")
    def test_connect_both_key_fails_password_succeeds(
        self,
        mock_parse_key: MagicMock,
        mock_get_config: MagicMock,
        mock_ssh_class: MagicMock,
        connection_manager: SSHConnectionManager,
    ) -> None:
        """
        Verify 'both' method falls back to password when key fails.
        """
        # First client for key auth (will fail)
        mock_client_key = MagicMock()
        mock_client_key.get_transport.return_value = None  # No active connection

        # Second client for password auth (will succeed)
        mock_client_pwd = MagicMock()
        mock_transport = MagicMock()
        mock_host_key = MagicMock()
        mock_host_key.get_fingerprint.return_value = b"fingerprint123"
        mock_transport.get_remote_server_key.return_value = mock_host_key
        mock_transport.is_active.return_value = True
        mock_client_pwd.get_transport.return_value = mock_transport

        # Return different clients for each SSHClient() call
        mock_ssh_class.side_effect = [mock_client_key, mock_client_pwd]

        mock_pkey = MagicMock()
        mock_pkey.get_name.return_value = "ssh-rsa"
        mock_pkey.get_bits.return_value = 4096
        mock_parse_key.return_value = mock_pkey

        # Key auth fails
        mock_client_key.connect.side_effect = paramiko.AuthenticationException("Key failed")

        mock_config = MagicMock()
        mock_get_config.return_value = mock_config

        result = connection_manager.connect_with_credentials(
            hostname="server.example.com",
            port=22,
            username="admin",
            auth_method="both",
            credential=SAMPLE_RSA_PRIVATE_KEY,
            password="working_password",
            service_name="test_service",
        )

        assert result.success is True
        assert result.auth_method_used == "password"


# =============================================================================
# connect_with_credentials Tests - Error Handling
# =============================================================================


class TestConnectionErrors:
    """Tests for various connection error scenarios."""

    @patch("backend.app.services.ssh.connection_manager.SSHClient")
    @patch("backend.app.services.ssh.connection_manager.SSHConnectionManager._get_config_manager")
    def test_connection_timeout(
        self,
        mock_get_config: MagicMock,
        mock_ssh_class: MagicMock,
        connection_manager: SSHConnectionManager,
    ) -> None:
        """
        Verify socket timeout is handled correctly.
        """
        mock_client = MagicMock()
        mock_ssh_class.return_value = mock_client
        mock_client.connect.side_effect = socket.timeout("Connection timed out")

        mock_config = MagicMock()
        mock_get_config.return_value = mock_config

        result = connection_manager.connect_with_credentials(
            hostname="slow.server.com",
            port=22,
            username="admin",
            auth_method="password",
            credential="password",
            service_name="test_service",
            timeout=10,
        )

        assert result.success is False
        assert result.error_type == "timeout"
        assert "timeout" in result.error_message.lower()

    @patch("backend.app.services.ssh.connection_manager.SSHClient")
    @patch("backend.app.services.ssh.connection_manager.SSHConnectionManager._get_config_manager")
    def test_connection_refused(
        self,
        mock_get_config: MagicMock,
        mock_ssh_class: MagicMock,
        connection_manager: SSHConnectionManager,
    ) -> None:
        """
        Verify connection refused error is handled correctly.
        """
        mock_client = MagicMock()
        mock_ssh_class.return_value = mock_client

        socket_error = socket.error()
        socket_error.errno = errno.ECONNREFUSED
        mock_client.connect.side_effect = socket_error

        mock_config = MagicMock()
        mock_get_config.return_value = mock_config

        result = connection_manager.connect_with_credentials(
            hostname="no.ssh.server.com",
            port=22,
            username="admin",
            auth_method="password",
            credential="password",
            service_name="test_service",
        )

        assert result.success is False
        assert result.error_type == "connection_error"
        assert "refused" in result.error_message.lower()

    @patch("backend.app.services.ssh.connection_manager.SSHClient")
    @patch("backend.app.services.ssh.connection_manager.SSHConnectionManager._get_config_manager")
    def test_host_unreachable(
        self,
        mock_get_config: MagicMock,
        mock_ssh_class: MagicMock,
        connection_manager: SSHConnectionManager,
    ) -> None:
        """
        Verify host unreachable error is handled correctly.
        """
        mock_client = MagicMock()
        mock_ssh_class.return_value = mock_client

        socket_error = socket.error()
        socket_error.errno = errno.EHOSTUNREACH
        mock_client.connect.side_effect = socket_error

        mock_config = MagicMock()
        mock_get_config.return_value = mock_config

        result = connection_manager.connect_with_credentials(
            hostname="unreachable.server.com",
            port=22,
            username="admin",
            auth_method="password",
            credential="password",
            service_name="test_service",
        )

        assert result.success is False
        assert result.error_type == "connection_error"
        assert "unreachable" in result.error_message.lower()

    @patch("backend.app.services.ssh.connection_manager.SSHClient")
    @patch("backend.app.services.ssh.connection_manager.SSHConnectionManager._get_config_manager")
    def test_ssh_protocol_error(
        self,
        mock_get_config: MagicMock,
        mock_ssh_class: MagicMock,
        connection_manager: SSHConnectionManager,
    ) -> None:
        """
        Verify SSH protocol errors are handled correctly.
        """
        mock_client = MagicMock()
        mock_ssh_class.return_value = mock_client
        mock_client.connect.side_effect = paramiko.SSHException("Banner exchange failed")

        mock_config = MagicMock()
        mock_get_config.return_value = mock_config

        result = connection_manager.connect_with_credentials(
            hostname="bad.ssh.server.com",
            port=22,
            username="admin",
            auth_method="password",
            credential="password",
            service_name="test_service",
        )

        assert result.success is False
        assert result.error_type == "ssh_error"

    def test_unsupported_auth_method(
        self, connection_manager: SSHConnectionManager
    ) -> None:
        """
        Verify unsupported auth method returns appropriate error.
        """
        with patch("backend.app.services.ssh.connection_manager.SSHClient"):
            with patch.object(connection_manager, "_get_config_manager"):
                result = connection_manager.connect_with_credentials(
                    hostname="server.example.com",
                    port=22,
                    username="admin",
                    auth_method="unsupported_method",
                    credential="anything",
                    service_name="test_service",
                )

        assert result.success is False
        assert result.error_type == "auth_error"
        assert "Unsupported authentication method" in result.error_message


# =============================================================================
# execute_command_advanced Tests
# =============================================================================


class TestExecuteCommandAdvanced:
    """Tests for the execute_command_advanced method."""

    def test_execute_command_success(
        self, connection_manager: SSHConnectionManager
    ) -> None:
        """
        Verify successful command execution returns correct result.
        """
        mock_client = MagicMock()
        mock_stdin = MagicMock()
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()

        mock_stdout.read.return_value = b"command output"
        mock_stderr.read.return_value = b""
        mock_stdout.channel.recv_exit_status.return_value = 0

        mock_client.exec_command.return_value = (mock_stdin, mock_stdout, mock_stderr)

        result = connection_manager.execute_command_advanced(
            ssh_connection=mock_client,
            command="echo 'hello'",
            timeout=30,
        )

        assert result.success is True
        assert result.stdout == "command output"
        assert result.stderr == ""
        assert result.exit_code == 0
        assert result.duration >= 0

    def test_execute_command_non_zero_exit(
        self, connection_manager: SSHConnectionManager
    ) -> None:
        """
        Verify non-zero exit code is captured correctly.
        """
        mock_client = MagicMock()
        mock_stdin = MagicMock()
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()

        mock_stdout.read.return_value = b""
        mock_stderr.read.return_value = b"command not found"
        mock_stdout.channel.recv_exit_status.return_value = 127

        mock_client.exec_command.return_value = (mock_stdin, mock_stdout, mock_stderr)

        result = connection_manager.execute_command_advanced(
            ssh_connection=mock_client,
            command="nonexistent_command",
            timeout=30,
        )

        assert result.success is False
        assert result.exit_code == 127
        assert "command not found" in result.stderr

    def test_execute_command_timeout(
        self, connection_manager: SSHConnectionManager
    ) -> None:
        """
        Verify command timeout is handled correctly.
        """
        mock_client = MagicMock()
        mock_client.exec_command.side_effect = socket.timeout("Command timed out")

        result = connection_manager.execute_command_advanced(
            ssh_connection=mock_client,
            command="sleep 1000",
            timeout=5,
        )

        assert result.success is False
        # Check for "timed out" which is the actual message format
        assert "timed out" in result.error_message.lower() or "timeout" in result.error_message.lower()

    def test_execute_command_exception(
        self, connection_manager: SSHConnectionManager
    ) -> None:
        """
        Verify general exceptions are handled correctly.
        """
        mock_client = MagicMock()
        mock_client.exec_command.side_effect = Exception("Channel error")

        result = connection_manager.execute_command_advanced(
            ssh_connection=mock_client,
            command="any command",
            timeout=30,
        )

        assert result.success is False
        assert "failed" in result.error_message.lower()

    def test_execute_command_default_timeout(
        self, connection_manager: SSHConnectionManager
    ) -> None:
        """
        Verify default timeout (300s) is used when not specified.
        """
        mock_client = MagicMock()
        mock_stdin = MagicMock()
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()

        mock_stdout.read.return_value = b"output"
        mock_stderr.read.return_value = b""
        mock_stdout.channel.recv_exit_status.return_value = 0

        mock_client.exec_command.return_value = (mock_stdin, mock_stdout, mock_stderr)

        connection_manager.execute_command_advanced(
            ssh_connection=mock_client,
            command="long_running_command",
            timeout=None,  # Should use default 300
        )

        call_kwargs = mock_client.exec_command.call_args[1]
        assert call_kwargs["timeout"] == 300

    def test_execute_command_encoding_errors(
        self, connection_manager: SSHConnectionManager
    ) -> None:
        """
        Verify non-UTF8 output is handled with replacement.
        """
        mock_client = MagicMock()
        mock_stdin = MagicMock()
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()

        # Invalid UTF-8 sequence
        mock_stdout.read.return_value = b"valid\xff\xfeinvalid"
        mock_stderr.read.return_value = b""
        mock_stdout.channel.recv_exit_status.return_value = 0

        mock_client.exec_command.return_value = (mock_stdin, mock_stdout, mock_stderr)

        result = connection_manager.execute_command_advanced(
            ssh_connection=mock_client,
            command="binary_output_command",
            timeout=30,
        )

        assert result.success is True
        # Should have replacement characters, not crash
        assert "valid" in result.stdout


# =============================================================================
# execute_minimal_system_check Tests
# =============================================================================


class TestExecuteMinimalSystemCheck:
    """Tests for the execute_minimal_system_check method."""

    @patch.object(SSHConnectionManager, "connect_with_credentials")
    @patch.object(SSHConnectionManager, "execute_command_advanced")
    def test_minimal_check_success(
        self,
        mock_execute: MagicMock,
        mock_connect: MagicMock,
        connection_manager: SSHConnectionManager,
    ) -> None:
        """
        Verify successful minimal system check.
        """
        mock_ssh = MagicMock()
        mock_connect.return_value = SSHConnectionResult(
            success=True,
            connection=mock_ssh,
        )

        mock_execute.side_effect = [
            SSHCommandResult(success=True, stdout="redhat", exit_code=0),
            SSHCommandResult(success=True, stdout="yes", exit_code=0),
        ]

        result = connection_manager.execute_minimal_system_check(
            hostname="server.example.com",
            port=22,
            username="admin",
            auth_method="password",
            credential="password",
            service_name="test",
        )

        assert "os_family" in result
        assert result["os_family"] == "redhat"
        assert "oscap_available" in result
        assert result["oscap_available"] == "yes"
        mock_ssh.close.assert_called_once()

    @patch.object(SSHConnectionManager, "connect_with_credentials")
    def test_minimal_check_connection_failed(
        self,
        mock_connect: MagicMock,
        connection_manager: SSHConnectionManager,
    ) -> None:
        """
        Verify connection failure returns appropriate error.
        """
        mock_connect.return_value = SSHConnectionResult(
            success=False,
            error_message="Connection refused",
            error_type="connection_error",
        )

        result = connection_manager.execute_minimal_system_check(
            hostname="unreachable.server.com",
            port=22,
            username="admin",
            auth_method="password",
            credential="password",
            service_name="test",
        )

        assert "error" in result
        assert result["error_type"] == "connection_error"


# =============================================================================
# _load_private_key Tests
# =============================================================================


class TestLoadPrivateKey:
    """Tests for the _load_private_key method."""

    def test_load_private_key_rsa(
        self, connection_manager: SSHConnectionManager
    ) -> None:
        """
        Verify RSA key loading attempts.
        """
        # Create mock that fails for RSA (since test key is fake)
        key_file = io.StringIO("fake key content")

        result = connection_manager._load_private_key(key_file)

        # Should return None for fake key
        assert result is None

    def test_load_private_key_tries_all_types(
        self, connection_manager: SSHConnectionManager
    ) -> None:
        """
        Verify all supported key types are attempted when loading.

        OpenWatch supports Ed25519, RSA, and ECDSA keys.
        DSA keys are not supported (deprecated, insecure).
        """
        key_file = io.StringIO("fake key content")

        with patch.object(paramiko.RSAKey, "from_private_key") as mock_rsa:
            with patch.object(paramiko.Ed25519Key, "from_private_key") as mock_ed25519:
                with patch.object(paramiko.ECDSAKey, "from_private_key") as mock_ecdsa:
                    mock_rsa.side_effect = Exception("Not RSA")
                    mock_ed25519.side_effect = Exception("Not Ed25519")
                    mock_ecdsa.side_effect = Exception("Not ECDSA")

                    result = connection_manager._load_private_key(key_file)

                    # All supported key types should be attempted
                    assert mock_rsa.called
                    assert mock_ed25519.called
                    assert mock_ecdsa.called
                    assert result is None


# =============================================================================
# Error Handler Tests
# =============================================================================


class TestErrorHandlers:
    """Tests for error handling methods."""

    def test_handle_auth_exception_no_methods(
        self, connection_manager: SSHConnectionManager
    ) -> None:
        """
        Verify 'no authentication methods' error is detected.
        """
        exception = paramiko.AuthenticationException(
            "No authentication methods available"
        )

        result = connection_manager._handle_auth_exception(
            exception, "admin", "server.com", 22, "password"
        )

        assert result.success is False
        assert result.error_type == "auth_failed"
        assert "No authentication methods" in result.error_message

    def test_handle_auth_exception_permission_denied(
        self, connection_manager: SSHConnectionManager
    ) -> None:
        """
        Verify 'permission denied' error is detected.
        """
        exception = paramiko.AuthenticationException("Permission denied")

        result = connection_manager._handle_auth_exception(
            exception, "admin", "server.com", 22, "ssh_key"
        )

        assert result.success is False
        assert "Permission denied" in result.error_message

    def test_handle_ssh_exception_host_key(
        self, connection_manager: SSHConnectionManager
    ) -> None:
        """
        Verify host key error is detected.
        """
        exception = paramiko.SSHException("Host key verification failed")

        result = connection_manager._handle_ssh_exception(
            exception, "server.com", 22
        )

        assert result.success is False
        assert result.error_type == "ssh_error"
        assert "Host key" in result.error_message

    def test_handle_socket_error_timeout(
        self, connection_manager: SSHConnectionManager
    ) -> None:
        """
        Verify socket timeout error is detected.
        """
        exception = socket.error()
        exception.errno = errno.ETIMEDOUT

        result = connection_manager._handle_socket_error(
            exception, "server.com", 22
        )

        assert result.success is False
        assert result.error_type == "connection_error"
        assert "timed out" in result.error_message.lower()
