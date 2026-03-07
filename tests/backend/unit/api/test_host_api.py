"""
Unit tests for host API contracts: test-connection (POST /api/hosts/test-connection)
behavioral contract.

Spec: specs/api/hosts/test-connection.spec.yaml
Tests test_connection endpoint from routes/hosts/crud.py.
"""

import inspect

import pytest

from app.routes.hosts.crud import TestConnectionRequest
from app.routes.hosts.crud import test_connection as _test_connection_handler

# ---------------------------------------------------------------------------
# AC-1: TCP socket check before SSH authentication
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestConnectionAC1SocketCheck:
    """AC-1: TCP socket check performed before SSH auth."""

    def test_socket_create_connection_present(self):
        """Verify socket.create_connection is used for TCP check."""
        source = inspect.getsource(_test_connection_handler)
        assert "socket.create_connection" in source

    def test_network_connectivity_set_on_success(self):
        """Verify network_connectivity is set to True on socket success."""
        source = inspect.getsource(_test_connection_handler)
        assert 'result["network_connectivity"] = True' in source

    def test_early_return_on_socket_failure(self):
        """Verify early return with error when socket fails."""
        source = inspect.getsource(_test_connection_handler)
        assert "socket.timeout" in source or "OSError" in source
        assert "Cannot reach" in source


# ---------------------------------------------------------------------------
# AC-2: system_default queries unified_credentials
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestConnectionAC2SystemDefault:
    """AC-2: system_default resolves from unified_credentials table."""

    def test_queries_unified_credentials(self):
        """Verify QueryBuilder targets unified_credentials table."""
        source = inspect.getsource(_test_connection_handler)
        assert "unified_credentials" in source

    def test_filters_scope_system(self):
        """Verify scope=system filter applied."""
        source = inspect.getsource(_test_connection_handler)
        assert '"system"' in source or "'system'" in source
        assert "scope" in source

    def test_filters_is_default_true(self):
        """Verify is_default=true filter applied."""
        source = inspect.getsource(_test_connection_handler)
        assert "is_default" in source

    def test_filters_is_active_true(self):
        """Verify is_active=true filter applied."""
        source = inspect.getsource(_test_connection_handler)
        assert "is_active" in source


# ---------------------------------------------------------------------------
# AC-3: base64 decode + AES-256-GCM decryption
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestConnectionAC3Decryption:
    """AC-3: Credential decryption uses base64 decode then AES-256-GCM."""

    def test_base64_decode_present(self):
        """Verify base64.b64decode is used before decryption."""
        source = inspect.getsource(_test_connection_handler)
        assert "base64.b64decode" in source or "b64decode" in source

    def test_encryption_service_used(self):
        """Verify create_encryption_service is used for decryption."""
        source = inspect.getsource(_test_connection_handler)
        assert "create_encryption_service" in source

    def test_master_key_from_settings(self):
        """Verify master_key is sourced from application settings."""
        source = inspect.getsource(_test_connection_handler)
        assert "settings.master_key" in source

    def test_decrypt_called(self):
        """Verify enc_svc.decrypt is called on the encrypted bytes."""
        source = inspect.getsource(_test_connection_handler)
        assert "enc_svc.decrypt" in source


# ---------------------------------------------------------------------------
# AC-4: SSH key format support (RSA, Ed25519, ECDSA)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestConnectionAC4KeyFormats:
    """AC-4: SSH key parsing supports RSA, Ed25519, and ECDSA."""

    def test_rsa_key_support(self):
        """Verify paramiko.RSAKey.from_private_key is tried."""
        source = inspect.getsource(_test_connection_handler)
        assert "paramiko.RSAKey.from_private_key" in source

    def test_ed25519_key_support(self):
        """Verify paramiko.Ed25519Key.from_private_key is tried."""
        source = inspect.getsource(_test_connection_handler)
        assert "paramiko.Ed25519Key.from_private_key" in source

    def test_ecdsa_key_support(self):
        """Verify paramiko.ECDSAKey.from_private_key is tried."""
        source = inspect.getsource(_test_connection_handler)
        assert "paramiko.ECDSAKey.from_private_key" in source


# ---------------------------------------------------------------------------
# AC-5: "both" mode sets pkey AND password
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestConnectionAC5BothMode:
    """AC-5: both mode includes pkey and password in connect_kwargs."""

    def test_both_mode_adds_password(self):
        """Verify both mode explicitly adds password after setting pkey."""
        source = inspect.getsource(_test_connection_handler)
        assert 'auth_method == "both"' in source or "auth_method == 'both'" in source
        # Verify password is set for both mode separately from the key
        assert 'connect_kwargs["password"]' in source

    def test_both_mode_not_elif_password(self):
        """Verify password for both mode is not behind an elif that skips it."""
        source = inspect.getsource(_test_connection_handler)
        # After the ssh_key/both block, there should be a specific check
        # for both mode to add password, not just elif password
        lines = source.split("\n")
        found_both_password = False
        for line in lines:
            if "both" in line and "password" in line and "connect_kwargs" not in line:
                found_both_password = True
                break
        assert found_both_password, "Expected explicit both+password check"


# ---------------------------------------------------------------------------
# AC-6: OS detection via /etc/os-release
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestConnectionAC6OSDetection:
    """AC-6: OS detection parses /etc/os-release."""

    def test_os_release_command(self):
        """Verify cat /etc/os-release is executed via SSH."""
        source = inspect.getsource(_test_connection_handler)
        assert "/etc/os-release" in source

    def test_pretty_name_parsed(self):
        """Verify PRETTY_NAME field is extracted."""
        source = inspect.getsource(_test_connection_handler)
        assert "PRETTY_NAME=" in source

    def test_version_id_parsed(self):
        """Verify VERSION_ID field is extracted."""
        source = inspect.getsource(_test_connection_handler)
        assert "VERSION_ID=" in source

    def test_os_detection_in_try_block(self):
        """Verify OS detection failure does not cause overall failure."""
        source = inspect.getsource(_test_connection_handler)
        # The OS detection should be in its own try/except
        detect_idx = source.find("/etc/os-release")
        # There should be a try before it and except after it
        preceding = source[:detect_idx]
        assert "try:" in preceding.split("ssh.connect")[1]


# ---------------------------------------------------------------------------
# AC-7: No system default credential returns error
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestConnectionAC7NoCredential:
    """AC-7: Missing system default credential returns descriptive error."""

    def test_no_credential_error_message(self):
        """Verify error message when no system default credential found."""
        source = inspect.getsource(_test_connection_handler)
        assert "No system default credential configured" in source


# ---------------------------------------------------------------------------
# AC-8: Response includes response_time_ms
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestConnectionAC8ResponseTime:
    """AC-8: Response includes response_time_ms from monotonic clock."""

    def test_monotonic_clock_used(self):
        """Verify monotonic clock is used for timing."""
        source = inspect.getsource(_test_connection_handler)
        assert "monotonic" in source

    def test_response_time_in_result(self):
        """Verify response_time_ms is set in result dict."""
        source = inspect.getsource(_test_connection_handler)
        assert 'result["response_time_ms"]' in source


# ---------------------------------------------------------------------------
# AC-9: SSH banner captured from TCP socket
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestConnectionAC9SSHBanner:
    """AC-9: SSH banner captured and returned in ssh_version."""

    def test_banner_read_from_socket(self):
        """Verify SSH banner is read from the socket."""
        source = inspect.getsource(_test_connection_handler)
        assert "sock.recv" in source

    def test_banner_starts_with_ssh(self):
        """Verify only SSH-prefixed banners are stored."""
        source = inspect.getsource(_test_connection_handler)
        assert 'startswith("SSH-")' in source

    def test_ssh_version_stored(self):
        """Verify banner is stored in ssh_version field."""
        source = inspect.getsource(_test_connection_handler)
        assert 'result["ssh_version"]' in source


# ---------------------------------------------------------------------------
# AC-10: TestConnectionRequest Pydantic model fields
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestConnectionAC10RequestModel:
    """AC-10: TestConnectionRequest has correct fields and defaults."""

    def test_hostname_required(self):
        """Verify hostname is a required field."""
        fields = TestConnectionRequest.model_fields
        assert "hostname" in fields
        assert fields["hostname"].is_required()

    def test_port_default_22(self):
        """Verify port defaults to 22."""
        fields = TestConnectionRequest.model_fields
        assert "port" in fields
        assert fields["port"].default == 22

    def test_auth_method_default_system_default(self):
        """Verify auth_method defaults to system_default."""
        fields = TestConnectionRequest.model_fields
        assert "auth_method" in fields
        assert fields["auth_method"].default == "system_default"

    def test_username_optional(self):
        """Verify username is optional."""
        fields = TestConnectionRequest.model_fields
        assert "username" in fields
        assert not fields["username"].is_required()

    def test_ssh_key_optional(self):
        """Verify ssh_key is optional."""
        fields = TestConnectionRequest.model_fields
        assert "ssh_key" in fields
        assert not fields["ssh_key"].is_required()

    def test_password_optional(self):
        """Verify password is optional."""
        fields = TestConnectionRequest.model_fields
        assert "password" in fields
        assert not fields["password"].is_required()

    def test_timeout_default_30(self):
        """Verify timeout defaults to 30."""
        fields = TestConnectionRequest.model_fields
        assert "timeout" in fields
        assert fields["timeout"].default == 30
