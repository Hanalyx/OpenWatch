"""
Unit tests for SSH connection management: auth methods, timeouts, error types,
result dataclasses, policy defaults, and credential error handling.

Spec: specs/services/ssh/ssh-connection.spec.yaml
Tests connection manager, config manager, models, and credential provider contracts.
"""

import dataclasses
import inspect

import pytest

from app.services.ssh.config_manager import SSHConfigManager
from app.services.ssh.connection_manager import SSHConnectionManager
from app.services.ssh.models import SSHCommandResult, SSHConnectionResult

# ---------------------------------------------------------------------------
# AC-1: SUPPORTED_AUTH_METHODS maps 6 keys
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC1SupportedAuthMethods:
    """AC-1: SUPPORTED_AUTH_METHODS maps exactly 6 keys."""

    EXPECTED_KEYS = {"password", "key", "ssh_key", "ssh-key", "agent", "both"}

    def test_exactly_six_keys(self):
        assert len(SSHConnectionManager.SUPPORTED_AUTH_METHODS) == 6

    def test_expected_keys_present(self):
        actual = set(SSHConnectionManager.SUPPORTED_AUTH_METHODS.keys())
        assert actual == self.EXPECTED_KEYS

    def test_all_values_are_strings(self):
        for key, value in SSHConnectionManager.SUPPORTED_AUTH_METHODS.items():
            assert isinstance(value, str), f"Value for '{key}' is not a string"


# ---------------------------------------------------------------------------
# AC-2: "both" tries key first, falls back to password
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC2BothAuthMethodOrder:
    """AC-2: 'both' auth method tries key first, falls back to password."""

    def test_key_attempted_before_password(self):
        """Source-parse _connect_with_both: key attempt precedes password fallback."""
        source = inspect.getsource(SSHConnectionManager._connect_with_both)
        lines = source.split("\n")

        key_attempt_line = None
        password_fallback_line = None

        for i, line in enumerate(lines):
            if "pkey=" in line and key_attempt_line is None:
                key_attempt_line = i
            if "password=" in line and "fallback" in lines[max(0, i - 5) : i + 1].__repr__().lower():
                password_fallback_line = i
            elif "password=" in line and key_attempt_line is not None and password_fallback_line is None:
                password_fallback_line = i

        assert key_attempt_line is not None, "No SSH key attempt found in _connect_with_both"
        assert password_fallback_line is not None, "No password fallback found in _connect_with_both"
        assert key_attempt_line < password_fallback_line, (
            f"Key attempt (line {key_attempt_line}) should precede "
            f"password fallback (line {password_fallback_line})"
        )

    def test_catches_authentication_exception_for_fallback(self):
        """Verify _connect_with_both catches AuthenticationException before password fallback."""
        source = inspect.getsource(SSHConnectionManager._connect_with_both)
        assert "AuthenticationException" in source


# ---------------------------------------------------------------------------
# AC-3: Connection timeout 30s, command timeout 300s
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC3TimeoutDefaults:
    """AC-3: Connection timeout defaults to 30s; command timeout to 300s."""

    def test_connection_timeout_default_30(self):
        """Source-parse connect_with_credentials: timeout or 30."""
        source = inspect.getsource(SSHConnectionManager.connect_with_credentials)
        assert "timeout or 30" in source

    def test_command_timeout_default_300(self):
        """Source-parse execute_command_advanced: timeout or 300."""
        source = inspect.getsource(SSHConnectionManager.execute_command_advanced)
        assert "timeout or 300" in source


# ---------------------------------------------------------------------------
# AC-4: Error types categorized
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC4ErrorTypeCategories:
    """AC-4: Error types include auth_failed, key_error, ssh_error, timeout, connection_error."""

    REQUIRED_ERROR_TYPES = {"auth_failed", "key_error", "ssh_error", "timeout", "connection_error"}

    def test_all_error_types_present_in_source(self):
        """Verify all 5 error_type strings appear in connection_manager.py."""
        source = inspect.getsource(SSHConnectionManager)
        for error_type in self.REQUIRED_ERROR_TYPES:
            assert f'"{error_type}"' in source, f"Error type '{error_type}' not found in SSHConnectionManager source"


# ---------------------------------------------------------------------------
# AC-5: SSHConnectionResult is a dataclass with required fields
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC5ConnectionResultDataclass:
    """AC-5: SSHConnectionResult is a dataclass with required fields."""

    REQUIRED_FIELDS = {
        "success",
        "connection",
        "error_message",
        "error_type",
        "host_key_fingerprint",
        "auth_method_used",
    }

    def test_is_dataclass(self):
        assert dataclasses.is_dataclass(SSHConnectionResult)

    def test_required_fields_present(self):
        field_names = {f.name for f in dataclasses.fields(SSHConnectionResult)}
        assert self.REQUIRED_FIELDS.issubset(field_names), f"Missing fields: {self.REQUIRED_FIELDS - field_names}"

    def test_success_field_is_required(self):
        """success should not have a default (it's a required positional field)."""
        fields = {f.name: f for f in dataclasses.fields(SSHConnectionResult)}
        success_field = fields["success"]
        assert success_field.default is dataclasses.MISSING


# ---------------------------------------------------------------------------
# AC-6: SSHCommandResult is a dataclass with required fields
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC6CommandResultDataclass:
    """AC-6: SSHCommandResult is a dataclass with required fields."""

    REQUIRED_FIELDS = {
        "success",
        "stdout",
        "stderr",
        "exit_code",
        "duration",
        "error_message",
    }

    def test_is_dataclass(self):
        assert dataclasses.is_dataclass(SSHCommandResult)

    def test_required_fields_present(self):
        field_names = {f.name for f in dataclasses.fields(SSHCommandResult)}
        assert self.REQUIRED_FIELDS.issubset(field_names), f"Missing fields: {self.REQUIRED_FIELDS - field_names}"

    def test_default_values(self):
        """Verify sensible defaults for optional fields."""
        result = SSHCommandResult(success=False)
        assert result.stdout == ""
        assert result.stderr == ""
        assert result.exit_code == -1
        assert result.duration == 0.0
        assert result.error_message is None


# ---------------------------------------------------------------------------
# AC-7: Default SSH policy is "auto_add_warning"
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC7DefaultSSHPolicy:
    """AC-7: Default SSH policy is 'auto_add_warning' when no DB setting exists."""

    def test_default_policy_no_db(self):
        config = SSHConfigManager(db=None)
        policy = config.get_ssh_policy()
        assert policy == "auto_add_warning"


# ---------------------------------------------------------------------------
# AC-8: VALID_POLICIES includes 4 policy types
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC8ValidPolicies:
    """AC-8: VALID_POLICIES includes strict, auto_add, auto_add_warning, bypass_trusted."""

    EXPECTED_POLICIES = {"strict", "auto_add", "auto_add_warning", "bypass_trusted"}

    def test_expected_policies_present(self):
        actual = set(SSHConfigManager.VALID_POLICIES)
        assert self.EXPECTED_POLICIES.issubset(actual), f"Missing policies: {self.EXPECTED_POLICIES - actual}"

    def test_valid_policies_is_list(self):
        assert isinstance(SSHConfigManager.VALID_POLICIES, list)


# ---------------------------------------------------------------------------
# AC-9: Credential provider raises RuntimeError for missing credentials
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC9CredentialProviderError:
    """AC-9: Credential provider raises RuntimeError with 'No SSH credentials for host'."""

    def test_credential_not_found_raises_runtime_error(self):
        """Source-parse executor.py: CredentialNotFoundError -> RuntimeError."""
        from app.plugins.kensa.executor import OpenWatchCredentialProvider

        source = inspect.getsource(OpenWatchCredentialProvider.get_credentials_for_host)
        assert "CredentialNotFoundError" in source
        assert "RuntimeError" in source
        assert "No SSH credentials for host" in source


# ---------------------------------------------------------------------------
# AC-10: Unsupported auth method returns auth_error
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC10UnsupportedAuthMethod:
    """AC-10: Unsupported auth method returns error_type 'auth_error' with valid methods list."""

    def test_unsupported_auth_returns_auth_error(self):
        """Source-parse connect_with_credentials: else branch returns auth_error."""
        source = inspect.getsource(SSHConnectionManager.connect_with_credentials)
        assert '"auth_error"' in source

    def test_error_message_lists_valid_methods(self):
        """Source-parse: error message includes supported method names."""
        source = inspect.getsource(SSHConnectionManager.connect_with_credentials)
        assert "Unsupported authentication method" in source
        assert "password" in source
        assert "ssh_key" in source
        assert "agent" in source
        assert "both" in source
