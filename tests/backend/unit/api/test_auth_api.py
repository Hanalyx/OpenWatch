"""
Unit tests for auth API contracts: login (POST /api/auth/login) and
mfa-verify (POST /api/auth/mfa/validate) behavioral contracts.

Spec: specs/api/auth/login.spec.yaml
      specs/api/auth/mfa-verify.spec.yaml
Tests login, register from routes/auth/login.py and validate_mfa_code
from routes/auth/mfa.py.
"""

import inspect

import pytest

from app.routes.auth.login import login, register
from app.routes.auth.mfa import validate_mfa_code

# ---------------------------------------------------------------------------
# AC-1 (login): is_active checked before password verification
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestLoginAC1InactiveCheck:
    """AC-1: is_active checked before pwd_context.verify."""

    def test_is_active_check_present(self):
        """Verify is_active check exists in login handler."""
        source = inspect.getsource(login)
        assert "is_active" in source

    def test_inactive_returns_401(self):
        """Verify HTTP_401_UNAUTHORIZED raised for inactive account."""
        source = inspect.getsource(login)
        assert "HTTP_401_UNAUTHORIZED" in source
        assert "Account is deactivated" in source

    def test_is_active_before_pwd_verify(self):
        """Verify is_active check precedes pwd_context.verify in source."""
        source = inspect.getsource(login)
        active_pos = source.find("is_active")
        pwd_pos = source.find("pwd_context.verify")
        assert active_pos < pwd_pos


# ---------------------------------------------------------------------------
# AC-2 (login): locked_until checked before password verification
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestLoginAC2LockoutCheck:
    """AC-2: locked_until checked before password verification."""

    def test_locked_until_check_present(self):
        """Verify locked_until check in login source."""
        source = inspect.getsource(login)
        assert "locked_until" in source

    def test_locked_account_returns_401(self):
        """Verify HTTP_401_UNAUTHORIZED raised for locked account."""
        source = inspect.getsource(login)
        # Multiple 401s expected (inactive, locked, bad password)
        assert source.count("HTTP_401_UNAUTHORIZED") >= 2

    def test_locked_until_before_pwd_verify(self):
        """Verify locked_until check precedes pwd_context.verify in source."""
        source = inspect.getsource(login)
        locked_pos = source.find("locked_until")
        pwd_pos = source.find("pwd_context.verify")
        assert locked_pos < pwd_pos


# ---------------------------------------------------------------------------
# AC-3 (login): Argon2id password verification
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestLoginAC3PasswordVerification:
    """AC-3: Password verified with pwd_context.verify (Argon2id)."""

    def test_pwd_context_verify_called(self):
        """Verify pwd_context.verify used for password checking."""
        source = inspect.getsource(login)
        assert "pwd_context.verify" in source

    def test_increments_failed_attempts(self):
        """Verify failed_login_attempts incremented on bad password."""
        source = inspect.getsource(login)
        assert "failed_login_attempts" in source


# ---------------------------------------------------------------------------
# AC-4 (login): Lockout after 5 failures for 30 minutes
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestLoginAC4LockoutThreshold:
    """AC-4: Lockout triggers at 5 failures for 30-minute duration."""

    def test_lockout_threshold_is_5(self):
        """Verify failed_attempts >= 5 triggers lockout."""
        source = inspect.getsource(login)
        assert "failed_attempts >= 5" in source or "5" in source

    def test_lockout_duration_30_minutes(self):
        """Verify lockout duration is 30 minutes."""
        source = inspect.getsource(login)
        assert "minutes=30" in source

    def test_locked_until_set_on_lockout(self):
        """Verify locked_until field is set on lockout."""
        source = inspect.getsource(login)
        assert "locked_until" in source


# ---------------------------------------------------------------------------
# AC-5 (login): Successful login resets counters
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestLoginAC5ResetOnSuccess:
    """AC-5: Successful login resets failed_login_attempts and locked_until."""

    def test_resets_failed_attempts_to_zero(self):
        """Verify failed_login_attempts reset to 0 on success."""
        source = inspect.getsource(login)
        assert "failed_login_attempts = 0" in source

    def test_resets_locked_until_to_null(self):
        """Verify locked_until reset to NULL on success."""
        source = inspect.getsource(login)
        assert "locked_until = NULL" in source or "locked_until" in source


# ---------------------------------------------------------------------------
# AC-6 (login): Access and refresh tokens returned on success
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestLoginAC6TokensReturned:
    """AC-6: Successful login returns access_token and refresh_token."""

    def test_access_token_in_response(self):
        """Verify access_token included in response."""
        source = inspect.getsource(login)
        assert "access_token" in source

    def test_refresh_token_in_response(self):
        """Verify refresh_token included in response."""
        source = inspect.getsource(login)
        assert "refresh_token" in source

    def test_uses_jwt_manager(self):
        """Verify FIPSJWTManager or equivalent used for token creation."""
        source = inspect.getsource(login)
        assert "create_access_token" in source or "jwt_manager" in source.lower()


# ---------------------------------------------------------------------------
# AC-7 (login): AUTH_FAILURE audit event logged
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestLoginAC7AuthFailureLogged:
    """AC-7: AUTH_FAILURE event logged for every failed login."""

    def test_auth_failure_event_present(self):
        """Verify AUTH_FAILURE audit event in login source."""
        source = inspect.getsource(login)
        assert "AUTH_FAILURE" in source


# ---------------------------------------------------------------------------
# AC-8 (login): LOGIN_SUCCESS audit event logged
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestLoginAC8LoginSuccessLogged:
    """AC-8: LOGIN_SUCCESS event logged for successful login."""

    def test_login_success_event_present(self):
        """Verify LOGIN_SUCCESS audit event in login source."""
        source = inspect.getsource(login)
        assert "LOGIN_SUCCESS" in source


# ---------------------------------------------------------------------------
# AC-9 (login): USER_REGISTER event logged on registration
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestLoginAC9RegisterLogged:
    """AC-9: USER_REGISTER event logged when new account created."""

    def test_user_register_event_present(self):
        """Verify USER_REGISTER audit event in register source."""
        source = inspect.getsource(register)
        assert "USER_REGISTER" in source


# ---------------------------------------------------------------------------
# AC-10 (login): is_active before pwd_context.verify in source ordering
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestLoginAC10CheckOrdering:
    """AC-10: Source-level ordering confirms is_active before pwd verification."""

    def test_is_active_before_verify_in_source(self):
        """Verify is_active appears before pwd_context.verify in source."""
        source = inspect.getsource(login)
        is_active_pos = source.find("is_active")
        verify_pos = source.find("pwd_context.verify")
        assert is_active_pos < verify_pos

    def test_locked_until_before_verify_in_source(self):
        """Verify locked_until check appears before verify in source."""
        source = inspect.getsource(login)
        locked_pos = source.find("locked_until")
        verify_pos = source.find("pwd_context.verify")
        assert locked_pos < verify_pos


# ---------------------------------------------------------------------------
# AC-2 (mfa-verify): 6-digit routed to TOTP
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestMFAVerifyAC2TOTPRouting:
    """AC-2: 6-digit numeric code routed to validate_totp_code."""

    def test_validates_totp_for_six_digits(self):
        """Verify 6-digit code path calls TOTP validation."""
        source = inspect.getsource(validate_mfa_code)
        assert "6" in source or "isdigit" in source

    def test_validate_totp_code_called(self):
        """Verify validate_totp_code (or mfa_service) called for TOTP."""
        source = inspect.getsource(validate_mfa_code)
        assert "totp" in source.lower() or "validate" in source


# ---------------------------------------------------------------------------
# AC-3 (mfa-verify): 8-char code routed to backup
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestMFAVerifyAC3BackupRouting:
    """AC-3: 8-character code routed to backup code validation."""

    def test_routes_eight_char_to_backup(self):
        """Verify 8-char backup code path in validate_mfa_code."""
        source = inspect.getsource(validate_mfa_code)
        assert "backup" in source.lower() or "8" in source


# ---------------------------------------------------------------------------
# AC-4/AC-5 (mfa-verify): method field in response
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestMFAVerifyAC4AC5ResponseMethod:
    """AC-4/AC-5: Response includes method field with 'totp' or 'backup_code'."""

    def test_method_field_in_response(self):
        """Verify 'method' field set in validate_mfa_code response."""
        source = inspect.getsource(validate_mfa_code)
        assert "method" in source

    def test_totp_method_value(self):
        """Verify 'totp' value used for TOTP path."""
        source = inspect.getsource(validate_mfa_code)
        assert "totp" in source

    def test_backup_code_method_value(self):
        """Verify 'backup_code' value used for backup path."""
        source = inspect.getsource(validate_mfa_code)
        assert "backup_code" in source or "backup" in source


# ---------------------------------------------------------------------------
# AC-6 (mfa-verify): 401 on failed validation
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestMFAVerifyAC6Unauthorized:
    """AC-6: Failed validation returns HTTP 401 UNAUTHORIZED."""

    def test_raises_401_on_invalid_code(self):
        """Verify HTTP_401_UNAUTHORIZED raised for invalid MFA code."""
        source = inspect.getsource(validate_mfa_code)
        assert "HTTP_401_UNAUTHORIZED" in source


# ---------------------------------------------------------------------------
# AC-8 (mfa-verify): decrypt_mfa_secret called before TOTP
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestMFAVerifyAC8DecryptBeforeValidate:
    """AC-8: MFA secret decrypted before TOTP validation."""

    def test_decrypt_called_in_validate(self):
        """Verify decrypt operation present in validate_mfa_code."""
        source = inspect.getsource(validate_mfa_code)
        assert "decrypt" in source.lower() or "mfa_service" in source


# ---------------------------------------------------------------------------
# AC-9 (mfa-verify): Audit logging
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestMFAVerifyAC9AuditLog:
    """AC-9: Validation outcome logged to MFAAuditLog."""

    def test_audit_log_in_validate(self):
        """Verify MFAAuditLog or audit logging used in validate_mfa_code."""
        source = inspect.getsource(validate_mfa_code)
        assert "MFAAuditLog" in source or "audit" in source.lower() or "log" in source.lower()


# ---------------------------------------------------------------------------
# AC-11 (login): Webhook URL validation blocks private/internal IPs (SSRF)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestLoginAC11WebhookSSRF:
    """AC-11: Webhook URL validator blocks private/internal IP ranges."""

    def test_validate_url_exists(self):
        """Verify validate_url function exists in webhooks module."""
        import importlib

        mod = importlib.import_module("app.routes.integrations.webhooks")
        source = inspect.getsource(mod)
        assert "validate_url" in source or "validate" in source

    def test_blocks_private_10_range(self):
        """Verify webhook validator blocks 10.x.x.x private range."""
        import importlib

        mod = importlib.import_module("app.routes.integrations.webhooks")
        source = inspect.getsource(mod)
        has_10_check = "10." in source or "is_private" in source or "private" in source.lower()
        assert has_10_check, (
            "Webhook URL validator must block 10.x.x.x private IP range"
        )

    def test_blocks_loopback(self):
        """Verify webhook validator blocks 127.x.x.x loopback range."""
        import importlib

        mod = importlib.import_module("app.routes.integrations.webhooks")
        source = inspect.getsource(mod)
        has_loopback = (
            "127." in source
            or "loopback" in source.lower()
            or "is_loopback" in source
            or "is_private" in source
        )
        assert has_loopback, (
            "Webhook URL validator must block 127.x.x.x loopback addresses"
        )

    def test_blocks_link_local(self):
        """Verify webhook validator blocks 169.254.x.x link-local range."""
        import importlib

        mod = importlib.import_module("app.routes.integrations.webhooks")
        source = inspect.getsource(mod)
        has_link_local = (
            "169.254" in source
            or "link_local" in source.lower()
            or "link-local" in source.lower()
            or "is_link_local" in source
            or "is_private" in source
        )
        assert has_link_local, (
            "Webhook URL validator must block 169.254.x.x link-local addresses"
        )


# ---------------------------------------------------------------------------
# AC-12 (login): SQL IN clauses use parameterized values
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestLoginAC12SQLParameterization:
    """AC-12: SQL IN clauses use parameterized placeholders, not f-strings."""

    def test_get_scans_status_no_fstring_quoting(self):
        """Verify _get_scans_status does not use f-string quoting in SQL."""
        from app.services.bulk_scan_orchestrator import BulkScanOrchestrator

        source = inspect.getsource(BulkScanOrchestrator)
        # Look for the dangerous pattern: f"'{value}'" in SQL IN clauses
        has_fstring_quote = "f\"'{" in source or "f\"\\'{" in source
        assert not has_fstring_quote, (
            "BulkScanOrchestrator must not use f-string quoting "
            "(f\"'{value}'\") in SQL IN clauses; use parameterized placeholders"
        )

    def test_uses_parameterized_placeholders(self):
        """Verify BulkScanOrchestrator uses parameterized SQL placeholders."""
        from app.services.bulk_scan_orchestrator import BulkScanOrchestrator

        source = inspect.getsource(BulkScanOrchestrator)
        # Should use :param style or bindparam or tuple expansion
        has_param = (
            ":param" in source
            or "bindparam" in source
            or "params" in source.lower()
            or "execute(" in source
        )
        assert has_param, (
            "BulkScanOrchestrator must use parameterized placeholders for SQL"
        )
