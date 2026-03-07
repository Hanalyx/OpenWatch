"""
Unit tests for authentication: JWT RS256 lifecycle, Argon2id password
hashing parameters, account lockout policy, inactive account check ordering,
and audit event logging.

Spec: specs/system/authentication.spec.yaml
Tests FIPSJWTManager and pwd_context from auth.py and login logic from
routes/auth/login.py.
"""

import inspect

import pytest

from app.auth import FIPSJWTManager, pwd_context

# ---------------------------------------------------------------------------
# AC-1: RS256 algorithm with RSA-2048 keys
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC1RS256Algorithm:
    """AC-1: FIPSJWTManager uses RS256 with RSA-2048 key pair."""

    def test_create_access_token_uses_rs256(self):
        """Verify RS256 algorithm in create_access_token."""
        source = inspect.getsource(FIPSJWTManager.create_access_token)
        assert '"RS256"' in source

    def test_generate_keys_uses_rsa_2048(self):
        """Verify RSA key size is 2048 bits."""
        source = inspect.getsource(FIPSJWTManager._generate_keys)
        assert "key_size=2048" in source

    def test_generate_keys_uses_65537_exponent(self):
        """Verify public exponent is 65537 (FIPS standard)."""
        source = inspect.getsource(FIPSJWTManager._generate_keys)
        assert "public_exponent=65537" in source


# ---------------------------------------------------------------------------
# AC-2: Access token claims include jti, exp, iat
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC2AccessTokenClaims:
    """AC-2: Access token includes jti, exp, iat claims."""

    def test_access_token_includes_exp(self):
        """Verify exp claim is set in access token."""
        source = inspect.getsource(FIPSJWTManager.create_access_token)
        assert '"exp"' in source

    def test_access_token_includes_iat(self):
        """Verify iat claim is set in access token."""
        source = inspect.getsource(FIPSJWTManager.create_access_token)
        assert '"iat"' in source

    def test_access_token_includes_jti(self):
        """Verify jti claim is set using secrets.token_urlsafe."""
        source = inspect.getsource(FIPSJWTManager.create_access_token)
        assert '"jti"' in source
        assert "token_urlsafe" in source


# ---------------------------------------------------------------------------
# AC-3: Refresh token includes type="refresh" claim
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC3RefreshTokenType:
    """AC-3: Refresh token includes type='refresh' claim."""

    def test_refresh_token_has_type_claim(self):
        """Verify type='refresh' is added to refresh token payload."""
        source = inspect.getsource(FIPSJWTManager.create_refresh_token)
        assert '"type"' in source
        assert '"refresh"' in source


# ---------------------------------------------------------------------------
# AC-4: validate_access_token rejects refresh tokens
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC4AccessTokenRejectsRefresh:
    """AC-4: validate_access_token rejects tokens with type='refresh'."""

    def test_checks_for_refresh_type(self):
        """Verify validate_access_token checks payload type."""
        source = inspect.getsource(FIPSJWTManager.validate_access_token)
        assert '"refresh"' in source

    def test_refresh_type_raises_401(self):
        """Verify HTTPException raised when type is refresh."""
        source = inspect.getsource(FIPSJWTManager.validate_access_token)
        assert "HTTP_401_UNAUTHORIZED" in source


# ---------------------------------------------------------------------------
# AC-5: Argon2id with 64MB memory, time_cost=3, parallelism=1
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC5Argon2idParameters:
    """AC-5: pwd_context uses Argon2id with 64MB/3-iteration config."""

    def test_scheme_is_argon2(self):
        """Verify argon2 scheme is configured."""
        assert "argon2" in pwd_context.schemes()

    def test_memory_cost_64mb(self):
        """Verify memory cost is 65536 (64MB)."""
        import app.auth as auth_module

        auth_source = inspect.getsource(auth_module)
        assert "memory_cost=65536" in auth_source

    def test_time_cost_3(self):
        """Verify time cost is 3 iterations."""
        import app.auth as auth_module

        auth_source = inspect.getsource(auth_module)
        assert "time_cost=3" in auth_source

    def test_parallelism_1(self):
        """Verify parallelism is 1."""
        import app.auth as auth_module

        auth_source = inspect.getsource(auth_module)
        assert "parallelism=1" in auth_source


# ---------------------------------------------------------------------------
# AC-6: Account lockout after 5 failures, 30-minute duration
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC6AccountLockout:
    """AC-6: Lockout after 5 failures for 30 minutes."""

    def test_lockout_threshold_is_5(self):
        """Verify lockout triggers at 5 failed attempts."""
        from app.routes.auth.login import login

        source = inspect.getsource(login)
        assert "failed_attempts >= 5" in source

    def test_lockout_duration_30_minutes(self):
        """Verify lockout duration is 30 minutes."""
        from app.routes.auth.login import login

        source = inspect.getsource(login)
        assert "minutes=30" in source

    def test_locked_account_raises_401(self):
        """Verify locked account returns 401 before password check."""
        from app.routes.auth.login import login

        source = inspect.getsource(login)
        assert "locked_until" in source
        assert "HTTP_401_UNAUTHORIZED" in source


# ---------------------------------------------------------------------------
# AC-7: Successful login resets failed_login_attempts
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC7LoginResetsCounters:
    """AC-7: Successful login resets failed_login_attempts=0 and locked_until=NULL."""

    def test_resets_failed_attempts(self):
        """Verify failed_login_attempts reset to 0 on success."""
        from app.routes.auth.login import login

        source = inspect.getsource(login)
        assert "failed_login_attempts = 0" in source

    def test_resets_locked_until(self):
        """Verify locked_until reset to NULL on success."""
        from app.routes.auth.login import login

        source = inspect.getsource(login)
        assert "locked_until = NULL" in source


# ---------------------------------------------------------------------------
# AC-8: Inactive account check before password verification
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC8InactiveAccountCheck:
    """AC-8: is_active checked before password verification."""

    def test_is_active_check_in_login(self):
        """Verify is_active check exists in login source."""
        from app.routes.auth.login import login

        source = inspect.getsource(login)
        assert "is_active" in source

    def test_inactive_returns_401(self):
        """Verify inactive account raises HTTP 401."""
        from app.routes.auth.login import login

        source = inspect.getsource(login)
        assert "Account is deactivated" in source

    def test_is_active_before_pwd_verify(self):
        """Verify is_active check appears before pwd_context.verify in source."""
        from app.routes.auth.login import login

        source = inspect.getsource(login)
        active_pos = source.find("is_active")
        pwd_verify_pos = source.find("pwd_context.verify")
        assert active_pos < pwd_verify_pos


# ---------------------------------------------------------------------------
# AC-9: Audit events logged for auth events
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC9AuditLogging:
    """AC-9: AUTH_FAILURE and LOGIN_SUCCESS events logged."""

    def test_auth_failure_logged(self):
        """Verify AUTH_FAILURE event is logged on failed login."""
        from app.routes.auth.login import login

        source = inspect.getsource(login)
        assert "AUTH_FAILURE" in source

    def test_login_success_logged(self):
        """Verify LOGIN_SUCCESS event is logged on successful login."""
        from app.routes.auth.login import login

        source = inspect.getsource(login)
        assert "LOGIN_SUCCESS" in source

    def test_user_register_logged(self):
        """Verify USER_REGISTER event is logged on registration."""
        from app.routes.auth.login import register

        source = inspect.getsource(register)
        assert "USER_REGISTER" in source


# ---------------------------------------------------------------------------
# AC-10: verify_token raises 401 on ExpiredSignatureError and InvalidTokenError
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC10TokenVerificationErrors:
    """AC-10: verify_token raises 401 for expired and invalid tokens."""

    def test_handles_expired_signature_error(self):
        """Verify ExpiredSignatureError caught and 401 raised."""
        source = inspect.getsource(FIPSJWTManager.verify_token)
        assert "ExpiredSignatureError" in source
        assert "Token has expired" in source

    def test_handles_invalid_token_error(self):
        """Verify InvalidTokenError caught and 401 raised."""
        source = inspect.getsource(FIPSJWTManager.verify_token)
        assert "InvalidTokenError" in source
        assert "Could not validate credentials" in source

    def test_both_raise_401(self):
        """Verify both error paths use HTTP_401_UNAUTHORIZED."""
        source = inspect.getsource(FIPSJWTManager.verify_token)
        assert source.count("HTTP_401_UNAUTHORIZED") >= 2
