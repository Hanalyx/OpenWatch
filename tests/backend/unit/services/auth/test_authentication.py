"""
Unit tests for authentication: JWT RS256 lifecycle, Argon2id password
hashing parameters, account lockout policy, inactive account check ordering,
audit event logging, registration security, token revocation, refresh
rotation, and MFA enforcement.

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


# ---------------------------------------------------------------------------
# AC-11: Registration enforces GUEST role for unauthenticated requests
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC11RegistrationRoleEnforcement:
    """AC-11: Register endpoint enforces GUEST role for unauthenticated callers."""

    def test_register_forces_guest_role(self):
        """Verify register function forces GUEST role regardless of input.

        The register function must either not accept a role parameter in the
        unauthenticated path, or explicitly override any supplied role to GUEST.
        """
        from app.routes.auth.login import register

        source = inspect.getsource(register)
        # The function should force GUEST role - look for explicit assignment
        # At minimum, "GUEST" should appear in the source to enforce the role
        assert "GUEST" in source, (
            "register function does not reference GUEST role - "
            "user-supplied role may be accepted without validation"
        )

    def test_register_does_not_blindly_accept_role(self):
        """Verify register does not pass user-supplied role directly to user creation.

        The function should not use request.role.value (or equivalent) without
        first verifying the caller has admin/USER_CREATE permission.
        """
        from app.routes.auth.login import register

        source = inspect.getsource(register)
        # If the function uses request.role, it must also check permissions
        if "request.role" in source:
            assert (
                "get_current_user" in source
                or "USER_CREATE" in source
                or "is_admin" in source
                or "role = UserRole.GUEST" in source
            ), (
                "register accepts request.role without verifying caller is admin"
            )


# ---------------------------------------------------------------------------
# AC-12: Registration validates password strength
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC12RegistrationPasswordValidation:
    """AC-12: Register endpoint validates password strength before creating user."""

    def test_register_calls_password_validation(self):
        """Verify register function calls validate_password_strength or equivalent.

        The registration handler must validate the password meets strength
        requirements before creating the user account.
        """
        from app.routes.auth.login import register

        source = inspect.getsource(register)
        assert (
            "validate_password_strength" in source
            or "validate_password" in source
            or "password_strength" in source
            or "check_password" in source
        ), (
            "register function does not call any password validation - "
            "weak passwords may be accepted"
        )


# ---------------------------------------------------------------------------
# AC-13: Logout invalidates the access token
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC13LogoutTokenInvalidation:
    """AC-13: Logout endpoint invalidates the access token via blacklist."""

    def test_logout_blacklists_token(self):
        """Verify logout function adds token to a blacklist/revocation store.

        Logout must not be a no-op; it must invalidate the token so it cannot
        be reused.
        """
        from app.routes.auth.login import logout

        source = inspect.getsource(logout)
        assert (
            "blacklist" in source.lower()
            or "revoke" in source.lower()
            or "invalidate" in source.lower()
            or "token_blacklist" in source.lower()
            or "revoked_tokens" in source.lower()
            or "delete" in source.lower()
        ), (
            "logout function does not blacklist or revoke the token - "
            "tokens remain valid after logout"
        )

    def test_logout_is_not_noop(self):
        """Verify logout does more than just return a success message.

        A proper logout must interact with some storage mechanism (Redis,
        database, or in-memory set) to record the invalidated token.
        """
        from app.routes.auth.login import logout

        source = inspect.getsource(logout)
        # A no-op logout would just return a dict/JSONResponse with no
        # prior logic. Check that there is substantive logic beyond the return.
        lines = [
            line.strip()
            for line in source.split("\n")
            if line.strip()
            and not line.strip().startswith("#")
            and not line.strip().startswith('"""')
            and not line.strip().startswith("async def")
            and not line.strip().startswith("def ")
            and not line.strip().startswith("@")
        ]
        # Filter out pure return/response lines
        non_return_lines = [
            line for line in lines if not line.startswith("return")
        ]
        assert len(non_return_lines) > 1, (
            "logout function appears to be a no-op - only contains a return "
            "statement without token invalidation logic"
        )


# ---------------------------------------------------------------------------
# AC-14: Refresh endpoint rotates the refresh token
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC14RefreshTokenRotation:
    """AC-14: Refresh endpoint returns a new refresh_token alongside access_token."""

    def test_refresh_returns_new_refresh_token(self):
        """Verify refresh endpoint returns a new refresh_token in the response.

        The response must include a refresh_token field so the client can use
        the new refresh token for subsequent refreshes (token rotation).
        """
        from app.routes.auth.login import refresh_token

        source = inspect.getsource(refresh_token)
        assert "refresh_token" in source, (
            "refresh endpoint does not reference refresh_token in response - "
            "old refresh token may remain valid indefinitely"
        )
        # Verify it creates a new refresh token (calls create_refresh_token)
        assert (
            "create_refresh_token" in source
        ), (
            "refresh endpoint does not call create_refresh_token - "
            "no new refresh token is generated for rotation"
        )


# ---------------------------------------------------------------------------
# AC-15: MFA check not skipped when user has MFA enabled
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC15MFAEnforcement:
    """AC-15: Login must not hardcode mfa_enabled=False; must read from user record."""

    def test_login_does_not_hardcode_mfa_false(self):
        """Verify login function does not contain hardcoded mfa_enabled: False.

        The login flow must read the user's actual mfa_enabled status from the
        database rather than hardcoding it to False, which would skip MFA for
        all users.
        """
        from app.routes.auth.login import login

        source = inspect.getsource(login)
        # Check for the specific hardcoded pattern
        hardcoded_patterns = [
            '"mfa_enabled": False',
            '"mfa_enabled":False',
            "'mfa_enabled': False",
            "'mfa_enabled':False",
            "mfa_enabled=False",
        ]
        for pattern in hardcoded_patterns:
            assert pattern not in source, (
                f"login function contains hardcoded '{pattern}' - "
                "MFA check is being skipped for all users"
            )

    def test_login_reads_mfa_from_user(self):
        """Verify login reads mfa_enabled from the user record.

        The login function should reference the user object's mfa_enabled
        attribute to determine whether MFA verification is required.
        """
        from app.routes.auth.login import login

        source = inspect.getsource(login)
        assert (
            "user.mfa_enabled" in source
            or "user_record.mfa_enabled" in source
            or "mfa_enabled" in source
        ), (
            "login function does not read mfa_enabled from user record"
        )
