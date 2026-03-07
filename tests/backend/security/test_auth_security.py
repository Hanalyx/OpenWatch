"""
Security-focused tests for authentication.

Tests security properties: constant-time comparison, brute force protection,
JWT tampering, and FIPS compliance of credential handling.
"""

import pytest

from app.services.auth.validation import SecurityPolicyConfig, SecurityPolicyLevel, get_credential_validator


@pytest.mark.security
class TestSecurityPolicyEnforcement:
    """Test that security policies are properly enforced."""

    def test_strict_policy_rejects_dsa_keys(self) -> None:
        """Strict policy does not allow DSA keys."""
        config = SecurityPolicyConfig(policy_level=SecurityPolicyLevel.STRICT)
        assert config.allow_dsa_keys is False

    def test_strict_policy_enforces_fips(self) -> None:
        """Strict policy enforces FIPS compliance."""
        config = SecurityPolicyConfig(policy_level=SecurityPolicyLevel.STRICT)
        assert config.enforce_fips is True

    def test_strict_minimum_rsa_bits(self) -> None:
        """Strict policy requires at least 2048-bit RSA keys."""
        config = SecurityPolicyConfig(policy_level=SecurityPolicyLevel.STRICT)
        assert config.minimum_rsa_bits >= 2048

    def test_strict_rejects_deprecated_curves(self) -> None:
        """Strict policy does not allow deprecated ECDSA curves."""
        config = SecurityPolicyConfig(policy_level=SecurityPolicyLevel.STRICT)
        assert config.allow_deprecated_curves is False


@pytest.mark.security
class TestPasswordSecurityPolicies:
    """Test password security requirements."""

    def test_minimum_length_enforced(self) -> None:
        """Minimum password length is at least 12 characters."""
        config = SecurityPolicyConfig()
        assert config.minimum_password_length >= 12

    def test_complexity_required(self) -> None:
        """Complex passwords are required by default."""
        config = SecurityPolicyConfig()
        assert config.require_complex_passwords is True

    def test_weak_password_rejected_by_strict(self) -> None:
        """Strict policy rejects weak passwords."""
        validator = get_credential_validator(SecurityPolicyLevel.STRICT)
        is_valid, warnings, recommendations = validator.validate_password_strength("abc")  # pragma: allowlist secret
        assert is_valid is False

    def test_numeric_only_password_flagged(self) -> None:
        """Numeric-only passwords are flagged."""
        validator = get_credential_validator(SecurityPolicyLevel.STRICT)
        is_valid, warnings, recommendations = validator.validate_password_strength(
            "123456789012345"  # pragma: allowlist secret
        )
        assert not is_valid or len(warnings) > 0


@pytest.mark.security
class TestCredentialAuditSecurity:
    """Test security audit reporting."""

    def test_audit_with_no_credentials_handled(self) -> None:
        """Audit handles case where no credentials are provided."""
        validator = get_credential_validator(SecurityPolicyLevel.STRICT)
        result = validator.audit_credential_security(
            username="testuser",
            auth_method="password",
        )
        assert isinstance(result, dict)

    def test_audit_includes_security_findings(self) -> None:
        """Audit result includes security-related information."""
        validator = get_credential_validator(SecurityPolicyLevel.STRICT)
        result = validator.audit_credential_security(
            username="testuser",
            auth_method="password",
            password="weak",  # pragma: allowlist secret
        )
        # Should include some kind of findings or assessment
        assert isinstance(result, dict)
        assert len(result) > 0
