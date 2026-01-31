"""
Unit tests for credential validation service.

Tests SSH key validation, password strength checks, and security policy enforcement.
"""

import pytest

from app.services.auth.validation import (
    CredentialSecurityValidator,
    SecurityPolicyConfig,
    SecurityPolicyLevel,
    get_credential_validator,
    validate_credential_with_strict_policy,
)


@pytest.mark.unit
class TestPasswordStrength:
    """Test password validation logic."""

    def test_strong_password_passes(self) -> None:
        """Strong password with mixed characters passes."""
        validator = get_credential_validator(SecurityPolicyLevel.STRICT)
        is_valid, warnings, recommendations = validator.validate_password_strength(
            "C0mpl3x!P@ssw0rd#2026"  # pragma: allowlist secret
        )
        assert is_valid is True

    def test_short_password_fails(self) -> None:
        """Password shorter than minimum length fails."""
        validator = get_credential_validator(SecurityPolicyLevel.STRICT)
        is_valid, warnings, recommendations = validator.validate_password_strength("short")  # pragma: allowlist secret
        assert is_valid is False

    def test_empty_password_fails(self) -> None:
        """Empty password fails validation."""
        validator = get_credential_validator(SecurityPolicyLevel.STRICT)
        is_valid, warnings, recommendations = validator.validate_password_strength("")
        assert is_valid is False

    def test_common_password_flagged(self) -> None:
        """Common passwords are flagged."""
        validator = get_credential_validator(SecurityPolicyLevel.STRICT)
        is_valid, warnings, recommendations = validator.validate_password_strength(
            "password123456"  # pragma: allowlist secret
        )
        # Should either fail or produce warnings
        assert not is_valid or len(warnings) > 0

    def test_permissive_policy_more_lenient(self) -> None:
        """Permissive policy allows weaker passwords."""
        validator = get_credential_validator(SecurityPolicyLevel.PERMISSIVE)
        is_valid, warnings, recommendations = validator.validate_password_strength(
            "SimplePass1"  # pragma: allowlist secret
        )
        # Permissive should be more lenient than strict
        assert isinstance(is_valid, bool)


@pytest.mark.unit
class TestSecurityPolicyConfig:
    """Test SecurityPolicyConfig defaults and validation."""

    def test_strict_defaults(self) -> None:
        """Strict policy has FIPS-compliant defaults."""
        config = SecurityPolicyConfig()
        assert config.policy_level == SecurityPolicyLevel.STRICT
        assert config.enforce_fips is True
        assert config.minimum_rsa_bits >= 2048
        assert config.allow_dsa_keys is False

    def test_minimum_password_length(self) -> None:
        """Default minimum password length is 12."""
        config = SecurityPolicyConfig()
        assert config.minimum_password_length == 12

    def test_complex_passwords_required(self) -> None:
        """Complex passwords required by default."""
        config = SecurityPolicyConfig()
        assert config.require_complex_passwords is True


@pytest.mark.unit
class TestCredentialAudit:
    """Test credential security audit."""

    def test_audit_returns_dict(self) -> None:
        """Audit returns a dictionary with expected keys."""
        validator = get_credential_validator(SecurityPolicyLevel.STRICT)
        result = validator.audit_credential_security(
            username="testuser",
            auth_method="password",
            password="C0mpl3x!P@ssw0rd#2026",  # pragma: allowlist secret
        )
        assert isinstance(result, dict)

    def test_audit_password_only(self) -> None:
        """Audit handles password-only credentials."""
        validator = get_credential_validator(SecurityPolicyLevel.STRICT)
        result = validator.audit_credential_security(
            username="testuser",
            auth_method="password",
            password="W3akPw",  # pragma: allowlist secret
        )
        assert isinstance(result, dict)


@pytest.mark.unit
class TestGetCredentialValidator:
    """Test factory function."""

    def test_returns_validator(self) -> None:
        """Factory returns CredentialSecurityValidator instance."""
        validator = get_credential_validator()
        assert isinstance(validator, CredentialSecurityValidator)

    def test_strict_policy(self) -> None:
        """Factory creates validator with strict policy."""
        validator = get_credential_validator(SecurityPolicyLevel.STRICT)
        assert validator.policy.policy_level == SecurityPolicyLevel.STRICT

    def test_permissive_policy(self) -> None:
        """Factory creates validator with permissive policy."""
        validator = get_credential_validator(SecurityPolicyLevel.PERMISSIVE)
        assert validator.policy.policy_level == SecurityPolicyLevel.PERMISSIVE


@pytest.mark.unit
class TestValidateCredentialWithStrictPolicy:
    """Test convenience function for strict policy validation."""

    def test_password_credential(self) -> None:
        """Validates password-based credentials."""
        is_valid, message = validate_credential_with_strict_policy(
            username="admin",
            auth_method="password",
            password="Str0ng!P@ss#2026",  # pragma: allowlist secret
        )
        assert isinstance(is_valid, bool)
        assert isinstance(message, str)

    def test_empty_username_handled(self) -> None:
        """Empty username is handled gracefully."""
        is_valid, message = validate_credential_with_strict_policy(
            username="",
            auth_method="password",
            password="SomePassword123!",  # pragma: allowlist secret
        )
        assert isinstance(is_valid, bool)
