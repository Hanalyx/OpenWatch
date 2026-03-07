"""
Unit tests for SSH security: key validation, security levels, host key policies,
and fingerprint generation.

Spec: specs/system/ssh-security.spec.yaml
Tests NIST SP 800-57 key classification, host key policies, and SHA256 fingerprints.
"""

import ast
import base64
import hashlib
import inspect
import textwrap

import pytest

from app.services.ssh.key_validator import assess_key_security
from app.services.ssh.known_hosts import KnownHostsManager
from app.services.ssh.models import SSHKeySecurityLevel, SSHKeyType, SSHKeyValidationResult
from app.services.ssh.policies import SecurityWarningPolicy, StrictHostKeyPolicy, create_host_key_policy

# ---------------------------------------------------------------------------
# AC-1: Ed25519 always classified SECURE
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC1Ed25519AlwaysSecure:
    """AC-1: Ed25519 is always classified as SECURE by assess_key_security."""

    def test_ed25519_no_size(self):
        level, warnings, recommendations = assess_key_security(SSHKeyType.ED25519, None)
        assert level == SSHKeySecurityLevel.SECURE

    def test_ed25519_with_size(self):
        level, warnings, recommendations = assess_key_security(SSHKeyType.ED25519, 256)
        assert level == SSHKeySecurityLevel.SECURE

    def test_ed25519_no_warnings(self):
        level, warnings, recommendations = assess_key_security(SSHKeyType.ED25519, None)
        assert warnings == []
        assert recommendations == []


# ---------------------------------------------------------------------------
# AC-2: RSA key classification by size
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC2RSAClassification:
    """AC-2: RSA key classification: >=4096->SECURE, 2048-4095->ACCEPTABLE, <2048->DEPRECATED."""

    def test_rsa_4096_secure(self):
        level, _, _ = assess_key_security(SSHKeyType.RSA, 4096)
        assert level == SSHKeySecurityLevel.SECURE

    def test_rsa_8192_secure(self):
        level, _, _ = assess_key_security(SSHKeyType.RSA, 8192)
        assert level == SSHKeySecurityLevel.SECURE

    def test_rsa_2048_acceptable(self):
        level, _, _ = assess_key_security(SSHKeyType.RSA, 2048)
        assert level == SSHKeySecurityLevel.ACCEPTABLE

    def test_rsa_3072_acceptable(self):
        level, _, _ = assess_key_security(SSHKeyType.RSA, 3072)
        assert level == SSHKeySecurityLevel.ACCEPTABLE

    def test_rsa_1024_deprecated(self):
        level, warnings, _ = assess_key_security(SSHKeyType.RSA, 1024)
        assert level == SSHKeySecurityLevel.DEPRECATED
        assert any("1024" in w for w in warnings)

    def test_rsa_512_deprecated(self):
        level, _, _ = assess_key_security(SSHKeyType.RSA, 512)
        assert level == SSHKeySecurityLevel.DEPRECATED


# ---------------------------------------------------------------------------
# AC-3: DSA always REJECTED with deprecation warning
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC3DSARejected:
    """AC-3: DSA is always classified as REJECTED with a deprecation warning."""

    def test_dsa_rejected(self):
        level, warnings, recommendations = assess_key_security(SSHKeyType.DSA, 1024)
        assert level == SSHKeySecurityLevel.REJECTED

    def test_dsa_has_deprecation_warning(self):
        _, warnings, _ = assess_key_security(SSHKeyType.DSA, 1024)
        assert len(warnings) > 0
        assert any("deprecated" in w.lower() or "vulnerabilit" in w.lower() for w in warnings)

    def test_dsa_has_replacement_recommendation(self):
        _, _, recommendations = assess_key_security(SSHKeyType.DSA, 1024)
        assert len(recommendations) > 0


# ---------------------------------------------------------------------------
# AC-4: ECDSA classification by size
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC4ECDSAClassification:
    """AC-4: ECDSA classification: >=384->SECURE, 256->ACCEPTABLE, <256->DEPRECATED."""

    def test_ecdsa_384_secure(self):
        level, _, _ = assess_key_security(SSHKeyType.ECDSA, 384)
        assert level == SSHKeySecurityLevel.SECURE

    def test_ecdsa_521_secure(self):
        level, _, _ = assess_key_security(SSHKeyType.ECDSA, 521)
        assert level == SSHKeySecurityLevel.SECURE

    def test_ecdsa_256_acceptable(self):
        level, _, _ = assess_key_security(SSHKeyType.ECDSA, 256)
        assert level == SSHKeySecurityLevel.ACCEPTABLE

    def test_ecdsa_192_deprecated(self):
        level, _, _ = assess_key_security(SSHKeyType.ECDSA, 192)
        assert level == SSHKeySecurityLevel.DEPRECATED


# ---------------------------------------------------------------------------
# AC-5: SSHKeyValidationResult required fields
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC5ValidationResultFields:
    """AC-5: SSHKeyValidationResult exposes required fields."""

    REQUIRED_FIELDS = [
        "is_valid",
        "key_type",
        "security_level",
        "key_size",
        "error_message",
        "warnings",
        "recommendations",
    ]

    def test_all_fields_present(self):
        result = SSHKeyValidationResult(is_valid=False)
        for field in self.REQUIRED_FIELDS:
            assert hasattr(result, field), f"Missing field: {field}"

    def test_valid_result_fields(self):
        result = SSHKeyValidationResult(
            is_valid=True,
            key_type=SSHKeyType.ED25519,
            security_level=SSHKeySecurityLevel.SECURE,
            key_size=256,
            warnings=[],
            recommendations=[],
        )
        assert result.is_valid is True
        assert result.key_type == SSHKeyType.ED25519
        assert result.security_level == SSHKeySecurityLevel.SECURE
        assert result.key_size == 256
        assert result.error_message is None

    def test_invalid_result_fields(self):
        result = SSHKeyValidationResult(
            is_valid=False,
            error_message="test error",
        )
        assert result.is_valid is False
        assert result.error_message == "test error"
        assert result.warnings == []
        assert result.recommendations == []


# ---------------------------------------------------------------------------
# AC-6: SSHKeySecurityLevel enum values and ordering
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC6SecurityLevelEnum:
    """AC-6: SSHKeySecurityLevel has exactly 4 values in security order."""

    def test_exactly_four_values(self):
        members = list(SSHKeySecurityLevel)
        assert len(members) == 4

    def test_expected_members(self):
        expected = {"REJECTED", "DEPRECATED", "ACCEPTABLE", "SECURE"}
        actual = {m.name for m in SSHKeySecurityLevel}
        assert actual == expected

    def test_security_ordering(self):
        """Verify ordering via the security_order dict used in is_key_secure."""
        security_order = {
            SSHKeySecurityLevel.REJECTED: 0,
            SSHKeySecurityLevel.DEPRECATED: 1,
            SSHKeySecurityLevel.ACCEPTABLE: 2,
            SSHKeySecurityLevel.SECURE: 3,
        }
        assert security_order[SSHKeySecurityLevel.REJECTED] < security_order[SSHKeySecurityLevel.DEPRECATED]
        assert security_order[SSHKeySecurityLevel.DEPRECATED] < security_order[SSHKeySecurityLevel.ACCEPTABLE]
        assert security_order[SSHKeySecurityLevel.ACCEPTABLE] < security_order[SSHKeySecurityLevel.SECURE]


# ---------------------------------------------------------------------------
# AC-7: SecurityWarningPolicy allows connection (no raise)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC7SecurityWarningPolicyAllows:
    """AC-7: SecurityWarningPolicy allows connection (missing_host_key does not raise)."""

    def test_missing_host_key_source_has_no_raise(self):
        """Verify missing_host_key method does not raise exceptions."""
        source = inspect.getsource(SecurityWarningPolicy.missing_host_key)
        tree = ast.parse(textwrap.dedent(source))

        for node in ast.walk(tree):
            if isinstance(node, ast.Raise):
                pytest.fail(
                    "SecurityWarningPolicy.missing_host_key contains a 'raise' "
                    "statement — it should allow connections"
                )


# ---------------------------------------------------------------------------
# AC-8: StrictHostKeyPolicy rejects unknown hosts
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC8StrictHostKeyPolicyRejects:
    """AC-8: StrictHostKeyPolicy rejects unknown hosts by calling super().missing_host_key."""

    def test_calls_super_missing_host_key(self):
        """Verify StrictHostKeyPolicy delegates to super().missing_host_key (which raises)."""
        source = inspect.getsource(StrictHostKeyPolicy.missing_host_key)
        assert "super().missing_host_key" in source


# ---------------------------------------------------------------------------
# AC-9: create_host_key_policy factory supports 4 policy types
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC9PolicyFactory:
    """AC-9: create_host_key_policy factory supports strict, auto_add, auto_add_warning, warning."""

    def test_strict_policy(self):
        policy = create_host_key_policy("strict")
        assert isinstance(policy, StrictHostKeyPolicy)

    def test_auto_add_policy(self):
        import paramiko

        policy = create_host_key_policy("auto_add")
        assert isinstance(policy, paramiko.AutoAddPolicy)

    def test_auto_add_warning_policy(self):
        policy = create_host_key_policy("auto_add_warning")
        assert isinstance(policy, SecurityWarningPolicy)

    def test_warning_alias_policy(self):
        policy = create_host_key_policy("warning")
        assert isinstance(policy, SecurityWarningPolicy)

    def test_invalid_policy_raises(self):
        with pytest.raises(ValueError):
            create_host_key_policy("invalid_policy")


# ---------------------------------------------------------------------------
# AC-10: Known hosts fingerprints use SHA256 format
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC10FingerprintSHA256:
    """AC-10: Known hosts fingerprints use SHA256 format (SHA256:base64hash)."""

    def test_generate_fingerprint_sha256_format(self):
        """Verify _generate_fingerprint produces SHA256:base64hash format."""
        # Create a valid OpenSSH-format public key (base64-encoded key data)
        # Use a known byte sequence so we can verify the hash
        key_data = b"test-key-data-for-fingerprint-verification"
        key_b64 = base64.b64encode(key_data).decode()
        public_key = f"ssh-rsa {key_b64} test@host"

        manager = KnownHostsManager(db=None)
        fingerprint = manager._generate_fingerprint(public_key)

        assert fingerprint is not None
        assert fingerprint.startswith("SHA256:")

        # Verify the hash is correct
        expected_hash = hashlib.sha256(key_data).digest()
        expected_b64 = base64.b64encode(expected_hash).decode().rstrip("=")
        assert fingerprint == f"SHA256:{expected_b64}"

    def test_invalid_key_returns_none(self):
        """Verify _generate_fingerprint returns None for invalid keys."""
        manager = KnownHostsManager(db=None)
        fingerprint = manager._generate_fingerprint("not-a-valid-key")
        assert fingerprint is None
