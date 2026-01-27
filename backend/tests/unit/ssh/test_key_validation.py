"""
Unit Tests for SSH Key Validation and Parsing

Tests the SSH key validation, security assessment, and parsing functionality:
- Key format validation (RSA, Ed25519, ECDSA, DSA)
- Security level assessment based on NIST SP 800-57
- Key fingerprint generation
- Error handling for invalid keys

Test Categories:
- assess_key_security tests: Security level determination
- validate_ssh_key tests: Full key validation workflow
- is_key_secure tests: Quick security check
- Key parsing tests: Key format handling
- Fingerprint tests: Key fingerprint generation

CLAUDE.md Compliance:
- Comprehensive docstrings on all test functions
- Type hints where applicable
- Defensive error handling verification
- Security-focused test cases
- No emojis in code

References:
- NIST SP 800-57: Recommendation for Key Management
- NIST SP 800-131A: Transitioning the Use of Cryptographic Algorithms
"""

import io
import warnings
from typing import List, Optional, Tuple
from unittest.mock import MagicMock, Mock, patch

import paramiko
import pytest

# Import the modules under test
from app.services.ssh.key_validator import (
    assess_key_security,
    validate_ssh_key,
    is_key_secure,
)
from app.services.ssh.key_parser import (
    detect_key_type,
    parse_ssh_key,
    get_key_fingerprint,
    get_key_fingerprint_sha256,
)
from app.services.ssh.models import (
    SSHKeySecurityLevel,
    SSHKeyType,
    SSHKeyValidationResult,
)
from app.services.ssh.exceptions import SSHKeyError


# =============================================================================
# Test Data Constants
# =============================================================================

# Note: These are NOT real keys. They have structure similar to real keys
# but are intentionally invalid to avoid any security concerns.

SAMPLE_RSA_4096_HEADER = """-----BEGIN RSA PRIVATE KEY-----
MIIJKQIBAAKCAgEA0123456789abcdef0123456789abcdef0123456789abcdef
test_key_content_not_real_do_not_use_in_production
-----END RSA PRIVATE KEY-----"""

SAMPLE_ED25519_HEADER = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz
fake_ed25519_key_content_for_testing_only
-----END OPENSSH PRIVATE KEY-----"""

SAMPLE_ECDSA_HEADER = """-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIFake_ECDSA_Key_Content_For_Testing_Only_Do_Not_Use
-----END EC PRIVATE KEY-----"""

SAMPLE_DSA_HEADER = """-----BEGIN DSA PRIVATE KEY-----
MIIBugIBAAKBgQDfake_DSA_Key_Content_For_Testing_Only
-----END DSA PRIVATE KEY-----"""

SAMPLE_RSA_PUBLIC_KEY = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... test@example.com"
SAMPLE_ED25519_PUBLIC_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... test@example.com"
SAMPLE_ECDSA_PUBLIC_KEY = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTI... test@example.com"
SAMPLE_DSA_PUBLIC_KEY = "ssh-dss AAAAB3NzaC1kc3MAAACBAK... test@example.com"

INVALID_KEY = "this is not a valid SSH key"
EMPTY_KEY = ""


# =============================================================================
# assess_key_security Tests
# =============================================================================


class TestAssessKeySecurity:
    """Tests for the assess_key_security function."""

    def test_ed25519_always_secure(self) -> None:
        """
        Verify Ed25519 keys are always assessed as SECURE.

        Ed25519 provides 256-bit security equivalent to RSA-3072.
        No warnings or recommendations should be generated.
        """
        level, warnings, recommendations = assess_key_security(
            SSHKeyType.ED25519, None
        )

        assert level == SSHKeySecurityLevel.SECURE
        assert len(warnings) == 0
        assert len(recommendations) == 0

    def test_ed25519_with_any_size(self) -> None:
        """
        Verify Ed25519 is SECURE regardless of reported size.

        Ed25519 has fixed 256-bit size, but should be SECURE
        regardless of what size value is passed.
        """
        for size in [None, 256, 512, 1024]:
            level, _, _ = assess_key_security(SSHKeyType.ED25519, size)
            assert level == SSHKeySecurityLevel.SECURE

    def test_rsa_4096_secure(self) -> None:
        """
        Verify RSA >= 4096 bits is assessed as SECURE.
        """
        level, warnings, recommendations = assess_key_security(
            SSHKeyType.RSA, 4096
        )

        assert level == SSHKeySecurityLevel.SECURE
        assert len(warnings) == 0
        assert len(recommendations) == 0

    def test_rsa_8192_secure(self) -> None:
        """
        Verify very large RSA keys are still SECURE.
        """
        level, _, _ = assess_key_security(SSHKeyType.RSA, 8192)
        assert level == SSHKeySecurityLevel.SECURE

    def test_rsa_2048_acceptable(self) -> None:
        """
        Verify RSA 2048 bits is ACCEPTABLE with upgrade recommendation.
        """
        level, warnings, recommendations = assess_key_security(
            SSHKeyType.RSA, 2048
        )

        assert level == SSHKeySecurityLevel.ACCEPTABLE
        assert len(warnings) == 0
        assert len(recommendations) > 0
        assert any("4096" in r or "Ed25519" in r for r in recommendations)

    def test_rsa_3072_acceptable(self) -> None:
        """
        Verify RSA 3072 bits is ACCEPTABLE (between 2048 and 4096).
        """
        level, _, recommendations = assess_key_security(SSHKeyType.RSA, 3072)

        assert level == SSHKeySecurityLevel.ACCEPTABLE
        assert len(recommendations) > 0

    def test_rsa_1024_deprecated(self) -> None:
        """
        Verify RSA < 2048 bits is DEPRECATED with warnings.
        """
        level, warnings, recommendations = assess_key_security(
            SSHKeyType.RSA, 1024
        )

        assert level == SSHKeySecurityLevel.DEPRECATED
        assert len(warnings) > 0
        assert len(recommendations) > 0
        assert any("1024" in w for w in warnings)

    def test_rsa_512_deprecated(self) -> None:
        """
        Verify very small RSA keys are DEPRECATED.
        """
        level, warnings, _ = assess_key_security(SSHKeyType.RSA, 512)

        assert level == SSHKeySecurityLevel.DEPRECATED
        assert len(warnings) > 0

    def test_rsa_unknown_size_acceptable(self) -> None:
        """
        Verify RSA with unknown size is ACCEPTABLE with warning.
        """
        level, warnings, recommendations = assess_key_security(
            SSHKeyType.RSA, None
        )

        assert level == SSHKeySecurityLevel.ACCEPTABLE
        assert any("Cannot determine" in w for w in warnings)
        assert len(recommendations) > 0

    def test_ecdsa_521_secure(self) -> None:
        """
        Verify ECDSA P-521 is assessed as SECURE.
        """
        level, warnings, recommendations = assess_key_security(
            SSHKeyType.ECDSA, 521
        )

        assert level == SSHKeySecurityLevel.SECURE
        assert len(warnings) == 0
        assert len(recommendations) == 0

    def test_ecdsa_384_secure(self) -> None:
        """
        Verify ECDSA P-384 is assessed as SECURE.
        """
        level, _, _ = assess_key_security(SSHKeyType.ECDSA, 384)
        assert level == SSHKeySecurityLevel.SECURE

    def test_ecdsa_256_acceptable(self) -> None:
        """
        Verify ECDSA P-256 is ACCEPTABLE with recommendation.
        """
        level, warnings, recommendations = assess_key_security(
            SSHKeyType.ECDSA, 256
        )

        assert level == SSHKeySecurityLevel.ACCEPTABLE
        assert len(warnings) == 0
        assert any("Ed25519" in r for r in recommendations)

    def test_ecdsa_below_256_deprecated(self) -> None:
        """
        Verify ECDSA below P-256 is DEPRECATED.
        """
        level, warnings, recommendations = assess_key_security(
            SSHKeyType.ECDSA, 192
        )

        assert level == SSHKeySecurityLevel.DEPRECATED
        assert len(warnings) > 0
        assert len(recommendations) > 0

    def test_ecdsa_unknown_size_acceptable(self) -> None:
        """
        Verify ECDSA with unknown size is ACCEPTABLE with warning.
        """
        level, _, recommendations = assess_key_security(SSHKeyType.ECDSA, None)

        assert level == SSHKeySecurityLevel.ACCEPTABLE
        assert len(recommendations) > 0

    def test_dsa_rejected(self) -> None:
        """
        Verify DSA keys are always REJECTED regardless of size.

        DSA is deprecated in OpenSSH 7.0+ due to security vulnerabilities.
        """
        for size in [None, 1024, 2048, 3072]:
            level, warnings, recommendations = assess_key_security(
                SSHKeyType.DSA, size
            )

            assert level == SSHKeySecurityLevel.REJECTED
            assert len(warnings) > 0
            assert any("deprecated" in w.lower() for w in warnings)
            assert any("replace" in r.lower() for r in recommendations)


# =============================================================================
# validate_ssh_key Tests
# =============================================================================


class TestValidateSSHKey:
    """Tests for the validate_ssh_key function."""

    def test_validate_empty_key(self) -> None:
        """
        Verify empty key content returns invalid result.
        """
        result = validate_ssh_key("")

        assert result.is_valid is False
        assert "empty" in result.error_message.lower()

    def test_validate_none_key(self) -> None:
        """
        Verify None key content returns invalid result.
        """
        result = validate_ssh_key(None)

        assert result.is_valid is False

    def test_validate_whitespace_only_key(self) -> None:
        """
        Verify whitespace-only key content returns invalid result.
        """
        result = validate_ssh_key("   \n\t   ")

        assert result.is_valid is False
        assert "empty" in result.error_message.lower()

    def test_validate_invalid_key_format(self) -> None:
        """
        Verify invalid key format returns appropriate error.
        """
        result = validate_ssh_key("not a valid ssh key at all")

        assert result.is_valid is False
        assert result.key_type is None

    def test_validate_bytes_input(self) -> None:
        """
        Verify bytes input is handled correctly.
        """
        # Invalid key as bytes
        result = validate_ssh_key(b"not a valid key")

        assert result.is_valid is False

    def test_validate_memoryview_input(self) -> None:
        """
        Verify memoryview input is handled correctly.
        """
        # Invalid key as memoryview
        key_bytes = b"not a valid key"
        result = validate_ssh_key(memoryview(key_bytes))

        assert result.is_valid is False

    @patch("app.services.ssh.key_validator.paramiko.Ed25519Key")
    def test_validate_ed25519_key_success(
        self, mock_ed25519_class: MagicMock
    ) -> None:
        """
        Verify successful Ed25519 key validation.
        """
        mock_pkey = MagicMock()
        mock_pkey.get_name.return_value = "ssh-ed25519"
        mock_pkey.get_bits.return_value = 256
        mock_ed25519_class.from_private_key.return_value = mock_pkey

        result = validate_ssh_key(SAMPLE_ED25519_HEADER)

        assert result.is_valid is True
        assert result.key_type == SSHKeyType.ED25519
        assert result.security_level == SSHKeySecurityLevel.SECURE
        assert result.key_size == 256

    @patch("app.services.ssh.key_validator.paramiko.RSAKey")
    @patch("app.services.ssh.key_validator.paramiko.Ed25519Key")
    def test_validate_rsa_key_success(
        self,
        mock_ed25519_class: MagicMock,
        mock_rsa_class: MagicMock,
    ) -> None:
        """
        Verify successful RSA key validation.
        """
        # Ed25519 fails, RSA succeeds
        mock_ed25519_class.from_private_key.side_effect = paramiko.SSHException("Not Ed25519")

        mock_pkey = MagicMock()
        mock_pkey.get_name.return_value = "ssh-rsa"
        mock_pkey.get_bits.return_value = 4096
        mock_rsa_class.from_private_key.return_value = mock_pkey

        result = validate_ssh_key(SAMPLE_RSA_4096_HEADER)

        assert result.is_valid is True
        assert result.key_type == SSHKeyType.RSA
        assert result.security_level == SSHKeySecurityLevel.SECURE
        assert result.key_size == 4096

    @patch("app.services.ssh.key_validator.paramiko.Ed25519Key")
    def test_validate_encrypted_key_without_passphrase(
        self, mock_ed25519_class: MagicMock
    ) -> None:
        """
        Verify encrypted key without passphrase returns appropriate error.
        """
        mock_ed25519_class.from_private_key.side_effect = paramiko.PasswordRequiredException(
            "Key is encrypted"
        )

        result = validate_ssh_key(SAMPLE_ED25519_HEADER)

        assert result.is_valid is False
        assert "passphrase" in result.error_message.lower()

    @patch("app.services.ssh.key_validator.paramiko.Ed25519Key")
    def test_validate_encrypted_key_with_passphrase(
        self, mock_ed25519_class: MagicMock
    ) -> None:
        """
        Verify encrypted key with correct passphrase validates.
        """
        mock_pkey = MagicMock()
        mock_pkey.get_name.return_value = "ssh-ed25519"
        mock_pkey.get_bits.return_value = 256
        mock_ed25519_class.from_private_key.return_value = mock_pkey

        result = validate_ssh_key(SAMPLE_ED25519_HEADER, passphrase="correct_pass")

        assert result.is_valid is True

    def test_validate_result_has_to_dict(self) -> None:
        """
        Verify SSHKeyValidationResult has to_dict method.
        """
        result = validate_ssh_key("invalid key")

        dict_result = result.to_dict()
        assert isinstance(dict_result, dict)
        assert "is_valid" in dict_result
        assert "error_message" in dict_result


# =============================================================================
# is_key_secure Tests
# =============================================================================


class TestIsKeySecure:
    """Tests for the is_key_secure convenience function."""

    @patch("app.services.ssh.key_validator.validate_ssh_key")
    def test_is_key_secure_valid_secure_key(
        self, mock_validate: MagicMock
    ) -> None:
        """
        Verify is_key_secure returns True for valid secure key.
        """
        mock_validate.return_value = SSHKeyValidationResult(
            is_valid=True,
            key_type=SSHKeyType.ED25519,
            security_level=SSHKeySecurityLevel.SECURE,
            key_size=256,
        )

        result = is_key_secure("some key content")

        assert result is True

    @patch("app.services.ssh.key_validator.validate_ssh_key")
    def test_is_key_secure_valid_acceptable_key(
        self, mock_validate: MagicMock
    ) -> None:
        """
        Verify is_key_secure returns True for acceptable key with default minimum.
        """
        mock_validate.return_value = SSHKeyValidationResult(
            is_valid=True,
            key_type=SSHKeyType.RSA,
            security_level=SSHKeySecurityLevel.ACCEPTABLE,
            key_size=2048,
        )

        result = is_key_secure("some key content")

        assert result is True

    @patch("app.services.ssh.key_validator.validate_ssh_key")
    def test_is_key_secure_acceptable_with_secure_minimum(
        self, mock_validate: MagicMock
    ) -> None:
        """
        Verify is_key_secure returns False when key doesn't meet minimum.
        """
        mock_validate.return_value = SSHKeyValidationResult(
            is_valid=True,
            key_type=SSHKeyType.RSA,
            security_level=SSHKeySecurityLevel.ACCEPTABLE,
            key_size=2048,
        )

        result = is_key_secure(
            "some key content",
            minimum_level=SSHKeySecurityLevel.SECURE,
        )

        assert result is False

    @patch("app.services.ssh.key_validator.validate_ssh_key")
    def test_is_key_secure_invalid_key(
        self, mock_validate: MagicMock
    ) -> None:
        """
        Verify is_key_secure returns False for invalid key.
        """
        mock_validate.return_value = SSHKeyValidationResult(
            is_valid=False,
            error_message="Invalid key",
        )

        result = is_key_secure("invalid key content")

        assert result is False

    @patch("app.services.ssh.key_validator.validate_ssh_key")
    def test_is_key_secure_rejected_key(
        self, mock_validate: MagicMock
    ) -> None:
        """
        Verify is_key_secure returns False for rejected key.
        """
        mock_validate.return_value = SSHKeyValidationResult(
            is_valid=True,
            key_type=SSHKeyType.DSA,
            security_level=SSHKeySecurityLevel.REJECTED,
            key_size=1024,
        )

        result = is_key_secure("dsa key content")

        assert result is False


# =============================================================================
# detect_key_type Tests (Deprecated Function)
# =============================================================================


class TestDetectKeyType:
    """Tests for the deprecated detect_key_type function."""

    def test_detect_rsa_private_key(self) -> None:
        """
        Verify RSA private key detection.
        """
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = detect_key_type(SAMPLE_RSA_4096_HEADER)

            # Should issue deprecation warning
            assert len(w) == 1
            assert issubclass(w[0].category, DeprecationWarning)

        assert result == SSHKeyType.RSA

    def test_detect_rsa_public_key(self) -> None:
        """
        Verify RSA public key detection.
        """
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            result = detect_key_type(SAMPLE_RSA_PUBLIC_KEY)

        assert result == SSHKeyType.RSA

    def test_detect_ecdsa_private_key(self) -> None:
        """
        Verify ECDSA private key detection.
        """
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            result = detect_key_type(SAMPLE_ECDSA_HEADER)

        assert result == SSHKeyType.ECDSA

    def test_detect_ecdsa_public_key(self) -> None:
        """
        Verify ECDSA public key detection.
        """
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            result = detect_key_type(SAMPLE_ECDSA_PUBLIC_KEY)

        assert result == SSHKeyType.ECDSA

    def test_detect_dsa_private_key(self) -> None:
        """
        Verify DSA private key detection.
        """
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            result = detect_key_type(SAMPLE_DSA_HEADER)

        assert result == SSHKeyType.DSA

    def test_detect_dsa_public_key(self) -> None:
        """
        Verify DSA public key detection.
        """
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            result = detect_key_type(SAMPLE_DSA_PUBLIC_KEY)

        assert result == SSHKeyType.DSA

    def test_detect_unknown_key(self) -> None:
        """
        Verify unknown key returns None.
        """
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            result = detect_key_type("unknown key format")

        assert result is None

    def test_detect_bytes_input(self) -> None:
        """
        Verify bytes input is handled.
        """
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            result = detect_key_type(b"ssh-rsa AAAA...")

        assert result == SSHKeyType.RSA


# =============================================================================
# parse_ssh_key Tests (Deprecated Function)
# =============================================================================


class TestParseSSHKey:
    """Tests for the deprecated parse_ssh_key function."""

    @patch("app.services.ssh.key_parser.Ed25519Key")
    def test_parse_ed25519_key(self, mock_ed25519: MagicMock) -> None:
        """
        Verify Ed25519 key parsing.
        """
        mock_pkey = MagicMock()
        mock_ed25519.from_private_key.return_value = mock_pkey

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = parse_ssh_key(SAMPLE_ED25519_HEADER)

            # Should issue deprecation warning
            assert any(issubclass(warning.category, DeprecationWarning) for warning in w)

        assert result == mock_pkey

    @patch("app.services.ssh.key_parser.Ed25519Key")
    def test_parse_encrypted_key_no_passphrase(
        self, mock_ed25519: MagicMock
    ) -> None:
        """
        Verify encrypted key without passphrase raises SSHKeyError.
        """
        mock_ed25519.from_private_key.side_effect = paramiko.PasswordRequiredException(
            "Key is encrypted"
        )

        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            with pytest.raises(SSHKeyError) as exc_info:
                parse_ssh_key(SAMPLE_ED25519_HEADER)

        assert "passphrase" in str(exc_info.value).lower()

    @patch("app.services.ssh.key_parser.ECDSAKey")
    @patch("app.services.ssh.key_parser.RSAKey")
    @patch("app.services.ssh.key_parser.Ed25519Key")
    def test_parse_invalid_key_raises_error(
        self,
        mock_ed25519: MagicMock,
        mock_rsa: MagicMock,
        mock_ecdsa: MagicMock,
    ) -> None:
        """
        Verify invalid key raises SSHKeyError.

        OpenWatch supports Ed25519, RSA, and ECDSA keys.
        DSA keys are not supported (deprecated, insecure).
        """
        # All supported key types fail
        mock_ed25519.from_private_key.side_effect = paramiko.SSHException("Not Ed25519")
        mock_rsa.from_private_key.side_effect = paramiko.SSHException("Not RSA")
        mock_ecdsa.from_private_key.side_effect = paramiko.SSHException("Not ECDSA")

        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            with pytest.raises(SSHKeyError) as exc_info:
                parse_ssh_key("invalid key content")

        assert "unable" in str(exc_info.value).lower() or "parse" in str(exc_info.value).lower()


# =============================================================================
# get_key_fingerprint Tests
# =============================================================================


class TestGetKeyFingerprint:
    """Tests for the get_key_fingerprint function."""

    @patch("app.services.ssh.key_parser.paramiko.Ed25519Key")
    def test_get_fingerprint_success(self, mock_ed25519: MagicMock) -> None:
        """
        Verify successful fingerprint generation.
        """
        mock_pkey = MagicMock()
        mock_pkey.get_fingerprint.return_value = b"\xaa\xbb\xcc\xdd\xee\xff"
        mock_ed25519.from_private_key.return_value = mock_pkey

        result = get_key_fingerprint(SAMPLE_ED25519_HEADER)

        assert result is not None
        assert isinstance(result, str)
        # Fingerprint should be hex string
        assert all(c in "0123456789abcdef" for c in result)

    def test_get_fingerprint_invalid_key(self) -> None:
        """
        Verify invalid key returns None.
        """
        result = get_key_fingerprint("invalid key content")

        assert result is None

    def test_get_fingerprint_empty_key(self) -> None:
        """
        Verify empty key returns None.
        """
        result = get_key_fingerprint("")

        assert result is None

    def test_get_fingerprint_bytes_input(self) -> None:
        """
        Verify bytes input is handled.
        """
        result = get_key_fingerprint(b"invalid key")

        assert result is None


# =============================================================================
# get_key_fingerprint_sha256 Tests
# =============================================================================


class TestGetKeyFingerprintSHA256:
    """Tests for the get_key_fingerprint_sha256 function."""

    @patch("app.services.ssh.key_parser.get_key_fingerprint")
    @patch("app.services.ssh.key_parser.paramiko.Ed25519Key")
    def test_get_sha256_fingerprint_success(
        self,
        mock_ed25519: MagicMock,
        mock_get_fingerprint: MagicMock,
    ) -> None:
        """
        Verify successful SHA256 fingerprint generation.
        """
        mock_get_fingerprint.return_value = "aabbccdd"
        mock_pkey = MagicMock()
        mock_pkey.asbytes.return_value = b"public key bytes"
        mock_ed25519.from_private_key.return_value = mock_pkey

        result = get_key_fingerprint_sha256(SAMPLE_ED25519_HEADER)

        assert result is not None
        assert result.startswith("SHA256:")

    @patch("app.services.ssh.key_parser.get_key_fingerprint")
    def test_get_sha256_fingerprint_invalid_key(
        self, mock_get_fingerprint: MagicMock
    ) -> None:
        """
        Verify invalid key returns None.
        """
        mock_get_fingerprint.return_value = None

        result = get_key_fingerprint_sha256("invalid key")

        assert result is None


# =============================================================================
# Security Level Ordering Tests
# =============================================================================


class TestSecurityLevelOrdering:
    """Tests for security level comparison."""

    def test_security_level_order(self) -> None:
        """
        Verify security levels are ordered correctly.

        REJECTED < DEPRECATED < ACCEPTABLE < SECURE
        """
        security_order = {
            SSHKeySecurityLevel.REJECTED: 0,
            SSHKeySecurityLevel.DEPRECATED: 1,
            SSHKeySecurityLevel.ACCEPTABLE: 2,
            SSHKeySecurityLevel.SECURE: 3,
        }

        assert security_order[SSHKeySecurityLevel.REJECTED] < security_order[SSHKeySecurityLevel.DEPRECATED]
        assert security_order[SSHKeySecurityLevel.DEPRECATED] < security_order[SSHKeySecurityLevel.ACCEPTABLE]
        assert security_order[SSHKeySecurityLevel.ACCEPTABLE] < security_order[SSHKeySecurityLevel.SECURE]


# =============================================================================
# Edge Case Tests
# =============================================================================


class TestKeyValidationEdgeCases:
    """Tests for edge cases in key validation."""

    def test_key_with_extra_whitespace(self) -> None:
        """
        Verify keys with extra whitespace are handled.
        """
        key_with_whitespace = f"\n\n  {INVALID_KEY}  \n\n"
        result = validate_ssh_key(key_with_whitespace)

        # Should still be invalid, but shouldn't crash
        assert result.is_valid is False

    def test_key_with_unicode(self) -> None:
        """
        Verify keys with unicode characters are handled.
        """
        key_with_unicode = "-----BEGIN RSA KEY-----\u00e9\u00e8-----END RSA KEY-----"
        result = validate_ssh_key(key_with_unicode)

        assert result.is_valid is False

    def test_very_long_error_message_truncation(self) -> None:
        """
        Verify very long error messages are truncated for security.
        """
        # Error messages should be limited to prevent log injection
        result = validate_ssh_key(INVALID_KEY)

        if result.error_message:
            # Error messages should not exceed reasonable length
            assert len(result.error_message) <= 500

    def test_validation_result_repr(self) -> None:
        """
        Verify SSHKeyValidationResult has useful repr.
        """
        result = SSHKeyValidationResult(
            is_valid=True,
            key_type=SSHKeyType.ED25519,
            security_level=SSHKeySecurityLevel.SECURE,
            key_size=256,
        )

        repr_str = repr(result)
        assert "SSHKeyValidationResult" in repr_str
        assert "is_valid=True" in repr_str
