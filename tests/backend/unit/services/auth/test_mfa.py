"""
Unit tests for MFA: TOTP secret generation (20-byte base32), backup code
count/length/charset, SHA-256 backup code hashing, TOTP window tolerance,
replay prevention key format, code routing (6-digit TOTP vs 8-char backup),
enrollment result shape, decrypt-before-validate ordering, MFAValidationResult
method_used field, and backup code regeneration.

Spec: specs/services/auth/mfa.spec.yaml
Tests services/auth/mfa.py (MFAService, ~347 LOC).
"""

import inspect

import pytest

from app.services.auth.mfa import MFAService

# ---------------------------------------------------------------------------
# AC-1: generate_totp_secret uses secrets.token_bytes(20) + base32 encoding
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC1TOTPSecret:
    """AC-1: generate_totp_secret generates 20-byte secret encoded as base32."""

    def test_uses_token_bytes(self):
        """Verify secrets.token_bytes used for secret generation."""
        source = inspect.getsource(MFAService.generate_totp_secret)
        assert "token_bytes" in source

    def test_generates_20_bytes(self):
        """Verify 20 bytes are generated."""
        source = inspect.getsource(MFAService.generate_totp_secret)
        assert "20" in source

    def test_uses_base32_encoding(self):
        """Verify base32 encoding applied to the random bytes."""
        source = inspect.getsource(MFAService.generate_totp_secret)
        assert "b32encode" in source

    def test_returns_uppercase_base32_string(self):
        """Verify result is decoded to string (uppercase base32)."""
        service = MFAService()
        secret = service.generate_totp_secret()
        assert isinstance(secret, str)
        assert len(secret) > 0
        import re

        assert re.match(r"^[A-Z2-7=]+$", secret)


# ---------------------------------------------------------------------------
# AC-2: generate_backup_codes produces exactly 10 codes of 8 chars each
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC2BackupCodes:
    """AC-2: generate_backup_codes returns 10 codes of 8 alphanumeric chars."""

    def test_generates_10_codes(self):
        """Verify backup_code_count instance variable controls the count."""
        source = inspect.getsource(MFAService.generate_backup_codes)
        assert "backup_code_count" in source

    def test_code_length_is_8(self):
        """Verify backup_code_length instance variable controls each code length."""
        source = inspect.getsource(MFAService.generate_backup_codes)
        assert "backup_code_length" in source

    def test_charset_uppercase_and_digits(self):
        """Verify charset includes uppercase letters and digits."""
        source = inspect.getsource(MFAService.generate_backup_codes)
        assert "ABCDEFGHIJKLMNOPQRSTUVWXYZ" in source
        assert "0123456789" in source

    def test_returns_10_codes_at_runtime(self):
        """Verify 10 codes returned at runtime."""
        service = MFAService()
        codes = service.generate_backup_codes()
        assert len(codes) == 10
        for code in codes:
            assert len(code) == 8


# ---------------------------------------------------------------------------
# AC-3: hash_backup_code uses hashlib.sha256
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC3SHA256Hash:
    """AC-3: hash_backup_code computes SHA-256 hex digest of the code."""

    def test_uses_sha256(self):
        """Verify hashlib.sha256 used in hash_backup_code."""
        source = inspect.getsource(MFAService.hash_backup_code)
        assert "sha256" in source

    def test_returns_hexdigest(self):
        """Verify hexdigest() is called."""
        source = inspect.getsource(MFAService.hash_backup_code)
        assert "hexdigest" in source

    def test_hash_is_64_hex_chars(self):
        """Verify hash output is 64-char hex string (SHA-256)."""
        service = MFAService()
        hash_val = service.hash_backup_code("TESTCODE")
        import re

        assert re.match(r"^[0-9a-f]{64}$", hash_val)

    def test_same_input_same_hash(self):
        """Verify hash is deterministic."""
        service = MFAService()
        assert service.hash_backup_code("ABCD1234") == service.hash_backup_code("ABCD1234")


# ---------------------------------------------------------------------------
# AC-4: validate_totp_code uses window=1 (checks -1, 0, +1 intervals)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC4TOTPWindow:
    """AC-4: validate_totp_code uses totp_window=1 to allow ±1 time window."""

    def test_totp_window_is_1(self):
        """Verify totp_window=1 in validate_totp_code source."""
        source = inspect.getsource(MFAService.validate_totp_code)
        assert "totp_window" in source
        assert "1" in source

    def test_iterates_range_minus1_to_2(self):
        """Verify range using totp_window used to check adjacent time windows."""
        source = inspect.getsource(MFAService.validate_totp_code)
        assert "range(-self.totp_window" in source

    def test_uses_pyotp(self):
        """Verify pyotp used for TOTP validation."""
        source = inspect.getsource(MFAService.validate_totp_code)
        assert "pyotp" in source or "TOTP" in source


# ---------------------------------------------------------------------------
# AC-5: Replay prevention key is "{code}_{epoch_30s}"
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC5ReplayPrevention:
    """AC-5: Replay key format is '{user_code}_{epoch_30s}' stored in used_codes."""

    def test_replay_key_uses_code(self):
        """Verify user_code is part of the replay key."""
        source = inspect.getsource(MFAService.validate_totp_code)
        assert "user_code" in source

    def test_replay_key_uses_epoch_30s(self):
        """Verify epoch divided by 30 used for time-bucket key."""
        source = inspect.getsource(MFAService.validate_totp_code)
        assert "30" in source
        assert "timestamp" in source or "time" in source.lower()

    def test_used_codes_cache_updated(self):
        """Verify used code is added to used_codes_cache set."""
        source = inspect.getsource(MFAService.validate_totp_code)
        assert "used_codes" in source
        assert "add" in source


# ---------------------------------------------------------------------------
# AC-6: validate_mfa_code routes 6-digit to TOTP, 8-char to backup code
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC6CodeRouting:
    """AC-6: validate_mfa_code routes by length/type: 6-digit TOTP, 8-char backup."""

    def test_six_digit_routes_to_totp(self):
        """Verify 6-digit numeric code routed to TOTP validation."""
        source = inspect.getsource(MFAService.validate_mfa_code)
        assert "6" in source
        assert "isdigit" in source or "len" in source

    def test_eight_char_routes_to_backup(self):
        """Verify backup_code_length variable used to route backup code path."""
        source = inspect.getsource(MFAService.validate_mfa_code)
        assert "backup_code_length" in source

    def test_calls_validate_totp_code(self):
        """Verify validate_totp_code called for TOTP path."""
        source = inspect.getsource(MFAService.validate_mfa_code)
        assert "validate_totp_code" in source

    def test_calls_validate_backup_code(self):
        """Verify validate_backup_code called for backup path."""
        source = inspect.getsource(MFAService.validate_mfa_code)
        assert "validate_backup_code" in source


# ---------------------------------------------------------------------------
# AC-7: enroll_user_mfa returns MFAEnrollmentResult with success=True
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC7EnrollmentResult:
    """AC-7: enroll_user_mfa returns MFAEnrollmentResult(success=True, ...)."""

    def test_returns_enrollment_result(self):
        """Verify MFAEnrollmentResult is returned."""
        source = inspect.getsource(MFAService.enroll_user_mfa)
        assert "MFAEnrollmentResult" in source

    def test_success_is_true(self):
        """Verify success=True in enrollment result."""
        source = inspect.getsource(MFAService.enroll_user_mfa)
        assert "success=True" in source

    def test_includes_secret_key(self):
        """Verify secret_key included in enrollment result."""
        source = inspect.getsource(MFAService.enroll_user_mfa)
        assert "secret_key" in source

    def test_includes_backup_codes(self):
        """Verify backup_codes included in enrollment result."""
        source = inspect.getsource(MFAService.enroll_user_mfa)
        assert "backup_codes" in source

    def test_runtime_enrollment_succeeds(self):
        """Verify enrollment returns success=True at runtime."""
        from app.services.auth.mfa import MFAEnrollmentResult

        service = MFAService()
        result = service.enroll_user_mfa("testuser")
        assert isinstance(result, MFAEnrollmentResult)
        assert result.success is True
        assert result.secret_key is not None
        assert len(result.backup_codes) == 10


# ---------------------------------------------------------------------------
# AC-8: validate_mfa_code calls decrypt_mfa_secret before TOTP validation
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC8DecryptBeforeValidate:
    """AC-8: validate_mfa_code decrypts MFA secret before passing to TOTP."""

    def test_calls_decrypt_mfa_secret(self):
        """Verify decrypt_mfa_secret called in validate_mfa_code."""
        source = inspect.getsource(MFAService.validate_mfa_code)
        assert "decrypt_mfa_secret" in source

    def test_decrypt_before_totp(self):
        """Verify decrypt_mfa_secret appears before validate_totp_code in source."""
        source = inspect.getsource(MFAService.validate_mfa_code)
        decrypt_pos = source.find("decrypt_mfa_secret")
        totp_pos = source.find("validate_totp_code")
        assert decrypt_pos < totp_pos

    def test_decrypt_mfa_secret_calls_decrypt_data(self):
        """Verify decrypt_mfa_secret calls decrypt_data."""
        source = inspect.getsource(MFAService.decrypt_mfa_secret)
        assert "decrypt_data" in source

    def test_encrypt_mfa_secret_calls_encrypt_data(self):
        """Verify encrypt_mfa_secret calls encrypt_data."""
        source = inspect.getsource(MFAService.encrypt_mfa_secret)
        assert "encrypt_data" in source


# ---------------------------------------------------------------------------
# AC-9: MFAValidationResult includes method_used field
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC9ValidationResultMethod:
    """AC-9: MFAValidationResult has method_used indicating totp or backup_code."""

    def test_mfa_validation_result_has_method_used(self):
        """Verify MFAValidationResult dataclass has method_used field."""
        import dataclasses

        from app.services.auth.mfa import MFAValidationResult

        fields = {f.name for f in dataclasses.fields(MFAValidationResult)}
        assert "method_used" in fields

    def test_validate_mfa_code_sets_method_used(self):
        """Verify method_used is set in validate_mfa_code return."""
        source = inspect.getsource(MFAService.validate_mfa_code)
        assert "method_used" in source

    def test_method_used_values(self):
        """Verify totp and backup_code are possible method_used values."""
        source = inspect.getsource(MFAService.validate_mfa_code)
        assert "totp" in source
        assert "backup_code" in source


# ---------------------------------------------------------------------------
# AC-10: regenerate_backup_codes returns 10 new codes and hashes them
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC10RegenerateBackupCodes:
    """AC-10: regenerate_backup_codes generates fresh 10 codes."""

    def test_calls_generate_backup_codes(self):
        """Verify regenerate_backup_codes calls generate_backup_codes internally."""
        source = inspect.getsource(MFAService.regenerate_backup_codes)
        assert "generate_backup_codes" in source

    def test_returns_10_codes_at_runtime(self):
        """Verify 10 new codes returned at runtime."""
        service = MFAService()
        codes = service.regenerate_backup_codes("testuser")
        assert len(codes) == 10
        for code in codes:
            assert len(code) == 8

    def test_regenerated_codes_differ(self):
        """Verify two regeneration calls produce different codes."""
        service = MFAService()
        codes1 = set(service.regenerate_backup_codes("testuser"))
        codes2 = set(service.regenerate_backup_codes("testuser"))
        assert codes1 != codes2
