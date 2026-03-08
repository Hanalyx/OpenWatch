"""
Unit tests for encryption: AES-256-GCM algorithm parameters, PBKDF2 key
derivation defaults, ciphertext format (salt+nonce+ciphertext), per-call
randomness, minimum length validation, KDF iteration floor, credential
base64 storage, MFA secret encryption, typed error hierarchy, and soft
delete/purge retention policy.

Spec: specs/system/encryption.spec.yaml
Tests encryption/service.py, encryption/config.py,
services/auth/credential_service.py, and services/auth/mfa.py.
"""

import inspect

import pytest

from app.encryption.config import DEFAULT_CONFIG, EncryptionConfig, KDFAlgorithm
from app.encryption.exceptions import DecryptionError, InvalidDataError
from app.encryption.service import EncryptionService

# ---------------------------------------------------------------------------
# AC-1: AES-256-GCM with 32-byte key
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC1AES256GCM:
    """AC-1: EncryptionService uses AESGCM with key_length=32."""

    def test_uses_aesgcm(self):
        """Verify AESGCM is used in encrypt method."""
        source = inspect.getsource(EncryptionService.encrypt)
        assert "AESGCM" in source

    def test_key_length_32(self):
        """Verify default key_length is 32 bytes (AES-256)."""
        assert DEFAULT_CONFIG.key_length == 32

    def test_nonce_length_12(self):
        """Verify nonce_length is 12 bytes (GCM standard)."""
        assert DEFAULT_CONFIG.nonce_length == 12


# ---------------------------------------------------------------------------
# AC-2: Default KDF is PBKDF2-SHA256 with 100,000 iterations
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC2KDFDefaults:
    """AC-2: Default EncryptionConfig has 100,000 iterations and SHA256."""

    def test_default_iterations_100000(self):
        """Verify default kdf_iterations is 100,000."""
        assert DEFAULT_CONFIG.kdf_iterations == 100000

    def test_default_algorithm_sha256(self):
        """Verify default kdf_algorithm is SHA256."""
        assert DEFAULT_CONFIG.kdf_algorithm == KDFAlgorithm.SHA256

    def test_pbkdf2hmac_used_in_derive_key(self):
        """Verify PBKDF2HMAC is used for key derivation."""
        source = inspect.getsource(EncryptionService._derive_key)
        assert "PBKDF2HMAC" in source


# ---------------------------------------------------------------------------
# AC-3: Ciphertext format is salt+nonce+ciphertext_with_tag
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC3CiphertextFormat:
    """AC-3: Encrypt output is salt(16)+nonce(12)+ciphertext_with_tag."""

    def test_encrypt_combines_salt_nonce_ciphertext(self):
        """Verify salt + nonce + ciphertext concatenation in encrypt."""
        source = inspect.getsource(EncryptionService.encrypt)
        assert "salt + nonce + ciphertext" in source

    def test_decrypt_extracts_salt_then_nonce(self):
        """Verify decrypt extracts salt then nonce using config lengths."""
        source = inspect.getsource(EncryptionService.decrypt)
        assert "salt_length" in source
        assert "nonce_length" in source

    def test_default_salt_length_16(self):
        """Verify default salt_length is 16 bytes."""
        assert DEFAULT_CONFIG.salt_length == 16


# ---------------------------------------------------------------------------
# AC-4: Random salt and nonce per encryption (different ciphertext)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC4RandomSaltAndNonce:
    """AC-4: Each encrypt call generates fresh random salt and nonce."""

    def test_os_urandom_for_salt(self):
        """Verify os.urandom used to generate salt."""
        source = inspect.getsource(EncryptionService.encrypt)
        assert "os.urandom" in source

    def test_two_encryptions_differ(self):
        """Verify two encryptions of same plaintext produce different output."""
        service = EncryptionService(master_key="test-key-for-unit-test")
        plaintext = b"identical plaintext"
        enc1 = service.encrypt(plaintext)
        enc2 = service.encrypt(plaintext)
        assert enc1 != enc2


# ---------------------------------------------------------------------------
# AC-5: min_encrypted_data_length = salt + nonce + 16 (GCM tag)
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC5MinimumLength:
    """AC-5: min_encrypted_data_length equals salt_length + nonce_length + 16."""

    def test_min_length_formula(self):
        """Verify min_encrypted_data_length equals salt + nonce + 16."""
        config = EncryptionConfig()
        expected = config.salt_length + config.nonce_length + 16
        assert config.min_encrypted_data_length == expected

    def test_default_min_length_is_44(self):
        """Verify default min length is 16+12+16=44 bytes."""
        assert DEFAULT_CONFIG.min_encrypted_data_length == 44


# ---------------------------------------------------------------------------
# AC-6: kdf_iterations < 10000 raises ValueError
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC6KDFIterationFloor:
    """AC-6: EncryptionConfig validates kdf_iterations >= 10,000."""

    def test_below_minimum_raises_value_error(self):
        """Verify ValueError raised when kdf_iterations < 10000."""
        with pytest.raises(ValueError, match="10000"):
            EncryptionConfig(kdf_iterations=9999)

    def test_minimum_iterations_accepted(self):
        """Verify kdf_iterations=10000 is accepted."""
        config = EncryptionConfig(kdf_iterations=10000)
        assert config.kdf_iterations == 10000

    def test_validate_checks_iteration_floor(self):
        """Verify validate() source checks iteration minimum."""
        source = inspect.getsource(EncryptionConfig.validate)
        assert "10000" in source


# ---------------------------------------------------------------------------
# AC-7: CentralizedAuthService stores credentials as base64
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC7Base64Storage:
    """AC-7: Encrypted credentials stored as base64-encoded strings."""

    def test_store_credential_encodes_base64(self):
        """Verify base64.b64encode used when storing credentials."""
        from app.services.auth.credential_service import CentralizedAuthService

        source = inspect.getsource(CentralizedAuthService.store_credential)
        assert "b64encode" in source

    def test_decrypt_field_decodes_base64(self):
        """Verify base64.b64decode used when decrypting credentials."""
        from app.services.auth.credential_service import CentralizedAuthService

        source = inspect.getsource(CentralizedAuthService._decrypt_field)
        assert "b64decode" in source


# ---------------------------------------------------------------------------
# AC-8: MFA secrets encrypted at rest
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC8MFASecretEncryption:
    """AC-8: MFAService encrypts secret before storage, decrypts before use."""

    def test_encrypt_mfa_secret_calls_encrypt_data(self):
        """Verify encrypt_mfa_secret calls encrypt_data."""
        from app.services.auth.mfa import MFAService

        source = inspect.getsource(MFAService.encrypt_mfa_secret)
        assert "encrypt_data" in source

    def test_decrypt_mfa_secret_calls_decrypt_data(self):
        """Verify decrypt_mfa_secret calls decrypt_data."""
        from app.services.auth.mfa import MFAService

        source = inspect.getsource(MFAService.decrypt_mfa_secret)
        assert "decrypt_data" in source

    def test_validate_mfa_code_decrypts_before_totp(self):
        """Verify validate_mfa_code decrypts secret before TOTP validation."""
        from app.services.auth.mfa import MFAService

        source = inspect.getsource(MFAService.validate_mfa_code)
        assert "decrypt_mfa_secret" in source


# ---------------------------------------------------------------------------
# AC-9: InvalidDataError on short data, DecryptionError on bad key
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC9TypedExceptions:
    """AC-9: decrypt raises InvalidDataError for short data, DecryptionError otherwise."""

    def test_invalid_data_error_on_short_input(self):
        """Verify InvalidDataError raised when input too short."""
        service = EncryptionService(master_key="test-key-for-unit-test")
        with pytest.raises(InvalidDataError):
            service.decrypt(b"too_short")

    def test_decryption_error_on_wrong_key(self):
        """Verify DecryptionError raised when decrypting with wrong key."""
        service1 = EncryptionService(master_key="correct-key")
        service2 = EncryptionService(master_key="wrong-key")
        encrypted = service1.encrypt(b"secret data")
        with pytest.raises(DecryptionError):
            service2.decrypt(encrypted)

    def test_decrypt_source_checks_min_length(self):
        """Verify decrypt source checks min_encrypted_data_length."""
        source = inspect.getsource(EncryptionService.decrypt)
        assert "min_encrypted_data_length" in source
        assert "InvalidDataError" in source


# ---------------------------------------------------------------------------
# AC-10: Soft delete with 90-day retention before hard delete
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC10SoftDeleteRetention:
    """AC-10: delete_credential soft-deletes; purge uses 90-day cutoff."""

    def test_delete_sets_is_active_false(self):
        """Verify delete_credential sets is_active=false."""
        from app.services.auth.credential_service import CentralizedAuthService

        source = inspect.getsource(CentralizedAuthService.delete_credential)
        assert "is_active = false" in source

    def test_purge_default_retention_90_days(self):
        """Verify purge_old_inactive_credentials defaults to 90 days."""
        from app.services.auth.credential_service import CentralizedAuthService

        source = inspect.getsource(CentralizedAuthService.purge_old_inactive_credentials)
        assert "retention_days: int = 90" in source or "90" in source

    def test_purge_hard_deletes(self):
        """Verify purge uses DELETE (hard delete) not UPDATE."""
        from app.services.auth.credential_service import CentralizedAuthService

        source = inspect.getsource(CentralizedAuthService.purge_old_inactive_credentials)
        assert "DELETE FROM unified_credentials" in source


# ---------------------------------------------------------------------------
# AC-11: AES-GCM encryption SHOULD include AAD
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAC11AADUsage:
    """AC-11: encrypt SHOULD pass contextual AAD to aesgcm.encrypt() to prevent ciphertext swapping."""

    def test_encrypt_passes_aad_to_aesgcm(self):
        """Verify encrypt method passes non-None AAD to aesgcm.encrypt().

        This is a SHOULD-level requirement (informational). If AAD is None,
        the test documents the gap: ciphertext can be swapped between records
        without detection. Finding I-3: service.py line 125 passes None as AAD.
        """
        source = inspect.getsource(EncryptionService.encrypt)
        # Look for aesgcm.encrypt() call and check if AAD argument is not None
        # The call signature is: aesgcm.encrypt(nonce, data, aad)
        # If None is passed as AAD, this test should fail to document the gap
        if "aesgcm.encrypt(nonce, data, None)" in source:
            pytest.fail(
                "EncryptionService.encrypt passes None as AAD to aesgcm.encrypt(). "
                "Contextual AAD (e.g., record ID or field name) SHOULD be passed "
                "to prevent ciphertext swapping between records (finding I-3)."
            )
        # Also check the more general pattern where AAD might be a variable set to None
        assert ".encrypt(" in source, (
            "Expected aesgcm.encrypt() call in EncryptionService.encrypt"
        )

    def test_encrypt_aad_parameter_documented(self):
        """Verify the AAD parameter usage is documented in encrypt method."""
        source = inspect.getsource(EncryptionService.encrypt)
        # At minimum, if None is used, it should be documented why
        has_aad_docs = "aad" in source.lower() or "additional authenticated" in source.lower()
        has_non_none_aad = "None" not in source.split(".encrypt(")[-1].split(")")[0] if ".encrypt(" in source else False
        assert has_aad_docs or has_non_none_aad, (
            "AAD usage is neither documented nor non-None in EncryptionService.encrypt. "
            "The AAD parameter SHOULD be documented if intentionally set to None."
        )
