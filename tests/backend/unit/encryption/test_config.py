"""
Unit tests for EncryptionConfig.

Tests configuration validation, predefined configs, and edge cases.
"""

import pytest

from app.encryption.config import DEFAULT_CONFIG, FAST_TEST_CONFIG, HIGH_SECURITY_CONFIG, EncryptionConfig, KDFAlgorithm


@pytest.mark.unit
class TestEncryptionConfigDefaults:
    """Test default configuration values."""

    def test_default_iterations(self) -> None:
        """Default KDF iterations is 100000."""
        config = EncryptionConfig()
        assert config.kdf_iterations == 100000

    def test_default_algorithm(self) -> None:
        """Default KDF algorithm is SHA256."""
        config = EncryptionConfig()
        assert config.kdf_algorithm == KDFAlgorithm.SHA256

    def test_default_salt_length(self) -> None:
        """Default salt length is 16 bytes."""
        config = EncryptionConfig()
        assert config.salt_length == 16

    def test_default_nonce_length(self) -> None:
        """Default nonce length is 12 bytes (GCM standard)."""
        config = EncryptionConfig()
        assert config.nonce_length == 12

    def test_default_key_length(self) -> None:
        """Default key length is 32 bytes (AES-256)."""
        config = EncryptionConfig()
        assert config.key_length == 32


@pytest.mark.unit
class TestEncryptionConfigValidation:
    """Test configuration validation rules."""

    def test_iterations_below_minimum_raises(self) -> None:
        """KDF iterations below 10000 raises ValueError."""
        with pytest.raises(ValueError, match="KDF iterations"):
            EncryptionConfig(kdf_iterations=9999)

    def test_iterations_at_minimum_ok(self) -> None:
        """KDF iterations at exactly 10000 is valid."""
        config = EncryptionConfig(kdf_iterations=10000)
        assert config.kdf_iterations == 10000

    def test_salt_below_minimum_raises(self) -> None:
        """Salt length below 16 raises ValueError."""
        with pytest.raises(ValueError, match="Salt length"):
            EncryptionConfig(salt_length=15)

    def test_salt_at_minimum_ok(self) -> None:
        """Salt length at exactly 16 is valid."""
        config = EncryptionConfig(salt_length=16)
        assert config.salt_length == 16

    def test_nonce_not_12_raises(self) -> None:
        """Nonce length != 12 raises ValueError (GCM requirement)."""
        with pytest.raises(ValueError, match="Nonce length"):
            EncryptionConfig(nonce_length=16)

    def test_invalid_key_length_raises(self) -> None:
        """Key length not in {16, 24, 32} raises ValueError."""
        with pytest.raises(ValueError, match="Key length"):
            EncryptionConfig(key_length=20)

    def test_valid_key_lengths(self) -> None:
        """Key lengths 16, 24, 32 are all valid (AES-128, AES-192, AES-256)."""
        for length in [16, 24, 32]:
            config = EncryptionConfig(key_length=length)
            assert config.key_length == length


@pytest.mark.unit
class TestMinEncryptedDataLength:
    """Test min_encrypted_data_length property."""

    def test_default_min_length(self) -> None:
        """Default min encrypted data length is salt(16) + nonce(12) + tag(16) = 44."""
        config = EncryptionConfig()
        assert config.min_encrypted_data_length == 44

    def test_custom_salt_affects_min_length(self) -> None:
        """Larger salt increases minimum encrypted data length."""
        config = EncryptionConfig(salt_length=32)
        assert config.min_encrypted_data_length == 32 + 12 + 16  # 60


@pytest.mark.unit
class TestPredefinedConfigs:
    """Test predefined configuration presets."""

    def test_default_config(self) -> None:
        """DEFAULT_CONFIG has production defaults."""
        assert DEFAULT_CONFIG.kdf_iterations == 100000
        assert DEFAULT_CONFIG.kdf_algorithm == KDFAlgorithm.SHA256

    def test_fast_test_config(self) -> None:
        """FAST_TEST_CONFIG has minimum iterations for speed."""
        assert FAST_TEST_CONFIG.kdf_iterations == 10000
        assert FAST_TEST_CONFIG.kdf_algorithm == KDFAlgorithm.SHA256

    def test_high_security_config(self) -> None:
        """HIGH_SECURITY_CONFIG has extra iterations and SHA512."""
        assert HIGH_SECURITY_CONFIG.kdf_iterations == 200000
        assert HIGH_SECURITY_CONFIG.kdf_algorithm == KDFAlgorithm.SHA512


@pytest.mark.unit
class TestKDFAlgorithm:
    """Test KDFAlgorithm enum."""

    def test_sha256_value(self) -> None:
        """SHA256 enum value is correct."""
        assert KDFAlgorithm.SHA256.value == "SHA256"

    def test_sha512_value(self) -> None:
        """SHA512 enum value is correct."""
        assert KDFAlgorithm.SHA512.value == "SHA512"

    def test_only_two_algorithms(self) -> None:
        """Only SHA256 and SHA512 are supported."""
        assert len(KDFAlgorithm) == 2
