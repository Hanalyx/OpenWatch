"""
Tests for EncryptionConfig dataclass and validation.
"""
import pytest
from backend.app.encryption import (
    EncryptionConfig,
    KDFAlgorithm,
    DEFAULT_CONFIG,
    FAST_TEST_CONFIG,
    HIGH_SECURITY_CONFIG,
    ConfigurationError
)


class TestEncryptionConfig:
    """Test EncryptionConfig dataclass"""

    def test_default_config(self):
        """Test default configuration values"""
        config = EncryptionConfig()

        assert config.kdf_iterations == 100000
        assert config.kdf_algorithm == KDFAlgorithm.SHA256
        assert config.salt_length == 16
        assert config.nonce_length == 12
        assert config.key_length == 32

    def test_custom_config(self):
        """Test custom configuration values"""
        config = EncryptionConfig(
            kdf_iterations=200000,
            kdf_algorithm=KDFAlgorithm.SHA512,
            salt_length=32
        )

        assert config.kdf_iterations == 200000
        assert config.kdf_algorithm == KDFAlgorithm.SHA512
        assert config.salt_length == 32
        assert config.nonce_length == 12  # Default
        assert config.key_length == 32    # Default

    def test_min_encrypted_data_length(self):
        """Test minimum encrypted data length calculation"""
        config = EncryptionConfig()

        # salt(16) + nonce(12) + tag(16) = 44 bytes minimum
        assert config.min_encrypted_data_length == 44

    def test_validation_too_few_iterations(self):
        """Test validation rejects too few KDF iterations"""
        with pytest.raises(ValueError, match="KDF iterations.*must be >= 10000"):
            EncryptionConfig(kdf_iterations=5000)

    def test_validation_minimum_iterations(self):
        """Test validation accepts minimum KDF iterations"""
        config = EncryptionConfig(kdf_iterations=10000)
        assert config.kdf_iterations == 10000

    def test_validation_too_short_salt(self):
        """Test validation rejects too short salt"""
        with pytest.raises(ValueError, match="Salt length.*must be >= 16"):
            EncryptionConfig(salt_length=8)

    def test_validation_minimum_salt(self):
        """Test validation accepts minimum salt length"""
        config = EncryptionConfig(salt_length=16)
        assert config.salt_length == 16

    def test_validation_wrong_nonce_length(self):
        """Test validation rejects non-12-byte nonce"""
        with pytest.raises(ValueError, match="Nonce length.*must be exactly 12"):
            EncryptionConfig(nonce_length=16)

    def test_validation_invalid_key_length(self):
        """Test validation rejects invalid AES key length"""
        with pytest.raises(ValueError, match="Key length.*must be 16.*24.*or 32"):
            EncryptionConfig(key_length=20)

    def test_validation_accepts_all_aes_sizes(self):
        """Test validation accepts all valid AES key sizes"""
        # AES-128
        config128 = EncryptionConfig(key_length=16)
        assert config128.key_length == 16

        # AES-192
        config192 = EncryptionConfig(key_length=24)
        assert config192.key_length == 24

        # AES-256
        config256 = EncryptionConfig(key_length=32)
        assert config256.key_length == 32

    def test_predefined_default_config(self):
        """Test DEFAULT_CONFIG preset"""
        assert DEFAULT_CONFIG.kdf_iterations == 100000
        assert DEFAULT_CONFIG.kdf_algorithm == KDFAlgorithm.SHA256

    def test_predefined_fast_test_config(self):
        """Test FAST_TEST_CONFIG preset"""
        assert FAST_TEST_CONFIG.kdf_iterations == 10000
        assert FAST_TEST_CONFIG.kdf_algorithm == KDFAlgorithm.SHA256

    def test_predefined_high_security_config(self):
        """Test HIGH_SECURITY_CONFIG preset"""
        assert HIGH_SECURITY_CONFIG.kdf_iterations == 200000
        assert HIGH_SECURITY_CONFIG.kdf_algorithm == KDFAlgorithm.SHA512


class TestKDFAlgorithm:
    """Test KDFAlgorithm enum"""

    def test_sha256_algorithm(self):
        """Test SHA256 algorithm enum value"""
        assert KDFAlgorithm.SHA256.value == "SHA256"

    def test_sha512_algorithm(self):
        """Test SHA512 algorithm enum value"""
        assert KDFAlgorithm.SHA512.value == "SHA512"

    def test_algorithm_enum_values(self):
        """Test all algorithm enum values"""
        algorithms = [alg.value for alg in KDFAlgorithm]
        assert "SHA256" in algorithms
        assert "SHA512" in algorithms
        assert len(algorithms) == 2
