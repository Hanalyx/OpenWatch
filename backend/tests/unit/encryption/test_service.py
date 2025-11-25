"""
Tests for EncryptionService (refactored, no singleton).
"""

import pytest

from backend.app.encryption import (
    FAST_TEST_CONFIG,
    DecryptionError,
    EncryptionConfig,
    EncryptionService,
    InvalidDataError,
    KDFAlgorithm,
    create_encryption_service,
)


class TestEncryptionService:
    """Test EncryptionService class"""

    @pytest.fixture
    def service(self):
        """Create encryption service with fast config for testing"""
        return EncryptionService("test-master-key", FAST_TEST_CONFIG)

    def test_initialization_with_defaults(self):
        """Test service initialization with default config"""
        service = EncryptionService("my-secret-key")

        assert service.master_key == b"my-secret-key"
        assert service.config.kdf_iterations == 100000
        assert service.config.kdf_algorithm == KDFAlgorithm.SHA256

    def test_initialization_with_custom_config(self):
        """Test service initialization with custom config"""
        config = EncryptionConfig(kdf_iterations=50000)
        service = EncryptionService("my-key", config)

        assert service.master_key == b"my-key"
        assert service.config.kdf_iterations == 50000

    def test_encrypt_basic(self, service):
        """Test basic encryption"""
        plaintext = b"test data"
        encrypted = service.encrypt(plaintext)

        # Verify format: salt(16) + nonce(12) + ciphertext_with_tag
        assert len(encrypted) > 28  # At least salt + nonce
        assert isinstance(encrypted, bytes)

    def test_encrypt_decrypt_roundtrip(self, service):
        """Test encrypt-decrypt roundtrip"""
        plaintext = b"sensitive credential data"

        encrypted = service.encrypt(plaintext)
        decrypted = service.decrypt(encrypted)

        assert decrypted == plaintext

    def test_encrypt_unicode_string(self, service):
        """Test encryption with unicode strings (converted to bytes)"""
        plaintext = "Hello 世界 🌍".encode("utf-8")

        encrypted = service.encrypt(plaintext)
        decrypted = service.decrypt(encrypted)

        assert decrypted.decode("utf-8") == "Hello 世界 🌍"

    def test_encrypt_empty_data(self, service):
        """Test encryption of empty data"""
        plaintext = b""

        encrypted = service.encrypt(plaintext)
        decrypted = service.decrypt(encrypted)

        assert decrypted == b""

    def test_encrypt_large_data(self, service):
        """Test encryption of large data (1 MB)"""
        plaintext = b"x" * (1024 * 1024)

        encrypted = service.encrypt(plaintext)
        decrypted = service.decrypt(encrypted)

        assert decrypted == plaintext
        assert len(decrypted) == 1024 * 1024

    def test_different_encryptions_produce_different_ciphertexts(self, service):
        """Test that encrypting same data twice produces different ciphertexts"""
        plaintext = b"same data"

        encrypted1 = service.encrypt(plaintext)
        encrypted2 = service.encrypt(plaintext)

        # Different due to random salt and nonce
        assert encrypted1 != encrypted2

        # But both decrypt to same plaintext
        assert service.decrypt(encrypted1) == plaintext
        assert service.decrypt(encrypted2) == plaintext

    def test_decrypt_invalid_data_too_short(self, service):
        """Test decryption rejects data that's too short"""
        invalid_data = b"too short"

        with pytest.raises(InvalidDataError, match="Encrypted data too short"):
            service.decrypt(invalid_data)

    def test_decrypt_invalid_data_wrong_key(self, service):
        """Test decryption fails with wrong key"""
        plaintext = b"secret data"

        # Encrypt with service1
        encrypted = service.encrypt(plaintext)

        # Try to decrypt with different key
        service2 = EncryptionService("different-key", FAST_TEST_CONFIG)

        with pytest.raises(DecryptionError, match="Decryption failed"):
            service2.decrypt(encrypted)

    def test_decrypt_corrupted_ciphertext(self, service):
        """Test decryption fails with corrupted data"""
        plaintext = b"secret data"
        encrypted = service.encrypt(plaintext)

        # Corrupt the ciphertext (but keep valid length)
        corrupted = encrypted[:28] + b"\xff" * (len(encrypted) - 28)

        with pytest.raises(DecryptionError, match="Decryption failed"):
            service.decrypt(corrupted)

    def test_different_services_same_key_can_decrypt(self):
        """Test that different service instances with same key can decrypt"""
        key = "shared-master-key"
        config = FAST_TEST_CONFIG

        service1 = EncryptionService(key, config)
        service2 = EncryptionService(key, config)

        plaintext = b"shared secret"
        encrypted = service1.encrypt(plaintext)
        decrypted = service2.decrypt(encrypted)

        assert decrypted == plaintext

    def test_different_configs_produce_different_ciphertexts(self):
        """Test that different configs produce incompatible ciphertexts"""
        key = "same-key"
        plaintext = b"test data"

        # Service with default config (100k iterations, SHA256)
        service1 = EncryptionService(key, EncryptionConfig(kdf_iterations=10000))

        # Service with different config (200k iterations, SHA512)
        config2 = EncryptionConfig(kdf_iterations=20000, kdf_algorithm=KDFAlgorithm.SHA512)
        service2 = EncryptionService(key, config2)

        # Encrypt with service1
        encrypted = service1.encrypt(plaintext)

        # Cannot decrypt with service2 (different KDF parameters)
        with pytest.raises(DecryptionError):
            service2.decrypt(encrypted)

    def test_encryption_is_authenticated(self, service):
        """Test that GCM provides authenticated encryption (tamper detection)"""
        plaintext = b"secret data"
        encrypted = service.encrypt(plaintext)

        # Tamper with a byte in the ciphertext (after salt + nonce)
        tampered = bytearray(encrypted)
        tampered[30] ^= 0xFF  # Flip bits in ciphertext
        tampered_bytes = bytes(tampered)

        # Decryption should fail due to authentication tag mismatch
        with pytest.raises(DecryptionError):
            service.decrypt(tampered_bytes)


class TestCreateEncryptionService:
    """Test create_encryption_service factory function"""

    def test_factory_with_defaults(self):
        """Test factory creates service with default config"""
        service = create_encryption_service("test-key")

        assert isinstance(service, EncryptionService)
        assert service.master_key == b"test-key"
        assert service.config.kdf_iterations == 100000

    def test_factory_with_custom_config(self):
        """Test factory creates service with custom config"""
        config = EncryptionConfig(kdf_iterations=50000)
        service = create_encryption_service("test-key", config)

        assert isinstance(service, EncryptionService)
        assert service.config.kdf_iterations == 50000

    def test_factory_produces_working_service(self):
        """Test factory-created service can encrypt/decrypt"""
        service = create_encryption_service("factory-key", FAST_TEST_CONFIG)

        plaintext = b"factory test"
        encrypted = service.encrypt(plaintext)
        decrypted = service.decrypt(encrypted)

        assert decrypted == plaintext


class TestEncryptionServiceNoSingleton:
    """Test that refactored service has NO singleton behavior"""

    def test_multiple_instances_are_independent(self):
        """Test that multiple service instances don't share state"""
        service1 = EncryptionService("key1", FAST_TEST_CONFIG)
        service2 = EncryptionService("key2", FAST_TEST_CONFIG)

        # They should be different objects
        assert service1 is not service2

        # They should have different keys
        assert service1.master_key != service2.master_key

        # Encryption with service1 cannot be decrypted by service2
        plaintext = b"test"
        encrypted = service1.encrypt(plaintext)

        with pytest.raises(DecryptionError):
            service2.decrypt(encrypted)

    def test_factory_creates_new_instances(self):
        """Test that factory creates new instances each time"""
        service1 = create_encryption_service("same-key", FAST_TEST_CONFIG)
        service2 = create_encryption_service("same-key", FAST_TEST_CONFIG)

        # Different objects (NOT singleton)
        assert service1 is not service2

        # But same functionality (same key)
        plaintext = b"test"
        encrypted = service1.encrypt(plaintext)
        decrypted = service2.decrypt(encrypted)
        assert decrypted == plaintext
