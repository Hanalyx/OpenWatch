"""
Unit tests for EncryptionService.

Tests AES-256-GCM encryption/decryption with PBKDF2 key derivation.
Covers round-trip, error handling, and security properties.
"""

import os

import pytest

from app.encryption import DecryptionError, EncryptionService, InvalidDataError
from app.encryption.config import FAST_TEST_CONFIG, EncryptionConfig, KDFAlgorithm


@pytest.mark.unit
class TestEncryptDecryptRoundTrip:
    """Test encrypt/decrypt round-trip for various inputs."""

    def test_roundtrip_basic(self, master_key: str) -> None:
        """Basic encrypt/decrypt round-trip succeeds."""
        service = EncryptionService(master_key, FAST_TEST_CONFIG)
        plaintext = b"hello world"
        encrypted = service.encrypt(plaintext)
        decrypted = service.decrypt(encrypted)
        assert decrypted == plaintext

    def test_roundtrip_empty_bytes(self, master_key: str) -> None:
        """Empty bytes can be encrypted and decrypted."""
        service = EncryptionService(master_key, FAST_TEST_CONFIG)
        plaintext = b""
        encrypted = service.encrypt(plaintext)
        decrypted = service.decrypt(encrypted)
        assert decrypted == plaintext

    def test_roundtrip_large_data(self, master_key: str) -> None:
        """Large data (1MB) can be encrypted and decrypted."""
        service = EncryptionService(master_key, FAST_TEST_CONFIG)
        plaintext = os.urandom(1024 * 1024)  # 1 MB
        encrypted = service.encrypt(plaintext)
        decrypted = service.decrypt(encrypted)
        assert decrypted == plaintext

    def test_roundtrip_unicode_encoded(self, master_key: str) -> None:
        """Unicode strings (encoded to bytes) round-trip correctly."""
        service = EncryptionService(master_key, FAST_TEST_CONFIG)
        plaintext = "Compliance: 100% \u2714".encode("utf-8")
        encrypted = service.encrypt(plaintext)
        decrypted = service.decrypt(encrypted)
        assert decrypted == plaintext

    def test_roundtrip_binary_data(self, master_key: str) -> None:
        """Arbitrary binary data round-trips correctly."""
        service = EncryptionService(master_key, FAST_TEST_CONFIG)
        plaintext = bytes(range(256))
        encrypted = service.encrypt(plaintext)
        decrypted = service.decrypt(encrypted)
        assert decrypted == plaintext

    def test_roundtrip_with_sha512(self, master_key: str) -> None:
        """Round-trip works with SHA512 KDF algorithm."""
        config = EncryptionConfig(
            kdf_iterations=10000,
            kdf_algorithm=KDFAlgorithm.SHA512,
        )
        service = EncryptionService(master_key, config)
        plaintext = b"sha512 test data"
        encrypted = service.encrypt(plaintext)
        decrypted = service.decrypt(encrypted)
        assert decrypted == plaintext


@pytest.mark.unit
class TestEncryptionOutput:
    """Test properties of encrypted output."""

    def test_encrypted_larger_than_plaintext(self, master_key: str) -> None:
        """Encrypted data is larger than plaintext (salt + nonce + tag overhead)."""
        service = EncryptionService(master_key, FAST_TEST_CONFIG)
        plaintext = b"short"
        encrypted = service.encrypt(plaintext)
        # Overhead: 16 (salt) + 12 (nonce) + 16 (GCM tag) = 44 bytes
        assert len(encrypted) == len(plaintext) + 44

    def test_same_plaintext_different_ciphertext(self, master_key: str) -> None:
        """Same plaintext produces different ciphertext (random salt/nonce)."""
        service = EncryptionService(master_key, FAST_TEST_CONFIG)
        plaintext = b"deterministic input"
        encrypted1 = service.encrypt(plaintext)
        encrypted2 = service.encrypt(plaintext)
        assert encrypted1 != encrypted2

    def test_different_keys_different_ciphertext(self, master_key: str, alt_master_key: str) -> None:
        """Different master keys produce different encrypted output."""
        service1 = EncryptionService(master_key, FAST_TEST_CONFIG)
        service2 = EncryptionService(alt_master_key, FAST_TEST_CONFIG)
        plaintext = b"same data"
        encrypted1 = service1.encrypt(plaintext)
        encrypted2 = service2.encrypt(plaintext)
        assert encrypted1 != encrypted2


@pytest.mark.unit
class TestDecryptionErrors:
    """Test decryption failure scenarios."""

    def test_wrong_key_fails(self, master_key: str, alt_master_key: str) -> None:
        """Decryption with wrong key raises DecryptionError."""
        service1 = EncryptionService(master_key, FAST_TEST_CONFIG)
        service2 = EncryptionService(alt_master_key, FAST_TEST_CONFIG)
        encrypted = service1.encrypt(b"secret")
        with pytest.raises(DecryptionError):
            service2.decrypt(encrypted)

    def test_truncated_data_raises_invalid(self, master_key: str) -> None:
        """Truncated encrypted data raises InvalidDataError."""
        service = EncryptionService(master_key, FAST_TEST_CONFIG)
        with pytest.raises(InvalidDataError):
            service.decrypt(b"too short")

    def test_empty_data_raises_invalid(self, master_key: str) -> None:
        """Empty encrypted data raises InvalidDataError."""
        service = EncryptionService(master_key, FAST_TEST_CONFIG)
        with pytest.raises(InvalidDataError):
            service.decrypt(b"")

    def test_tampered_ciphertext_raises_error(self, master_key: str) -> None:
        """Tampered ciphertext raises DecryptionError (GCM auth tag failure)."""
        service = EncryptionService(master_key, FAST_TEST_CONFIG)
        encrypted = service.encrypt(b"important data")
        # Tamper with the ciphertext portion (after salt + nonce)
        tampered = bytearray(encrypted)
        tampered[-1] ^= 0xFF  # Flip last byte (in tag)
        with pytest.raises(DecryptionError):
            service.decrypt(bytes(tampered))

    def test_tampered_salt_raises_error(self, master_key: str) -> None:
        """Tampered salt causes decryption to fail (derives wrong key)."""
        service = EncryptionService(master_key, FAST_TEST_CONFIG)
        encrypted = service.encrypt(b"important data")
        tampered = bytearray(encrypted)
        tampered[0] ^= 0xFF  # Flip first byte (in salt)
        with pytest.raises(DecryptionError):
            service.decrypt(bytes(tampered))

    def test_tampered_nonce_raises_error(self, master_key: str) -> None:
        """Tampered nonce causes decryption to fail."""
        service = EncryptionService(master_key, FAST_TEST_CONFIG)
        encrypted = service.encrypt(b"important data")
        tampered = bytearray(encrypted)
        tampered[16] ^= 0xFF  # Flip first nonce byte (after 16-byte salt)
        with pytest.raises(DecryptionError):
            service.decrypt(bytes(tampered))


@pytest.mark.unit
class TestEncryptionServiceInit:
    """Test EncryptionService initialization."""

    def test_default_config(self, master_key: str) -> None:
        """Service initializes with default config when none provided."""
        service = EncryptionService(master_key)
        assert service.config.kdf_iterations == 100000
        assert service.config.kdf_algorithm == KDFAlgorithm.SHA256

    def test_custom_config(self, master_key: str) -> None:
        """Service accepts custom configuration."""
        config = EncryptionConfig(
            kdf_iterations=50000,
            kdf_algorithm=KDFAlgorithm.SHA512,
        )
        service = EncryptionService(master_key, config)
        assert service.config.kdf_iterations == 50000
        assert service.config.kdf_algorithm == KDFAlgorithm.SHA512

    def test_master_key_stored_as_bytes(self, master_key: str) -> None:
        """Master key is encoded to bytes internally."""
        service = EncryptionService(master_key, FAST_TEST_CONFIG)
        assert isinstance(service.master_key, bytes)
        assert service.master_key == master_key.encode("utf-8")


@pytest.mark.unit
class TestCreateEncryptionService:
    """Test the factory function."""

    def test_factory_creates_service(self, master_key: str) -> None:
        """Factory function creates a working EncryptionService."""
        from app.encryption import create_encryption_service

        service = create_encryption_service(master_key, FAST_TEST_CONFIG)
        assert isinstance(service, EncryptionService)
        encrypted = service.encrypt(b"test")
        assert service.decrypt(encrypted) == b"test"
