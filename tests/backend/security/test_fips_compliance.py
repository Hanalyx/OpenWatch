"""
Security tests for FIPS 140-2 compliance of the encryption module.

Verifies that encryption uses NIST-approved algorithms and parameters.
"""

import pytest

from app.encryption import EncryptionService
from app.encryption.config import DEFAULT_CONFIG, FAST_TEST_CONFIG, EncryptionConfig


@pytest.mark.security
class TestFIPSAlgorithmCompliance:
    """Verify FIPS 140-2 approved algorithm usage."""

    def test_uses_aes_256_gcm(self) -> None:
        """Encryption uses AES-256-GCM (NIST SP 800-38D)."""
        # AES-256 requires 32-byte key
        assert DEFAULT_CONFIG.key_length == 32

    def test_gcm_nonce_length(self) -> None:
        """GCM nonce is 12 bytes per NIST SP 800-38D recommendation."""
        assert DEFAULT_CONFIG.nonce_length == 12

    def test_pbkdf2_minimum_iterations(self) -> None:
        """PBKDF2 uses at least 100,000 iterations (exceeds NIST 10,000 minimum)."""
        assert DEFAULT_CONFIG.kdf_iterations >= 100000

    def test_salt_minimum_length(self) -> None:
        """Salt is at least 16 bytes per NIST SP 800-132."""
        assert DEFAULT_CONFIG.salt_length >= 16


@pytest.mark.security
class TestEncryptionRandomness:
    """Verify proper random number generation in encryption."""

    def test_unique_salts(self) -> None:
        """Each encryption produces a unique salt."""
        service = EncryptionService("test-key", FAST_TEST_CONFIG)  # pragma: allowlist secret
        plaintext = b"same data"
        encrypted1 = service.encrypt(plaintext)
        encrypted2 = service.encrypt(plaintext)

        # Extract salts (first 16 bytes)
        salt1 = encrypted1[:16]
        salt2 = encrypted2[:16]
        assert salt1 != salt2

    def test_unique_nonces(self) -> None:
        """Each encryption produces a unique nonce."""
        service = EncryptionService("test-key", FAST_TEST_CONFIG)  # pragma: allowlist secret
        plaintext = b"same data"
        encrypted1 = service.encrypt(plaintext)
        encrypted2 = service.encrypt(plaintext)

        # Extract nonces (bytes 16-28)
        nonce1 = encrypted1[16:28]
        nonce2 = encrypted2[16:28]
        assert nonce1 != nonce2


@pytest.mark.security
class TestAuthenticatedEncryption:
    """Verify GCM authenticated encryption properties."""

    def test_integrity_check_on_tampered_data(self) -> None:
        """GCM detects tampered ciphertext (authentication tag failure)."""
        service = EncryptionService("test-key", FAST_TEST_CONFIG)  # pragma: allowlist secret
        encrypted = service.encrypt(b"sensitive credential")
        # Tamper with ciphertext body (between nonce and tag)
        tampered = bytearray(encrypted)
        mid = len(tampered) // 2
        tampered[mid] ^= 0xFF
        with pytest.raises(Exception):  # DecryptionError or InvalidDataError
            service.decrypt(bytes(tampered))

    def test_config_rejects_weak_iterations(self) -> None:
        """Configuration rejects iteration count below NIST minimum."""
        with pytest.raises(ValueError):
            EncryptionConfig(kdf_iterations=5000)

    def test_config_rejects_short_salt(self) -> None:
        """Configuration rejects salt shorter than 16 bytes."""
        with pytest.raises(ValueError):
            EncryptionConfig(salt_length=8)
