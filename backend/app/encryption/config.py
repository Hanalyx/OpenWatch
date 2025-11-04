"""
Encryption configuration for OpenWatch.

Provides configurable parameters for encryption operations, allowing
for flexibility in security requirements and testing scenarios.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class KDFAlgorithm(Enum):
    """Supported Key Derivation Function algorithms"""

    SHA256 = "SHA256"
    SHA512 = "SHA512"


@dataclass
class EncryptionConfig:
    """
    Configuration for encryption service.

    All parameters have secure defaults aligned with NIST SP 800-132 and
    FIPS 140-2 compliance requirements.

    Attributes:
        kdf_iterations: Number of PBKDF2 iterations (min 10000, recommended 100000+)
        kdf_algorithm: Hash algorithm for key derivation (SHA256 or SHA512)
        salt_length: Length of random salt in bytes (min 16)
        nonce_length: Length of random nonce in bytes (must be 12 for GCM)
        key_length: Derived key length in bytes (32 for AES-256)

    Example:
        >>> # Use defaults (recommended for production)
        >>> config = EncryptionConfig()

        >>> # Fast config for testing
        >>> test_config = EncryptionConfig(kdf_iterations=1000)

        >>> # High-security config
        >>> secure_config = EncryptionConfig(
        ...     kdf_iterations=200000,
        ...     kdf_algorithm=KDFAlgorithm.SHA512
        ... )
    """

    kdf_iterations: int = 100000
    """Number of PBKDF2 iterations (NIST SP 800-132 recommends 10000+)"""

    kdf_algorithm: KDFAlgorithm = KDFAlgorithm.SHA256
    """Hash algorithm for key derivation"""

    salt_length: int = 16
    """Length of random salt in bytes (NIST recommends 16+ bytes)"""

    nonce_length: int = 12
    """Length of random nonce in bytes (GCM standard is 12 bytes)"""

    key_length: int = 32
    """Derived key length in bytes (32 bytes = 256 bits for AES-256)"""

    def validate(self) -> None:
        """
        Validate configuration parameters against security requirements.

        Raises:
            ValueError: If any parameter fails validation
        """
        # Validate KDF iterations (NIST SP 800-132 minimum)
        if self.kdf_iterations < 10000:
            raise ValueError(
                f"KDF iterations ({self.kdf_iterations}) must be >= 10000 "
                f"for security (NIST SP 800-132). Use 100000+ for production."
            )

        # Validate salt length
        if self.salt_length < 16:
            raise ValueError(
                f"Salt length ({self.salt_length}) must be >= 16 bytes "
                f"for security (NIST SP 800-132)"
            )

        # Validate nonce length for GCM mode
        if self.nonce_length != 12:
            raise ValueError(
                f"Nonce length ({self.nonce_length}) must be exactly 12 bytes "
                f"for AES-GCM mode (NIST SP 800-38D)"
            )

        # Validate key length for AES-256
        if self.key_length not in [16, 24, 32]:
            raise ValueError(
                f"Key length ({self.key_length}) must be 16 (AES-128), "
                f"24 (AES-192), or 32 (AES-256) bytes"
            )

    @property
    def min_encrypted_data_length(self) -> int:
        """
        Minimum length of valid encrypted data.

        Format: salt + nonce + ciphertext + tag
        Tag is 16 bytes for GCM mode.

        Returns:
            Minimum length in bytes
        """
        return self.salt_length + self.nonce_length + 16  # +16 for GCM tag

    def __post_init__(self):
        """Validate configuration on initialization"""
        self.validate()


# Predefined configurations for common scenarios
DEFAULT_CONFIG = EncryptionConfig()
"""Default production configuration (100000 iterations, SHA256)"""

FAST_TEST_CONFIG = EncryptionConfig(kdf_iterations=10000)
"""Fast configuration for unit tests (10000 iterations minimum)"""

HIGH_SECURITY_CONFIG = EncryptionConfig(kdf_iterations=200000, kdf_algorithm=KDFAlgorithm.SHA512)
"""High-security configuration (200000 iterations, SHA512)"""
