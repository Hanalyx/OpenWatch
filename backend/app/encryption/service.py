"""
Encryption service for sensitive data using AES-256-GCM.

Provides FIPS 140-2 compliant encryption with configurable parameters
and dependency injection support.
"""
import os
import logging
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .config import EncryptionConfig, KDFAlgorithm
from .exceptions import EncryptionError, DecryptionError, InvalidDataError

logger = logging.getLogger(__name__)


class EncryptionService:
    """
    Encryption service using AES-256-GCM with PBKDF2 key derivation.

    Features:
    - FIPS 140-2 compliant AES-256-GCM encryption
    - PBKDF2-HMAC-SHA256 key derivation (100,000 iterations by default)
    - Authenticated encryption (integrity + confidentiality)
    - Thread-safe and stateless (except for master key storage)
    - No global state (dependency injection)
    - Configurable algorithm parameters

    Security:
    - Algorithm: AES-256-GCM (NIST SP 800-38D)
    - Key Derivation: PBKDF2-HMAC (NIST SP 800-132)
    - Default iterations: 100,000 (exceeds NIST minimum of 10,000)
    - Random salt per encryption (16 bytes)
    - Random nonce per encryption (12 bytes, GCM standard)
    - Authenticated encryption (prevents tampering)

    Example:
        >>> from app.encryption import EncryptionService, EncryptionConfig
        >>>
        >>> # Create service with default config
        >>> service = EncryptionService(master_key="my-secret-key")
        >>>
        >>> # Encrypt data
        >>> plaintext = b"sensitive credential data"
        >>> encrypted = service.encrypt(plaintext)
        >>>
        >>> # Decrypt data
        >>> decrypted = service.decrypt(encrypted)
        >>> assert decrypted == plaintext
        >>>
        >>> # Use custom config
        >>> config = EncryptionConfig(kdf_iterations=200000)
        >>> service = EncryptionService(master_key="my-key", config=config)
    """

    def __init__(
        self,
        master_key: str,
        config: Optional[EncryptionConfig] = None
    ):
        """
        Initialize encryption service.

        Args:
            master_key: Master encryption key (will be encoded to bytes)
            config: Optional configuration (uses secure defaults if not provided)

        Raises:
            ConfigurationError: If config validation fails

        Example:
            >>> # With defaults
            >>> service = EncryptionService("my-secret-key")
            >>>
            >>> # With custom config
            >>> config = EncryptionConfig(kdf_iterations=200000)
            >>> service = EncryptionService("my-secret-key", config)
        """
        self.master_key = master_key.encode('utf-8')
        self.config = config or EncryptionConfig()
        # Config validation happens in EncryptionConfig.__post_init__

        logger.debug(
            f"EncryptionService initialized with {self.config.kdf_iterations} "
            f"KDF iterations, {self.config.kdf_algorithm.value} algorithm"
        )

    def encrypt(self, data: bytes) -> bytes:
        """
        Encrypt data using AES-256-GCM.

        The encrypted data format is:
            salt (16 bytes) + nonce (12 bytes) + ciphertext_with_tag

        The GCM tag is automatically appended to the ciphertext by the
        AESGCM.encrypt() method.

        Args:
            data: Plaintext bytes to encrypt

        Returns:
            Encrypted bytes (salt + nonce + ciphertext_with_tag)

        Raises:
            EncryptionError: If encryption fails

        Example:
            >>> service = EncryptionService("my-key")
            >>> encrypted = service.encrypt(b"secret data")
            >>> len(encrypted)  # salt(16) + nonce(12) + ciphertext + tag(16)
            60  # 16 + 12 + 11 + 16 + padding
        """
        try:
            # Generate random salt and nonce
            salt = os.urandom(self.config.salt_length)
            nonce = os.urandom(self.config.nonce_length)

            # Derive encryption key from master key and salt
            key = self._derive_key(salt)

            # Encrypt data with AES-256-GCM
            aesgcm = AESGCM(key)
            ciphertext = aesgcm.encrypt(nonce, data, None)

            # Combine components: salt + nonce + ciphertext_with_tag
            encrypted_data = salt + nonce + ciphertext

            logger.debug(
                f"Encrypted {len(data)} bytes → {len(encrypted_data)} bytes "
                f"(salt={self.config.salt_length}, nonce={self.config.nonce_length})"
            )

            return encrypted_data

        except Exception as e:
            logger.error(f"Encryption failed: {type(e).__name__}: {e}")
            raise EncryptionError(f"Encryption failed: {e}") from e

    def decrypt(self, encrypted_data: bytes) -> bytes:
        """
        Decrypt data using AES-256-GCM.

        Expects data in format: salt + nonce + ciphertext_with_tag

        Args:
            encrypted_data: Encrypted bytes (salt + nonce + ciphertext_with_tag)

        Returns:
            Decrypted plaintext bytes

        Raises:
            InvalidDataError: If encrypted data format is invalid
            DecryptionError: If decryption fails (wrong key, corrupted data, etc.)

        Example:
            >>> service = EncryptionService("my-key")
            >>> encrypted = service.encrypt(b"secret")
            >>> decrypted = service.decrypt(encrypted)
            >>> decrypted
            b'secret'
        """
        # Validate input format
        min_length = self.config.min_encrypted_data_length
        if len(encrypted_data) < min_length:
            error_msg = (
                f"Encrypted data too short: {len(encrypted_data)} < {min_length} bytes "
                f"(expected: salt[{self.config.salt_length}] + "
                f"nonce[{self.config.nonce_length}] + ciphertext + tag[16])"
            )
            logger.error(error_msg)
            raise InvalidDataError(error_msg)

        try:
            # Extract components
            salt = encrypted_data[:self.config.salt_length]
            nonce_end = self.config.salt_length + self.config.nonce_length
            nonce = encrypted_data[self.config.salt_length:nonce_end]
            ciphertext = encrypted_data[nonce_end:]

            # Derive key from master key and salt
            key = self._derive_key(salt)

            # Decrypt data
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)

            logger.debug(
                f"Decrypted {len(encrypted_data)} bytes → {len(plaintext)} bytes"
            )

            return plaintext

        except InvalidDataError:
            # Re-raise validation errors without wrapping
            raise
        except Exception as e:
            logger.error(f"Decryption failed: {type(e).__name__}: {e}")
            raise DecryptionError(f"Decryption failed: {e}") from e

    def _derive_key(self, salt: bytes) -> bytes:
        """
        Derive encryption key from master key and salt using PBKDF2.

        Args:
            salt: Random salt bytes

        Returns:
            Derived key bytes (32 bytes for AES-256)

        Note:
            This method uses the algorithm and iteration count from self.config.
        """
        # Select hash algorithm based on config
        if self.config.kdf_algorithm == KDFAlgorithm.SHA256:
            algorithm = hashes.SHA256()
        elif self.config.kdf_algorithm == KDFAlgorithm.SHA512:
            algorithm = hashes.SHA512()
        else:
            # Should never happen due to enum validation
            algorithm = hashes.SHA256()

        kdf = PBKDF2HMAC(
            algorithm=algorithm,
            length=self.config.key_length,
            salt=salt,
            iterations=self.config.kdf_iterations,
        )

        return kdf.derive(self.master_key)


def create_encryption_service(
    master_key: str,
    config: Optional[EncryptionConfig] = None
) -> EncryptionService:
    """
    Factory function to create an EncryptionService instance.

    This is the recommended way to create encryption services in application code.

    Args:
        master_key: Master encryption key
        config: Optional configuration (uses defaults if not provided)

    Returns:
        EncryptionService instance

    Example:
        >>> from app.config import get_settings
        >>> from app.encryption import create_encryption_service
        >>>
        >>> settings = get_settings()
        >>> encryption_service = create_encryption_service(settings.master_key)
        >>>
        >>> # Now inject into services that need it
        >>> auth_service = AuthService(db, encryption_service)
    """
    return EncryptionService(master_key, config)
