"""
Encryption compatibility layer for migration from crypto.py to encryption.py.

This module provides dual-decrypt capability, attempting decryption with both
encryption modules to support smooth migration. It also tracks which format
was used for monitoring migration progress.

Usage:
    >>> from app.services.encryption_compatibility import decrypt_credentials_dual
    >>>
    >>> # Works with both crypto.py and encryption.py formats
    >>> plaintext, format_used = decrypt_credentials_dual(encrypted_data)
    >>> print(f"Decrypted successfully using: {format_used}")
"""
import base64
import logging
from typing import Tuple, Optional, Union
from enum import Enum

# Import both encryption modules
from backend.app.services import crypto
from backend.app.services.encryption import get_encryption_service

# Import new modular encryption
from backend.app.encryption import (
    EncryptionService,
    create_encryption_service,
    DecryptionError,
    InvalidDataError
)

logger = logging.getLogger(__name__)


class EncryptionFormat(Enum):
    """Enum for tracking which encryption format was used"""
    ENCRYPTION_PY = "encryption.py"
    CRYPTO_PY = "crypto.py"
    UNKNOWN = "unknown"


class MigrationStats:
    """
    Track migration statistics for monitoring progress.

    This is a simple in-memory counter. For production monitoring,
    consider logging to database or metrics system.
    """
    def __init__(self):
        self.encryption_py_count = 0
        self.crypto_py_count = 0
        self.failure_count = 0

    def record_success(self, format_used: EncryptionFormat):
        """Record successful decryption"""
        if format_used == EncryptionFormat.ENCRYPTION_PY:
            self.encryption_py_count += 1
        elif format_used == EncryptionFormat.CRYPTO_PY:
            self.crypto_py_count += 1

    def record_failure(self):
        """Record decryption failure"""
        self.failure_count += 1

    def get_stats(self) -> dict:
        """Get current statistics"""
        total = self.encryption_py_count + self.crypto_py_count
        return {
            "encryption_py": self.encryption_py_count,
            "crypto_py": self.crypto_py_count,
            "failures": self.failure_count,
            "total_successes": total,
            "migration_progress_pct": (
                (self.encryption_py_count / total * 100) if total > 0 else 0
            )
        }


# Global migration stats tracker
_migration_stats = MigrationStats()


def get_migration_stats() -> dict:
    """Get current migration statistics"""
    return _migration_stats.get_stats()


def decrypt_credentials_dual(
    encrypted_data: Union[bytes, str, memoryview],
    master_key: Optional[str] = None
) -> Tuple[str, EncryptionFormat]:
    """
    Decrypt credentials using dual-format support.

    This function attempts decryption in the following order:
    1. Try encryption.py format (preferred, new format)
    2. Fall back to crypto.py format (legacy)

    Args:
        encrypted_data: Encrypted data (bytes, base64 string, or memoryview)
        master_key: Optional master key (uses settings if not provided)

    Returns:
        Tuple of (plaintext: str, format_used: EncryptionFormat)

    Raises:
        ValueError: If decryption fails with both formats

    Example:
        >>> encrypted = crypto.encrypt_credentials("password123")
        >>> plaintext, fmt = decrypt_credentials_dual(encrypted)
        >>> assert plaintext == "password123"
        >>> assert fmt == EncryptionFormat.CRYPTO_PY
    """
    # Handle different input types
    if isinstance(encrypted_data, memoryview):
        encrypted_bytes = bytes(encrypted_data)
    elif isinstance(encrypted_data, str):
        # Assume base64-encoded string
        try:
            encrypted_bytes = base64.b64decode(encrypted_data.encode('ascii'))
        except Exception as e:
            logger.error(f"Failed to decode base64 string: {e}")
            _migration_stats.record_failure()
            raise ValueError(f"Invalid base64 encoding: {e}")
    elif isinstance(encrypted_data, bytes):
        encrypted_bytes = encrypted_data
    else:
        logger.error(f"Invalid encrypted data type: {type(encrypted_data)}")
        _migration_stats.record_failure()
        raise ValueError(f"Invalid encrypted data type: {type(encrypted_data)}")

    # Validate minimum length (both formats need at least 28 bytes)
    if len(encrypted_bytes) < 28:
        logger.error(f"Encrypted data too short: {len(encrypted_bytes)} bytes")
        _migration_stats.record_failure()
        raise ValueError(
            f"Encrypted data too short: {len(encrypted_bytes)} bytes "
            f"(minimum: 28 bytes for salt + nonce)"
        )

    # Try encryption.py format first (preferred)
    try:
        logger.debug("Attempting decryption with encryption.py format")
        enc_service = get_encryption_service()
        plaintext_bytes = enc_service.decrypt(encrypted_bytes)
        plaintext = plaintext_bytes.decode('utf-8')

        logger.info(f"Successfully decrypted with encryption.py (length: {len(plaintext)})")
        _migration_stats.record_success(EncryptionFormat.ENCRYPTION_PY)
        return plaintext, EncryptionFormat.ENCRYPTION_PY

    except Exception as e:
        logger.debug(f"encryption.py decryption failed: {type(e).__name__}: {e}")

    # Fall back to crypto.py format
    try:
        logger.debug("Attempting decryption with crypto.py format")
        plaintext = crypto.decrypt_credentials(encrypted_bytes)

        logger.info(f"Successfully decrypted with crypto.py (length: {len(plaintext)})")
        logger.warning(
            "MIGRATION ALERT: Used legacy crypto.py format. "
            "This data should be re-encrypted with encryption.py format."
        )
        _migration_stats.record_success(EncryptionFormat.CRYPTO_PY)
        return plaintext, EncryptionFormat.CRYPTO_PY

    except Exception as e:
        logger.error(f"crypto.py decryption failed: {type(e).__name__}: {e}")

    # Both formats failed
    logger.error("Decryption failed with both encryption.py and crypto.py formats")
    _migration_stats.record_failure()
    raise ValueError(
        "Failed to decrypt credentials with both encryption formats. "
        "Data may be corrupted or encrypted with unknown key."
    )


def encrypt_credentials_new(
    plaintext: str,
    master_key: Optional[str] = None,
    return_base64: bool = True
) -> Union[bytes, str]:
    """
    Encrypt credentials using NEW encryption.py format only.

    This function should be used for all NEW encryption operations
    during and after the migration period.

    Args:
        plaintext: Plaintext string to encrypt
        master_key: Optional master key (uses settings if not provided)
        return_base64: If True, return base64-encoded string; else return bytes

    Returns:
        Encrypted data as bytes or base64 string (depending on return_base64)

    Example:
        >>> encrypted = encrypt_credentials_new("password123")
        >>> plaintext, fmt = decrypt_credentials_dual(encrypted)
        >>> assert plaintext == "password123"
        >>> assert fmt == EncryptionFormat.ENCRYPTION_PY
    """
    try:
        enc_service = get_encryption_service()
        plaintext_bytes = plaintext.encode('utf-8')
        encrypted_bytes = enc_service.encrypt(plaintext_bytes)

        if return_base64:
            return base64.b64encode(encrypted_bytes).decode('ascii')
        else:
            return encrypted_bytes

    except Exception as e:
        logger.error(f"Encryption failed: {type(e).__name__}: {e}")
        raise ValueError(f"Failed to encrypt credentials: {e}")


def migrate_encrypted_value(
    encrypted_data: Union[bytes, str, memoryview],
    master_key: Optional[str] = None
) -> Tuple[str, EncryptionFormat, EncryptionFormat]:
    """
    Migrate an encrypted value from crypto.py to encryption.py format.

    This function:
    1. Decrypts with dual-format support
    2. Re-encrypts using encryption.py format
    3. Returns both old and new format indicators

    Args:
        encrypted_data: Encrypted data in any supported format
        master_key: Optional master key (uses settings if not provided)

    Returns:
        Tuple of (
            new_encrypted_base64: str,
            old_format: EncryptionFormat,
            new_format: EncryptionFormat
        )

    Example:
        >>> # Migrate old crypto.py data
        >>> old_encrypted = crypto.encrypt_credentials("password123")
        >>> new_encrypted, old_fmt, new_fmt = migrate_encrypted_value(old_encrypted)
        >>> assert old_fmt == EncryptionFormat.CRYPTO_PY
        >>> assert new_fmt == EncryptionFormat.ENCRYPTION_PY
    """
    # Decrypt with dual support
    plaintext, old_format = decrypt_credentials_dual(encrypted_data, master_key)

    # Re-encrypt with new format
    new_encrypted = encrypt_credentials_new(plaintext, master_key, return_base64=True)

    logger.info(
        f"Migrated credential from {old_format.value} to {EncryptionFormat.ENCRYPTION_PY.value}"
    )

    return new_encrypted, old_format, EncryptionFormat.ENCRYPTION_PY


def verify_dual_encryption() -> bool:
    """
    Verify that both encryption formats are working correctly.

    This function:
    1. Encrypts test data with crypto.py
    2. Encrypts test data with encryption.py
    3. Decrypts both with dual-format function
    4. Verifies correct format detection

    Returns:
        True if all tests pass, False otherwise
    """
    test_data = "test-credential-verification-12345"

    try:
        # Test crypto.py format
        logger.info("Testing crypto.py encryption/decryption...")
        crypto_encrypted = crypto.encrypt_credentials(test_data)
        crypto_plaintext, crypto_format = decrypt_credentials_dual(crypto_encrypted)

        if crypto_plaintext != test_data:
            logger.error(f"crypto.py decryption mismatch: {crypto_plaintext} != {test_data}")
            return False
        if crypto_format != EncryptionFormat.CRYPTO_PY:
            logger.error(f"crypto.py format detection failed: {crypto_format}")
            return False

        logger.info("✓ crypto.py format test passed")

        # Test encryption.py format
        logger.info("Testing encryption.py encryption/decryption...")
        enc_encrypted = encrypt_credentials_new(test_data, return_base64=False)
        enc_plaintext, enc_format = decrypt_credentials_dual(enc_encrypted)

        if enc_plaintext != test_data:
            logger.error(f"encryption.py decryption mismatch: {enc_plaintext} != {test_data}")
            return False
        if enc_format != EncryptionFormat.ENCRYPTION_PY:
            logger.error(f"encryption.py format detection failed: {enc_format}")
            return False

        logger.info("✓ encryption.py format test passed")

        # Test migration
        logger.info("Testing credential migration...")
        new_encrypted, old_fmt, new_fmt = migrate_encrypted_value(crypto_encrypted)
        migrated_plaintext, migrated_format = decrypt_credentials_dual(new_encrypted)

        if migrated_plaintext != test_data:
            logger.error(f"Migration decryption mismatch: {migrated_plaintext} != {test_data}")
            return False
        if old_fmt != EncryptionFormat.CRYPTO_PY:
            logger.error(f"Migration old format detection failed: {old_fmt}")
            return False
        if new_fmt != EncryptionFormat.ENCRYPTION_PY:
            logger.error(f"Migration new format detection failed: {new_fmt}")
            return False
        if migrated_format != EncryptionFormat.ENCRYPTION_PY:
            logger.error(f"Migrated data format detection failed: {migrated_format}")
            return False

        logger.info("✓ Migration test passed")

        logger.info("✅ All encryption compatibility tests passed")
        return True

    except Exception as e:
        logger.error(f"Encryption compatibility test failed: {type(e).__name__}: {e}")
        return False
