"""
Encryption service wrapper for credential operations.

This module provides a simplified interface for encrypting and decrypting credentials
using the new modular encryption system (backend.app.encryption).

Historical Note:
This file previously provided dual-decrypt capability to support migration from
the legacy crypto.py module. As of 2025-11-01, all credentials have been migrated
to the new encryption format, so crypto.py support has been removed.

Usage:
    >>> from app.services.encryption_compatibility import decrypt_credentials
    >>>
    >>> # Decrypt credentials using new encryption format
    >>> plaintext = decrypt_credentials(encrypted_data)
"""

import base64
import logging
from typing import Union

from backend.app.encryption import (
    DecryptionError,
    EncryptionService,
    InvalidDataError,
    create_encryption_service,
)

# Import new modular encryption only
from backend.app.services.encryption import get_encryption_service

logger = logging.getLogger(__name__)


def decrypt_credentials(encrypted_data: Union[bytes, str, memoryview]) -> str:
    """
    Decrypt credentials using the new encryption format.

    Args:
        encrypted_data: Encrypted data (bytes, base64 string, or memoryview)

    Returns:
        Decrypted plaintext string

    Raises:
        ValueError: If decryption fails

    Example:
        >>> encrypted = encrypt_credentials("password123")
        >>> plaintext = decrypt_credentials(encrypted)
        >>> assert plaintext == "password123"
    """
    # Handle different input types
    if isinstance(encrypted_data, memoryview):
        encrypted_bytes = bytes(encrypted_data)
    elif isinstance(encrypted_data, str):
        # Assume base64-encoded string
        try:
            encrypted_bytes = base64.b64decode(encrypted_data.encode("ascii"))
        except Exception as e:
            logger.error(f"Failed to decode base64 string: {e}")
            raise ValueError(f"Invalid base64 encoding: {e}")
    elif isinstance(encrypted_data, bytes):
        encrypted_bytes = encrypted_data
    else:
        logger.error(f"Invalid encrypted data type: {type(encrypted_data)}")
        raise ValueError(f"Invalid encrypted data type: {type(encrypted_data)}")

    # Validate minimum length
    if len(encrypted_bytes) < 28:
        logger.error(f"Encrypted data too short: {len(encrypted_bytes)} bytes")
        raise ValueError(
            f"Encrypted data too short: {len(encrypted_bytes)} bytes " f"(minimum: 28 bytes for salt + nonce)"
        )

    # Decrypt using new encryption service
    try:
        logger.debug("Decrypting credentials with new encryption format")
        enc_service = get_encryption_service()
        plaintext_bytes = enc_service.decrypt(encrypted_bytes)
        plaintext = plaintext_bytes.decode("utf-8")

        logger.debug(f"Successfully decrypted credentials (length: {len(plaintext)})")
        return plaintext

    except Exception as e:
        logger.error(f"Decryption failed: {type(e).__name__}: {e}")
        raise ValueError(f"Failed to decrypt credentials: {type(e).__name__}: {e}")


def encrypt_credentials(plaintext: str, return_base64: bool = True) -> Union[bytes, str]:
    """
    Encrypt credentials using the new encryption format.

    Args:
        plaintext: Plaintext string to encrypt
        return_base64: If True, return base64-encoded string; else return bytes

    Returns:
        Encrypted data as bytes or base64 string (depending on return_base64)

    Example:
        >>> encrypted = encrypt_credentials("password123")
        >>> plaintext = decrypt_credentials(encrypted)
        >>> assert plaintext == "password123"
    """
    try:
        enc_service = get_encryption_service()
        plaintext_bytes = plaintext.encode("utf-8")
        encrypted_bytes = enc_service.encrypt(plaintext_bytes)

        if return_base64:
            return base64.b64encode(encrypted_bytes).decode("ascii")
        else:
            return encrypted_bytes

    except Exception as e:
        logger.error(f"Encryption failed: {type(e).__name__}: {e}")
        raise ValueError(f"Failed to encrypt credentials: {e}")


def encrypt_string(data: str) -> str:
    """
    Encrypt string and return base64 encoded result.

    This function provides API compatibility with legacy crypto.py module.

    Args:
        data: Plaintext string to encrypt

    Returns:
        Base64-encoded encrypted string
    """
    return encrypt_credentials(data, return_base64=True)


def decrypt_string(encrypted_b64: str) -> str:
    """
    Decrypt base64 encoded encrypted string.

    This function provides API compatibility with legacy crypto.py module.

    Args:
        encrypted_b64: Base64-encoded encrypted string

    Returns:
        Decrypted plaintext string
    """
    return decrypt_credentials(encrypted_b64)


def verify_encryption() -> bool:
    """
    Verify that encryption/decryption is working correctly.

    Returns:
        True if encryption/decryption test passes, False otherwise
    """
    test_data = "test-credential-verification-12345"

    try:
        logger.info("Testing encryption/decryption...")
        encrypted = encrypt_credentials(test_data, return_base64=False)
        decrypted = decrypt_credentials(encrypted)

        if decrypted != test_data:
            logger.error(f"Encryption verification mismatch: {decrypted} != {test_data}")
            return False

        logger.info("Encryption verification passed")
        return True

    except Exception as e:
        logger.error(f"Encryption verification failed: {type(e).__name__}: {e}")
        return False
