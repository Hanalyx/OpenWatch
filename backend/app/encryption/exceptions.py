"""
Custom exceptions for encryption operations.

Provides specific exception types for different encryption failure modes,
enabling better error handling and debugging.
"""


class EncryptionError(Exception):
    """
    Base exception for all encryption-related errors.

    All encryption exceptions inherit from this class, allowing
    callers to catch all encryption errors with a single except clause.

    Example:
        >>> try:
        ...     service.encrypt(data)
        ... except EncryptionError as e:
        ...     logger.error(f"Encryption failed: {e}")
    """

    pass


class DecryptionError(EncryptionError):
    """
    Raised when decryption fails.

    This typically indicates:
    - Wrong decryption key
    - Corrupted ciphertext
    - Authentication tag verification failure (GCM)
    - Algorithm mismatch

    Example:
        >>> try:
        ...     service.decrypt(encrypted_data)
        ... except DecryptionError as e:
        ...     logger.error(f"Decryption failed: {e}")
        ...     # Could be wrong key or corrupted data
    """

    pass


class InvalidDataError(EncryptionError):
    """
    Raised when encrypted data format is invalid.

    This indicates structural problems with the encrypted data:
    - Data too short (missing salt, nonce, or ciphertext)
    - Invalid format or encoding
    - Missing required components

    This is different from DecryptionError which indicates
    the data structure is valid but decryption failed.

    Example:
        >>> try:
        ...     service.decrypt(b"invalid")
        ... except InvalidDataError as e:
        ...     logger.error(f"Invalid data format: {e}")
        ...     # Data is structurally invalid
    """

    pass


class ConfigurationError(EncryptionError):
    """
    Raised when encryption configuration is invalid.

    This indicates problems with EncryptionConfig parameters:
    - Invalid parameter values (e.g., too few KDF iterations)
    - Incompatible parameter combinations
    - Security policy violations

    Example:
        >>> try:
        ...     config = EncryptionConfig(kdf_iterations=100)
        ... except ConfigurationError as e:
        ...     logger.error(f"Invalid configuration: {e}")
    """

    pass
