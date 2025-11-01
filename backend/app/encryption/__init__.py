"""
Encryption module for OpenWatch.

Provides FIPS 140-2 compliant AES-256-GCM encryption with configurable
parameters and proper dependency injection.

This module replaces the legacy singleton-based encryption.py with a
more modular, testable, and configurable design.

Public API:
    - EncryptionService: Main encryption service class
    - EncryptionConfig: Configuration dataclass
    - create_encryption_service: Factory function
    - KDFAlgorithm: Supported KDF algorithms enum
    - Exception classes: EncryptionError, DecryptionError, InvalidDataError

Quick Start:
    >>> from app.encryption import EncryptionService, EncryptionConfig
    >>>
    >>> # Create service with defaults
    >>> service = EncryptionService(master_key="your-secret-key")
    >>>
    >>> # Encrypt and decrypt
    >>> encrypted = service.encrypt(b"sensitive data")
    >>> decrypted = service.decrypt(encrypted)
    >>> assert decrypted == b"sensitive data"

Dependency Injection Example:
    >>> from app.config import get_settings
    >>> from app.encryption import create_encryption_service
    >>>
    >>> # In application startup (FastAPI lifespan)
    >>> settings = get_settings()
    >>> encryption_service = create_encryption_service(settings.master_key)
    >>>
    >>> # Inject into services
    >>> auth_service = AuthService(db, encryption_service)
    >>> host_monitor = HostMonitor(db, encryption_service)

Custom Configuration:
    >>> from app.encryption import EncryptionConfig, KDFAlgorithm
    >>>
    >>> # High-security config
    >>> config = EncryptionConfig(
    ...     kdf_iterations=200000,
    ...     kdf_algorithm=KDFAlgorithm.SHA512
    ... )
    >>> service = EncryptionService(master_key="key", config=config)
    >>>
    >>> # Fast config for testing
    >>> test_config = EncryptionConfig(kdf_iterations=10000)
    >>> test_service = EncryptionService(master_key="key", config=test_config)

Error Handling:
    >>> from app.encryption import (
    ...     EncryptionService,
    ...     EncryptionError,
    ...     DecryptionError,
    ...     InvalidDataError
    ... )
    >>>
    >>> try:
    ...     service = EncryptionService("key")
    ...     encrypted = service.encrypt(b"data")
    ...     decrypted = service.decrypt(encrypted)
    ... except InvalidDataError as e:
    ...     print(f"Invalid data format: {e}")
    ... except DecryptionError as e:
    ...     print(f"Decryption failed: {e}")
    ... except EncryptionError as e:
    ...     print(f"Encryption error: {e}")
"""

from .service import EncryptionService, create_encryption_service
from .config import (
    EncryptionConfig,
    KDFAlgorithm,
    DEFAULT_CONFIG,
    FAST_TEST_CONFIG,
    HIGH_SECURITY_CONFIG,
)
from .exceptions import (
    EncryptionError,
    DecryptionError,
    InvalidDataError,
    ConfigurationError,
)

__all__ = [
    # Main service
    "EncryptionService",
    "create_encryption_service",
    # Configuration
    "EncryptionConfig",
    "KDFAlgorithm",
    "DEFAULT_CONFIG",
    "FAST_TEST_CONFIG",
    "HIGH_SECURITY_CONFIG",
    # Exceptions
    "EncryptionError",
    "DecryptionError",
    "InvalidDataError",
    "ConfigurationError",
]

__version__ = "2.0.0"
__author__ = "OpenWatch Security Team"
