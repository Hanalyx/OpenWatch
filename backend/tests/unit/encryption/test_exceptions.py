"""
Tests for custom encryption exceptions.
"""

import pytest

from app.encryption import ConfigurationError, DecryptionError, EncryptionError, InvalidDataError


class TestExceptionHierarchy:
    """Test exception class hierarchy"""

    def test_encryption_error_is_base_exception(self):
        """Test EncryptionError is base exception"""
        exc = EncryptionError("test error")
        assert isinstance(exc, Exception)
        assert str(exc) == "test error"

    def test_decryption_error_inherits_from_encryption_error(self):
        """Test DecryptionError inherits from EncryptionError"""
        exc = DecryptionError("decryption failed")
        assert isinstance(exc, EncryptionError)
        assert isinstance(exc, Exception)
        assert str(exc) == "decryption failed"

    def test_invalid_data_error_inherits_from_encryption_error(self):
        """Test InvalidDataError inherits from EncryptionError"""
        exc = InvalidDataError("invalid data format")
        assert isinstance(exc, EncryptionError)
        assert isinstance(exc, Exception)
        assert str(exc) == "invalid data format"

    def test_configuration_error_inherits_from_encryption_error(self):
        """Test ConfigurationError inherits from EncryptionError"""
        exc = ConfigurationError("invalid config")
        assert isinstance(exc, EncryptionError)
        assert isinstance(exc, Exception)
        assert str(exc) == "invalid config"


class TestExceptionCatching:
    """Test exception catching patterns"""

    def test_catch_specific_exception(self):
        """Test catching specific exception type"""
        try:
            raise DecryptionError("wrong key")
        except DecryptionError as e:
            assert str(e) == "wrong key"
        except EncryptionError:
            pytest.fail("Should have caught DecryptionError specifically")

    def test_catch_base_encryption_error(self):
        """Test catching base EncryptionError catches all subtypes"""
        exceptions = [
            DecryptionError("decrypt failed"),
            InvalidDataError("invalid format"),
            ConfigurationError("bad config"),
            EncryptionError("generic error"),
        ]

        for exc in exceptions:
            try:
                raise exc
            except EncryptionError as e:
                # All should be caught by base exception
                assert isinstance(e, EncryptionError)
            except Exception:
                pytest.fail(f"Should have caught {type(exc).__name__} as EncryptionError")

    def test_exception_messages(self):
        """Test exception messages are preserved"""
        message = "Detailed error message with context"

        exc = EncryptionError(message)
        assert str(exc) == message

        exc = DecryptionError(message)
        assert str(exc) == message

        exc = InvalidDataError(message)
        assert str(exc) == message

        exc = ConfigurationError(message)
        assert str(exc) == message


class TestExceptionUsagePatterns:
    """Test realistic exception usage patterns"""

    def test_decryption_error_with_context(self):
        """Test DecryptionError with contextual information"""
        scan_id = "550e8400-e29b-41d4-a716-446655440000"
        error_msg = f"Failed to decrypt credentials for scan {scan_id}"

        exc = DecryptionError(error_msg)
        assert "550e8400" in str(exc)
        assert "decrypt credentials" in str(exc)

    def test_invalid_data_error_with_length_info(self):
        """Test InvalidDataError with data length information"""
        actual_length = 20
        min_length = 44
        error_msg = f"Encrypted data too short: {actual_length} < {min_length} bytes"

        exc = InvalidDataError(error_msg)
        assert "20" in str(exc)
        assert "44" in str(exc)

    def test_configuration_error_with_parameter_details(self):
        """Test ConfigurationError with parameter details"""
        iterations = 5000
        minimum = 10000
        error_msg = f"KDF iterations ({iterations}) must be >= {minimum}"

        exc = ConfigurationError(error_msg)
        assert "5000" in str(exc)
        assert "10000" in str(exc)

    def test_exception_chaining(self):
        """Test exception chaining with 'from' clause"""
        with pytest.raises(EncryptionError) as exc_info:
            try:
                # Simulate low-level error
                raise ValueError("Invalid key format")
            except ValueError as e:
                # Raise encryption-specific error with chaining
                raise EncryptionError("Encryption initialization failed") from e

        # Verify the exception was chained correctly
        assert "Encryption initialization failed" in str(exc_info.value)
        assert exc_info.value.__cause__ is not None
        assert isinstance(exc_info.value.__cause__, ValueError)
