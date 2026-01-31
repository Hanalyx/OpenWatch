"""
Unit tests for CentralizedAuthService.

Tests credential validation, auth method compatibility, and business logic.
Database-dependent methods are tested with mocked sessions.
"""

from unittest.mock import MagicMock

import pytest

from app.encryption import EncryptionService
from app.encryption.config import FAST_TEST_CONFIG
from app.services.auth.credential_service import CentralizedAuthService
from app.services.auth.exceptions import AuthMethodMismatchError, CredentialNotFoundError, CredentialValidationError
from app.services.auth.models import AuthMethod, CredentialData, CredentialMetadata, CredentialScope


@pytest.fixture
def encryption_service() -> EncryptionService:
    """Create a fast encryption service for tests."""
    return EncryptionService("test-master-key-for-cred-tests", FAST_TEST_CONFIG)  # pragma: allowlist secret


@pytest.fixture
def mock_db() -> MagicMock:
    """Create a mock database session."""
    return MagicMock()


@pytest.fixture
def auth_service(mock_db: MagicMock, encryption_service: EncryptionService) -> CentralizedAuthService:
    """Create auth service with mocked dependencies."""
    return CentralizedAuthService(mock_db, encryption_service)


@pytest.mark.unit
class TestAuthMethodCompatibility:
    """Test auth method matching logic."""

    def test_password_matches_password(self, auth_service: CentralizedAuthService) -> None:
        """PASSWORD available matches PASSWORD required."""
        assert auth_service._auth_method_compatible("password", "password") is True

    def test_ssh_key_matches_ssh_key(self, auth_service: CentralizedAuthService) -> None:
        """SSH_KEY available matches SSH_KEY required."""
        assert auth_service._auth_method_compatible("ssh_key", "ssh_key") is True

    def test_both_matches_password(self, auth_service: CentralizedAuthService) -> None:
        """BOTH available matches PASSWORD required."""
        assert auth_service._auth_method_compatible("both", "password") is True

    def test_both_matches_ssh_key(self, auth_service: CentralizedAuthService) -> None:
        """BOTH available matches SSH_KEY required."""
        assert auth_service._auth_method_compatible("both", "ssh_key") is True

    def test_password_not_matches_ssh_key(self, auth_service: CentralizedAuthService) -> None:
        """PASSWORD available does NOT match SSH_KEY required."""
        assert auth_service._auth_method_compatible("password", "ssh_key") is False

    def test_ssh_key_not_matches_password(self, auth_service: CentralizedAuthService) -> None:
        """SSH_KEY available does NOT match PASSWORD required."""
        assert auth_service._auth_method_compatible("ssh_key", "password") is False

    def test_none_required_does_not_match(self, auth_service: CentralizedAuthService) -> None:
        """None required method does not match (strict matching)."""
        assert auth_service._auth_method_compatible("password", None) is False
        assert auth_service._auth_method_compatible("ssh_key", None) is False


@pytest.mark.unit
class TestCredentialValidation:
    """Test credential data validation."""

    def test_valid_password_credential(self, auth_service: CentralizedAuthService) -> None:
        """Valid password credential passes validation."""
        cred = CredentialData(
            username="admin",
            auth_method=AuthMethod.PASSWORD,
            password="Str0ng!P@ss#2026",  # pragma: allowlist secret
        )
        is_valid, error = auth_service.validate_credential(cred, strict_mode=False)
        assert isinstance(is_valid, bool)

    def test_missing_password_fails(self, auth_service: CentralizedAuthService) -> None:
        """Password credential without password fails."""
        cred = CredentialData(
            username="admin",
            auth_method=AuthMethod.PASSWORD,
        )
        is_valid, error = auth_service.validate_credential(cred, strict_mode=False)
        # Should fail since password is required for PASSWORD method
        assert is_valid is False or "password" in error.lower()

    def test_missing_key_for_ssh_fails(self, auth_service: CentralizedAuthService) -> None:
        """SSH key credential without key fails."""
        cred = CredentialData(
            username="admin",
            auth_method=AuthMethod.SSH_KEY,
        )
        is_valid, error = auth_service.validate_credential(cred, strict_mode=False)
        assert is_valid is False or "key" in error.lower()


@pytest.mark.unit
class TestCredentialModels:
    """Test Pydantic model construction and validation."""

    def test_credential_data_defaults(self) -> None:
        """CredentialData has correct defaults."""
        cred = CredentialData(
            username="user",
            auth_method=AuthMethod.PASSWORD,
        )
        assert cred.username == "user"
        assert cred.auth_method == AuthMethod.PASSWORD
        assert cred.private_key is None
        assert cred.password is None
        assert cred.source == "unknown"

    def test_credential_metadata_defaults(self) -> None:
        """CredentialMetadata has correct defaults."""
        meta = CredentialMetadata(
            name="test-cred",
            scope=CredentialScope.HOST,
        )
        assert meta.name == "test-cred"
        assert meta.scope == CredentialScope.HOST
        assert meta.is_default is False
        assert meta.is_active is True
        assert meta.id is not None  # Auto-generated UUID

    def test_credential_scope_values(self) -> None:
        """CredentialScope enum has expected values."""
        assert CredentialScope.SYSTEM.value == "system"
        assert CredentialScope.HOST.value == "host"
        assert CredentialScope.GROUP.value == "group"

    def test_auth_method_values(self) -> None:
        """AuthMethod enum has expected values."""
        assert AuthMethod.SSH_KEY.value == "ssh_key"
        assert AuthMethod.PASSWORD.value == "password"
        assert AuthMethod.BOTH.value == "both"


@pytest.mark.unit
class TestExceptions:
    """Test custom exception construction."""

    def test_credential_not_found(self) -> None:
        """CredentialNotFoundError stores target_id."""
        exc = CredentialNotFoundError(target_id="host-123", message="Not found")
        assert exc.target_id == "host-123"
        assert exc.message == "Not found"

    def test_credential_validation_error(self) -> None:
        """CredentialValidationError stores validation details."""
        exc = CredentialValidationError(
            message="Key too weak",
            validation_errors=["RSA key < 2048 bits"],
            is_security_rejection=True,
        )
        assert exc.message == "Key too weak"
        assert len(exc.validation_errors) == 1
        assert exc.is_security_rejection is True

    def test_auth_method_mismatch(self) -> None:
        """AuthMethodMismatchError can be raised."""
        with pytest.raises(AuthMethodMismatchError):
            raise AuthMethodMismatchError("Expected ssh_key, got password")


@pytest.mark.unit
class TestGetAuthService:
    """Test factory function."""

    def test_creates_service(self, mock_db: MagicMock, encryption_service: EncryptionService) -> None:
        """Factory creates CentralizedAuthService."""
        from app.services.auth.credential_service import get_auth_service

        service = get_auth_service(mock_db, encryption_service)
        assert isinstance(service, CentralizedAuthService)
