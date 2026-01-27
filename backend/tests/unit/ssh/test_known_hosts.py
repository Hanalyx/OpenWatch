"""
Unit Tests for KnownHostsManager

Tests the SSH known hosts database management functionality including:
- CRUD operations for known host entries
- Fingerprint generation from public keys
- Trust status management
- Database error handling

These tests use mocked database sessions to isolate unit testing
from database dependencies.

Test Categories:
- Initialization tests: Verify proper setup with/without db
- get_known_hosts tests: Retrieval and filtering
- add_known_host tests: Insertion with fingerprint generation
- remove_known_host tests: Deletion with audit logging
- update_last_verified tests: Timestamp updates
- set_trust_status tests: Trust management
- find_by_fingerprint tests: Fingerprint-based lookup
- _generate_fingerprint tests: Fingerprint algorithm verification

CLAUDE.md Compliance:
- Comprehensive docstrings on all test functions
- Type hints where applicable
- Defensive error handling verification
- Security-focused test cases
- No emojis in code

References:
- OpenSSH known_hosts format: man 8 sshd (AUTHORIZED_KEYS FILE FORMAT)
- SSH public key fingerprints: RFC 4716
"""

import base64
import hashlib
from datetime import datetime
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, Mock, patch, PropertyMock

import pytest

# Import the class under test
from app.services.ssh.known_hosts import KnownHostsManager


# =============================================================================
# Test Data Constants
# =============================================================================

# Sample SSH public keys for testing (generated for tests only)
# These are NOT real keys and should never be used in production
# These keys have proper base64 encoding for fingerprint generation tests

# Valid base64-encoded RSA public key (simplified for testing)
SAMPLE_RSA_KEY = (
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDMjJvA4+qz+CqRxnA8tZ7mAj8R"
    "xRASWYz7N2H8L7wj8sIwpzC8tN7mAj8RxRASWYz7N2H8L7wj8sIwpzC8tN7mAj8R"
    "xRASWYz7N2H8L7wj8sIwpzC8tN7m+w== test@example.com"
)

# Valid Ed25519 public key (from real key generation, safe for testing)
SAMPLE_ED25519_KEY = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH4+w2e8SoiX5nJC6IpE/HwP8N7z"
    "PqJH+D4e+GxKB7aY test@example.com"
)

# Valid ECDSA public key
SAMPLE_ECDSA_KEY = (
    "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYA"
    "AABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v"
    "0mKV0U2w0WZ2YB/++Tpockg= test@example.com"
)

# Invalid key for testing error handling
INVALID_KEY = "not-a-valid-ssh-key"


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def mock_db_session() -> MagicMock:
    """
    Create a mock database session for isolated unit testing.

    Returns:
        MagicMock configured to behave like a SQLAlchemy Session
    """
    mock_session = MagicMock()
    mock_session.execute.return_value = MagicMock()
    mock_session.commit.return_value = None
    mock_session.rollback.return_value = None
    return mock_session


@pytest.fixture
def known_hosts_manager(mock_db_session: MagicMock) -> KnownHostsManager:
    """
    Create a KnownHostsManager instance with mocked database.

    Args:
        mock_db_session: Mocked SQLAlchemy session

    Returns:
        KnownHostsManager instance ready for testing
    """
    return KnownHostsManager(db=mock_db_session)


@pytest.fixture
def known_hosts_manager_no_db() -> KnownHostsManager:
    """
    Create a KnownHostsManager instance without a database session.

    Used for testing fallback behavior when no database is available.

    Returns:
        KnownHostsManager instance with db=None
    """
    return KnownHostsManager(db=None)


@pytest.fixture
def sample_host_row() -> MagicMock:
    """
    Create a mock database row representing a known host.

    Returns:
        MagicMock configured to behave like a SQLAlchemy result row
    """
    row = MagicMock()
    row.id = 1
    row.hostname = "server.example.com"
    row.ip_address = "192.168.1.100"
    row.key_type = "ed25519"
    row.fingerprint = "SHA256:abcdef123456"
    row.first_seen = datetime(2024, 1, 1, 12, 0, 0)
    row.last_verified = datetime(2024, 6, 1, 12, 0, 0)
    row.is_trusted = True
    row.notes = "Production server"
    return row


# =============================================================================
# Initialization Tests
# =============================================================================


class TestKnownHostsManagerInit:
    """Tests for KnownHostsManager initialization."""

    def test_init_with_db_session(self, mock_db_session: MagicMock) -> None:
        """
        Verify manager initializes correctly with a database session.

        The database session should be stored for later use in
        all CRUD operations.
        """
        manager = KnownHostsManager(db=mock_db_session)

        assert manager.db is mock_db_session
        assert manager.db is not None

    def test_init_without_db_session(self) -> None:
        """
        Verify manager initializes correctly without a database session.

        When no database is available, the manager should still function
        but return empty results/False for all operations.
        """
        manager = KnownHostsManager(db=None)

        assert manager.db is None


# =============================================================================
# get_known_hosts Tests
# =============================================================================


class TestGetKnownHosts:
    """Tests for the get_known_hosts method."""

    def test_get_known_hosts_no_db_returns_empty(
        self, known_hosts_manager_no_db: KnownHostsManager
    ) -> None:
        """
        Verify get_known_hosts returns empty list when no database session.

        Without a database connection, no hosts can be retrieved.
        """
        result = known_hosts_manager_no_db.get_known_hosts()

        assert result == []

    def test_get_known_hosts_returns_list(
        self,
        known_hosts_manager: KnownHostsManager,
        sample_host_row: MagicMock,
    ) -> None:
        """
        Verify get_known_hosts returns properly formatted list.

        Each host should be converted to a dictionary with expected keys.
        """
        # Configure mock to return sample row
        mock_result = MagicMock()
        mock_result.__iter__ = Mock(return_value=iter([sample_host_row]))
        known_hosts_manager.db.execute.return_value = mock_result

        result = known_hosts_manager.get_known_hosts()

        assert len(result) == 1
        assert result[0]["hostname"] == "server.example.com"
        assert result[0]["ip_address"] == "192.168.1.100"
        assert result[0]["key_type"] == "ed25519"
        assert result[0]["is_trusted"] is True

    def test_get_known_hosts_with_hostname_filter(
        self,
        known_hosts_manager: KnownHostsManager,
        sample_host_row: MagicMock,
    ) -> None:
        """
        Verify get_known_hosts filters by hostname when provided.

        The hostname parameter should be passed to the database query.
        """
        mock_result = MagicMock()
        mock_result.__iter__ = Mock(return_value=iter([sample_host_row]))
        known_hosts_manager.db.execute.return_value = mock_result

        result = known_hosts_manager.get_known_hosts(hostname="server.example.com")

        # Verify query was called with hostname parameter
        known_hosts_manager.db.execute.assert_called_once()
        call_args = known_hosts_manager.db.execute.call_args
        params = call_args[0][1]  # Second argument is params dict
        assert params["hostname"] == "server.example.com"

    def test_get_known_hosts_empty_result(
        self, known_hosts_manager: KnownHostsManager
    ) -> None:
        """
        Verify get_known_hosts returns empty list when no hosts found.
        """
        mock_result = MagicMock()
        mock_result.__iter__ = Mock(return_value=iter([]))
        known_hosts_manager.db.execute.return_value = mock_result

        result = known_hosts_manager.get_known_hosts()

        assert result == []

    def test_get_known_hosts_datetime_formatting(
        self,
        known_hosts_manager: KnownHostsManager,
        sample_host_row: MagicMock,
    ) -> None:
        """
        Verify datetime fields are formatted as ISO strings.

        first_seen and last_verified should be converted to ISO format.
        """
        mock_result = MagicMock()
        mock_result.__iter__ = Mock(return_value=iter([sample_host_row]))
        known_hosts_manager.db.execute.return_value = mock_result

        result = known_hosts_manager.get_known_hosts()

        assert result[0]["first_seen"] == "2024-01-01T12:00:00"
        assert result[0]["last_verified"] == "2024-06-01T12:00:00"

    def test_get_known_hosts_none_datetime(
        self, known_hosts_manager: KnownHostsManager
    ) -> None:
        """
        Verify None datetime fields are handled correctly.
        """
        row = MagicMock()
        row.id = 1
        row.hostname = "test.example.com"
        row.ip_address = None
        row.key_type = "rsa"
        row.fingerprint = "SHA256:xyz"
        row.first_seen = None
        row.last_verified = None
        row.is_trusted = False
        row.notes = None

        mock_result = MagicMock()
        mock_result.__iter__ = Mock(return_value=iter([row]))
        known_hosts_manager.db.execute.return_value = mock_result

        result = known_hosts_manager.get_known_hosts()

        assert result[0]["first_seen"] is None
        assert result[0]["last_verified"] is None

    def test_get_known_hosts_database_error(
        self, known_hosts_manager: KnownHostsManager
    ) -> None:
        """
        Verify get_known_hosts handles database errors gracefully.

        Database errors should not propagate up - empty list returned.
        """
        known_hosts_manager.db.execute.side_effect = Exception("Database error")

        result = known_hosts_manager.get_known_hosts()

        assert result == []


# =============================================================================
# add_known_host Tests
# =============================================================================


class TestAddKnownHost:
    """Tests for the add_known_host method."""

    def test_add_known_host_no_db_returns_false(
        self, known_hosts_manager_no_db: KnownHostsManager
    ) -> None:
        """
        Verify add_known_host returns False when no database session.

        Without a database connection, hosts cannot be persisted.
        """
        result = known_hosts_manager_no_db.add_known_host(
            hostname="server.example.com",
            ip_address="192.168.1.100",
            key_type="ed25519",
            public_key=SAMPLE_ED25519_KEY,
            notes="Test server",
        )

        assert result is False

    def test_add_known_host_success(
        self, known_hosts_manager: KnownHostsManager
    ) -> None:
        """
        Verify add_known_host returns True on successful insertion.
        """
        result = known_hosts_manager.add_known_host(
            hostname="server.example.com",
            ip_address="192.168.1.100",
            key_type="ed25519",
            public_key=SAMPLE_ED25519_KEY,
            notes="Test server",
        )

        assert result is True
        known_hosts_manager.db.execute.assert_called_once()
        known_hosts_manager.db.commit.assert_called_once()

    def test_add_known_host_generates_fingerprint(
        self, known_hosts_manager: KnownHostsManager
    ) -> None:
        """
        Verify add_known_host generates SHA256 fingerprint.

        The fingerprint should be in OpenSSH format (SHA256:base64hash).
        """
        known_hosts_manager.add_known_host(
            hostname="server.example.com",
            ip_address="192.168.1.100",
            key_type="ed25519",
            public_key=SAMPLE_ED25519_KEY,
        )

        # Check that execute was called with fingerprint parameter
        call_args = known_hosts_manager.db.execute.call_args
        params = call_args[0][1]  # Second argument is params dict
        assert params["fingerprint"].startswith("SHA256:")

    def test_add_known_host_invalid_key_returns_false(
        self, known_hosts_manager: KnownHostsManager
    ) -> None:
        """
        Verify add_known_host returns False for invalid public key.

        Invalid keys cannot have fingerprints generated.
        """
        result = known_hosts_manager.add_known_host(
            hostname="server.example.com",
            ip_address="192.168.1.100",
            key_type="ed25519",
            public_key=INVALID_KEY,
        )

        assert result is False
        known_hosts_manager.db.execute.assert_not_called()

    def test_add_known_host_database_error(
        self, known_hosts_manager: KnownHostsManager
    ) -> None:
        """
        Verify add_known_host handles database errors gracefully.
        """
        known_hosts_manager.db.execute.side_effect = Exception("Insert failed")

        result = known_hosts_manager.add_known_host(
            hostname="server.example.com",
            ip_address="192.168.1.100",
            key_type="ed25519",
            public_key=SAMPLE_ED25519_KEY,
        )

        assert result is False
        known_hosts_manager.db.rollback.assert_called_once()

    def test_add_known_host_optional_ip_address(
        self, known_hosts_manager: KnownHostsManager
    ) -> None:
        """
        Verify add_known_host works with None ip_address.
        """
        # Mock fingerprint generation since sample keys are not real
        with patch.object(
            known_hosts_manager, "_generate_fingerprint", return_value="mock_fingerprint"
        ):
            result = known_hosts_manager.add_known_host(
                hostname="server.example.com",
                ip_address=None,
                key_type="rsa",
                public_key=SAMPLE_RSA_KEY,
            )

            assert result is True
            call_args = known_hosts_manager.db.execute.call_args
            params = call_args[0][1]
            assert params["ip_address"] is None

    def test_add_known_host_optional_notes(
        self, known_hosts_manager: KnownHostsManager
    ) -> None:
        """
        Verify add_known_host works with None notes.
        """
        # Mock fingerprint generation since sample keys are not real
        with patch.object(
            known_hosts_manager, "_generate_fingerprint", return_value="mock_fingerprint"
        ):
            result = known_hosts_manager.add_known_host(
                hostname="server.example.com",
                ip_address="192.168.1.100",
                key_type="rsa",
                public_key=SAMPLE_RSA_KEY,
                notes=None,
            )

            assert result is True
            call_args = known_hosts_manager.db.execute.call_args
            params = call_args[0][1]
            assert params["notes"] is None


# =============================================================================
# remove_known_host Tests
# =============================================================================


class TestRemoveKnownHost:
    """Tests for the remove_known_host method."""

    def test_remove_known_host_no_db_returns_false(
        self, known_hosts_manager_no_db: KnownHostsManager
    ) -> None:
        """
        Verify remove_known_host returns False when no database session.
        """
        result = known_hosts_manager_no_db.remove_known_host(
            hostname="server.example.com",
            key_type="ed25519",
        )

        assert result is False

    def test_remove_known_host_success(
        self, known_hosts_manager: KnownHostsManager
    ) -> None:
        """
        Verify remove_known_host returns True when host is deleted.
        """
        # Mock rowcount to indicate deletion
        mock_result = MagicMock()
        mock_result.rowcount = 1
        known_hosts_manager.db.execute.return_value = mock_result

        result = known_hosts_manager.remove_known_host(
            hostname="server.example.com",
            key_type="ed25519",
        )

        assert result is True
        known_hosts_manager.db.commit.assert_called_once()

    def test_remove_known_host_not_found(
        self, known_hosts_manager: KnownHostsManager
    ) -> None:
        """
        Verify remove_known_host returns False when host not found.
        """
        mock_result = MagicMock()
        mock_result.rowcount = 0
        known_hosts_manager.db.execute.return_value = mock_result

        result = known_hosts_manager.remove_known_host(
            hostname="nonexistent.example.com",
            key_type="ed25519",
        )

        assert result is False

    def test_remove_known_host_database_error(
        self, known_hosts_manager: KnownHostsManager
    ) -> None:
        """
        Verify remove_known_host handles database errors gracefully.
        """
        known_hosts_manager.db.execute.side_effect = Exception("Delete failed")

        result = known_hosts_manager.remove_known_host(
            hostname="server.example.com",
            key_type="ed25519",
        )

        assert result is False
        known_hosts_manager.db.rollback.assert_called_once()


# =============================================================================
# update_last_verified Tests
# =============================================================================


class TestUpdateLastVerified:
    """Tests for the update_last_verified method."""

    def test_update_last_verified_no_db_returns_false(
        self, known_hosts_manager_no_db: KnownHostsManager
    ) -> None:
        """
        Verify update_last_verified returns False when no database session.
        """
        result = known_hosts_manager_no_db.update_last_verified(
            hostname="server.example.com",
            key_type="ed25519",
        )

        assert result is False

    def test_update_last_verified_success(
        self, known_hosts_manager: KnownHostsManager
    ) -> None:
        """
        Verify update_last_verified returns True when record is updated.
        """
        mock_result = MagicMock()
        mock_result.rowcount = 1
        known_hosts_manager.db.execute.return_value = mock_result

        result = known_hosts_manager.update_last_verified(
            hostname="server.example.com",
            key_type="ed25519",
        )

        assert result is True
        known_hosts_manager.db.commit.assert_called_once()

    def test_update_last_verified_not_found(
        self, known_hosts_manager: KnownHostsManager
    ) -> None:
        """
        Verify update_last_verified returns False when record not found.
        """
        mock_result = MagicMock()
        mock_result.rowcount = 0
        known_hosts_manager.db.execute.return_value = mock_result

        result = known_hosts_manager.update_last_verified(
            hostname="nonexistent.example.com",
            key_type="ed25519",
        )

        assert result is False

    def test_update_last_verified_database_error(
        self, known_hosts_manager: KnownHostsManager
    ) -> None:
        """
        Verify update_last_verified handles database errors gracefully.
        """
        known_hosts_manager.db.execute.side_effect = Exception("Update failed")

        result = known_hosts_manager.update_last_verified(
            hostname="server.example.com",
            key_type="ed25519",
        )

        assert result is False
        known_hosts_manager.db.rollback.assert_called_once()


# =============================================================================
# set_trust_status Tests
# =============================================================================


class TestSetTrustStatus:
    """Tests for the set_trust_status method."""

    def test_set_trust_status_no_db_returns_false(
        self, known_hosts_manager_no_db: KnownHostsManager
    ) -> None:
        """
        Verify set_trust_status returns False when no database session.
        """
        result = known_hosts_manager_no_db.set_trust_status(
            hostname="server.example.com",
            key_type="ed25519",
            is_trusted=True,
        )

        assert result is False

    def test_set_trust_status_true_success(
        self, known_hosts_manager: KnownHostsManager
    ) -> None:
        """
        Verify set_trust_status returns True when setting trusted.
        """
        mock_result = MagicMock()
        mock_result.rowcount = 1
        known_hosts_manager.db.execute.return_value = mock_result

        result = known_hosts_manager.set_trust_status(
            hostname="server.example.com",
            key_type="ed25519",
            is_trusted=True,
        )

        assert result is True
        known_hosts_manager.db.commit.assert_called_once()

    def test_set_trust_status_false_success(
        self, known_hosts_manager: KnownHostsManager
    ) -> None:
        """
        Verify set_trust_status returns True when setting untrusted.
        """
        mock_result = MagicMock()
        mock_result.rowcount = 1
        known_hosts_manager.db.execute.return_value = mock_result

        result = known_hosts_manager.set_trust_status(
            hostname="server.example.com",
            key_type="ed25519",
            is_trusted=False,
        )

        assert result is True

    def test_set_trust_status_not_found(
        self, known_hosts_manager: KnownHostsManager
    ) -> None:
        """
        Verify set_trust_status returns False when record not found.
        """
        mock_result = MagicMock()
        mock_result.rowcount = 0
        known_hosts_manager.db.execute.return_value = mock_result

        result = known_hosts_manager.set_trust_status(
            hostname="nonexistent.example.com",
            key_type="ed25519",
            is_trusted=True,
        )

        assert result is False

    def test_set_trust_status_database_error(
        self, known_hosts_manager: KnownHostsManager
    ) -> None:
        """
        Verify set_trust_status handles database errors gracefully.
        """
        known_hosts_manager.db.execute.side_effect = Exception("Update failed")

        result = known_hosts_manager.set_trust_status(
            hostname="server.example.com",
            key_type="ed25519",
            is_trusted=True,
        )

        assert result is False
        known_hosts_manager.db.rollback.assert_called_once()


# =============================================================================
# find_by_fingerprint Tests
# =============================================================================


class TestFindByFingerprint:
    """Tests for the find_by_fingerprint method."""

    def test_find_by_fingerprint_no_db_returns_none(
        self, known_hosts_manager_no_db: KnownHostsManager
    ) -> None:
        """
        Verify find_by_fingerprint returns None when no database session.
        """
        result = known_hosts_manager_no_db.find_by_fingerprint(
            fingerprint="SHA256:abcdef123456"
        )

        assert result is None

    def test_find_by_fingerprint_found(
        self,
        known_hosts_manager: KnownHostsManager,
        sample_host_row: MagicMock,
    ) -> None:
        """
        Verify find_by_fingerprint returns host dict when found.
        """
        mock_result = MagicMock()
        mock_result.fetchone.return_value = sample_host_row
        known_hosts_manager.db.execute.return_value = mock_result

        result = known_hosts_manager.find_by_fingerprint(
            fingerprint="SHA256:abcdef123456"
        )

        assert result is not None
        assert result["hostname"] == "server.example.com"
        assert result["fingerprint"] == "SHA256:abcdef123456"

    def test_find_by_fingerprint_not_found(
        self, known_hosts_manager: KnownHostsManager
    ) -> None:
        """
        Verify find_by_fingerprint returns None when not found.
        """
        mock_result = MagicMock()
        mock_result.fetchone.return_value = None
        known_hosts_manager.db.execute.return_value = mock_result

        result = known_hosts_manager.find_by_fingerprint(
            fingerprint="SHA256:nonexistent"
        )

        assert result is None

    def test_find_by_fingerprint_database_error(
        self, known_hosts_manager: KnownHostsManager
    ) -> None:
        """
        Verify find_by_fingerprint handles database errors gracefully.
        """
        known_hosts_manager.db.execute.side_effect = Exception("Query failed")

        result = known_hosts_manager.find_by_fingerprint(
            fingerprint="SHA256:abcdef123456"
        )

        assert result is None


# =============================================================================
# _generate_fingerprint Tests
# =============================================================================


class TestGenerateFingerprint:
    """Tests for the _generate_fingerprint method."""

    def test_generate_fingerprint_valid_ed25519(
        self, known_hosts_manager: KnownHostsManager
    ) -> None:
        """
        Verify fingerprint generation for valid Ed25519 key.

        Fingerprint should be in SHA256:base64 format.
        """
        result = known_hosts_manager._generate_fingerprint(SAMPLE_ED25519_KEY)

        assert result is not None
        assert result.startswith("SHA256:")
        # Verify base64 portion is valid
        base64_part = result.split(":")[1]
        assert len(base64_part) > 0

    def test_generate_fingerprint_valid_rsa(
        self, known_hosts_manager: KnownHostsManager
    ) -> None:
        """
        Verify fingerprint generation for valid RSA key.
        """
        result = known_hosts_manager._generate_fingerprint(SAMPLE_RSA_KEY)

        assert result is not None
        assert result.startswith("SHA256:")

    def test_generate_fingerprint_valid_ecdsa(
        self, known_hosts_manager: KnownHostsManager
    ) -> None:
        """
        Verify fingerprint generation for valid ECDSA key.
        """
        result = known_hosts_manager._generate_fingerprint(SAMPLE_ECDSA_KEY)

        assert result is not None
        assert result.startswith("SHA256:")

    def test_generate_fingerprint_invalid_format(
        self, known_hosts_manager: KnownHostsManager
    ) -> None:
        """
        Verify fingerprint returns None for invalid key format.
        """
        result = known_hosts_manager._generate_fingerprint("invalid key")

        assert result is None

    def test_generate_fingerprint_empty_string(
        self, known_hosts_manager: KnownHostsManager
    ) -> None:
        """
        Verify fingerprint returns None for empty string.
        """
        result = known_hosts_manager._generate_fingerprint("")

        assert result is None

    def test_generate_fingerprint_single_word(
        self, known_hosts_manager: KnownHostsManager
    ) -> None:
        """
        Verify fingerprint returns None for single-word input.

        Valid keys have at least 2 parts: algorithm and base64 data.
        """
        result = known_hosts_manager._generate_fingerprint("ssh-rsa")

        assert result is None

    def test_generate_fingerprint_invalid_base64(
        self, known_hosts_manager: KnownHostsManager
    ) -> None:
        """
        Verify fingerprint returns None for invalid base64 data.
        """
        result = known_hosts_manager._generate_fingerprint("ssh-rsa !!!invalid!!!")

        assert result is None

    def test_generate_fingerprint_no_padding(
        self, known_hosts_manager: KnownHostsManager
    ) -> None:
        """
        Verify fingerprint base64 has no padding characters.

        OpenSSH format uses unpadded base64.
        """
        result = known_hosts_manager._generate_fingerprint(SAMPLE_ED25519_KEY)

        assert result is not None
        assert not result.endswith("=")

    def test_generate_fingerprint_deterministic(
        self, known_hosts_manager: KnownHostsManager
    ) -> None:
        """
        Verify fingerprint is deterministic for same key.

        Same key should always produce same fingerprint.
        """
        result1 = known_hosts_manager._generate_fingerprint(SAMPLE_ED25519_KEY)
        result2 = known_hosts_manager._generate_fingerprint(SAMPLE_ED25519_KEY)

        assert result1 == result2

    def test_generate_fingerprint_different_keys(
        self, known_hosts_manager: KnownHostsManager
    ) -> None:
        """
        Verify different keys produce different fingerprints.
        """
        fp_ed25519 = known_hosts_manager._generate_fingerprint(SAMPLE_ED25519_KEY)
        fp_rsa = known_hosts_manager._generate_fingerprint(SAMPLE_RSA_KEY)
        fp_ecdsa = known_hosts_manager._generate_fingerprint(SAMPLE_ECDSA_KEY)

        assert fp_ed25519 != fp_rsa
        assert fp_ed25519 != fp_ecdsa
        assert fp_rsa != fp_ecdsa


# =============================================================================
# Edge Case Tests
# =============================================================================


class TestKnownHostsManagerEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_empty_hostname(
        self, known_hosts_manager: KnownHostsManager
    ) -> None:
        """
        Verify handling of empty hostname.
        """
        result = known_hosts_manager.add_known_host(
            hostname="",
            ip_address=None,
            key_type="ed25519",
            public_key=SAMPLE_ED25519_KEY,
        )

        # Should still work (database constraints may catch this)
        assert result is True

    def test_unicode_hostname(
        self, known_hosts_manager: KnownHostsManager
    ) -> None:
        """
        Verify handling of unicode characters in hostname.
        """
        result = known_hosts_manager.add_known_host(
            hostname="server-\u00e9\u00e8.example.com",
            ip_address=None,
            key_type="ed25519",
            public_key=SAMPLE_ED25519_KEY,
        )

        assert result is True

    def test_very_long_notes(
        self, known_hosts_manager: KnownHostsManager
    ) -> None:
        """
        Verify handling of very long notes field.
        """
        long_notes = "x" * 10000
        result = known_hosts_manager.add_known_host(
            hostname="server.example.com",
            ip_address=None,
            key_type="ed25519",
            public_key=SAMPLE_ED25519_KEY,
            notes=long_notes,
        )

        assert result is True

    def test_special_characters_in_hostname(
        self, known_hosts_manager: KnownHostsManager
    ) -> None:
        """
        Verify handling of special characters in hostname.
        """
        # SQL injection attempt (should be safely parameterized)
        result = known_hosts_manager.add_known_host(
            hostname="server'; DROP TABLE ssh_known_hosts; --",
            ip_address=None,
            key_type="ed25519",
            public_key=SAMPLE_ED25519_KEY,
        )

        # Should succeed (parameterized queries prevent injection)
        assert result is True


# =============================================================================
# Workflow Integration Tests (Still Unit Tests with Mocks)
# =============================================================================


class TestKnownHostsWorkflows:
    """Tests for complete known hosts workflows."""

    def test_add_then_remove_workflow(
        self, known_hosts_manager: KnownHostsManager
    ) -> None:
        """
        Verify the complete add then remove workflow.
        """
        # Add host
        add_result = known_hosts_manager.add_known_host(
            hostname="server.example.com",
            ip_address="192.168.1.100",
            key_type="ed25519",
            public_key=SAMPLE_ED25519_KEY,
        )
        assert add_result is True

        # Configure mock for removal
        mock_result = MagicMock()
        mock_result.rowcount = 1
        known_hosts_manager.db.execute.return_value = mock_result

        # Remove host
        remove_result = known_hosts_manager.remove_known_host(
            hostname="server.example.com",
            key_type="ed25519",
        )
        assert remove_result is True

    def test_add_then_update_trust_workflow(
        self, known_hosts_manager: KnownHostsManager
    ) -> None:
        """
        Verify the add then update trust status workflow.
        """
        # Add host
        add_result = known_hosts_manager.add_known_host(
            hostname="server.example.com",
            ip_address="192.168.1.100",
            key_type="ed25519",
            public_key=SAMPLE_ED25519_KEY,
        )
        assert add_result is True

        # Configure mock for trust update
        mock_result = MagicMock()
        mock_result.rowcount = 1
        known_hosts_manager.db.execute.return_value = mock_result

        # Update trust status
        trust_result = known_hosts_manager.set_trust_status(
            hostname="server.example.com",
            key_type="ed25519",
            is_trusted=False,
        )
        assert trust_result is True
