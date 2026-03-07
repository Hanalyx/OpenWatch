"""
Unit test fixtures and helpers.

Provides lightweight fixtures for unit testing that do NOT require
database connections or running services.
"""

import pytest


@pytest.fixture
def master_key() -> str:
    """Provide a test master key for encryption tests."""
    return "test-master-key-for-unit-tests"  # pragma: allowlist secret


@pytest.fixture
def alt_master_key() -> str:
    """Provide an alternative master key for testing key differences."""
    return "different-master-key-for-tests"  # pragma: allowlist secret
