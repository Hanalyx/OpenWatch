"""
Fixtures and helpers for repository unit tests.

Provides mock infrastructure for Beanie Document operations
without requiring a real MongoDB connection.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest


class MockCursor:
    """
    Mock Beanie cursor supporting fluent chaining.

    Simulates the cursor returned by Document.find() with
    chainable methods (.sort, .skip, .limit) and async
    terminal methods (.to_list, .count, .update, .delete).
    """

    def __init__(self, results: list | None = None) -> None:
        self._results = results if results is not None else []
        self.to_list = AsyncMock(return_value=self._results)
        self.count = AsyncMock(return_value=len(self._results))

        # update/delete return objects with modified_count/deleted_count
        update_result = MagicMock()
        update_result.modified_count = len(self._results)
        self.update = AsyncMock(return_value=update_result)

        delete_result = MagicMock()
        delete_result.deleted_count = len(self._results)
        self.delete = AsyncMock(return_value=delete_result)

    def sort(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        """Chainable sort (returns self)."""
        return self

    def skip(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        """Chainable skip (returns self)."""
        return self

    def limit(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        """Chainable limit (returns self)."""
        return self


class MockAggCursor:
    """Mock cursor returned by Document.aggregate()."""

    def __init__(self, results: list | None = None) -> None:
        self._results = results if results is not None else []
        self.to_list = AsyncMock(return_value=self._results)


@pytest.fixture
def mock_cursor() -> MockCursor:
    """Empty MockCursor fixture."""
    return MockCursor([])


@pytest.fixture
def mock_agg_cursor() -> MockAggCursor:
    """Empty MockAggCursor fixture."""
    return MockAggCursor([])
