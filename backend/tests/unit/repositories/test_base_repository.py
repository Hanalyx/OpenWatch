"""
Unit tests for BaseRepository.

Tests all CRUD operations, pagination, and performance logging
using mocked Beanie Document operations.
"""

import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.repositories.base_repository import BaseRepository

from .conftest import MockAggCursor, MockCursor

# --- Stub document and repository for testing ---


class StubDocument:
    """Minimal stand-in for a Beanie Document."""

    __name__ = "StubDocument"

    find_one = AsyncMock()
    find = MagicMock()
    aggregate = MagicMock()


class StubRepository(BaseRepository["StubDocument"]):
    """Concrete repository for testing BaseRepository logic."""

    def __init__(self) -> None:
        # Bypass super().__init__ to inject StubDocument directly
        self.model = StubDocument  # type: ignore[assignment]
        self.logger = logging.getLogger("test.StubRepository")
        self._slow_query_threshold = 1.0


# --- Helpers ---


def _make_doc(**kwargs) -> MagicMock:  # type: ignore[no-untyped-def]
    """Create a mock document with optional attributes."""
    doc = MagicMock()
    doc.insert = AsyncMock()
    doc.update = AsyncMock()
    doc.delete = AsyncMock()
    for k, v in kwargs.items():
        setattr(doc, k, v)
    return doc


# --- find_one ---


@pytest.mark.unit
class TestFindOne:
    """Test BaseRepository.find_one."""

    @pytest.mark.asyncio
    async def test_returns_document_when_found(self) -> None:
        repo = StubRepository()
        expected = _make_doc(name="test")
        repo.model.find_one = AsyncMock(return_value=expected)

        result = await repo.find_one({"name": "test"})

        assert result is expected
        repo.model.find_one.assert_awaited_once_with({"name": "test"})

    @pytest.mark.asyncio
    async def test_returns_none_when_not_found(self) -> None:
        repo = StubRepository()
        repo.model.find_one = AsyncMock(return_value=None)

        result = await repo.find_one({"name": "missing"})

        assert result is None

    @pytest.mark.asyncio
    async def test_propagates_exception(self) -> None:
        repo = StubRepository()
        repo.model.find_one = AsyncMock(side_effect=RuntimeError("db error"))

        with pytest.raises(RuntimeError, match="db error"):
            await repo.find_one({"bad": True})


# --- find_many ---


@pytest.mark.unit
class TestFindMany:
    """Test BaseRepository.find_many."""

    @pytest.mark.asyncio
    async def test_returns_list(self) -> None:
        repo = StubRepository()
        docs = [_make_doc(name="a"), _make_doc(name="b")]
        cursor = MockCursor(docs)
        repo.model.find = MagicMock(return_value=cursor)

        result = await repo.find_many({"status": "active"})

        assert result == docs
        repo.model.find.assert_called_once_with({"status": "active"})

    @pytest.mark.asyncio
    async def test_default_query_is_empty_dict(self) -> None:
        repo = StubRepository()
        cursor = MockCursor([])
        repo.model.find = MagicMock(return_value=cursor)

        await repo.find_many()

        repo.model.find.assert_called_once_with({})

    @pytest.mark.asyncio
    async def test_applies_sort(self) -> None:
        repo = StubRepository()
        cursor = MockCursor([])
        # Make sort return the cursor so chaining works
        cursor.sort = MagicMock(return_value=cursor)
        repo.model.find = MagicMock(return_value=cursor)

        await repo.find_many(sort=[("name", 1)])

        cursor.sort.assert_called_once_with([("name", 1)])

    @pytest.mark.asyncio
    async def test_propagates_exception(self) -> None:
        repo = StubRepository()
        repo.model.find = MagicMock(side_effect=RuntimeError("db error"))

        with pytest.raises(RuntimeError, match="db error"):
            await repo.find_many()


# --- count ---


@pytest.mark.unit
class TestCount:
    """Test BaseRepository.count."""

    @pytest.mark.asyncio
    async def test_returns_integer(self) -> None:
        repo = StubRepository()
        cursor = MockCursor([_make_doc(), _make_doc(), _make_doc()])
        cursor.count = AsyncMock(return_value=3)
        repo.model.find = MagicMock(return_value=cursor)

        result = await repo.count({"severity": "high"})

        assert result == 3

    @pytest.mark.asyncio
    async def test_default_query_is_empty_dict(self) -> None:
        repo = StubRepository()
        cursor = MockCursor([])
        cursor.count = AsyncMock(return_value=0)
        repo.model.find = MagicMock(return_value=cursor)

        await repo.count()

        repo.model.find.assert_called_once_with({})

    @pytest.mark.asyncio
    async def test_propagates_exception(self) -> None:
        repo = StubRepository()
        repo.model.find = MagicMock(side_effect=RuntimeError("db error"))

        with pytest.raises(RuntimeError, match="db error"):
            await repo.count()


# --- create ---


@pytest.mark.unit
class TestCreate:
    """Test BaseRepository.create."""

    @pytest.mark.asyncio
    async def test_calls_insert_and_returns_document(self) -> None:
        repo = StubRepository()
        doc = _make_doc(name="new_doc")

        result = await repo.create(doc)

        assert result is doc
        doc.insert.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_propagates_exception(self) -> None:
        repo = StubRepository()
        doc = _make_doc()
        doc.insert = AsyncMock(side_effect=RuntimeError("insert failed"))

        with pytest.raises(RuntimeError, match="insert failed"):
            await repo.create(doc)


# --- update_one ---


@pytest.mark.unit
class TestUpdateOne:
    """Test BaseRepository.update_one."""

    @pytest.mark.asyncio
    async def test_finds_and_updates(self) -> None:
        repo = StubRepository()
        doc = _make_doc(name="existing")
        repo.model.find_one = AsyncMock(return_value=doc)

        result = await repo.update_one({"name": "existing"}, {"$set": {"status": "done"}})

        assert result is doc
        doc.update.assert_awaited_once_with({"$set": {"status": "done"}})

    @pytest.mark.asyncio
    async def test_returns_none_when_not_found(self) -> None:
        repo = StubRepository()
        repo.model.find_one = AsyncMock(return_value=None)

        result = await repo.update_one({"name": "missing"}, {"$set": {"x": 1}})

        assert result is None

    @pytest.mark.asyncio
    async def test_propagates_exception(self) -> None:
        repo = StubRepository()
        repo.model.find_one = AsyncMock(side_effect=RuntimeError("db error"))

        with pytest.raises(RuntimeError, match="db error"):
            await repo.update_one({"x": 1}, {"$set": {"y": 2}})


# --- update_many ---


@pytest.mark.unit
class TestUpdateMany:
    """Test BaseRepository.update_many."""

    @pytest.mark.asyncio
    async def test_returns_modified_count(self) -> None:
        repo = StubRepository()
        cursor = MockCursor([_make_doc(), _make_doc()])
        update_result = MagicMock()
        update_result.modified_count = 2
        cursor.update = AsyncMock(return_value=update_result)
        repo.model.find = MagicMock(return_value=cursor)

        result = await repo.update_many({"status": "old"}, {"$set": {"status": "new"}})

        assert result == 2

    @pytest.mark.asyncio
    async def test_returns_zero_when_result_is_none(self) -> None:
        repo = StubRepository()
        cursor = MockCursor([])
        cursor.update = AsyncMock(return_value=None)
        repo.model.find = MagicMock(return_value=cursor)

        result = await repo.update_many({"status": "x"}, {"$set": {"status": "y"}})

        assert result == 0


# --- delete_one ---


@pytest.mark.unit
class TestDeleteOne:
    """Test BaseRepository.delete_one."""

    @pytest.mark.asyncio
    async def test_returns_true_when_deleted(self) -> None:
        repo = StubRepository()
        doc = _make_doc()
        repo.model.find_one = AsyncMock(return_value=doc)

        result = await repo.delete_one({"_id": "123"})

        assert result is True
        doc.delete.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_returns_false_when_not_found(self) -> None:
        repo = StubRepository()
        repo.model.find_one = AsyncMock(return_value=None)

        result = await repo.delete_one({"_id": "missing"})

        assert result is False

    @pytest.mark.asyncio
    async def test_propagates_exception(self) -> None:
        repo = StubRepository()
        repo.model.find_one = AsyncMock(side_effect=RuntimeError("db error"))

        with pytest.raises(RuntimeError, match="db error"):
            await repo.delete_one({"_id": "bad"})


# --- delete_many ---


@pytest.mark.unit
class TestDeleteMany:
    """Test BaseRepository.delete_many."""

    @pytest.mark.asyncio
    async def test_returns_deleted_count(self) -> None:
        repo = StubRepository()
        cursor = MockCursor([_make_doc(), _make_doc(), _make_doc()])
        delete_result = MagicMock()
        delete_result.deleted_count = 3
        cursor.delete = AsyncMock(return_value=delete_result)
        repo.model.find = MagicMock(return_value=cursor)

        result = await repo.delete_many({"status": "expired"})

        assert result == 3

    @pytest.mark.asyncio
    async def test_returns_zero_when_result_is_none(self) -> None:
        repo = StubRepository()
        cursor = MockCursor([])
        cursor.delete = AsyncMock(return_value=None)
        repo.model.find = MagicMock(return_value=cursor)

        result = await repo.delete_many({"status": "x"})

        assert result == 0


# --- aggregate ---


@pytest.mark.unit
class TestAggregate:
    """Test BaseRepository.aggregate."""

    @pytest.mark.asyncio
    async def test_returns_results(self) -> None:
        repo = StubRepository()
        expected = [{"_id": "high", "count": 5}]
        agg_cursor = MockAggCursor(expected)
        repo.model.aggregate = MagicMock(return_value=agg_cursor)

        pipeline = [{"$group": {"_id": "$severity", "count": {"$sum": 1}}}]
        result = await repo.aggregate(pipeline)

        assert result == expected

    @pytest.mark.asyncio
    async def test_propagates_exception(self) -> None:
        repo = StubRepository()
        agg_cursor = MockAggCursor([])
        agg_cursor.to_list = AsyncMock(side_effect=RuntimeError("agg error"))
        repo.model.aggregate = MagicMock(return_value=agg_cursor)

        with pytest.raises(RuntimeError, match="agg error"):
            await repo.aggregate([{"$match": {}}])


# --- find_with_pagination ---


@pytest.mark.unit
class TestFindWithPagination:
    """Test BaseRepository.find_with_pagination."""

    @pytest.mark.asyncio
    async def test_returns_docs_total_and_pages(self) -> None:
        repo = StubRepository()
        docs = [_make_doc(name="a"), _make_doc(name="b")]

        with (
            patch.object(repo, "find_many", new_callable=AsyncMock, return_value=docs),
            patch.object(repo, "count", new_callable=AsyncMock, return_value=5),
        ):
            result_docs, total, total_pages = await repo.find_with_pagination(
                query={"status": "active"},
                page=1,
                per_page=2,
            )

        assert result_docs == docs
        assert total == 5
        assert total_pages == 3  # ceil(5 / 2) = 3

    @pytest.mark.asyncio
    async def test_page_1_skip_0(self) -> None:
        repo = StubRepository()

        with (
            patch.object(repo, "find_many", new_callable=AsyncMock, return_value=[]) as mock_find,
            patch.object(repo, "count", new_callable=AsyncMock, return_value=0),
        ):
            await repo.find_with_pagination(page=1, per_page=20)

        mock_find.assert_awaited_once()
        call_kwargs = mock_find.call_args
        assert call_kwargs.kwargs.get("skip") == 0 or call_kwargs[1].get("skip") == 0

    @pytest.mark.asyncio
    async def test_calculates_total_pages_correctly(self) -> None:
        repo = StubRepository()

        with (
            patch.object(repo, "find_many", new_callable=AsyncMock, return_value=[]),
            patch.object(repo, "count", new_callable=AsyncMock, return_value=10),
        ):
            _, _, total_pages = await repo.find_with_pagination(per_page=3)

        assert total_pages == 4  # ceil(10 / 3) = 4


# --- _log_query_performance ---


@pytest.mark.unit
class TestLogQueryPerformance:
    """Test slow query logging."""

    def test_slow_query_logs_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        repo = StubRepository()
        repo._slow_query_threshold = 1.0

        with caplog.at_level(logging.WARNING):
            repo._log_query_performance(
                operation="find_one",
                query={"test": True},
                duration=2.5,
            )

        assert "SLOW QUERY" in caplog.text

    def test_fast_query_logs_debug(self, caplog: pytest.LogCaptureFixture) -> None:
        repo = StubRepository()
        repo._slow_query_threshold = 1.0

        with caplog.at_level(logging.DEBUG):
            repo._log_query_performance(
                operation="find_one",
                query={"test": True},
                duration=0.05,
            )

        assert "SLOW QUERY" not in caplog.text
        assert "find_one completed" in caplog.text
