"""
Unit Tests for BaseRepository
OW-REFACTOR-002: MongoDB Repository Pattern

Note: These tests require Beanie/MongoDB to be initialized.
In CI environments without MongoDB, tests will be skipped.
"""

import os
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from beanie import Document

from app.repositories.base_repository import BaseRepository


# Skip all tests in this module in CI environment (no MongoDB service available)
# To run these tests locally, ensure MongoDB is running and Beanie is initialized
pytestmark = pytest.mark.skipif(
    os.getenv("TESTING", "").lower() == "true" and not os.getenv("MONGODB_URL"),
    reason="MongoDB not available in CI - skipping Beanie repository tests"
)


# Test model for generic repository testing
class TestDocument(Document):
    """Test document model"""

    name: str
    value: int
    created_at: datetime = datetime.utcnow()

    class Settings:
        name = "test_documents"


class TestBaseRepository:
    """Test suite for BaseRepository class"""

    @pytest.fixture
    def repository(self):
        """Create test repository instance"""
        return BaseRepository(TestDocument)

    @pytest.mark.asyncio
    async def test_init(self, repository):
        """Test repository initialization"""
        assert repository.model == TestDocument
        assert repository._slow_query_threshold == 1.0
        assert repository.logger is not None

    @pytest.mark.asyncio
    async def test_find_one_success(self, repository):
        """Test finding single document"""
        mock_doc = TestDocument(name="test", value=42)

        with patch.object(TestDocument, "find_one", new_callable=AsyncMock) as mock_find:
            mock_find.return_value = mock_doc

            result = await repository.find_one({"name": "test"})

            assert result == mock_doc
            mock_find.assert_called_once_with({"name": "test"})

    @pytest.mark.asyncio
    async def test_find_one_not_found(self, repository):
        """Test finding non-existent document"""
        with patch.object(TestDocument, "find_one", new_callable=AsyncMock) as mock_find:
            mock_find.return_value = None

            result = await repository.find_one({"name": "nonexistent"})

            assert result is None

    @pytest.mark.asyncio
    async def test_find_one_error_handling(self, repository):
        """Test error handling in find_one"""
        with patch.object(TestDocument, "find_one", new_callable=AsyncMock) as mock_find:
            mock_find.side_effect = Exception("Database error")

            with pytest.raises(Exception, match="Database error"):
                await repository.find_one({"name": "test"})

    @pytest.mark.asyncio
    async def test_find_many_basic(self, repository):
        """Test finding multiple documents"""
        mock_docs = [TestDocument(name="doc1", value=1), TestDocument(name="doc2", value=2)]

        mock_cursor = MagicMock()
        mock_cursor.skip.return_value = mock_cursor
        mock_cursor.limit.return_value = mock_cursor
        mock_cursor.to_list = AsyncMock(return_value=mock_docs)

        with patch.object(TestDocument, "find") as mock_find:
            mock_find.return_value = mock_cursor

            result = await repository.find_many({"value": {"$gt": 0}})

            assert len(result) == 2
            assert result[0].name == "doc1"
            assert result[1].name == "doc2"

    @pytest.mark.asyncio
    async def test_find_many_with_pagination(self, repository):
        """Test pagination in find_many"""
        mock_cursor = MagicMock()
        mock_cursor.skip.return_value = mock_cursor
        mock_cursor.limit.return_value = mock_cursor
        mock_cursor.to_list = AsyncMock(return_value=[])

        with patch.object(TestDocument, "find") as mock_find:
            mock_find.return_value = mock_cursor

            await repository.find_many({}, skip=10, limit=5)

            mock_cursor.skip.assert_called_once_with(10)
            mock_cursor.limit.assert_called_once_with(5)

    @pytest.mark.asyncio
    async def test_find_many_with_sorting(self, repository):
        """Test sorting in find_many"""
        mock_cursor = MagicMock()
        mock_cursor.sort.return_value = mock_cursor
        mock_cursor.skip.return_value = mock_cursor
        mock_cursor.limit.return_value = mock_cursor
        mock_cursor.to_list = AsyncMock(return_value=[])

        with patch.object(TestDocument, "find") as mock_find:
            mock_find.return_value = mock_cursor

            await repository.find_many({}, sort=[("name", 1), ("value", -1)])

            mock_cursor.sort.assert_called_once_with([("name", 1), ("value", -1)])

    @pytest.mark.asyncio
    async def test_count_basic(self, repository):
        """Test counting documents"""
        mock_cursor = MagicMock()
        mock_cursor.count = AsyncMock(return_value=42)

        with patch.object(TestDocument, "find") as mock_find:
            mock_find.return_value = mock_cursor

            result = await repository.count({"value": {"$gt": 0}})

            assert result == 42

    @pytest.mark.asyncio
    async def test_count_empty_query(self, repository):
        """Test counting all documents"""
        mock_cursor = MagicMock()
        mock_cursor.count = AsyncMock(return_value=100)

        with patch.object(TestDocument, "find") as mock_find:
            mock_find.return_value = mock_cursor

            result = await repository.count()

            assert result == 100
            mock_find.assert_called_once_with({})

    @pytest.mark.asyncio
    async def test_create_success(self, repository):
        """Test creating document"""
        mock_doc = TestDocument(name="new_doc", value=99)

        with patch.object(mock_doc, "insert", new_callable=AsyncMock) as mock_insert:
            result = await repository.create(mock_doc)

            assert result == mock_doc
            mock_insert.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_error_handling(self, repository):
        """Test error handling in create"""
        mock_doc = TestDocument(name="duplicate", value=1)

        with patch.object(mock_doc, "insert", new_callable=AsyncMock) as mock_insert:
            mock_insert.side_effect = Exception("Duplicate key error")

            with pytest.raises(Exception, match="Duplicate key error"):
                await repository.create(mock_doc)

    @pytest.mark.asyncio
    async def test_update_one_success(self, repository):
        """Test updating single document"""
        mock_doc = TestDocument(name="test", value=1)
        mock_doc.update = AsyncMock()

        with patch.object(TestDocument, "find_one", new_callable=AsyncMock) as mock_find:
            mock_find.return_value = mock_doc

            result = await repository.update_one({"name": "test"}, {"$set": {"value": 42}})

            assert result == mock_doc
            mock_doc.update.assert_called_once_with({"$set": {"value": 42}})

    @pytest.mark.asyncio
    async def test_update_one_not_found(self, repository):
        """Test updating non-existent document"""
        with patch.object(TestDocument, "find_one", new_callable=AsyncMock) as mock_find:
            mock_find.return_value = None

            result = await repository.update_one({"name": "nonexistent"}, {"$set": {"value": 42}})

            assert result is None

    @pytest.mark.asyncio
    async def test_update_many_success(self, repository):
        """Test updating multiple documents"""
        mock_result = MagicMock()
        mock_result.modified_count = 5

        mock_cursor = MagicMock()
        mock_cursor.update = AsyncMock(return_value=mock_result)

        with patch.object(TestDocument, "find") as mock_find:
            mock_find.return_value = mock_cursor

            result = await repository.update_many({"value": {"$lt": 10}}, {"$inc": {"value": 1}})

            assert result == 5

    @pytest.mark.asyncio
    async def test_delete_one_success(self, repository):
        """Test deleting single document"""
        mock_doc = TestDocument(name="test", value=1)
        mock_doc.delete = AsyncMock()

        with patch.object(TestDocument, "find_one", new_callable=AsyncMock) as mock_find:
            mock_find.return_value = mock_doc

            result = await repository.delete_one({"name": "test"})

            assert result is True
            mock_doc.delete.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_one_not_found(self, repository):
        """Test deleting non-existent document"""
        with patch.object(TestDocument, "find_one", new_callable=AsyncMock) as mock_find:
            mock_find.return_value = None

            result = await repository.delete_one({"name": "nonexistent"})

            assert result is False

    @pytest.mark.asyncio
    async def test_delete_many_success(self, repository):
        """Test deleting multiple documents"""
        mock_result = MagicMock()
        mock_result.deleted_count = 3

        mock_cursor = MagicMock()
        mock_cursor.delete = AsyncMock(return_value=mock_result)

        with patch.object(TestDocument, "find") as mock_find:
            mock_find.return_value = mock_cursor

            result = await repository.delete_many({"value": {"$lt": 5}})

            assert result == 3

    @pytest.mark.asyncio
    async def test_aggregate_success(self, repository):
        """Test aggregation pipeline"""
        pipeline = [{"$match": {"value": {"$gt": 0}}}, {"$group": {"_id": "$name", "total": {"$sum": "$value"}}}]

        expected_results = [{"_id": "doc1", "total": 10}, {"_id": "doc2", "total": 20}]

        mock_cursor = MagicMock()
        mock_cursor.to_list = AsyncMock(return_value=expected_results)

        with patch.object(TestDocument, "aggregate") as mock_aggregate:
            mock_aggregate.return_value = mock_cursor

            result = await repository.aggregate(pipeline)

            assert result == expected_results
            mock_aggregate.assert_called_once_with(pipeline)

    @pytest.mark.asyncio
    async def test_find_with_pagination_success(self, repository):
        """Test pagination with metadata"""
        mock_docs = [TestDocument(name=f"doc{i}", value=i) for i in range(20)]

        # Mock find_many and count
        async def mock_find_many(*args, **kwargs):
            skip = kwargs.get("skip", 0)
            limit = kwargs.get("limit", 20)
            return mock_docs[skip : skip + limit]

        async def mock_count(*args, **kwargs):
            return 100

        with patch.object(repository, "find_many", side_effect=mock_find_many):
            with patch.object(repository, "count", side_effect=mock_count):
                docs, total, pages = await repository.find_with_pagination(query={}, page=1, per_page=20)

                assert len(docs) == 20
                assert total == 100
                assert pages == 5

    @pytest.mark.asyncio
    async def test_find_with_pagination_last_page(self, repository):
        """Test pagination on last partial page"""

        async def mock_find_many(*args, **kwargs):
            return []

        async def mock_count(*args, **kwargs):
            return 15

        with patch.object(repository, "find_many", side_effect=mock_find_many):
            with patch.object(repository, "count", side_effect=mock_count):
                docs, total, pages = await repository.find_with_pagination(query={}, page=1, per_page=20)

                assert total == 15
                assert pages == 1  # Ceiling of 15/20

    @pytest.mark.asyncio
    async def test_slow_query_logging(self, repository, caplog):
        """Test slow query detection and logging"""
        import logging

        caplog.set_level(logging.WARNING)

        # Simulate slow query (>1 second)
        with patch("time.time", side_effect=[0, 1.5]):  # 1.5 second duration
            repository._log_query_performance(
                operation="find_one", query={"name": "test"}, duration=1.5, result_count=1
            )

        # Check that warning was logged
        assert "SLOW QUERY" in caplog.text
        assert "find_one" in caplog.text

    @pytest.mark.asyncio
    async def test_fast_query_logging(self, repository, caplog):
        """Test that fast queries use debug logging"""
        import logging

        caplog.set_level(logging.DEBUG)

        repository._log_query_performance(
            operation="find_one", query={"name": "test"}, duration=0.05, result_count=1  # Fast query
        )

        # Check that no warning was logged
        assert "SLOW QUERY" not in caplog.text
