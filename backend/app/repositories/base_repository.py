"""
Base Repository for MongoDB Operations
OW-REFACTOR-002: MongoDB Repository Pattern

Provides common CRUD operations and query patterns for all MongoDB collections.
Implements consistent error handling, logging, and performance monitoring.
"""

from typing import TypeVar, Generic, List, Dict, Any, Optional, Tuple
from beanie import Document
import logging
import time

T = TypeVar("T", bound=Document)


class BaseRepository(Generic[T]):
    """
    Base repository providing common CRUD operations for MongoDB collections.

    Features:
    - Generic type support for any Beanie Document
    - Consistent error handling and logging
    - Performance monitoring for slow queries
    - Pagination support
    - Count and aggregation helpers

    Example:
        class MyRepository(BaseRepository[MyModel]):
            def __init__(self):
                super().__init__(MyModel)
    """

    def __init__(self, model: type[T]):
        """
        Initialize repository with a Beanie Document model.

        Args:
            model: Beanie Document class (e.g., ComplianceRule)
        """
        self.model = model
        self.logger = logging.getLogger(f"{__name__}.{model.__name__}")
        self._slow_query_threshold = 1.0  # seconds

    async def find_one(self, query: Dict[str, Any]) -> Optional[T]:
        """
        Find single document by query.

        Args:
            query: MongoDB query dict

        Returns:
            Document if found, None otherwise

        Raises:
            Exception: If database operation fails

        Example:
            doc = await repo.find_one({"_id": "123"})
        """
        start_time = time.time()
        try:
            result = await self.model.find_one(query)

            self._log_query_performance(
                operation="find_one", query=query, duration=time.time() - start_time
            )

            return result
        except Exception as e:
            self.logger.error(f"Error in find_one with query {query}: {e}")
            raise

    async def find_many(
        self,
        query: Dict[str, Any] = None,
        skip: int = 0,
        limit: int = 100,
        sort: Optional[List[Tuple[str, int]]] = None,
    ) -> List[T]:
        """
        Find multiple documents with pagination and sorting.

        Args:
            query: MongoDB query dict (default: {})
            skip: Number of documents to skip for pagination
            limit: Maximum number of documents to return
            sort: List of (field, direction) tuples for sorting
                  Example: [("created_at", -1), ("name", 1)]

        Returns:
            List of documents

        Raises:
            Exception: If database operation fails

        Example:
            docs = await repo.find_many(
                query={"status": "active"},
                skip=0,
                limit=20,
                sort=[("created_at", -1)]
            )
        """
        if query is None:
            query = {}

        start_time = time.time()
        try:
            cursor = self.model.find(query)

            if sort:
                cursor = cursor.sort(sort)

            cursor = cursor.skip(skip).limit(limit)
            result = await cursor.to_list()

            self._log_query_performance(
                operation="find_many",
                query=query,
                duration=time.time() - start_time,
                result_count=len(result),
            )

            return result
        except Exception as e:
            self.logger.error(f"Error in find_many with query {query}: {e}")
            raise

    async def count(self, query: Dict[str, Any] = None) -> int:
        """
        Count documents matching query.

        Args:
            query: MongoDB query dict (default: {})

        Returns:
            Number of matching documents

        Raises:
            Exception: If database operation fails

        Example:
            total = await repo.count({"status": "active"})
        """
        if query is None:
            query = {}

        start_time = time.time()
        try:
            result = await self.model.find(query).count()

            self._log_query_performance(
                operation="count",
                query=query,
                duration=time.time() - start_time,
                result_count=result,
            )

            return result
        except Exception as e:
            self.logger.error(f"Error in count with query {query}: {e}")
            raise

    async def create(self, document: T) -> T:
        """
        Create new document.

        Args:
            document: Document instance to create

        Returns:
            Created document with ID

        Raises:
            Exception: If database operation fails

        Example:
            new_doc = MyModel(name="Test")
            created = await repo.create(new_doc)
        """
        start_time = time.time()
        try:
            await document.insert()

            self._log_query_performance(
                operation="create",
                query={"model": self.model.__name__},
                duration=time.time() - start_time,
            )

            return document
        except Exception as e:
            self.logger.error(f"Error creating document: {e}")
            raise

    async def update_one(
        self, query: Dict[str, Any], update: Dict[str, Any]
    ) -> Optional[T]:
        """
        Update single document and return updated version.

        Args:
            query: MongoDB query to find document
            update: Update operations (use $set, $inc, etc.)

        Returns:
            Updated document if found, None otherwise

        Raises:
            Exception: If database operation fails

        Example:
            updated = await repo.update_one(
                {"_id": "123"},
                {"$set": {"status": "completed"}}
            )
        """
        start_time = time.time()
        try:
            doc = await self.model.find_one(query)
            if not doc:
                return None

            await doc.update(update)

            self._log_query_performance(
                operation="update_one", query=query, duration=time.time() - start_time
            )

            return doc
        except Exception as e:
            self.logger.error(f"Error in update_one with query {query}: {e}")
            raise

    async def update_many(self, query: Dict[str, Any], update: Dict[str, Any]) -> int:
        """
        Update multiple documents matching query.

        Args:
            query: MongoDB query to find documents
            update: Update operations (use $set, $inc, etc.)

        Returns:
            Number of documents modified

        Raises:
            Exception: If database operation fails

        Example:
            count = await repo.update_many(
                {"status": "pending"},
                {"$set": {"status": "processed"}}
            )
        """
        start_time = time.time()
        try:
            result = await self.model.find(query).update(update)
            modified_count = result.modified_count if result else 0

            self._log_query_performance(
                operation="update_many",
                query=query,
                duration=time.time() - start_time,
                result_count=modified_count,
            )

            return modified_count
        except Exception as e:
            self.logger.error(f"Error in update_many with query {query}: {e}")
            raise

    async def delete_one(self, query: Dict[str, Any]) -> bool:
        """
        Delete single document matching query.

        Args:
            query: MongoDB query to find document

        Returns:
            True if document was deleted, False otherwise

        Raises:
            Exception: If database operation fails

        Example:
            deleted = await repo.delete_one({"_id": "123"})
        """
        start_time = time.time()
        try:
            doc = await self.model.find_one(query)
            if not doc:
                return False

            await doc.delete()

            self._log_query_performance(
                operation="delete_one", query=query, duration=time.time() - start_time
            )

            return True
        except Exception as e:
            self.logger.error(f"Error in delete_one with query {query}: {e}")
            raise

    async def delete_many(self, query: Dict[str, Any]) -> int:
        """
        Delete multiple documents matching query.

        Args:
            query: MongoDB query to find documents

        Returns:
            Number of documents deleted

        Raises:
            Exception: If database operation fails

        Example:
            count = await repo.delete_many({"status": "expired"})
        """
        start_time = time.time()
        try:
            result = await self.model.find(query).delete()
            deleted_count = result.deleted_count if result else 0

            self._log_query_performance(
                operation="delete_many",
                query=query,
                duration=time.time() - start_time,
                result_count=deleted_count,
            )

            return deleted_count
        except Exception as e:
            self.logger.error(f"Error in delete_many with query {query}: {e}")
            raise

    async def aggregate(self, pipeline: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Execute aggregation pipeline.

        Args:
            pipeline: MongoDB aggregation pipeline

        Returns:
            List of aggregation results

        Raises:
            Exception: If database operation fails

        Example:
            results = await repo.aggregate([
                {"$match": {"status": "active"}},
                {"$group": {"_id": "$type", "count": {"$sum": 1}}}
            ])
        """
        start_time = time.time()
        try:
            result = await self.model.aggregate(pipeline).to_list()

            self._log_query_performance(
                operation="aggregate",
                query={"pipeline_stages": len(pipeline)},
                duration=time.time() - start_time,
                result_count=len(result),
            )

            return result
        except Exception as e:
            self.logger.error(f"Error in aggregate with pipeline {pipeline}: {e}")
            raise

    async def find_with_pagination(
        self,
        query: Dict[str, Any] = None,
        page: int = 1,
        per_page: int = 20,
        sort: Optional[List[Tuple[str, int]]] = None,
    ) -> Tuple[List[T], int, int]:
        """
        Find documents with pagination metadata.

        Args:
            query: MongoDB query dict (default: {})
            page: Page number (1-indexed)
            per_page: Documents per page
            sort: List of (field, direction) tuples

        Returns:
            Tuple of (documents, total_count, total_pages)

        Example:
            docs, total, pages = await repo.find_with_pagination(
                query={"status": "active"},
                page=1,
                per_page=20
            )
        """
        if query is None:
            query = {}

        # Calculate pagination
        skip = (page - 1) * per_page

        # Execute queries in parallel
        import asyncio

        docs_task = self.find_many(query=query, skip=skip, limit=per_page, sort=sort)
        count_task = self.count(query=query)

        docs, total = await asyncio.gather(docs_task, count_task)

        # Calculate total pages
        total_pages = (total + per_page - 1) // per_page

        return docs, total, total_pages

    def _log_query_performance(
        self,
        operation: str,
        query: Dict[str, Any],
        duration: float,
        result_count: Optional[int] = None,
    ):
        """
        Log query performance and warn about slow queries.

        Args:
            operation: Operation name (find_one, find_many, etc.)
            query: MongoDB query
            duration: Query duration in seconds
            result_count: Number of results (if applicable)
        """
        log_msg = f"{operation} completed in {duration:.3f}s"

        if result_count is not None:
            log_msg += f" ({result_count} results)"

        if duration > self._slow_query_threshold:
            self.logger.warning(f"SLOW QUERY: {log_msg} - Query: {query}")
        else:
            self.logger.debug(log_msg)
