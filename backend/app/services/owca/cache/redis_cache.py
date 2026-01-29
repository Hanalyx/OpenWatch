"""
OWCA Cache Layer - Redis Caching

Provides caching for OWCA calculations to improve performance.
"""

import json
import logging
from typing import Optional

import redis
from redis.exceptions import RedisError

from app.config import get_settings

logger = logging.getLogger(__name__)


class OWCACache:
    """
    Redis-backed cache for OWCA calculations.

    Provides transparent caching with automatic serialization/deserialization.
    """

    def __init__(self):
        """
        Initialize Redis cache connection.

        Uses redis_url from settings which includes authentication credentials.
        Falls back to individual host/port settings if URL parsing fails.
        """
        settings = get_settings()
        try:
            # Use redis_url which includes authentication (same as Celery)
            self.redis_client = redis.from_url(
                settings.redis_url,
                db=settings.redis_db,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_keepalive=True,
            )
            # Test connection
            self.redis_client.ping()
            logger.info("OWCA Redis cache initialized successfully")
            self.enabled = True
        except RedisError as e:
            logger.warning(f"Failed to connect to Redis: {e}. Cache disabled.")
            self.enabled = False

    async def get(self, key: str) -> Optional[dict]:
        """
        Get value from cache.

        Args:
            key: Cache key

        Returns:
            Cached value as dict, or None if not found or cache disabled

        Example:
            >>> cache = OWCACache()
            >>> value = await cache.get("host_score:uuid-123")
        """
        if not self.enabled:
            return None

        try:
            value = self.redis_client.get(key)
            if value:
                logger.debug(f"Cache HIT: {key}")
                return json.loads(value)
            else:
                logger.debug(f"Cache MISS: {key}")
                return None
        except RedisError as e:
            logger.error(f"Redis GET error for key {key}: {e}")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error for key {key}: {e}")
            return None

    async def set(self, key: str, value: dict, ttl: int = 300) -> bool:
        """
        Set value in cache with TTL.

        Args:
            key: Cache key
            value: Value to cache (must be JSON-serializable)
            ttl: Time to live in seconds (default: 300 = 5 minutes)

        Returns:
            True if successful, False otherwise

        Example:
            >>> cache = OWCACache()
            >>> await cache.set("host_score:uuid-123", score_dict, ttl=600)
        """
        if not self.enabled:
            return False

        try:
            serialized = json.dumps(value, default=str)
            self.redis_client.setex(key, ttl, serialized)
            logger.debug(f"Cache SET: {key} (TTL: {ttl}s)")
            return True
        except RedisError as e:
            logger.error(f"Redis SET error for key {key}: {e}")
            return False
        except (TypeError, ValueError) as e:
            logger.error(f"JSON encode error for key {key}: {e}")
            return False

    async def delete(self, key: str) -> bool:
        """
        Delete value from cache.

        Args:
            key: Cache key to delete

        Returns:
            True if deleted, False otherwise

        Example:
            >>> cache = OWCACache()
            >>> await cache.delete("host_score:uuid-123")
        """
        if not self.enabled:
            return False

        try:
            deleted = self.redis_client.delete(key)
            logger.debug(f"Cache DELETE: {key} (deleted: {deleted})")
            return bool(deleted)
        except RedisError as e:
            logger.error(f"Redis DELETE error for key {key}: {e}")
            return False

    async def invalidate_host(self, host_id: str) -> int:
        """
        Invalidate all cache entries for a specific host.

        Args:
            host_id: UUID of the host

        Returns:
            Number of keys deleted

        Example:
            >>> cache = OWCACache()
            >>> await cache.invalidate_host("uuid-123")
        """
        if not self.enabled:
            return 0

        try:
            pattern = f"*{host_id}*"
            keys = self.redis_client.keys(pattern)
            if keys:
                deleted = self.redis_client.delete(*keys)
                logger.info(f"Invalidated {deleted} cache entries for host {host_id}")
                return deleted
            return 0
        except RedisError as e:
            logger.error(f"Redis invalidation error for host {host_id}: {e}")
            return 0

    async def flush_all(self) -> bool:
        """
        Flush all OWCA cache entries.

        CAUTION: This clears ALL cache data.

        Returns:
            True if successful, False otherwise

        Example:
            >>> cache = OWCACache()
            >>> await cache.flush_all()
        """
        if not self.enabled:
            return False

        try:
            self.redis_client.flushdb()
            logger.warning("OWCA cache flushed - all entries deleted")
            return True
        except RedisError as e:
            logger.error(f"Redis flush error: {e}")
            return False

    def is_available(self) -> bool:
        """
        Check if cache is available.

        Returns:
            True if Redis is available, False otherwise
        """
        if not self.enabled:
            return False

        try:
            self.redis_client.ping()
            return True
        except RedisError:
            return False
