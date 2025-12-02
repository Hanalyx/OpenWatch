"""
Rule Cache Service for OpenWatch

Provides advanced caching capabilities for rule queries with intelligent
invalidation and warming. Uses Redis for distributed caching across
backend and worker containers.

Redis Connection:
    Uses settings from config.py (redis_host, redis_port, redis_db).
    Falls back to graceful degradation if Redis unavailable.

Security:
    - No sensitive data cached (only rule metadata)
    - Cache entries are pickle-serialized (internal use only)
    - TTLs prevent stale data accumulation
"""

import asyncio
import hashlib
import json
import logging
import pickle
from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import redis.asyncio as redis

from ..config import get_settings

logger = logging.getLogger(__name__)


class CacheStrategy(Enum):
    """Cache strategies for different query types"""

    LRU = "lru"
    LFU = "lfu"
    TTL_BASED = "ttl_based"
    PRIORITY_BASED = "priority_based"


class CachePriority(Enum):
    """Cache priority levels"""

    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class CacheMetrics:
    """Cache performance metrics"""

    total_requests: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    evictions: int = 0
    avg_hit_time: float = 0.0
    avg_miss_time: float = 0.0
    cache_size: int = 0
    memory_usage: int = 0
    last_updated: Optional[datetime] = None


@dataclass
class CacheEntry:
    """Individual cache entry"""

    key: str
    data: Any
    created_at: datetime
    accessed_at: datetime
    access_count: int
    ttl: int
    priority: CachePriority
    size_bytes: int
    tags: List[str]


class RuleCacheService:
    """
    Advanced cache service for rule queries.

    Provides distributed caching for compliance rule queries using Redis.
    Supports multiple cache strategies, automatic eviction, and cache warming.

    Attributes:
        redis_url: Redis connection URL (constructed from config)
        redis_client: Async Redis client instance
        cache_prefix: Key prefix for cache entries
        max_memory_mb: Maximum cache memory limit
        default_ttl: Default time-to-live for cache entries

    Usage:
        cache = RuleCacheService()
        await cache.initialize()
        await cache.set("key", data, priority=CachePriority.HIGH)
        result = await cache.get("key")
    """

    def __init__(self, redis_url: Optional[str] = None):
        """
        Initialize the Rule Cache Service.

        Args:
            redis_url: Optional Redis URL override. If not provided,
                uses redis_url from settings (includes authentication)
                with database 2 for rule cache isolation.
        """
        # Build Redis URL from configuration if not provided
        if redis_url is None:
            settings = get_settings()
            # Use redis_url from config which includes authentication
            # e.g., redis://:password@redis:6379
            base_url = settings.redis_url.rstrip("/")
            # Database 2 is reserved for rule cache (separate from Celery db 0)
            # Strip any existing database number and append /2
            if base_url.count("/") >= 3:
                # URL has format redis://[:password@]host:port/db - replace db
                base_url = "/".join(base_url.rsplit("/", 1)[:-1])
            self.redis_url = f"{base_url}/2"
        else:
            self.redis_url = redis_url

        self.redis_client: Optional[redis.Redis] = None
        self.cache_prefix = "openwatch:rules:"

        # Cache configuration
        self.max_memory_mb = 512  # 512MB cache limit
        self.default_ttl = 1800  # 30 minutes
        self.strategy = CacheStrategy.PRIORITY_BASED

        # TTL by priority
        self.priority_ttl_map = {
            CachePriority.LOW: 3600,  # 1 hour
            CachePriority.NORMAL: 1800,  # 30 minutes
            CachePriority.HIGH: 600,  # 10 minutes
            CachePriority.CRITICAL: 0,  # No cache
        }

        # Metrics tracking
        self.metrics = CacheMetrics(last_updated=datetime.utcnow())

        # Warming queries for common rule lookups
        self.warm_queries = [
            ("platform_rules", {"platform": "rhel", "version": "8"}),
            ("platform_rules", {"platform": "ubuntu", "version": "22.04"}),
            ("severity_rules", {"severity": ["high", "critical"]}),
            ("framework_rules", {"framework": "nist"}),
        ]

    async def initialize(self) -> None:
        """Initialize cache service"""
        try:
            self.redis_client = redis.from_url(
                self.redis_url,
                decode_responses=False,  # We'll handle encoding ourselves
                retry_on_timeout=True,
                socket_connect_timeout=5,
                socket_timeout=5,
            )

            # Test connection
            await self.redis_client.ping()
            logger.info("RuleCacheService connected to Redis successfully")

            # Initialize metrics
            await self._initialize_metrics()

            # Start cache warming if enabled
            asyncio.create_task(self._warm_cache())

        except Exception as e:
            logger.error(f"Failed to initialize RuleCacheService: {str(e)}")
            # Fallback to memory cache if Redis unavailable
            self.redis_client = None

    async def get(self, key: str) -> Optional[Any]:
        """Get cached value with metrics tracking"""
        start_time = datetime.utcnow()

        try:
            cache_key = f"{self.cache_prefix}{key}"

            if self.redis_client:
                # Redis cache
                cached_data = await self.redis_client.get(cache_key)
                if cached_data:
                    # Deserialize and update access time
                    entry = pickle.loads(cached_data)
                    entry.accessed_at = datetime.utcnow()
                    entry.access_count += 1

                    # Update entry in cache
                    await self.redis_client.set(
                        cache_key,
                        pickle.dumps(entry),
                        ex=entry.ttl if entry.ttl > 0 else None,
                    )

                    await self._record_hit(start_time)
                    return entry.data

            await self._record_miss(start_time)
            return None

        except Exception as e:
            logger.error(f"Cache get error for key {key}: {str(e)}")
            await self._record_miss(start_time)
            return None

    async def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[int] = None,
        priority: CachePriority = CachePriority.NORMAL,
        tags: Optional[List[str]] = None,
    ) -> bool:
        """Set cached value with advanced options"""
        try:
            if self.redis_client is None:
                return False

            # Determine TTL
            if ttl is None:
                ttl = self.priority_ttl_map.get(priority, self.default_ttl)

            # Don't cache CRITICAL priority items
            if priority == CachePriority.CRITICAL:
                return False

            # Create cache entry
            serialized_data = pickle.dumps(value)
            entry = CacheEntry(
                key=key,
                data=value,
                created_at=datetime.utcnow(),
                accessed_at=datetime.utcnow(),
                access_count=1,
                ttl=ttl,
                priority=priority,
                size_bytes=len(serialized_data),
                tags=tags or [],
            )

            cache_key = f"{self.cache_prefix}{key}"

            # Check memory limits before setting
            if await self._check_memory_limit(entry.size_bytes):
                await self._evict_entries()

            # Set in Redis
            entry_data = pickle.dumps(entry)
            if ttl > 0:
                await self.redis_client.set(cache_key, entry_data, ex=ttl)
            else:
                await self.redis_client.set(cache_key, entry_data)

            # Add to tags index
            if tags:
                for tag in tags:
                    tag_key = f"{self.cache_prefix}tags:{tag}"
                    await self.redis_client.sadd(tag_key, key)
                    await self.redis_client.expire(tag_key, ttl)

            await self._update_size_metrics()
            return True

        except Exception as e:
            logger.error(f"Cache set error for key {key}: {str(e)}")
            return False

    async def delete(self, key: str) -> bool:
        """Delete cached value"""
        try:
            if self.redis_client is None:
                return False

            cache_key = f"{self.cache_prefix}{key}"
            result = await self.redis_client.delete(cache_key)

            if result > 0:
                await self._update_size_metrics()

            return bool(result > 0)

        except Exception as e:
            logger.error(f"Cache delete error for key {key}: {str(e)}")
            return False

    async def invalidate_by_tags(self, tags: List[str]) -> int:
        """Invalidate cache entries by tags"""
        try:
            if self.redis_client is None:
                return 0

            invalidated = 0

            for tag in tags:
                tag_key = f"{self.cache_prefix}tags:{tag}"
                keys = await self.redis_client.smembers(tag_key)

                if keys:
                    # Delete cache entries
                    cache_keys = [f"{self.cache_prefix}{key.decode()}" for key in keys]
                    deleted = await self.redis_client.delete(*cache_keys)
                    invalidated += deleted

                    # Delete tag index
                    await self.redis_client.delete(tag_key)

            if invalidated > 0:
                await self._update_size_metrics()
                self.metrics.evictions += invalidated

            logger.info(f"Invalidated {invalidated} cache entries for tags: {tags}")
            return invalidated

        except Exception as e:
            logger.error(f"Cache invalidation error for tags {tags}: {str(e)}")
            return 0

    async def invalidate_pattern(self, pattern: str) -> int:
        """Invalidate cache entries matching pattern"""
        try:
            if self.redis_client is None:
                return 0

            cache_pattern = f"{self.cache_prefix}{pattern}"
            keys = []

            async for key in self.redis_client.scan_iter(match=cache_pattern):
                keys.append(key)

                # Process in batches of 100
                if len(keys) >= 100:
                    deleted = await self.redis_client.delete(*keys)
                    self.metrics.evictions += deleted
                    keys = []

            # Process remaining keys
            if keys:
                deleted = await self.redis_client.delete(*keys)
                self.metrics.evictions += deleted

            await self._update_size_metrics()
            logger.info(f"Invalidated cache entries matching pattern: {pattern}")
            return self.metrics.evictions

        except Exception as e:
            logger.error(f"Cache pattern invalidation error for {pattern}: {str(e)}")
            return 0

    async def flush(self) -> bool:
        """Flush all cache entries"""
        try:
            if self.redis_client is None:
                return False

            # Get all cache keys
            cache_pattern = f"{self.cache_prefix}*"
            keys = []

            async for key in self.redis_client.scan_iter(match=cache_pattern):
                keys.append(key)

            if keys:
                deleted = await self.redis_client.delete(*keys)
                self.metrics.evictions += deleted
                logger.info(f"Flushed {deleted} cache entries")

            await self._reset_metrics()
            return True

        except Exception as e:
            logger.error(f"Cache flush error: {str(e)}")
            return False

    async def get_cache_info(self) -> Dict[str, Any]:
        """Get comprehensive cache information"""
        try:
            if self.redis_client is None:
                return {"status": "unavailable", "metrics": asdict(self.metrics)}

            # Update current metrics
            await self._update_size_metrics()

            # Redis info
            redis_info = await self.redis_client.info("memory")

            # Calculate hit rate
            total = self.metrics.cache_hits + self.metrics.cache_misses
            hit_rate = (self.metrics.cache_hits / total * 100) if total > 0 else 0

            cache_info = {
                "status": "active",
                "strategy": self.strategy.value,
                "hit_rate": round(hit_rate, 2),
                "total_requests": total,
                "cache_hits": self.metrics.cache_hits,
                "cache_misses": self.metrics.cache_misses,
                "evictions": self.metrics.evictions,
                "cache_size": self.metrics.cache_size,
                "memory_usage_mb": round(self.metrics.memory_usage / 1024 / 1024, 2),
                "max_memory_mb": self.max_memory_mb,
                "avg_hit_time_ms": round(self.metrics.avg_hit_time * 1000, 2),
                "avg_miss_time_ms": round(self.metrics.avg_miss_time * 1000, 2),
                "redis_memory_mb": round(redis_info.get("used_memory", 0) / 1024 / 1024, 2),
                "last_updated": (
                    self.metrics.last_updated.isoformat() if self.metrics.last_updated else None
                ),
            }

            return cache_info

        except Exception as e:
            logger.error(f"Error getting cache info: {str(e)}")
            return {"status": "error", "error": str(e)}

    async def warm_cache(self, queries: Optional[List[Tuple[str, Dict[str, Any]]]] = None) -> None:
        """Warm cache with common queries"""
        try:
            if self.redis_client is None:
                logger.warning("Cannot warm cache: Redis unavailable")
                return

            warm_queries = queries or self.warm_queries
            warmed = 0

            for query_type, params in warm_queries:
                try:
                    # Create cache key
                    params_dict: Dict[str, Any] = params if isinstance(params, dict) else {}
                    key = self._build_query_key(query_type, params_dict)

                    # Check if already cached
                    if await self.get(key) is not None:
                        continue

                    # This would integrate with actual rule service
                    # For now, create placeholder for cache warming architecture
                    placeholder_data = {
                        "query_type": query_type,
                        "params": params_dict,
                        "warmed_at": datetime.utcnow().isoformat(),
                        "placeholder": True,
                    }

                    success = await self.set(
                        key=key,
                        value=placeholder_data,
                        priority=CachePriority.LOW,
                        tags=["warmed", query_type],
                    )

                    if success:
                        warmed += 1

                except Exception as e:
                    logger.warning(f"Failed to warm query {query_type}: {str(e)}")

            logger.info(f"Cache warming completed: {warmed} queries warmed")

        except Exception as e:
            logger.error(f"Cache warming error: {str(e)}")

    # Private helper methods

    def _build_query_key(self, query_type: str, params: Dict[str, Any]) -> str:
        """Build consistent cache key from query parameters"""
        # Sort params for consistent keys
        sorted_params = sorted(params.items())
        params_str = json.dumps(sorted_params, sort_keys=True)

        # Create hash for long parameter strings (using SHA-256 for security)
        params_hash = hashlib.sha256(params_str.encode()).hexdigest()[:16]

        return f"{query_type}:{params_hash}"

    async def _initialize_metrics(self) -> None:
        """Initialize cache metrics"""
        try:
            if self.redis_client:
                metrics_key = f"{self.cache_prefix}metrics"
                cached_metrics = await self.redis_client.get(metrics_key)

                if cached_metrics:
                    metrics_data = pickle.loads(cached_metrics)
                    self.metrics = CacheMetrics(**metrics_data)
                else:
                    # Initialize fresh metrics
                    self.metrics = CacheMetrics(last_updated=datetime.utcnow())
                    await self._save_metrics()

        except Exception as e:
            logger.error(f"Failed to initialize cache metrics: {str(e)}")

    async def _save_metrics(self) -> None:
        """Save metrics to cache"""
        try:
            if self.redis_client:
                metrics_key = f"{self.cache_prefix}metrics"
                metrics_data = asdict(self.metrics)
                await self.redis_client.set(
                    metrics_key,
                    pickle.dumps(metrics_data),
                    ex=3600,  # Save metrics for 1 hour
                )
        except Exception as e:
            logger.error(f"Failed to save cache metrics: {str(e)}")

    async def _record_hit(self, start_time: datetime) -> None:
        """Record cache hit metrics"""
        duration = (datetime.utcnow() - start_time).total_seconds()

        self.metrics.total_requests += 1
        self.metrics.cache_hits += 1

        # Update rolling average
        total = self.metrics.cache_hits
        current_avg = self.metrics.avg_hit_time
        self.metrics.avg_hit_time = ((current_avg * (total - 1)) + duration) / total

        # Save metrics periodically
        if self.metrics.total_requests % 100 == 0:
            await self._save_metrics()

    async def _record_miss(self, start_time: datetime) -> None:
        """Record cache miss metrics"""
        duration = (datetime.utcnow() - start_time).total_seconds()

        self.metrics.total_requests += 1
        self.metrics.cache_misses += 1

        # Update rolling average
        total = self.metrics.cache_misses
        current_avg = self.metrics.avg_miss_time
        self.metrics.avg_miss_time = ((current_avg * (total - 1)) + duration) / total

        # Save metrics periodically
        if self.metrics.total_requests % 100 == 0:
            await self._save_metrics()

    async def _check_memory_limit(self, new_entry_size: int) -> bool:
        """Check if adding new entry would exceed memory limits"""
        try:
            if self.redis_client is None:
                return False

            redis_info = await self.redis_client.info("memory")
            current_memory: int = int(redis_info.get("used_memory", 0))
            max_memory: int = self.max_memory_mb * 1024 * 1024

            return bool((current_memory + new_entry_size) > max_memory)

        except Exception:
            return False

    async def _evict_entries(self) -> None:
        """Evict entries based on strategy"""
        try:
            if self.redis_client is None:
                return

            # Get cache entries for eviction analysis
            cache_pattern = f"{self.cache_prefix}*"
            keys = []

            async for key in self.redis_client.scan_iter(match=cache_pattern):
                if not key.decode().endswith(":metrics") and ":tags:" not in key.decode():
                    keys.append(key)

            if len(keys) <= 100:  # Don't evict if cache is small
                return

            # Evict 10% of entries based on priority and access patterns
            evict_count = max(10, len(keys) // 10)

            # For priority-based eviction, remove low-priority, least recently used
            entries_to_analyze = []

            for key in keys[: evict_count * 2]:  # Analyze more than we need
                try:
                    cached_data = await self.redis_client.get(key)
                    if cached_data:
                        entry = pickle.loads(cached_data)
                        entries_to_analyze.append((key, entry))
                except Exception:
                    continue

            # Sort by priority (low first) then by access time (oldest first)
            entries_to_analyze.sort(key=lambda x: (x[1].priority.value, x[1].accessed_at))

            # Evict entries
            keys_to_evict = [entry[0] for entry in entries_to_analyze[:evict_count]]
            if keys_to_evict:
                evicted = await self.redis_client.delete(*keys_to_evict)
                self.metrics.evictions += evicted
                logger.info(f"Evicted {evicted} cache entries due to memory pressure")

        except Exception as e:
            logger.error(f"Cache eviction error: {str(e)}")

    async def _update_size_metrics(self) -> None:
        """Update cache size metrics"""
        try:
            if self.redis_client:
                cache_pattern = f"{self.cache_prefix}*"
                count = 0

                async for key in self.redis_client.scan_iter(match=cache_pattern):
                    if not key.decode().endswith(":metrics") and ":tags:" not in key.decode():
                        count += 1

                self.metrics.cache_size = count

                # Get memory usage
                redis_info = await self.redis_client.info("memory")
                self.metrics.memory_usage = redis_info.get("used_memory", 0)
                self.metrics.last_updated = datetime.utcnow()

        except Exception as e:
            logger.error(f"Failed to update cache size metrics: {str(e)}")

    async def _reset_metrics(self) -> None:
        """Reset cache metrics"""
        self.metrics = CacheMetrics(last_updated=datetime.utcnow())
        await self._save_metrics()

    async def _warm_cache(self) -> None:
        """Background cache warming task"""
        try:
            # Wait a bit for system to stabilize
            await asyncio.sleep(30)

            # Warm cache every hour
            while True:
                await self.warm_cache()
                await asyncio.sleep(3600)  # 1 hour

        except Exception as e:
            logger.error(f"Background cache warming error: {str(e)}")

    async def close(self) -> None:
        """Close cache connections"""
        try:
            if self.redis_client:
                await self._save_metrics()
                await self.redis_client.close()

        except Exception as e:
            logger.error(f"Error closing cache service: {str(e)}")
