"""In-process rule cache using TTLCache (replaces Redis-backed cache).

Rules are static YAML files that rarely change, so a simple in-process
cache with TTL expiry is sufficient.  No cross-process sharing is
needed because every backend/worker process loads the same YAML files.

Security:
    - No sensitive data cached (only rule metadata)
    - TTL prevents stale data accumulation
"""

import logging
import threading
from typing import Any, Optional

from cachetools import TTLCache

logger = logging.getLogger(__name__)

_cache: TTLCache = TTLCache(maxsize=1024, ttl=1800)  # 30 min TTL, matches prior Redis config
_lock = threading.Lock()


def get_cached(key: str) -> Optional[Any]:
    """Retrieve a value from the cache.

    Args:
        key: Cache key.

    Returns:
        Cached value or None if not found / expired.
    """
    with _lock:
        return _cache.get(key)


def set_cached(key: str, value: Any, ttl: int = 1800) -> None:
    """Store a value in the cache.

    Args:
        key: Cache key.
        value: Value to cache.
        ttl: Time-to-live in seconds (ignored; the global TTL applies).
    """
    with _lock:
        _cache[key] = value


def delete_cached(key: str) -> None:
    """Remove a single key from the cache.

    Args:
        key: Cache key to remove.
    """
    with _lock:
        _cache.pop(key, None)


def clear_cache() -> None:
    """Remove all entries from the cache."""
    with _lock:
        _cache.clear()
    logger.info("Rule cache cleared")
