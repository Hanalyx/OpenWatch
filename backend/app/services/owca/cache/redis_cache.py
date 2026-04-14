"""In-process cache for OWCA compliance scoring (replaces Redis).

Uses cachetools TTLCache. The OWCA cache stores short-lived compliance
score results (5 min TTL) to avoid redundant recalculation. Cross-process
sharing is not needed — each worker computes its own scores.
"""

import json
import logging
import threading
from datetime import date, datetime
from typing import Any, Optional

from cachetools import TTLCache

logger = logging.getLogger(__name__)

_DEFAULT_TTL = 300  # 5 minutes
_DEFAULT_MAXSIZE = 512


class _DateTimeEncoder(json.JSONEncoder):
    """JSON encoder that handles datetime objects."""

    def default(self, obj: Any) -> Any:
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        return super().default(obj)


class OWCACache:
    """In-process compliance score cache (replaces Redis-backed cache)."""

    def __init__(self, maxsize: int = _DEFAULT_MAXSIZE, default_ttl: int = _DEFAULT_TTL):
        self._cache = TTLCache(maxsize=maxsize, ttl=default_ttl)
        self._lock = threading.Lock()

    async def get(self, key: str) -> Optional[Any]:
        with self._lock:
            val = self._cache.get(key)
        if val is None:
            return None
        try:
            return json.loads(val) if isinstance(val, str) else val
        except (json.JSONDecodeError, TypeError):
            return val

    async def set(self, key: str, value: Any, ttl: int = _DEFAULT_TTL) -> None:
        try:
            serialized = json.dumps(value, cls=_DateTimeEncoder) if not isinstance(value, str) else value
        except (TypeError, ValueError):
            serialized = str(value)
        with self._lock:
            self._cache[key] = serialized

    async def delete(self, key: str) -> None:
        with self._lock:
            self._cache.pop(key, None)

    async def clear(self) -> None:
        with self._lock:
            self._cache.clear()
