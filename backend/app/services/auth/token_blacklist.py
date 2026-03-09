"""
Redis-backed JWT token blacklist for logout invalidation.

Stores blacklisted JTI (JWT ID) values in Redis with a TTL matching
the token's remaining lifetime. This ensures revoked tokens cannot be
reused while avoiding unbounded storage growth.

Security: AC-13 from authentication.spec.yaml
"""

import logging
from typing import Optional

import redis

from ...config import get_settings

logger = logging.getLogger(__name__)

_BLACKLIST_PREFIX = "token_blacklist:"


class TokenBlacklist:
    """Redis-backed token blacklist for JWT revocation.

    Stores JTI claims as Redis keys with TTL matching remaining token
    lifetime. Falls back gracefully if Redis is unavailable.
    """

    def __init__(self) -> None:
        """Initialize Redis connection for token blacklist."""
        self._client: Optional[redis.Redis] = None
        self._connect()

    def _connect(self) -> None:
        """Establish Redis connection, logging warning on failure."""
        try:
            settings = get_settings()
            self._client = redis.Redis.from_url(
                settings.redis_url,
                decode_responses=True,
                socket_connect_timeout=2,
                socket_timeout=2,
            )
            # Verify connectivity
            self._client.ping()
        except Exception as e:
            logger.warning(
                "Token blacklist: Redis unavailable, token revocation " "will not persist until Redis is restored: %s",
                e,
            )
            self._client = None

    def blacklist_token(self, jti: str, expires_in: int) -> bool:
        """Add a token JTI to the blacklist.

        Args:
            jti: The JWT ID claim from the token.
            expires_in: Seconds until the token expires (used as TTL).

        Returns:
            True if the token was successfully blacklisted, False otherwise.
        """
        if not jti:
            return False

        # Ensure TTL is at least 1 second
        ttl = max(expires_in, 1)

        try:
            if self._client is None:
                self._connect()
            if self._client is None:
                logger.warning("Token blacklist: cannot blacklist token, Redis unavailable")
                return False

            key = f"{_BLACKLIST_PREFIX}{jti}"
            self._client.setex(key, ttl, "1")
            logger.info("Token blacklisted: jti=%s, ttl=%ds", jti, ttl)
            return True
        except Exception as e:
            logger.warning("Token blacklist: failed to blacklist token: %s", e)
            return False

    def is_blacklisted(self, jti: str) -> bool:
        """Check if a token JTI is in the blacklist.

        Args:
            jti: The JWT ID claim to check.

        Returns:
            True if the token is blacklisted (revoked), False otherwise.
            Returns False if Redis is unavailable (fail-open for availability).
        """
        if not jti:
            return False

        try:
            if self._client is None:
                self._connect()
            if self._client is None:
                # Fail open: if Redis is down, allow tokens through
                # rather than locking out all users.
                logger.warning("Token blacklist: cannot check blacklist, Redis unavailable")
                return False

            key = f"{_BLACKLIST_PREFIX}{jti}"
            return self._client.exists(key) > 0
        except Exception as e:
            logger.warning("Token blacklist: failed to check blacklist: %s", e)
            return False


# Module-level singleton
_token_blacklist: Optional[TokenBlacklist] = None


def get_token_blacklist() -> TokenBlacklist:
    """Get or create the token blacklist singleton."""
    global _token_blacklist
    if _token_blacklist is None:
        _token_blacklist = TokenBlacklist()
    return _token_blacklist
