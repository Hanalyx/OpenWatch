"""PostgreSQL-backed JWT token blacklist (replaces Redis).

Stores blacklisted JTI (JWT ID) values in PostgreSQL with an expiry
timestamp. Expired rows are cleaned up periodically. This ensures
revoked tokens cannot be reused while avoiding unbounded storage growth.

Security: AC-13 from authentication.spec.yaml
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import text
from sqlalchemy.orm import Session

from ...utils.mutation_builders import InsertBuilder

logger = logging.getLogger(__name__)


class TokenBlacklist:
    """PostgreSQL-backed token blacklist for JWT revocation.

    Stores JTI claims in the ``token_blacklist`` table with an
    ``expires_at`` timestamp.  Rows past their expiry are ignored on
    lookup and removed by ``cleanup_expired()``.
    """

    def __init__(self, db: Session) -> None:
        """Initialize with a SQLAlchemy session.

        Args:
            db: Active SQLAlchemy database session.
        """
        self.db = db

    def blacklist_token(self, jti: str, expires_in: int) -> bool:
        """Add a token JTI to the blacklist.

        Args:
            jti: The JWT ID claim from the token.
            expires_in: Seconds until the token expires (used to
                compute ``expires_at``).

        Returns:
            True if the token was successfully blacklisted, False otherwise.
        """
        if not jti:
            return False

        ttl = max(expires_in, 1)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl)

        try:
            builder = (
                InsertBuilder("token_blacklist")
                .columns("jti", "expires_at")
                .values(jti, expires_at)
                .on_conflict_do_nothing("jti")
            )
            q, p = builder.build()
            self.db.execute(text(q), p)
            self.db.commit()
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
            Returns False on database errors (fail-open for availability).
        """
        if not jti:
            return False

        try:
            row = self.db.execute(
                text("SELECT 1 FROM token_blacklist" " WHERE jti = :jti AND expires_at > :now"),
                {"jti": jti, "now": datetime.now(timezone.utc)},
            ).fetchone()
            return row is not None
        except Exception as e:
            logger.warning("Token blacklist: failed to check blacklist: %s", e)
            return False

    def cleanup_expired(self) -> int:
        """Remove expired entries from the blacklist.

        Returns:
            Number of rows deleted.
        """
        try:
            result = self.db.execute(
                text("DELETE FROM token_blacklist WHERE expires_at <= :now"),
                {"now": datetime.now(timezone.utc)},
            )
            self.db.commit()
            deleted = result.rowcount
            if deleted:
                logger.info("Token blacklist: cleaned up %d expired entries", deleted)
            return deleted
        except Exception as e:
            logger.warning("Token blacklist: cleanup failed: %s", e)
            return 0


# ---------------------------------------------------------------------------
# Module-level singleton (mirrors the Redis-backed interface)
# ---------------------------------------------------------------------------

_token_blacklist: Optional[TokenBlacklist] = None


def get_token_blacklist(db: Optional[Session] = None) -> TokenBlacklist:
    """Get or create the token blacklist singleton.

    Args:
        db: SQLAlchemy session.  Required on first call; subsequent
            calls reuse the existing instance.

    Returns:
        TokenBlacklist instance.
    """
    global _token_blacklist
    if _token_blacklist is None:
        if db is None:
            from ...database import get_db_session

            db = get_db_session()
        _token_blacklist = TokenBlacklist(db)
    return _token_blacklist
