"""PostgreSQL-backed SSO state storage (replaces Redis).

Stores single-use SSO state tokens with a short TTL to prevent CSRF
during the SSO login flow.  Tokens are consumed on validation and
expired rows are cleaned up periodically.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import text
from sqlalchemy.orm import Session

from ...utils.mutation_builders import InsertBuilder

logger = logging.getLogger(__name__)


class SSOStateStore:
    """PostgreSQL-backed SSO state storage.

    Each ``store()`` call persists a state token with a provider ID and
    expiry.  ``validate_and_consume()`` atomically deletes the token
    (single-use) and returns the associated provider ID.
    """

    def __init__(self, db: Session) -> None:
        """Initialize with a SQLAlchemy session.

        Args:
            db: Active SQLAlchemy database session.
        """
        self.db = db

    def store(self, state: str, provider_id: str, ttl_seconds: int = 300) -> None:
        """Store a state token for later validation.

        Args:
            state: Cryptographic state token (128+ bits).
            provider_id: UUID of the SSO provider.
            ttl_seconds: Seconds until the token expires (default 300 / 5 min).
        """
        expires = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
        builder = (
            InsertBuilder("sso_state")
            .columns("state_token", "provider_id", "expires_at")
            .values(state, provider_id, expires)
        )
        q, p = builder.build()
        self.db.execute(text(q), p)
        self.db.commit()

    def validate_and_consume(self, state: str) -> Optional[str]:
        """Validate state, delete it (single-use), return provider_id or None.

        Args:
            state: The state token to validate.

        Returns:
            The provider_id string if the token was valid and not
            expired, or None otherwise.
        """
        row = self.db.execute(
            text("DELETE FROM sso_state" " WHERE state_token = :s AND expires_at > :now" " RETURNING provider_id"),
            {"s": state, "now": datetime.now(timezone.utc)},
        ).fetchone()
        self.db.commit()
        return str(row.provider_id) if row else None

    def cleanup_expired(self) -> int:
        """Remove expired state tokens.

        Returns:
            Number of rows deleted.
        """
        result = self.db.execute(
            text("DELETE FROM sso_state WHERE expires_at <= :now"),
            {"now": datetime.now(timezone.utc)},
        )
        self.db.commit()
        deleted = result.rowcount
        if deleted:
            logger.info("SSO state: cleaned up %d expired entries", deleted)
        return deleted
