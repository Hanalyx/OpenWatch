"""
Session Migration Service for OpenWatch
Ensures zero-downtime migration of existing user sessions during security upgrades
"""

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

import jwt
from sqlalchemy import text
from sqlalchemy.orm import Session

from ...config import get_settings
from ..auth import jwt_manager

logger = logging.getLogger(__name__)
settings = get_settings()


class SessionMigrationService:
    """Service for managing zero-downtime session migration"""

    def __init__(self):
        self.migration_window_hours = 24  # 24-hour overlap for smooth transition
        self.legacy_secret_key = None  # Legacy HS256 secret if needed

    def set_legacy_secret_key(self, legacy_key: str):
        """Set legacy HS256 secret key for backward compatibility"""
        self.legacy_secret_key = legacy_key
        logger.info("Legacy secret key configured for session migration")

    def validate_legacy_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Validate legacy HS256 tokens during migration period

        Args:
            token: JWT token string

        Returns:
            Token payload if valid, None if invalid
        """
        if not self.legacy_secret_key:
            return None

        try:
            # Try to decode with legacy HS256 algorithm
            payload = jwt.decode(
                token,
                self.legacy_secret_key,
                algorithms=["HS256"],
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iat": True,
                },
            )

            # Check if token is within migration window
            iat = payload.get("iat")
            if iat:
                token_age = datetime.utcnow().timestamp() - iat
                max_age = self.migration_window_hours * 3600

                if token_age <= max_age:
                    logger.info(f"Legacy token accepted for user: {payload.get('sub')}")
                    return payload
                else:
                    logger.warning(f"Legacy token expired for user: {payload.get('sub')}")

            return None

        except jwt.ExpiredSignatureError:
            logger.debug("Legacy token has expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.debug(f"Legacy token validation failed: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error validating legacy token: {e}")
            return None

    def migrate_user_session(self, legacy_payload: Dict[str, Any]) -> Dict[str, str]:
        """
        Migrate legacy session to new RS256 tokens

        Args:
            legacy_payload: Validated legacy token payload

        Returns:
            Dictionary with new access and refresh tokens
        """
        try:
            # Create updated user data with current format
            user_data = {
                "sub": legacy_payload.get("sub"),
                "id": legacy_payload.get("id"),
                "username": legacy_payload.get("username"),
                "email": legacy_payload.get("email"),
                "role": legacy_payload.get("role"),
                "mfa_enabled": legacy_payload.get("mfa_enabled", False),
            }

            # Generate new RS256 tokens
            new_access_token = jwt_manager.create_access_token(user_data)
            new_refresh_token = jwt_manager.create_refresh_token(user_data)

            logger.info("Session migrated for user: ***REDACTED***")

            return {
                "access_token": new_access_token,
                "refresh_token": new_refresh_token,
                "token_type": "bearer",
                "expires_in": settings.access_token_expire_minutes * 60,
                "migrated": True,
            }

        except Exception as e:
            logger.error(f"Failed to migrate session: {e}")
            raise

    def validate_token_with_migration(self, token: str) -> Dict[str, Any]:
        """
        Validate token with automatic migration support

        Args:
            token: JWT token string

        Returns:
            Token payload (migrated if necessary)
        """
        try:
            # First try with current RS256 validation
            return jwt_manager.validate_access_token(token)

        except jwt.InvalidTokenError:
            # If RS256 fails, try legacy HS256 validation
            legacy_payload = self.validate_legacy_token(token)
            if legacy_payload:
                # Mark payload as requiring migration
                legacy_payload["_requires_migration"] = True
                return legacy_payload

            # If both fail, re-raise the original exception
            raise

    def get_migration_statistics(self) -> Dict[str, Any]:
        """Get session migration statistics"""
        return {
            "migration_window_hours": self.migration_window_hours,
            "legacy_secret_configured": bool(self.legacy_secret_key),
            "rs256_active": True,
            "migration_status": "active" if self.legacy_secret_key else "completed",
        }

    def check_session_compatibility(self, db: Session) -> Dict[str, Any]:
        """
        Check database for session compatibility requirements

        Args:
            db: Database session

        Returns:
            Compatibility status and recommendations
        """
        try:
            # Check user table schema for MFA fields
            result = db.execute(
                text(
                    """
                SELECT column_name FROM information_schema.columns
                WHERE table_name = 'users' AND column_name IN ('mfa_enabled', 'mfa_secret')
            """
                )
            )

            mfa_columns = [row[0] for row in result.fetchall()]

            # Check for legacy password hashes
            result = db.execute(
                text(
                    """
                SELECT COUNT(*) FROM users
                WHERE hashed_password LIKE '$2b$%'  -- bcrypt format
            """
                )
            )

            legacy_password_count = result.scalar()

            # Check for active sessions (rough estimate)
            recent_login_threshold = datetime.utcnow() - timedelta(hours=24)
            result = db.execute(
                text(
                    """
                SELECT COUNT(*) FROM users
                WHERE last_login > :threshold
            """
                ),
                {"threshold": recent_login_threshold},
            )

            active_session_estimate = result.scalar()

            return {
                "mfa_schema_ready": len(mfa_columns) >= 2,
                "legacy_passwords_remaining": legacy_password_count,
                "estimated_active_sessions": active_session_estimate,
                "migration_recommendations": [
                    "Enable legacy token support during peak hours",
                    "Monitor authentication failures for migration issues",
                    "Gradually phase out legacy support over 24-48 hours",
                ],
            }

        except Exception as e:
            logger.error(f"Failed to check session compatibility: {e}")
            return {
                "error": str(e),
                "migration_recommendations": [
                    "Manual verification of database schema required",
                    "Test authentication endpoints before full deployment",
                ],
            }

    def create_migration_plan(self, db: Session) -> Dict[str, Any]:
        """
        Create a comprehensive migration plan

        Args:
            db: Database session

        Returns:
            Migration plan with phases and timelines
        """
        compatibility = self.check_session_compatibility(db)

        plan = {
            "migration_phases": [
                {
                    "phase": 1,
                    "name": "Preparation",
                    "duration": "1 hour",
                    "tasks": [
                        "Verify database schema compatibility",
                        "Configure legacy secret key",
                        "Enable dual-token validation",
                        "Set up enhanced monitoring",
                    ],
                },
                {
                    "phase": 2,
                    "name": "Deployment",
                    "duration": "2 hours",
                    "tasks": [
                        "Deploy RS256 token generation",
                        "Maintain HS256 validation compatibility",
                        "Monitor authentication success rates",
                        "Begin gradual token migration",
                    ],
                },
                {
                    "phase": 3,
                    "name": "Migration",
                    "duration": "24 hours",
                    "tasks": [
                        "Automatic token refresh with RS256",
                        "Legacy token acceptance window",
                        "Monitor for authentication issues",
                        "User communication if needed",
                    ],
                },
                {
                    "phase": 4,
                    "name": "Cleanup",
                    "duration": "24 hours",
                    "tasks": [
                        "Disable legacy token validation",
                        "Remove legacy secret configuration",
                        "Verify all users migrated",
                        "Final monitoring and validation",
                    ],
                },
            ],
            "risk_assessment": {
                "overall_risk": "LOW",
                "estimated_impact": "Minimal user disruption expected",
                "rollback_plan": "Immediate revert to HS256 if issues detected",
                "monitoring_points": [
                    "Authentication failure rates",
                    "Token validation performance",
                    "User session duration",
                    "Error log patterns",
                ],
            },
            "success_criteria": [
                "Zero forced user logouts",
                "Authentication failure rate < 1%",
                "Token validation performance within SLA",
                "Complete migration within 48 hours",
            ],
            "compatibility_check": compatibility,
        }

        return plan


# Global session migration service instance
_session_migration_service = None


def get_session_migration_service() -> SessionMigrationService:
    """Get global session migration service instance"""
    global _session_migration_service
    if _session_migration_service is None:
        _session_migration_service = SessionMigrationService()
    return _session_migration_service


# Enhanced authentication middleware for migration support
def validate_token_with_migration_support(token: str) -> Dict[str, Any]:
    """
    Enhanced token validation with migration support

    Args:
        token: JWT token string

    Returns:
        Token payload with migration information
    """
    migration_service = get_session_migration_service()
    return migration_service.validate_token_with_migration(token)


def create_migration_plan_for_deployment(db: Session) -> Dict[str, Any]:
    """Create migration plan for current deployment"""
    migration_service = get_session_migration_service()
    return migration_service.create_migration_plan(db)
