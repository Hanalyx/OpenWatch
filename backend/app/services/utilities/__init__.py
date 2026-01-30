"""
Utilities services module.

Provides cross-cutting utility services including database migrations,
RSA key lifecycle management, and session migration support.

Usage:
    from app.services.utilities import run_startup_migrations
"""

from .csv_analyzer import CSVAnalyzer  # noqa: F401
from .key_lifecycle import (  # noqa: F401
    RSAKeyLifecycleManager,
    check_keys_for_rotation,
    get_active_jwt_key_id,
    get_key_lifecycle_manager,
    rotate_jwt_keys,
)
from .migration import MigrationRunner, run_startup_migrations  # noqa: F401

# session_migration imports are NOT eagerly loaded here to avoid circular imports:
# utilities -> session_migration -> auth -> auth/validation -> validation -> unified -> auth
# Import from app.services.utilities.session_migration directly when needed.

__all__ = [
    "MigrationRunner",
    "run_startup_migrations",
    "RSAKeyLifecycleManager",
    "get_key_lifecycle_manager",
    "rotate_jwt_keys",
    "get_active_jwt_key_id",
    "check_keys_for_rotation",
    "CSVAnalyzer",
]
