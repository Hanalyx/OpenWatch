"""
Automatic SQL Migration Runner
Executes SQL migrations from backend/app/migrations directory on application startup
"""

import logging
from pathlib import Path
from typing import Dict, List, Optional

from sqlalchemy import text
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


class MigrationRunner:
    """Runs SQL migrations from the migrations directory"""

    def __init__(self, db: Session, migrations_dir: Optional[Path] = None):
        self.db = db
        self.migrations_dir = migrations_dir or Path(__file__).parent.parent / "migrations"
        self._create_migrations_table()

    def _create_migrations_table(self):
        """Create migrations tracking table if it doesn't exist"""
        try:
            self.db.execute(text("""
                CREATE TABLE IF NOT EXISTS _migrations (
                    id SERIAL PRIMARY KEY,
                    filename VARCHAR(255) NOT NULL UNIQUE,
                    applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    success BOOLEAN NOT NULL DEFAULT TRUE,
                    error_message TEXT
                )
            """))
            self.db.commit()
            logger.info("Migrations tracking table ready")
        except Exception as e:
            logger.error(f"Failed to create migrations table: {e}")
            self.db.rollback()
            raise

    def _get_applied_migrations(self) -> List[str]:
        """Get list of already applied migrations"""
        try:
            result = self.db.execute(text("""
                SELECT filename FROM _migrations WHERE success = TRUE ORDER BY id
            """))
            return [row[0] for row in result]
        except Exception as e:
            logger.error(f"Failed to get applied migrations: {e}")
            return []

    def _get_pending_migrations(self) -> List[Path]:
        """Get list of SQL migration files that haven't been applied yet"""
        if not self.migrations_dir.exists():
            logger.warning(f"Migrations directory not found: {self.migrations_dir}")
            return []

        applied = set(self._get_applied_migrations())
        all_migrations = sorted(self.migrations_dir.glob("*.sql"))

        pending = [m for m in all_migrations if m.name not in applied]
        return pending

    def _apply_migration(self, migration_file: Path) -> bool:
        """Apply a single migration file"""
        try:
            logger.info(f"Applying migration: {migration_file.name}")

            # Read migration file
            with open(migration_file, "r") as f:
                sql = f.read()

            # Execute migration in a transaction
            self.db.execute(text(sql))

            # Record successful migration
            self.db.execute(
                text("""
                INSERT INTO _migrations (filename, success)
                VALUES (:filename, TRUE)
            """),
                {"filename": migration_file.name},
            )

            self.db.commit()
            logger.info(f"[OK] Migration applied successfully: {migration_file.name}")
            return True

        except Exception as e:
            logger.error(f"[ERROR] Migration failed: {migration_file.name}")
            logger.error(f"Error: {str(e)}")

            # Record failed migration
            try:
                self.db.rollback()
                self.db.execute(
                    text("""
                    INSERT INTO _migrations (filename, success, error_message)
                    VALUES (:filename, FALSE, :error)
                """),
                    {"filename": migration_file.name, "error": str(e)},
                )
                self.db.commit()
            except Exception as log_error:
                logger.error(f"Failed to log migration error: {log_error}")
                self.db.rollback()

            return False

    def run_migrations(self) -> Dict[str, any]:
        """Run all pending migrations"""
        logger.info("=" * 80)
        logger.info("AUTOMATIC MIGRATION RUNNER")
        logger.info("=" * 80)

        pending = self._get_pending_migrations()

        if not pending:
            logger.info("No pending migrations to apply")
            return {
                "success": True,
                "applied_count": 0,
                "failed_count": 0,
                "migrations": [],
            }

        logger.info(f"Found {len(pending)} pending migration(s)")

        results = []
        success_count = 0
        failed_count = 0

        for migration_file in pending:
            success = self._apply_migration(migration_file)
            results.append({"filename": migration_file.name, "success": success})

            if success:
                success_count += 1
            else:
                failed_count += 1

        logger.info("=" * 80)
        logger.info(f"Migration Summary: {success_count} applied, {failed_count} failed")
        logger.info("=" * 80)

        return {
            "success": failed_count == 0,
            "applied_count": success_count,
            "failed_count": failed_count,
            "migrations": results,
        }


def run_startup_migrations(db: Session) -> bool:
    """
    Run migrations on application startup
    Returns True if all migrations succeeded, False otherwise
    """
    try:
        runner = MigrationRunner(db)
        result = runner.run_migrations()
        return result["success"]
    except Exception as e:
        logger.error(f"Migration runner failed: {e}")
        return False
