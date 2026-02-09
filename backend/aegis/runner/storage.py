"""Result persistence using SQLite.

This module provides storage for compliance scan results, enabling historical
queries and diff reporting. Results are stored in a local SQLite database.

Example:
    >>> from runner.storage import ResultStore
    >>> store = ResultStore()
    >>> session_id = store.create_session(hosts=["192.168.1.100"], rules_path="rules/")
    >>> store.record_result(session_id, "192.168.1.100", "ssh-disable-root-login", True, "PermitRootLogin=no")
    >>> store.close()

"""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass


@dataclass
class Session:
    """A scan session record."""

    id: int
    timestamp: datetime
    hosts: list[str]
    rules_path: str
    options: str


@dataclass
class ResultRecord:
    """A single rule result record."""

    id: int
    session_id: int
    host: str
    rule_id: str
    passed: bool
    detail: str
    remediated: bool
    timestamp: datetime
    rule_hash: str | None


@dataclass
class HistoryEntry:
    """A summary entry for history display."""

    session_id: int
    timestamp: datetime
    host: str
    rule_id: str
    passed: bool
    remediated: bool


def get_db_path(project_root: Path | None = None) -> Path:
    """Get the database path for the project.

    Args:
        project_root: Project root directory. Defaults to current directory.

    Returns:
        Path to the SQLite database file.

    """
    root = project_root or Path.cwd()
    db_dir = root / ".aegis"
    db_dir.mkdir(exist_ok=True)
    return db_dir / "results.db"


class ResultStore:
    """SQLite-based result storage.

    Stores compliance scan results for historical queries and diff reporting.

    Attributes:
        db_path: Path to the SQLite database file.
        retention_days: Number of days to retain results (default 90).

    """

    SCHEMA_VERSION = 1

    def __init__(
        self,
        db_path: Path | None = None,
        retention_days: int = 90,
    ):
        """Initialize the result store.

        Args:
            db_path: Path to database file. Defaults to .aegis/results.db.
            retention_days: Days to retain results before pruning.

        """
        self.db_path = db_path or get_db_path()
        self.retention_days = retention_days
        self._conn: sqlite3.Connection | None = None
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        """Get or create database connection."""
        if self._conn is None:
            self._conn = sqlite3.connect(
                self.db_path,
                detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
            )
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def _init_db(self) -> None:
        """Initialize database schema."""
        conn = self._get_conn()
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY
            );

            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                hosts TEXT NOT NULL,
                rules_path TEXT NOT NULL,
                options TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                host TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                passed INTEGER NOT NULL,
                detail TEXT DEFAULT '',
                remediated INTEGER DEFAULT 0,
                timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                rule_hash TEXT,
                FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_results_session ON results(session_id);
            CREATE INDEX IF NOT EXISTS idx_results_host ON results(host);
            CREATE INDEX IF NOT EXISTS idx_results_rule ON results(rule_id);
            CREATE INDEX IF NOT EXISTS idx_sessions_timestamp ON sessions(timestamp);
            """
        )

        # Set schema version if not exists
        cursor = conn.execute("SELECT version FROM schema_version LIMIT 1")
        if cursor.fetchone() is None:
            conn.execute(
                "INSERT INTO schema_version (version) VALUES (?)",
                (self.SCHEMA_VERSION,),
            )

        conn.commit()

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None

    def create_session(
        self,
        hosts: list[str],
        rules_path: str,
        options: str = "",
    ) -> int:
        """Create a new scan session.

        Args:
            hosts: List of target hosts.
            rules_path: Path to rules directory or file.
            options: CLI options used for the scan.

        Returns:
            Session ID for recording results.

        """
        conn = self._get_conn()
        cursor = conn.execute(
            """
            INSERT INTO sessions (hosts, rules_path, options)
            VALUES (?, ?, ?)
            """,
            (",".join(hosts), rules_path, options),
        )
        conn.commit()
        return cursor.lastrowid  # type: ignore

    def record_result(
        self,
        session_id: int,
        host: str,
        rule_id: str,
        passed: bool,
        detail: str = "",
        remediated: bool = False,
        rule_hash: str | None = None,
    ) -> int:
        """Record a rule result.

        Args:
            session_id: Session ID from create_session().
            host: Target host.
            rule_id: Rule identifier.
            passed: Whether the check passed.
            detail: Result detail message.
            remediated: Whether remediation was applied.
            rule_hash: Hash of rule content for change detection.

        Returns:
            Result record ID.

        """
        conn = self._get_conn()
        cursor = conn.execute(
            """
            INSERT INTO results (session_id, host, rule_id, passed, detail, remediated, rule_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                host,
                rule_id,
                int(passed),
                detail,
                int(remediated),
                rule_hash,
            ),
        )
        conn.commit()
        return cursor.lastrowid  # type: ignore

    def get_session(self, session_id: int) -> Session | None:
        """Get session by ID.

        Args:
            session_id: Session ID.

        Returns:
            Session object or None if not found.

        """
        conn = self._get_conn()
        cursor = conn.execute(
            "SELECT id, timestamp, hosts, rules_path, options FROM sessions WHERE id = ?",
            (session_id,),
        )
        row = cursor.fetchone()
        if row is None:
            return None
        return Session(
            id=row["id"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
            hosts=row["hosts"].split(","),
            rules_path=row["rules_path"],
            options=row["options"],
        )

    def get_results(self, session_id: int) -> list[ResultRecord]:
        """Get all results for a session.

        Args:
            session_id: Session ID.

        Returns:
            List of result records.

        """
        conn = self._get_conn()
        cursor = conn.execute(
            """
            SELECT id, session_id, host, rule_id, passed, detail, remediated, timestamp, rule_hash
            FROM results
            WHERE session_id = ?
            ORDER BY host, rule_id
            """,
            (session_id,),
        )
        return [
            ResultRecord(
                id=row["id"],
                session_id=row["session_id"],
                host=row["host"],
                rule_id=row["rule_id"],
                passed=bool(row["passed"]),
                detail=row["detail"],
                remediated=bool(row["remediated"]),
                timestamp=datetime.fromisoformat(row["timestamp"]),
                rule_hash=row["rule_hash"],
            )
            for row in cursor.fetchall()
        ]

    def list_sessions(
        self,
        host: str | None = None,
        limit: int = 20,
    ) -> list[Session]:
        """List recent sessions.

        Args:
            host: Filter by host (optional).
            limit: Maximum number of sessions to return.

        Returns:
            List of sessions, most recent first.

        """
        conn = self._get_conn()
        if host:
            cursor = conn.execute(
                """
                SELECT DISTINCT s.id, s.timestamp, s.hosts, s.rules_path, s.options
                FROM sessions s
                JOIN results r ON s.id = r.session_id
                WHERE r.host = ?
                ORDER BY s.timestamp DESC
                LIMIT ?
                """,
                (host, limit),
            )
        else:
            cursor = conn.execute(
                """
                SELECT id, timestamp, hosts, rules_path, options
                FROM sessions
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (limit,),
            )

        return [
            Session(
                id=row["id"],
                timestamp=datetime.fromisoformat(row["timestamp"]),
                hosts=row["hosts"].split(","),
                rules_path=row["rules_path"],
                options=row["options"],
            )
            for row in cursor.fetchall()
        ]

    def get_history(
        self,
        host: str,
        rule_id: str | None = None,
        limit: int = 50,
    ) -> list[HistoryEntry]:
        """Get result history for a host.

        Args:
            host: Target host.
            rule_id: Filter by rule ID (optional).
            limit: Maximum entries to return.

        Returns:
            List of history entries, most recent first.

        """
        conn = self._get_conn()
        if rule_id:
            cursor = conn.execute(
                """
                SELECT r.session_id, r.timestamp, r.host, r.rule_id, r.passed, r.remediated
                FROM results r
                WHERE r.host = ? AND r.rule_id = ?
                ORDER BY r.timestamp DESC
                LIMIT ?
                """,
                (host, rule_id, limit),
            )
        else:
            cursor = conn.execute(
                """
                SELECT r.session_id, r.timestamp, r.host, r.rule_id, r.passed, r.remediated
                FROM results r
                WHERE r.host = ?
                ORDER BY r.timestamp DESC
                LIMIT ?
                """,
                (host, limit),
            )

        return [
            HistoryEntry(
                session_id=row["session_id"],
                timestamp=datetime.fromisoformat(row["timestamp"]),
                host=row["host"],
                rule_id=row["rule_id"],
                passed=bool(row["passed"]),
                remediated=bool(row["remediated"]),
            )
            for row in cursor.fetchall()
        ]

    def prune_old_results(self, days: int | None = None) -> int:
        """Remove results older than retention period.

        Args:
            days: Days to retain. Defaults to self.retention_days.

        Returns:
            Number of sessions deleted.

        """
        days = days or self.retention_days
        cutoff = datetime.now() - timedelta(days=days)
        conn = self._get_conn()

        # Delete old sessions (CASCADE will delete results)
        cursor = conn.execute(
            "DELETE FROM sessions WHERE timestamp < ?",
            (cutoff.isoformat(),),
        )
        conn.commit()
        return cursor.rowcount

    def get_stats(self) -> dict:
        """Get database statistics.

        Returns:
            Dict with session_count, result_count, oldest_session, newest_session.

        """
        conn = self._get_conn()

        session_count = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        result_count = conn.execute("SELECT COUNT(*) FROM results").fetchone()[0]

        oldest = conn.execute("SELECT MIN(timestamp) FROM sessions").fetchone()[0]
        newest = conn.execute("SELECT MAX(timestamp) FROM sessions").fetchone()[0]

        return {
            "session_count": session_count,
            "result_count": result_count,
            "oldest_session": oldest,
            "newest_session": newest,
            "db_path": str(self.db_path),
        }


def compute_rule_hash(rule_content: str) -> str:
    """Compute hash of rule content for change detection.

    Args:
        rule_content: Rule YAML content as string.

    Returns:
        SHA-256 hash prefix (16 chars).

    """
    return hashlib.sha256(rule_content.encode()).hexdigest()[:16]


@dataclass
class DiffEntry:
    """A single entry in a diff report."""

    host: str
    rule_id: str
    status: str  # "new_failure", "resolved", "new_pass", "regression", "unchanged"
    old_passed: bool | None
    new_passed: bool | None
    old_detail: str | None
    new_detail: str | None


@dataclass
class DiffReport:
    """Diff between two sessions."""

    session1_id: int
    session2_id: int
    session1_timestamp: datetime
    session2_timestamp: datetime
    entries: list[DiffEntry]

    @property
    def new_failures(self) -> list[DiffEntry]:
        """Rules that newly failed (passed before, fail now)."""
        return [e for e in self.entries if e.status == "regression"]

    @property
    def resolved(self) -> list[DiffEntry]:
        """Rules that are now passing (failed before, pass now)."""
        return [e for e in self.entries if e.status == "resolved"]

    @property
    def new_passes(self) -> list[DiffEntry]:
        """Rules that are new and passing (not in old, pass in new)."""
        return [e for e in self.entries if e.status == "new_pass"]

    @property
    def new_fails(self) -> list[DiffEntry]:
        """Rules that are new and failing (not in old, fail in new)."""
        return [e for e in self.entries if e.status == "new_failure"]

    @property
    def unchanged(self) -> list[DiffEntry]:
        """Rules with no change in status."""
        return [e for e in self.entries if e.status == "unchanged"]

    def summary(self) -> dict:
        """Summary counts."""
        return {
            "regressions": len(self.new_failures),
            "resolved": len(self.resolved),
            "new_passes": len(self.new_passes),
            "new_failures": len(self.new_fails),
            "unchanged": len(self.unchanged),
            "total_changes": len(self.entries) - len(self.unchanged),
        }


def diff_sessions(store: ResultStore, session1_id: int, session2_id: int) -> DiffReport:
    """Compare two sessions and generate a diff report.

    Args:
        store: ResultStore instance.
        session1_id: Older session ID.
        session2_id: Newer session ID.

    Returns:
        DiffReport with all changes.

    """
    session1 = store.get_session(session1_id)
    session2 = store.get_session(session2_id)

    if session1 is None:
        raise ValueError(f"Session {session1_id} not found")
    if session2 is None:
        raise ValueError(f"Session {session2_id} not found")

    results1 = store.get_results(session1_id)
    results2 = store.get_results(session2_id)

    # Build lookup maps: (host, rule_id) -> result
    map1: dict[tuple[str, str], ResultRecord] = {(r.host, r.rule_id): r for r in results1}
    map2: dict[tuple[str, str], ResultRecord] = {(r.host, r.rule_id): r for r in results2}

    entries = []
    all_keys = set(map1.keys()) | set(map2.keys())

    for host, rule_id in sorted(all_keys):
        old = map1.get((host, rule_id))
        new = map2.get((host, rule_id))

        if old is None and new is not None:
            # New in session2
            status = "new_pass" if new.passed else "new_failure"
            entries.append(
                DiffEntry(
                    host=host,
                    rule_id=rule_id,
                    status=status,
                    old_passed=None,
                    new_passed=new.passed,
                    old_detail=None,
                    new_detail=new.detail,
                )
            )
        elif old is not None and new is None:
            # Removed in session2 (skip for now - not a meaningful change)
            continue
        else:
            # Both exist - compare
            assert old is not None and new is not None
            if old.passed and not new.passed:
                status = "regression"
            elif not old.passed and new.passed:
                status = "resolved"
            else:
                status = "unchanged"

            entries.append(
                DiffEntry(
                    host=host,
                    rule_id=rule_id,
                    status=status,
                    old_passed=old.passed,
                    new_passed=new.passed,
                    old_detail=old.detail,
                    new_detail=new.detail,
                )
            )

    return DiffReport(
        session1_id=session1_id,
        session2_id=session2_id,
        session1_timestamp=session1.timestamp,
        session2_timestamp=session2.timestamp,
        entries=entries,
    )
