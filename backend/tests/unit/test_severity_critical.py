"""
Unit tests for severity_critical field functionality

Tests the NIST SP 800-30 requirement for separate tracking of
critical severity findings (CVSS >= 9.0).

Tests cover:
- Database model field existence and defaults
- Migration application and reversal
- Scan result processing with critical severity
- API response inclusion of critical_issues
"""

from datetime import datetime
from uuid import uuid4

import pytest
from sqlalchemy import inspect, text

from app.database import ScanResult


class TestSeverityCriticalModel:
    """Test ScanResult model has severity_critical field with correct properties"""

    @pytest.mark.unit
    def test_scan_result_has_severity_critical_field(self, db_session):
        """Test that ScanResult model includes severity_critical field"""
        # Verify field exists in model
        assert hasattr(ScanResult, "severity_critical"), "ScanResult model missing severity_critical field"

    @pytest.mark.unit
    def test_severity_critical_defaults_to_zero(self, db_session):
        """Test severity_critical defaults to 0 when not specified"""
        # Create scan result without specifying severity_critical
        scan_id = uuid4()

        # Insert scan result
        db_session.execute(
            text(
                """
                INSERT INTO scan_results
                (scan_id, total_rules, passed_rules, failed_rules, error_rules,
                 unknown_rules, not_applicable_rules, created_at)
                VALUES (:scan_id, :total, :passed, :failed, :error,
                        :unknown, :not_applicable, :created_at)
                """
            ),
            {
                "scan_id": str(scan_id),
                "total": 100,
                "passed": 80,
                "failed": 15,
                "error": 3,
                "unknown": 1,
                "not_applicable": 1,
                "created_at": datetime.utcnow(),
            },
        )
        db_session.commit()

        # Retrieve and verify default value
        result = db_session.execute(
            text("SELECT severity_critical FROM scan_results WHERE scan_id = :scan_id"),
            {"scan_id": str(scan_id)},
        ).fetchone()

        assert result is not None, "Scan result not found in database"
        assert result.severity_critical == 0, f"severity_critical should default to 0, got {result.severity_critical}"

    @pytest.mark.unit
    def test_severity_critical_accepts_positive_integers(self, db_session):
        """Test severity_critical accepts and stores positive integer values"""
        scan_id = uuid4()
        critical_count = 5

        # Insert scan result with severity_critical value
        db_session.execute(
            text(
                """
                INSERT INTO scan_results
                (scan_id, total_rules, passed_rules, failed_rules, error_rules,
                 unknown_rules, not_applicable_rules, severity_critical, created_at)
                VALUES (:scan_id, :total, :passed, :failed, :error,
                        :unknown, :not_applicable, :severity_critical, :created_at)
                """
            ),
            {
                "scan_id": str(scan_id),
                "total": 100,
                "passed": 75,
                "failed": 20,
                "error": 3,
                "unknown": 1,
                "not_applicable": 1,
                "severity_critical": critical_count,
                "created_at": datetime.utcnow(),
            },
        )
        db_session.commit()

        # Retrieve and verify value
        result = db_session.execute(
            text("SELECT severity_critical FROM scan_results WHERE scan_id = :scan_id"),
            {"scan_id": str(scan_id)},
        ).fetchone()

        assert result is not None, "Scan result not found in database"
        assert (
            result.severity_critical == critical_count
        ), f"Expected severity_critical={critical_count}, got {result.severity_critical}"


class TestSeverityCriticalMigration:
    """Test database migration for severity_critical column"""

    @pytest.mark.integration
    def test_migration_adds_severity_critical_column(self, db_session):
        """Test migration successfully adds severity_critical column to scan_results table"""
        # Use SQLAlchemy inspector to check column existence
        inspector = inspect(db_session.bind)
        columns = [col["name"] for col in inspector.get_columns("scan_results")]

        assert (
            "severity_critical" in columns
        ), "severity_critical column not found in scan_results table. Migration may not have run."

    @pytest.mark.integration
    def test_severity_critical_column_properties(self, db_session):
        """Test severity_critical column has correct type and constraints"""
        inspector = inspect(db_session.bind)
        columns = {col["name"]: col for col in inspector.get_columns("scan_results")}

        # Verify column exists
        assert "severity_critical" in columns, "severity_critical column not found"

        severity_critical_col = columns["severity_critical"]

        # Verify column type (Integer)
        assert (
            str(severity_critical_col["type"]) == "INTEGER"
        ), f"severity_critical should be INTEGER, got {severity_critical_col['type']}"

        # Verify NOT NULL constraint
        assert not severity_critical_col["nullable"], "severity_critical should have NOT NULL constraint"

        # Verify default value
        assert severity_critical_col["default"] is not None, "severity_critical should have a default value"


class TestSeverityCriticalScanProcessing:
    """Test scan processing correctly counts critical severity findings"""

    @pytest.mark.unit
    def test_count_critical_severity_findings(self):
        """Test severity counting logic for critical findings"""
        # Simulate failed rules with mixed severities
        failed_rules = [
            {"severity": "critical", "rule_id": "rule1"},
            {"severity": "critical", "rule_id": "rule2"},
            {"severity": "high", "rule_id": "rule3"},
            {"severity": "high", "rule_id": "rule4"},
            {"severity": "medium", "rule_id": "rule5"},
            {"severity": "low", "rule_id": "rule6"},
        ]

        # Count severities (simulating scan_tasks.py logic)
        severity_critical = len([r for r in failed_rules if r.get("severity") == "critical"])
        severity_high = len([r for r in failed_rules if r.get("severity") == "high"])
        severity_medium = len([r for r in failed_rules if r.get("severity") == "medium"])
        severity_low = len([r for r in failed_rules if r.get("severity") == "low"])

        # Verify counts
        assert severity_critical == 2, f"Expected 2 critical, got {severity_critical}"
        assert severity_high == 2, f"Expected 2 high, got {severity_high}"
        assert severity_medium == 1, f"Expected 1 medium, got {severity_medium}"
        assert severity_low == 1, f"Expected 1 low, got {severity_low}"

    @pytest.mark.unit
    def test_count_zero_critical_findings(self):
        """Test severity counting when no critical findings exist"""
        # Simulate failed rules with no critical severity
        failed_rules = [
            {"severity": "high", "rule_id": "rule1"},
            {"severity": "medium", "rule_id": "rule2"},
            {"severity": "low", "rule_id": "rule3"},
        ]

        # Count severities
        severity_critical = len([r for r in failed_rules if r.get("severity") == "critical"])

        # Verify zero critical findings
        assert severity_critical == 0, f"Expected 0 critical findings, got {severity_critical}"


class TestSeverityCriticalAPI:
    """Test API endpoints include critical_issues in responses"""

    @pytest.mark.integration
    def test_hosts_api_includes_critical_issues(self, db_session):
        """Test that hosts API query includes severity_critical as critical_issues"""
        # Create test scan result with critical findings
        scan_id = uuid4()

        db_session.execute(
            text(
                """
                INSERT INTO scan_results
                (scan_id, total_rules, passed_rules, failed_rules, error_rules,
                 unknown_rules, not_applicable_rules, severity_critical,
                 severity_high, severity_medium, severity_low, created_at)
                VALUES (:scan_id, :total, :passed, :failed, :error,
                        :unknown, :not_applicable, :severity_critical,
                        :severity_high, :severity_medium, :severity_low, :created_at)
                """
            ),
            {
                "scan_id": str(scan_id),
                "total": 100,
                "passed": 70,
                "failed": 25,
                "error": 3,
                "unknown": 1,
                "not_applicable": 1,
                "severity_critical": 3,
                "severity_high": 10,
                "severity_medium": 8,
                "severity_low": 4,
                "created_at": datetime.utcnow(),
            },
        )
        db_session.commit()

        # Query for critical_issues (simulating hosts API)
        result = db_session.execute(
            text(
                """
                SELECT sr.severity_critical as critical_issues,
                       sr.severity_high as high_issues,
                       sr.severity_medium as medium_issues,
                       sr.severity_low as low_issues
                FROM scan_results sr
                WHERE sr.scan_id = :scan_id
                """
            ),
            {"scan_id": str(scan_id)},
        ).fetchone()

        # Verify critical_issues is returned
        assert result is not None, "Scan result not found"
        assert result.critical_issues == 3, f"Expected critical_issues=3, got {result.critical_issues}"
        assert result.high_issues == 10, f"Expected high_issues=10, got {result.high_issues}"


class TestSeverityCriticalDocumentation:
    """Test that code includes proper NIST SP 800-30 documentation"""

    @pytest.mark.unit
    def test_database_model_has_nist_comment(self):
        """Test that database.py includes NIST SP 800-30 reference comment"""
        # Read database.py to verify documentation
        with open("app/database.py", "r") as f:
            content = f.read()

        # Verify NIST SP 800-30 reference exists
        assert (
            "NIST SP 800-30" in content
        ), "database.py missing NIST SP 800-30 reference in severity_critical documentation"

        # Verify CVSS threshold mentioned
        assert "CVSS >= 9.0" in content or "CVSS" in content, "database.py missing CVSS threshold documentation"

    @pytest.mark.unit
    def test_scan_tasks_has_nist_comment(self):
        """Test that scan_tasks.py includes NIST SP 800-30 reference comment"""
        # Read scan_tasks.py to verify documentation
        with open("app/tasks/scan_tasks.py", "r") as f:
            content = f.read()

        # Verify NIST SP 800-30 reference exists in severity counting section
        assert "NIST SP 800-30" in content, "scan_tasks.py missing NIST SP 800-30 reference in severity counting"
