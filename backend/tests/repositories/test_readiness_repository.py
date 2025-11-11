"""
Unit Tests for ReadinessRepository
Tests host readiness validation data access with QueryBuilder pattern
"""

from datetime import datetime, timedelta
from unittest.mock import MagicMock
from uuid import uuid4

import pytest

from app.models.readiness_models import HostReadiness, ReadinessCheckResult, ReadinessCheckType, ReadinessStatus
from app.repositories.readiness_repository import ReadinessRepository


class TestReadinessRepositoryInit:
    """Test repository initialization"""

    def test_init_with_session(self):
        """Test repository initialization with database session"""
        mock_db = MagicMock()
        repo = ReadinessRepository(mock_db)

        assert repo.db == mock_db

    def test_init_without_session_raises_error(self):
        """Test repository initialization without session raises TypeError"""
        with pytest.raises(TypeError):
            ReadinessRepository()


class TestGetCachedValidation:
    """Test cached validation retrieval"""

    @pytest.fixture
    def repo(self):
        """Create repository with mock database"""
        mock_db = MagicMock()
        return ReadinessRepository(mock_db)

    def test_cache_hit_within_ttl(self, repo):
        """Test cache hit when validation is within TTL"""
        host_id = uuid4()

        # Mock database result (recent validation within 24h)
        mock_row = MagicMock()
        mock_row._mapping = {
            "id": uuid4(),
            "host_id": host_id,
            "status": "ready",
            "overall_passed": True,
            "total_checks": 10,
            "passed_checks": 10,
            "failed_checks": 0,
            "warnings_count": 0,
            "validation_duration_ms": 1234.5,
            "completed_at": datetime.utcnow() - timedelta(hours=1),
            "cache_used": True,
            "parallel_execution": False,
        }

        mock_result = MagicMock()
        mock_result.fetchone.return_value = mock_row
        repo.db.execute.return_value = mock_result

        # Execute
        result = repo.get_cached_validation(host_id, cache_ttl_hours=24)

        # Verify query executed
        assert repo.db.execute.called
        call_args = repo.db.execute.call_args
        query_text = str(call_args[0][0])

        # Verify query includes TTL filter
        assert "completed_at >=" in query_text
        assert "host_id = :host_id" in query_text

        # Verify result
        assert result is not None
        assert isinstance(result, HostReadiness)
        assert result.host_id == host_id
        assert result.status == ReadinessStatus.READY
        assert result.overall_passed is True

    def test_cache_miss_expired(self, repo):
        """Test cache miss when validation is expired"""
        host_id = uuid4()

        # Mock database returns no results (validation too old)
        mock_result = MagicMock()
        mock_result.fetchone.return_value = None
        repo.db.execute.return_value = mock_result

        # Execute
        result = repo.get_cached_validation(host_id, cache_ttl_hours=24)

        # Verify no result returned
        assert result is None

    def test_cache_custom_ttl(self, repo):
        """Test cache with custom TTL (1 hour for pre-flight)"""
        host_id = uuid4()

        mock_result = MagicMock()
        mock_result.fetchone.return_value = None
        repo.db.execute.return_value = mock_result

        # Execute with 1 hour TTL
        repo.get_cached_validation(host_id, cache_ttl_hours=1)

        # Verify query uses 1 hour cutoff
        call_args = repo.db.execute.call_args
        params = call_args[0][1]

        cutoff_time = params["cutoff_time"]
        expected_cutoff = datetime.utcnow() - timedelta(hours=1)

        # Allow 5 second tolerance for test execution time
        assert abs((cutoff_time - expected_cutoff).total_seconds()) < 5


class TestStoreValidation:
    """Test validation result storage"""

    @pytest.fixture
    def repo(self):
        """Create repository with mock database"""
        mock_db = MagicMock()
        return ReadinessRepository(mock_db)

    def test_store_validation_success(self, repo):
        """Test storing successful validation run"""
        host_id = uuid4()
        validation_id = uuid4()

        # Mock database to return generated UUID
        mock_row = MagicMock()
        mock_row._mapping = {"id": validation_id}
        mock_result = MagicMock()
        mock_result.fetchone.return_value = mock_row
        repo.db.execute.return_value = mock_result

        # Execute
        result = repo.store_validation(
            host_id=host_id,
            status=ReadinessStatus.READY,
            overall_passed=True,
            total_checks=10,
            passed_checks=10,
            failed_checks=0,
            warnings_count=0,
            validation_duration_ms=1234.5,
            cache_used=False,
            parallel_execution=False,
        )

        # Verify INSERT query executed
        assert repo.db.execute.called
        call_args = repo.db.execute.call_args
        query_text = str(call_args[0][0])

        assert "INSERT INTO host_readiness_validations" in query_text
        assert "RETURNING id" in query_text

        # Verify commit called
        assert repo.db.commit.called

        # Verify result
        assert result == validation_id

    def test_store_validation_not_ready(self, repo):
        """Test storing failed validation"""
        host_id = uuid4()
        validation_id = uuid4()

        mock_row = MagicMock()
        mock_row._mapping = {"id": validation_id}
        mock_result = MagicMock()
        mock_result.fetchone.return_value = mock_row
        repo.db.execute.return_value = mock_result

        # Execute with failures
        repo.store_validation(
            host_id=host_id,
            status=ReadinessStatus.NOT_READY,
            overall_passed=False,
            total_checks=10,
            passed_checks=7,
            failed_checks=3,
            warnings_count=2,
            validation_duration_ms=2345.6,
            cache_used=False,
            parallel_execution=True,
        )

        # Verify parameters include failure counts
        call_args = repo.db.execute.call_args
        params = call_args[0][1]

        assert params["status"] == "not_ready"
        assert params["overall_passed"] is False
        assert params["failed_checks"] == 3
        assert params["warnings_count"] == 2

    def test_store_validation_database_error(self, repo):
        """Test error handling when database insert fails"""
        host_id = uuid4()

        # Mock database error
        repo.db.execute.side_effect = Exception("Database connection failed")

        # Execute and expect exception
        with pytest.raises(Exception, match="Database connection failed"):
            repo.store_validation(
                host_id=host_id,
                status=ReadinessStatus.READY,
                overall_passed=True,
                total_checks=10,
                passed_checks=10,
                failed_checks=0,
                warnings_count=0,
                validation_duration_ms=1000.0,
                cache_used=False,
                parallel_execution=False,
            )

        # Verify rollback was called
        assert repo.db.rollback.called


class TestStoreCheckResults:
    """Test individual check result storage"""

    @pytest.fixture
    def repo(self):
        """Create repository with mock database"""
        mock_db = MagicMock()
        return ReadinessRepository(mock_db)

    def test_store_single_check(self, repo):
        """Test storing single check result"""
        validation_id = uuid4()
        check = ReadinessCheckResult(
            check_type=ReadinessCheckType.CONNECTIVITY,
            check_name="ICMP Ping Test",
            passed=True,
            severity="info",
            message="Host is reachable via ICMP",
            details={"latency_ms": 12.34},
            check_duration_ms=50.0,
        )

        # Execute
        repo.store_check_results(validation_id, [check])

        # Verify INSERT executed
        assert repo.db.execute.called
        call_args = repo.db.execute.call_args
        query_text = str(call_args[0][0])
        params = call_args[0][1]

        assert "INSERT INTO host_readiness_checks" in query_text
        assert params["validation_id"] == str(validation_id)
        assert params["check_type"] == "connectivity"
        assert params["passed"] is True

        # Verify commit called
        assert repo.db.commit.called

    def test_store_multiple_checks(self, repo):
        """Test storing multiple check results"""
        validation_id = uuid4()
        checks = [
            ReadinessCheckResult(
                check_type=ReadinessCheckType.CONNECTIVITY,
                check_name="ICMP Ping",
                passed=True,
                severity="info",
                message="Ping successful",
                details={},
                check_duration_ms=50.0,
            ),
            ReadinessCheckResult(
                check_type=ReadinessCheckType.SSH,
                check_name="SSH Authentication",
                passed=True,
                severity="error",
                message="SSH login successful",
                details={"protocol": "SSH-2.0"},
                check_duration_ms=234.5,
            ),
            ReadinessCheckResult(
                check_type=ReadinessCheckType.DEPENDENCIES,
                check_name="oscap Version Check",
                passed=False,
                severity="error",
                message="oscap not found",
                details={"remediation": "yum install openscap-scanner"},
                check_duration_ms=100.0,
            ),
        ]

        # Execute
        repo.store_check_results(validation_id, checks)

        # Verify 3 INSERT calls (one per check)
        assert repo.db.execute.call_count == 3

        # Verify commit called once after all inserts
        assert repo.db.commit.call_count == 1

    def test_store_empty_checks_list(self, repo):
        """Test storing empty checks list does nothing"""
        validation_id = uuid4()

        # Execute with empty list
        repo.store_check_results(validation_id, [])

        # Verify no database calls
        assert not repo.db.execute.called
        assert not repo.db.commit.called


class TestGetValidationHistory:
    """Test validation history retrieval with pagination"""

    @pytest.fixture
    def repo(self):
        """Create repository with mock database"""
        mock_db = MagicMock()
        return ReadinessRepository(mock_db)

    def test_get_history_first_page(self, repo):
        """Test fetching first page of history"""
        host_id = uuid4()

        # Mock validation results
        mock_rows = [
            MagicMock(
                _mapping={
                    "id": uuid4(),
                    "host_id": host_id,
                    "status": "ready",
                    "overall_passed": True,
                    "total_checks": 10,
                    "passed_checks": 10,
                    "failed_checks": 0,
                    "warnings_count": 0,
                    "validation_duration_ms": 1000.0,
                    "completed_at": datetime.utcnow() - timedelta(hours=i),
                    "cache_used": False,
                    "parallel_execution": False,
                }
            )
            for i in range(20)
        ]

        # Mock count query
        mock_count_row = MagicMock(_mapping={"total": 45})

        # Setup mock to return different results for count vs data queries
        def execute_side_effect(query, params):
            query_str = str(query)
            mock_result = MagicMock()
            if "COUNT(*)" in query_str:
                mock_result.fetchone.return_value = mock_count_row
            else:
                mock_result.fetchall.return_value = mock_rows
            return mock_result

        repo.db.execute.side_effect = execute_side_effect

        # Execute
        results, total, total_pages = repo.get_validation_history(host_id=host_id, page=1, per_page=20)

        # Verify results
        assert len(results) == 20
        assert total == 45
        assert total_pages == 3  # ceil(45 / 20)
        assert all(isinstance(r, HostReadiness) for r in results)

        # Verify pagination parameters
        call_args = [c for c in repo.db.execute.call_args_list if "LIMIT" in str(c[0][0])]
        assert len(call_args) > 0
        params = call_args[0][0][1]
        assert params["limit_val"] == 20
        assert params["offset_val"] == 0

    def test_get_history_second_page(self, repo):
        """Test fetching second page of history"""
        host_id = uuid4()

        mock_rows = []
        mock_count_row = MagicMock(_mapping={"total": 45})

        def execute_side_effect(query, params):
            query_str = str(query)
            mock_result = MagicMock()
            if "COUNT(*)" in query_str:
                mock_result.fetchone.return_value = mock_count_row
            else:
                mock_result.fetchall.return_value = mock_rows
            return mock_result

        repo.db.execute.side_effect = execute_side_effect

        # Execute page 2
        results, total, total_pages = repo.get_validation_history(host_id=host_id, page=2, per_page=20)

        # Verify pagination offset
        call_args = [c for c in repo.db.execute.call_args_list if "OFFSET" in str(c[0][0])]
        assert len(call_args) > 0
        params = call_args[0][0][1]
        assert params["offset_val"] == 20  # Skip first 20

    def test_get_history_no_results(self, repo):
        """Test history for host with no validations"""
        host_id = uuid4()

        mock_count_row = MagicMock(_mapping={"total": 0})

        def execute_side_effect(query, params):
            query_str = str(query)
            mock_result = MagicMock()
            if "COUNT(*)" in query_str:
                mock_result.fetchone.return_value = mock_count_row
            else:
                mock_result.fetchall.return_value = []
            return mock_result

        repo.db.execute.side_effect = execute_side_effect

        # Execute
        results, total, total_pages = repo.get_validation_history(host_id=host_id, page=1, per_page=20)

        # Verify empty results
        assert len(results) == 0
        assert total == 0
        assert total_pages == 0


class TestGetValidationById:
    """Test fetching validation by ID with check results"""

    @pytest.fixture
    def repo(self):
        """Create repository with mock database"""
        mock_db = MagicMock()
        return ReadinessRepository(mock_db)

    def test_get_validation_with_checks(self, repo):
        """Test fetching validation with all check results"""
        validation_id = uuid4()
        host_id = uuid4()

        # Mock validation row
        validation_row = MagicMock(
            _mapping={
                "id": validation_id,
                "host_id": host_id,
                "status": "ready",
                "overall_passed": True,
                "total_checks": 2,
                "passed_checks": 2,
                "failed_checks": 0,
                "warnings_count": 0,
                "validation_duration_ms": 1234.5,
                "completed_at": datetime.utcnow(),
                "cache_used": False,
                "parallel_execution": False,
            }
        )

        # Mock check results
        check_rows = [
            MagicMock(
                _mapping={
                    "check_type": "connectivity",
                    "check_name": "ICMP Ping",
                    "passed": True,
                    "severity": "info",
                    "message": "Ping successful",
                    "details": "{}",
                    "check_duration_ms": 50.0,
                }
            ),
            MagicMock(
                _mapping={
                    "check_type": "ssh",
                    "check_name": "SSH Auth",
                    "passed": True,
                    "severity": "error",
                    "message": "SSH successful",
                    "details": '{"protocol": "SSH-2.0"}',
                    "check_duration_ms": 234.5,
                }
            ),
        ]

        # Setup mock to return different results for validation vs checks
        def execute_side_effect(query, params):
            query_str = str(query)
            mock_result = MagicMock()
            if "host_readiness_validations" in query_str:
                mock_result.fetchone.return_value = validation_row
            else:
                mock_result.fetchall.return_value = check_rows
            return mock_result

        repo.db.execute.side_effect = execute_side_effect

        # Execute
        result = repo.get_validation_by_id(validation_id)

        # Verify result structure
        assert result is not None
        assert isinstance(result, HostReadiness)
        assert result.validation_id == validation_id
        assert result.host_id == host_id
        assert len(result.checks) == 2
        assert all(isinstance(c, ReadinessCheckResult) for c in result.checks)

        # Verify check details
        assert result.checks[0].check_type == ReadinessCheckType.CONNECTIVITY
        assert result.checks[0].passed is True
        assert result.checks[1].check_type == ReadinessCheckType.SSH
        assert result.checks[1].passed is True

    def test_get_validation_not_found(self, repo):
        """Test fetching non-existent validation"""
        validation_id = uuid4()

        mock_result = MagicMock()
        mock_result.fetchone.return_value = None
        repo.db.execute.return_value = mock_result

        # Execute
        result = repo.get_validation_by_id(validation_id)

        # Verify None returned
        assert result is None


class TestDeleteOldValidations:
    """Test cleanup of old validation records"""

    @pytest.fixture
    def repo(self):
        """Create repository with mock database"""
        mock_db = MagicMock()
        return ReadinessRepository(mock_db)

    def test_delete_old_validations(self, repo):
        """Test deleting validations older than retention period"""
        host_id = uuid4()
        retention_days = 90

        mock_result = MagicMock()
        mock_result.rowcount = 15
        repo.db.execute.return_value = mock_result

        # Execute
        deleted_count = repo.delete_old_validations(host_id=host_id, retention_days=retention_days)

        # Verify DELETE query executed
        assert repo.db.execute.called
        call_args = repo.db.execute.call_args
        query_text = str(call_args[0][0])
        params = call_args[0][1]

        assert "DELETE FROM host_readiness_validations" in query_text
        assert "completed_at <" in query_text
        assert params["host_id"] == str(host_id)

        # Verify cutoff date calculation (90 days ago)
        cutoff_date = params["cutoff_date"]
        expected_cutoff = datetime.utcnow() - timedelta(days=90)
        assert abs((cutoff_date - expected_cutoff).total_seconds()) < 5

        # Verify commit called
        assert repo.db.commit.called

        # Verify count returned
        assert deleted_count == 15

    def test_delete_no_old_validations(self, repo):
        """Test delete when no old validations exist"""
        host_id = uuid4()

        mock_result = MagicMock()
        mock_result.rowcount = 0
        repo.db.execute.return_value = mock_result

        # Execute
        deleted_count = repo.delete_old_validations(host_id=host_id, retention_days=30)

        # Verify 0 deleted
        assert deleted_count == 0

    def test_delete_custom_retention(self, repo):
        """Test delete with custom retention period"""
        host_id = uuid4()

        mock_result = MagicMock()
        mock_result.rowcount = 5
        repo.db.execute.return_value = mock_result

        # Execute with 7 day retention
        repo.delete_old_validations(host_id=host_id, retention_days=7)

        # Verify 7 day cutoff
        call_args = repo.db.execute.call_args
        params = call_args[0][1]
        cutoff_date = params["cutoff_date"]
        expected_cutoff = datetime.utcnow() - timedelta(days=7)
        assert abs((cutoff_date - expected_cutoff).total_seconds()) < 5


class TestGetLatestValidation:
    """Test fetching most recent validation regardless of TTL"""

    @pytest.fixture
    def repo(self):
        """Create repository with mock database"""
        mock_db = MagicMock()
        return ReadinessRepository(mock_db)

    def test_get_latest_validation(self, repo):
        """Test fetching most recent validation"""
        host_id = uuid4()

        # Mock validation row (could be very old)
        mock_row = MagicMock(
            _mapping={
                "id": uuid4(),
                "host_id": host_id,
                "status": "ready",
                "overall_passed": True,
                "total_checks": 10,
                "passed_checks": 10,
                "failed_checks": 0,
                "warnings_count": 0,
                "validation_duration_ms": 1234.5,
                "completed_at": datetime.utcnow() - timedelta(days=30),  # 30 days old
                "cache_used": False,
                "parallel_execution": False,
            }
        )

        mock_result = MagicMock()
        mock_result.fetchone.return_value = mock_row
        repo.db.execute.return_value = mock_result

        # Execute
        result = repo.get_latest_validation_for_host(host_id)

        # Verify result returned (no TTL filter)
        assert result is not None
        assert isinstance(result, HostReadiness)
        assert result.host_id == host_id

        # Verify query does NOT include TTL filter
        call_args = repo.db.execute.call_args
        query_text = str(call_args[0][0])
        assert "completed_at >=" not in query_text
        assert "ORDER BY completed_at DESC" in query_text

    def test_get_latest_validation_no_history(self, repo):
        """Test latest validation when host has never been validated"""
        host_id = uuid4()

        mock_result = MagicMock()
        mock_result.fetchone.return_value = None
        repo.db.execute.return_value = mock_result

        # Execute
        result = repo.get_latest_validation_for_host(host_id)

        # Verify None returned
        assert result is None
