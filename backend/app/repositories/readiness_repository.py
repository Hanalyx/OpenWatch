"""
Readiness Validation Repository

Centralized data access layer for host readiness validation results.
Follows OpenWatch QueryBuilder pattern for PostgreSQL operations.

This repository provides:
- Smart caching with configurable TTL
- Validation history queries
- Individual check result retrieval
- Consistent error handling and logging

Used by: ReadinessValidatorService, API endpoints
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.app.models.readiness_models import (
    HostReadiness,
    HostReadinessCheck,
    HostReadinessValidation,
    ReadinessCheckResult,
    ReadinessCheckSeverity,
    ReadinessCheckType,
    ReadinessStatus,
)
from backend.app.utils.query_builder import QueryBuilder

logger = logging.getLogger(__name__)


class ReadinessRepository:
    """
    Repository for host readiness validation data access.

    Centralizes all database operations for readiness validation results,
    providing smart caching, history queries, and consistent error handling.

    Example:
        repo = ReadinessRepository(db)
        cached = await repo.get_cached_validation(host_id, cache_ttl_hours=24)
        if not cached:
            validation = await repo.store_validation(...)
    """

    def __init__(self, db: Session):
        """
        Initialize repository with database session.

        Args:
            db: SQLAlchemy database session
        """
        self.db = db
        self.logger = logger

    async def get_cached_validation(
        self,
        host_id: UUID,
        cache_ttl_hours: int = 24,
    ) -> Optional[HostReadiness]:
        """
        Get cached validation result if available and within TTL.

        Args:
            host_id: UUID of the host
            cache_ttl_hours: Cache time-to-live in hours (default: 24)

        Returns:
            HostReadiness object if cached result exists within TTL, None otherwise

        Example:
            cached = await repo.get_cached_validation(
                host_id=UUID("123..."),
                cache_ttl_hours=1
            )
            if cached:
                logger.info(f"Using cached validation for {cached.hostname}")
        """
        try:
            cutoff_time = datetime.utcnow() - timedelta(hours=cache_ttl_hours)

            # Query most recent validation within TTL using QueryBuilder
            builder = (
                QueryBuilder("host_readiness_validations")
                .select(
                    "id",
                    "status",
                    "overall_passed",
                    "total_checks",
                    "passed_checks",
                    "failed_checks",
                    "warnings_count",
                    "validation_duration_ms",
                    "completed_at",
                    "summary",
                )
                .where("host_id = :host_id", str(host_id), "host_id")
                .where("completed_at >= :cutoff_time", cutoff_time, "cutoff_time")
                .order_by("completed_at", "DESC")
                .paginate(page=1, per_page=1)
            )

            query, params = builder.build()
            result = self.db.execute(text(query), params)
            row = result.fetchone()

            if not row:
                self.logger.debug(f"No cached validation found for host {host_id} within {cache_ttl_hours}h TTL")
                return None

            validation_run_id = row[0]

            # Get host details
            from backend.app.database import Host

            host = self.db.query(Host).filter(Host.id == host_id).first()
            if not host:
                self.logger.warning(f"Host {host_id} not found for cached validation")
                return None

            # Get individual check results
            check_results = await self._get_check_results(validation_run_id)

            # Build HostReadiness from cached data
            cached_validation = HostReadiness(
                host_id=host_id,
                hostname=host.hostname,
                ip_address=host.ip_address,
                status=ReadinessStatus(row[1]),
                overall_passed=row[2],
                checks=check_results,
                total_checks=row[3],
                passed_checks=row[4],
                failed_checks=row[5],
                warnings_count=row[6],
                validation_duration_ms=row[7],
                completed_at=row[8],
                summary=row[9] or {},
            )

            self.logger.info(
                f"Retrieved cached validation for host {host_id} " f"(completed_at={row[8]}, status={row[1]})"
            )

            return cached_validation

        except Exception as e:
            self.logger.error(f"Error retrieving cached validation for host {host_id}: {e}")
            # Return None to trigger fresh validation
            return None

    async def _get_check_results(self, validation_run_id: UUID) -> List[ReadinessCheckResult]:
        """
        Get individual check results for a validation run.

        Args:
            validation_run_id: UUID of the validation run

        Returns:
            List of ReadinessCheckResult objects

        Example:
            results = await repo._get_check_results(validation_run_id)
            passed_count = sum(1 for r in results if r.passed)
        """
        builder = (
            QueryBuilder("host_readiness_checks")
            .select(
                "check_type",
                "check_name",
                "passed",
                "severity",
                "message",
                "details",
                "check_duration_ms",
            )
            .where(
                "validation_run_id = :validation_run_id",
                str(validation_run_id),
                "validation_run_id",
            )
            .order_by("created_at", "ASC")
        )

        query, params = builder.build()
        result = self.db.execute(text(query), params)

        check_results = []
        for row in result.fetchall():
            check_results.append(
                ReadinessCheckResult(
                    check_type=ReadinessCheckType(row[0]),
                    check_name=row[1],
                    passed=row[2],
                    severity=ReadinessCheckSeverity(row[3]),
                    message=row[4],
                    details=row[5] or {},
                    check_duration_ms=row[6],
                )
            )

        return check_results

    async def store_validation(
        self,
        host_id: UUID,
        status: ReadinessStatus,
        overall_passed: bool,
        total_checks: int,
        passed_checks: int,
        failed_checks: int,
        warnings_count: int,
        validation_duration_ms: float,
        user_id: Optional[UUID] = None,
        summary: Optional[Dict] = None,
    ) -> HostReadinessValidation:
        """
        Store validation run in database.

        Args:
            host_id: UUID of the validated host
            status: Overall readiness status (ready/not_ready/degraded)
            overall_passed: Whether all checks passed
            total_checks: Total number of checks executed
            passed_checks: Number of checks that passed
            failed_checks: Number of checks that failed
            warnings_count: Number of warnings generated
            validation_duration_ms: Total validation duration in milliseconds
            user_id: Optional UUID of user who triggered validation
            summary: Optional summary metadata dict

        Returns:
            Created HostReadinessValidation model instance

        Example:
            validation = await repo.store_validation(
                host_id=host.id,
                status=ReadinessStatus.READY,
                overall_passed=True,
                total_checks=7,
                passed_checks=7,
                failed_checks=0,
                warnings_count=1,
                validation_duration_ms=2345.67,
                user_id=current_user.id
            )
        """
        try:
            from uuid import uuid4

            validation_run = HostReadinessValidation(
                id=uuid4(),
                host_id=host_id,
                status=status.value,
                overall_passed=overall_passed,
                total_checks=total_checks,
                passed_checks=passed_checks,
                failed_checks=failed_checks,
                warnings_count=warnings_count,
                validation_duration_ms=validation_duration_ms,
                started_at=datetime.utcnow(),
                completed_at=datetime.utcnow(),
                created_by=user_id,
                summary=summary or {},
            )

            self.db.add(validation_run)
            self.db.commit()
            self.db.refresh(validation_run)

            self.logger.info(
                f"Stored validation run {validation_run.id} for host {host_id} "
                f"(status={status.value}, passed={overall_passed})"
            )

            return validation_run

        except Exception as e:
            self.logger.error(f"Error storing validation run for host {host_id}: {e}")
            self.db.rollback()
            raise

    async def store_check_results(
        self,
        validation_run_id: UUID,
        host_id: UUID,
        check_results: List[ReadinessCheckResult],
        user_id: Optional[UUID] = None,
    ) -> int:
        """
        Store individual check results in database.

        Args:
            validation_run_id: UUID of the validation run
            host_id: UUID of the validated host
            check_results: List of ReadinessCheckResult objects
            user_id: Optional UUID of user who triggered validation

        Returns:
            Number of check results stored

        Example:
            stored_count = await repo.store_check_results(
                validation_run_id=validation.id,
                host_id=host.id,
                check_results=[result1, result2, result3],
                user_id=current_user.id
            )
        """
        try:
            from uuid import uuid4

            for result in check_results:
                check_record = HostReadinessCheck(
                    id=uuid4(),
                    host_id=host_id,
                    validation_run_id=validation_run_id,
                    check_type=result.check_type.value,
                    check_name=result.check_name,
                    passed=result.passed,
                    severity=result.severity.value,
                    message=result.message,
                    details=result.details,
                    check_duration_ms=result.check_duration_ms,
                    created_at=datetime.utcnow(),
                    created_by=user_id,
                )

                self.db.add(check_record)

            self.db.commit()

            self.logger.info(f"Stored {len(check_results)} check results for validation run {validation_run_id}")

            return len(check_results)

        except Exception as e:
            self.logger.error(f"Error storing check results for validation run {validation_run_id}: {e}")
            self.db.rollback()
            raise

    async def get_validation_history(
        self,
        host_id: UUID,
        limit: int = 10,
        offset: int = 0,
    ) -> Tuple[List[Dict], int]:
        """
        Get validation history for a host with pagination.

        Args:
            host_id: UUID of the host
            limit: Maximum number of results to return (default: 10)
            offset: Number of results to skip for pagination (default: 0)

        Returns:
            Tuple of (validation_list, total_count)
            Each validation dict contains: id, status, overall_passed, checks counts,
            duration, completed_at

        Example:
            validations, total = await repo.get_validation_history(
                host_id=UUID("123..."),
                limit=20,
                offset=0
            )
            for v in validations:
                print(
                    f"{v['completed_at']}: {v['status']} "
                    f"({v['passed_checks']}/{v['total_checks']})"
                )
        """
        try:
            # Get total count
            count_builder = QueryBuilder("host_readiness_validations").where(
                "host_id = :host_id", str(host_id), "host_id"
            )
            count_query, count_params = count_builder.count_query()
            total = self.db.execute(text(count_query), count_params).scalar()

            # Get paginated results
            builder = (
                QueryBuilder("host_readiness_validations")
                .select(
                    "id",
                    "status",
                    "overall_passed",
                    "total_checks",
                    "passed_checks",
                    "failed_checks",
                    "warnings_count",
                    "validation_duration_ms",
                    "completed_at",
                )
                .where("host_id = :host_id", str(host_id), "host_id")
                .order_by("completed_at", "DESC")
                .paginate(page=(offset // limit) + 1, per_page=limit)
            )

            query, params = builder.build()
            result = self.db.execute(text(query), params)

            validations = []
            for row in result.fetchall():
                validations.append(
                    {
                        "id": str(row[0]),
                        "status": row[1],
                        "overall_passed": row[2],
                        "total_checks": row[3],
                        "passed_checks": row[4],
                        "failed_checks": row[5],
                        "warnings_count": row[6],
                        "validation_duration_ms": row[7],
                        "completed_at": row[8],
                    }
                )

            self.logger.debug(
                f"Retrieved {len(validations)} validation history records for host {host_id} "
                f"(total={total}, limit={limit}, offset={offset})"
            )

            return validations, total

        except Exception as e:
            self.logger.error(f"Error retrieving validation history for host {host_id}: {e}")
            raise

    async def get_validation_by_id(self, validation_id: UUID) -> Optional[Dict]:
        """
        Get detailed validation result by ID.

        Args:
            validation_id: UUID of the validation run

        Returns:
            Dict with validation details including check results, or None if not found

        Example:
            validation = await repo.get_validation_by_id(UUID("123..."))
            if validation:
                for check in validation['checks']:
                    print(f"{check['check_name']}: {check['passed']}")
        """
        try:
            builder = (
                QueryBuilder("host_readiness_validations v")
                .select(
                    "v.id",
                    "v.host_id",
                    "v.status",
                    "v.overall_passed",
                    "v.total_checks",
                    "v.passed_checks",
                    "v.failed_checks",
                    "v.warnings_count",
                    "v.validation_duration_ms",
                    "v.completed_at",
                    "v.summary",
                )
                .where("v.id = :validation_id", str(validation_id), "validation_id")
            )

            query, params = builder.build()
            result = self.db.execute(text(query), params)
            row = result.fetchone()

            if not row:
                self.logger.warning(f"Validation {validation_id} not found")
                return None

            # Get check results
            check_results = await self._get_check_results(validation_id)

            validation_dict = {
                "id": str(row[0]),
                "host_id": str(row[1]),
                "status": row[2],
                "overall_passed": row[3],
                "total_checks": row[4],
                "passed_checks": row[5],
                "failed_checks": row[6],
                "warnings_count": row[7],
                "validation_duration_ms": row[8],
                "completed_at": row[9],
                "summary": row[10] or {},
                "checks": [
                    {
                        "check_type": check.check_type.value,
                        "check_name": check.check_name,
                        "passed": check.passed,
                        "severity": check.severity.value,
                        "message": check.message,
                        "details": check.details,
                        "check_duration_ms": check.check_duration_ms,
                    }
                    for check in check_results
                ],
            }

            return validation_dict

        except Exception as e:
            self.logger.error(f"Error retrieving validation {validation_id}: {e}")
            raise

    async def get_latest_validation_for_host(self, host_id: UUID) -> Optional[Dict]:
        """
        Get the most recent validation for a host (regardless of TTL).

        Args:
            host_id: UUID of the host

        Returns:
            Dict with validation details, or None if no validation exists

        Example:
            latest = await repo.get_latest_validation_for_host(host.id)
            if latest:
                logger.info(f"Last validation: {latest['completed_at']} ({latest['status']})")
        """
        try:
            builder = (
                QueryBuilder("host_readiness_validations")
                .select(
                    "id",
                    "status",
                    "overall_passed",
                    "total_checks",
                    "passed_checks",
                    "failed_checks",
                    "warnings_count",
                    "validation_duration_ms",
                    "completed_at",
                )
                .where("host_id = :host_id", str(host_id), "host_id")
                .order_by("completed_at", "DESC")
                .limit(1)
            )

            query, params = builder.build()
            result = self.db.execute(text(query), params)
            row = result.fetchone()

            if not row:
                return None

            return {
                "id": str(row[0]),
                "status": row[1],
                "overall_passed": row[2],
                "total_checks": row[3],
                "passed_checks": row[4],
                "failed_checks": row[5],
                "warnings_count": row[6],
                "validation_duration_ms": row[7],
                "completed_at": row[8],
            }

        except Exception as e:
            self.logger.error(f"Error retrieving latest validation for host {host_id}: {e}")
            raise

    async def delete_old_validations(self, retention_days: int = 90) -> int:
        """
        Delete validation records older than retention period.

        Args:
            retention_days: Number of days to retain validation records (default: 90)

        Returns:
            Number of validation records deleted

        Example:
            deleted = await repo.delete_old_validations(retention_days=30)
            logger.info(f"Deleted {deleted} old validation records")
        """
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=retention_days)

            # Get IDs to delete
            builder = (
                QueryBuilder("host_readiness_validations")
                .select("id")
                .where("completed_at < :cutoff_date", cutoff_date, "cutoff_date")
            )

            query, params = builder.build()
            result = self.db.execute(text(query), params)
            validation_ids = [str(row[0]) for row in result.fetchall()]

            if not validation_ids:
                self.logger.info(f"No validation records older than {retention_days} days")
                return 0

            # Delete check results first (foreign key constraint)
            for validation_id in validation_ids:
                self.db.execute(
                    text("DELETE FROM host_readiness_checks WHERE validation_run_id = :validation_id"),
                    {"validation_id": validation_id},
                )

            # Delete validation records
            delete_count = len(validation_ids)
            for validation_id in validation_ids:
                self.db.execute(
                    text("DELETE FROM host_readiness_validations WHERE id = :id"),
                    {"id": validation_id},
                )

            self.db.commit()

            self.logger.info(f"Deleted {delete_count} validation records older than {retention_days} days")

            return delete_count

        except Exception as e:
            self.logger.error(f"Error deleting old validations: {e}")
            self.db.rollback()
            raise
