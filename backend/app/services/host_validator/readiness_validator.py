"""
Host Readiness Validator Service

Orchestrates all readiness checks and manages validation lifecycle.
This service coordinates the execution of individual check modules and
aggregates results into comprehensive readiness reports.

Architecture:
- Uses UnifiedSSHService for SSH operations (follows OpenWatch pattern)
- Executes modular checks from host_validator/checks/
- Stores results in PostgreSQL for audit trail and smart caching
- Integrates with existing AuthService for credential resolution

Smart Caching:
- Queries recent validation runs (default 24h TTL)
- Skips redundant checks for recently-validated hosts
- Reduces SSH overhead on target systems
"""

import asyncio
import logging
import time
from datetime import datetime, timedelta
from typing import List, Optional
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.app.models.readiness_models import (
    HostReadiness,
    HostReadinessCheck,
    HostReadinessValidation,
    ReadinessCheckResult,
    ReadinessCheckType,
    ReadinessStatus,
)
from backend.app.services.auth_service import AuthService
from backend.app.services.unified_ssh_service import UnifiedSSHService

# Import check modules
from .checks import (
    check_disk_space,
    check_memory,
    check_network_connectivity,
    check_operating_system,
    check_oscap_installation,
    check_selinux_status,
    check_sudo_access,
)

logger = logging.getLogger(__name__)


class ReadinessValidatorService:
    """
    Orchestrates host readiness validation checks.

    This service executes all readiness checks for hosts and manages
    the validation lifecycle including caching, result aggregation,
    and database persistence.
    """

    def __init__(
        self,
        db: Session,
        ssh_service: Optional[UnifiedSSHService] = None,
        auth_service: Optional[AuthService] = None,
    ):
        """
        Initialize the readiness validator service.

        Args:
            db: Database session (synchronous)
            ssh_service: Optional UnifiedSSHService instance (created if not provided)
            auth_service: Optional AuthService instance (created if not provided)
        """
        self.db = db
        self.ssh_service = ssh_service or UnifiedSSHService()
        self.auth_service = auth_service or AuthService(db)

        # Define all available checks
        self.all_checks = {
            ReadinessCheckType.OSCAP_INSTALLATION: check_oscap_installation,
            ReadinessCheckType.DISK_SPACE: check_disk_space,
            ReadinessCheckType.SUDO_ACCESS: check_sudo_access,
            ReadinessCheckType.OPERATING_SYSTEM: check_operating_system,
            ReadinessCheckType.NETWORK_CONNECTIVITY: check_network_connectivity,
            ReadinessCheckType.MEMORY_AVAILABILITY: check_memory,
            ReadinessCheckType.SELINUX_STATUS: check_selinux_status,
        }

    async def validate_host(
        self,
        host_id: UUID,
        check_types: Optional[List[ReadinessCheckType]] = None,
        use_cache: bool = True,
        cache_ttl_hours: int = 24,
        user_id: Optional[str] = None,
    ) -> HostReadiness:
        """
        Validate a single host's readiness for SCAP scanning.

        Args:
            host_id: UUID of the host to validate
            check_types: Specific checks to run (None = all checks)
            use_cache: Whether to use cached results within TTL
            cache_ttl_hours: Cache time-to-live in hours
            user_id: Optional user ID for audit logging

        Returns:
            HostReadiness object with complete validation results

        Raises:
            HTTPException: If host not found or validation fails
        """
        start_time = time.time()

        # Check cache first
        if use_cache:
            cached = await self._get_cached_validation(host_id, cache_ttl_hours)
            if cached:
                logger.info(
                    f"Using cached readiness validation for host {host_id}",
                    extra={"host_id": str(host_id), "user_id": user_id},
                )
                return cached

        # Get host from database
        from backend.app.models import Host

        host = self.db.query(Host).filter(Host.id == host_id).first()
        if not host:
            raise ValueError(f"Host {host_id} not found")

        # Resolve credentials  # pragma: allowlist secret
        credentials = self.auth_service.resolve_credential(str(host_id))  # pragma: allowlist secret
        if not credentials:  # pragma: allowlist secret
            raise ValueError(f"No credentials configured for host {host_id}")  # pragma: allowlist secret

        # Determine which checks to run
        checks_to_run = check_types or list(self.all_checks.keys())

        # Execute checks concurrently
        check_results = await self._execute_checks(
            host=host,
            credentials=credentials,  # pragma: allowlist secret
            check_types=checks_to_run,
            user_id=user_id,
        )

        # Aggregate results
        total_checks = len(check_results)
        passed_checks = sum(1 for r in check_results if r.passed)
        failed_checks = total_checks - passed_checks
        warnings_count = sum(1 for r in check_results if r.severity.value == "warning")

        # Determine overall status
        overall_passed = all(r.passed for r in check_results)
        if overall_passed:
            status = ReadinessStatus.READY
        elif any(r.severity.value == "error" and not r.passed for r in check_results):
            status = ReadinessStatus.NOT_READY
        else:
            status = ReadinessStatus.DEGRADED

        # Calculate duration
        validation_duration_ms = (time.time() - start_time) * 1000

        # Store validation run in database
        validation_run = await self._store_validation_run(
            host_id=host_id,
            status=status,
            overall_passed=overall_passed,
            total_checks=total_checks,
            passed_checks=passed_checks,
            failed_checks=failed_checks,
            warnings_count=warnings_count,
            validation_duration_ms=validation_duration_ms,
            user_id=user_id,
        )

        # Store individual check results
        await self._store_check_results(
            validation_run_id=validation_run.id,
            host_id=host_id,
            check_results=check_results,
            user_id=user_id,
        )

        # Build response
        return HostReadiness(
            host_id=host_id,
            hostname=host.hostname,
            ip_address=host.ip_address,
            status=status,
            overall_passed=overall_passed,
            checks=check_results,
            total_checks=total_checks,
            passed_checks=passed_checks,
            failed_checks=failed_checks,
            warnings_count=warnings_count,
            validation_duration_ms=validation_duration_ms,
            completed_at=datetime.utcnow(),
            summary={"validation_run_id": str(validation_run.id)},
        )

    async def _execute_checks(
        self,
        host,
        credentials,  # pragma: allowlist secret
        check_types: List[ReadinessCheckType],
        user_id: Optional[str] = None,
    ) -> List[ReadinessCheckResult]:
        """
        Execute readiness checks concurrently.

        Args:
            host: Host model instance
            credentials: Decrypted credentials  # pragma: allowlist secret
            check_types: List of check types to execute
            user_id: Optional user ID for audit logging

        Returns:
            List of ReadinessCheckResult objects
        """
        tasks = []
        for check_type in check_types:
            check_func = self.all_checks.get(check_type)
            if check_func:
                # Create async task for each check
                task = check_func(
                    host=host,
                    credentials=credentials,  # pragma: allowlist secret
                    ssh_service=self.ssh_service,
                    user_id=user_id,
                )
                tasks.append(task)

        # Execute all checks concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter out exceptions and convert to ReadinessCheckResult
        check_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                # Log exception and create error result
                check_type = check_types[i]
                logger.error(
                    f"Check {check_type} failed with exception: {result}",
                    extra={"host_id": str(host.id), "user_id": user_id},
                    exc_info=True,
                )
                # Create error result
                from backend.app.models.readiness_models import ReadinessCheckSeverity

                error_result = ReadinessCheckResult(
                    check_type=check_type,
                    check_name=check_type.value.replace("_", " ").title(),
                    passed=False,
                    severity=ReadinessCheckSeverity.ERROR,
                    message=f"Check failed: {str(result)}",
                    details={"error": str(result)},
                )
                check_results.append(error_result)
            else:
                check_results.append(result)

        return check_results

    async def _get_cached_validation(self, host_id: UUID, cache_ttl_hours: int) -> Optional[HostReadiness]:
        """
        Get cached validation result if available and within TTL.

        Args:
            host_id: UUID of the host
            cache_ttl_hours: Cache time-to-live in hours

        Returns:
            HostReadiness object if cached result exists, None otherwise
        """
        cutoff_time = datetime.utcnow() - timedelta(hours=cache_ttl_hours)

        # Query most recent validation within TTL
        result = self.db.execute(
            text(
                """
                SELECT id, status, overall_passed, total_checks, passed_checks,
                       failed_checks, warnings_count, validation_duration_ms,
                       completed_at, summary
                FROM host_readiness_validations
                WHERE host_id = :host_id
                  AND completed_at >= :cutoff_time
                ORDER BY completed_at DESC
                LIMIT 1
                """
            ),
            {"host_id": str(host_id), "cutoff_time": cutoff_time},
        )

        row = result.fetchone()
        if not row:
            return None

        validation_run_id = row[0]

        # Get host details
        from backend.app.models import Host

        host = self.db.query(Host).filter(Host.id == host_id).first()
        if not host:
            return None

        # Get individual check results
        check_results_query = self.db.execute(
            text(
                """
                SELECT check_type, check_name, passed, severity, message,
                       details, check_duration_ms
                FROM host_readiness_checks
                WHERE validation_run_id = :validation_run_id
                ORDER BY created_at
                """
            ),
            {"validation_run_id": str(validation_run_id)},
        )

        check_results = []
        for check_row in check_results_query.fetchall():
            from backend.app.models.readiness_models import ReadinessCheckSeverity

            check_results.append(
                ReadinessCheckResult(
                    check_type=ReadinessCheckType(check_row[0]),
                    check_name=check_row[1],
                    passed=check_row[2],
                    severity=ReadinessCheckSeverity(check_row[3]),
                    message=check_row[4],
                    details=check_row[5] or {},
                    check_duration_ms=check_row[6],
                )
            )

        # Build HostReadiness from cached data
        return HostReadiness(
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

    async def _store_validation_run(
        self,
        host_id: UUID,
        status: ReadinessStatus,
        overall_passed: bool,
        total_checks: int,
        passed_checks: int,
        failed_checks: int,
        warnings_count: int,
        validation_duration_ms: float,
        user_id: Optional[str] = None,
    ) -> HostReadinessValidation:
        """Store validation run in database."""
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
            created_by=UUID(user_id) if user_id else None,
        )

        self.db.add(validation_run)
        self.db.commit()
        self.db.refresh(validation_run)

        return validation_run

    async def _store_check_results(
        self,
        validation_run_id: UUID,
        host_id: UUID,
        check_results: List[ReadinessCheckResult],
        user_id: Optional[str] = None,
    ):
        """Store individual check results in database."""
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
                created_by=UUID(user_id) if user_id else None,
            )

            self.db.add(check_record)

        self.db.commit()
