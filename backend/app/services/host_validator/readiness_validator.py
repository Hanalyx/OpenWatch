"""
Host Readiness Validator Service

Orchestrates all readiness checks and manages validation lifecycle.
This service coordinates the execution of individual check modules and
aggregates results into comprehensive readiness reports.

Architecture:
- Uses UnifiedSSHService for SSH operations (follows OpenWatch pattern)
- Executes modular checks from host_validator/checks/
- Stores results in PostgreSQL for audit trail and smart caching
- Integrates with CentralizedAuthService for credential resolution

Smart Caching:
- Queries recent validation runs (default 24h TTL)
- Skips redundant checks for recently-validated hosts
- Reduces SSH overhead on target systems
"""

import asyncio
import logging
import time
from datetime import datetime
from typing import List, Optional
from uuid import UUID, uuid4

from sqlalchemy.orm import Session

from backend.app.config import get_settings
from backend.app.encryption import EncryptionConfig, EncryptionService, create_encryption_service
from backend.app.models.readiness_models import (
    HostReadiness,
    ReadinessCheckResult,
    ReadinessCheckType,
    ReadinessStatus,
)
from backend.app.repositories.readiness_repository import ReadinessRepository
from backend.app.services.auth_service import CentralizedAuthService
from backend.app.services.ssh_connection_context import SSHConnectionContext
from backend.app.services.unified_ssh_service import UnifiedSSHService

# Import check modules
from .checks import (
    check_component_detection,
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
        auth_service: Optional[CentralizedAuthService] = None,
        repository: Optional[ReadinessRepository] = None,
        encryption_service: Optional[EncryptionService] = None,
    ):
        """
        Initialize the readiness validator service.

        Args:
            db: Database session (synchronous)
            ssh_service: Optional UnifiedSSHService instance (created if not provided)
            auth_service: Optional CentralizedAuthService instance (created if not provided)
            repository: Optional ReadinessRepository instance (created if not provided)
            encryption_service: Optional EncryptionService instance (created if not provided, needed for auth_service)
        """
        self.db = db
        self.ssh_service = ssh_service or UnifiedSSHService()

        # Create auth_service if not provided (requires encryption_service)
        if auth_service is None:
            if encryption_service is None:
                # Load master key from settings (environment variable)
                settings = get_settings()
                enc_service = create_encryption_service(
                    master_key=settings.master_key, config=EncryptionConfig()
                )
            else:
                enc_service = encryption_service
            self.auth_service = CentralizedAuthService(db, enc_service)
        else:
            self.auth_service = auth_service

        self.repository = repository or ReadinessRepository(db)

        # Define all available checks
        self.all_checks = {
            ReadinessCheckType.OSCAP_INSTALLATION: check_oscap_installation,
            ReadinessCheckType.DISK_SPACE: check_disk_space,
            ReadinessCheckType.SUDO_ACCESS: check_sudo_access,
            ReadinessCheckType.OPERATING_SYSTEM: check_operating_system,
            ReadinessCheckType.NETWORK_CONNECTIVITY: check_network_connectivity,
            ReadinessCheckType.MEMORY_AVAILABILITY: check_memory,
            ReadinessCheckType.SELINUX_STATUS: check_selinux_status,
            ReadinessCheckType.COMPONENT_DETECTION: check_component_detection,
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

        # Check cache first using repository
        if use_cache:
            cached = await self.repository.get_cached_validation(host_id, cache_ttl_hours)
            if cached:
                logger.info(
                    f"Using cached readiness validation for host {host_id}",
                    extra={"host_id": str(host_id), "user_id": user_id},
                )
                return cached

        # Get host from database
        from backend.app.database import Host

        host = self.db.query(Host).filter(Host.id == host_id).first()
        if not host:
            raise ValueError(f"Host {host_id} not found")

        # Resolve credentials  # pragma: allowlist secret
        credentials = self.auth_service.resolve_credential(str(host_id))  # pragma: allowlist secret
        if not credentials:  # pragma: allowlist secret
            raise ValueError(
                f"No credentials configured for host {host_id}"
            )  # pragma: allowlist secret

        # Determine which checks to run
        checks_to_run = check_types or list(self.all_checks.keys())

        # Open SSH connection ONCE using context manager
        # This eliminates redundant SSH handshakes (7 checks = 1 connection, not 7 connections)
        try:
            async with SSHConnectionContext(
                self.ssh_service, host, credentials
            ) as ssh_ctx:  # pragma: allowlist secret
                # Execute all checks with shared connection
                check_results = await self._execute_checks(
                    host=host,
                    ssh_context=ssh_ctx,
                    check_types=checks_to_run,
                    user_id=user_id,
                )
            # Connection automatically closed when context exits
        except ConnectionError as e:
            logger.error(
                f"Failed to establish SSH connection to host {host_id}: {e}",
                extra={"host_id": str(host_id), "user_id": user_id},
            )
            # Return NOT_READY status with connection error
            return HostReadiness(
                host_id=host_id,
                hostname=host.hostname,
                ip_address=host.ip_address,
                status=ReadinessStatus.NOT_READY,
                overall_passed=False,
                checks=[],
                total_checks=0,
                passed_checks=0,
                failed_checks=0,
                warnings_count=0,
                validation_duration_ms=(time.time() - start_time) * 1000,
                completed_at=datetime.utcnow(),
                summary={"error": f"SSH connection failed: {str(e)}"},
            )

        # Aggregate results
        total_checks = len(check_results)
        passed_checks = sum(1 for r in check_results if r.passed)
        failed_checks = total_checks - passed_checks
        # Handle both enum and string values for severity
        warnings_count = sum(
            1
            for r in check_results
            if (r.severity if isinstance(r.severity, str) else r.severity.value) == "warning"
        )

        # Determine overall status
        overall_passed = all(r.passed for r in check_results)
        if overall_passed:
            status = ReadinessStatus.READY
        elif any(
            (r.severity if isinstance(r.severity, str) else r.severity.value) == "error"
            and not r.passed
            for r in check_results
        ):
            status = ReadinessStatus.NOT_READY
        else:
            status = ReadinessStatus.DEGRADED

        # Calculate duration
        validation_duration_ms = (time.time() - start_time) * 1000

        # Store validation run in database using repository
        # Note: user_id can be integer (legacy) or UUID string - skip UUID conversion for now
        validation_run = await self.repository.store_validation(
            host_id=host_id,
            status=status,
            overall_passed=overall_passed,
            total_checks=total_checks,
            passed_checks=passed_checks,
            failed_checks=failed_checks,
            warnings_count=warnings_count,
            validation_duration_ms=validation_duration_ms,
            user_id=None,  # Skip user_id for now to avoid UUID conversion issues
            summary={"validation_run_id": str(uuid4())},
        )

        # Store individual check results using repository
        await self.repository.store_check_results(
            validation_run_id=validation_run.id,
            host_id=host_id,
            check_results=check_results,
            user_id=None,  # Skip user_id for now to avoid UUID conversion issues
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
        ssh_context: SSHConnectionContext,
        check_types: List[ReadinessCheckType],
        user_id: Optional[str] = None,
    ) -> List[ReadinessCheckResult]:
        """
        Execute readiness checks concurrently using shared SSH connection.

        Args:
            host: Host model instance
            ssh_context: Active SSH connection context (reused by all checks)
            check_types: List of check types to execute
            user_id: Optional user ID for audit logging

        Returns:
            List of ReadinessCheckResult objects
        """
        tasks = []
        for check_type in check_types:
            check_func = self.all_checks.get(check_type)
            if check_func:
                # Create async task for each check with shared SSH context
                task = check_func(
                    host=host,
                    ssh_context=ssh_context,
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
