"""
SELinux Status Check

Checks SELinux configuration which may affect some compliance checks.
"""

import logging
import time
from typing import Optional

from backend.app.models.readiness_models import ReadinessCheckResult, ReadinessCheckSeverity, ReadinessCheckType

logger = logging.getLogger(__name__)


async def check_selinux_status(
    host, credentials, ssh_service, user_id: Optional[str] = None
) -> ReadinessCheckResult:  # pragma: allowlist secret
    """
    Check SELinux status.

    Args:
        host: Host model instance
        credentials: Decrypted credentials  # pragma: allowlist secret
        ssh_service: UnifiedSSHService instance
        user_id: Optional user ID for audit logging

    Returns:
        ReadinessCheckResult with SELinux status
    """
    start_time = time.time()

    try:
        # Check if SELinux is enabled
        result = await ssh_service.execute_command(
            host=host,
            credentials=credentials,  # pragma: allowlist secret
            command="getenforce 2>/dev/null || echo 'Not installed'",
            timeout=10,
        )

        duration_ms = (time.time() - start_time) * 1000

        if result.exit_code != 0:
            return ReadinessCheckResult(
                check_type=ReadinessCheckType.SELINUX_STATUS,
                check_name="SELinux Status",
                passed=True,  # Not having SELinux is not a failure
                severity=ReadinessCheckSeverity.INFO,
                message="SELinux not installed or not available",
                details={"selinux_status": "not_installed"},
                check_duration_ms=duration_ms,
            )

        selinux_status = result.stdout.strip().lower()

        # Enforcing mode may affect some checks
        if selinux_status == "enforcing":
            return ReadinessCheckResult(
                check_type=ReadinessCheckType.SELINUX_STATUS,
                check_name="SELinux Status",
                passed=True,
                severity=ReadinessCheckSeverity.WARNING,
                message="SELinux is in enforcing mode",
                details={
                    "selinux_status": "enforcing",
                    "note": "SELinux may affect some compliance checks. Ensure SCAP content has proper SELinux context.",
                },
                check_duration_ms=duration_ms,
            )

        return ReadinessCheckResult(
            check_type=ReadinessCheckType.SELINUX_STATUS,
            check_name="SELinux Status",
            passed=True,
            severity=ReadinessCheckSeverity.INFO,
            message=f"SELinux status: {selinux_status}",
            details={"selinux_status": selinux_status},
            check_duration_ms=duration_ms,
        )

    except Exception as e:
        duration_ms = (time.time() - start_time) * 1000
        return ReadinessCheckResult(
            check_type=ReadinessCheckType.SELINUX_STATUS,
            check_name="SELinux Status",
            passed=True,  # Not a critical failure
            severity=ReadinessCheckSeverity.INFO,
            message=f"Could not determine SELinux status: {str(e)}",
            details={"error": str(e)},
            check_duration_ms=duration_ms,
        )
