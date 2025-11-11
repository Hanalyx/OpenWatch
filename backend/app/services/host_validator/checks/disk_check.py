"""
Disk Space Check

Verifies sufficient disk space in /tmp for SCAP content transfer.
XCCDF and OVAL files can be 50-100MB, need buffer space.
"""

import logging
import time
from typing import TYPE_CHECKING, Optional

from backend.app.models.readiness_models import (
    ReadinessCheckResult,
    ReadinessCheckSeverity,
    ReadinessCheckType,
)

if TYPE_CHECKING:
    from backend.app.services.ssh_connection_context import SSHConnectionContext

logger = logging.getLogger(__name__)

REQUIRED_SPACE_MB = 500  # Minimum 500MB free space


async def check_disk_space(
    host, ssh_context: "SSHConnectionContext", user_id: Optional[str] = None
) -> ReadinessCheckResult:
    """
    Check available disk space in /tmp directory.

    Args:
        host: Host model instance
        ssh_context: Active SSH connection context (reuses existing connection)
        user_id: Optional user ID for audit logging

    Returns:
        ReadinessCheckResult with pass/fail status
    """
    start_time = time.time()

    try:
        # Get disk space in /tmp (output in MB) using existing SSH connection
        result = await ssh_context.execute_command(
            command="df -BM /tmp | awk 'NR==2 {print $4}' | sed 's/M//'",
            timeout=10,
        )

        duration_ms = (time.time() - start_time) * 1000

        if result.exit_code != 0:
            return ReadinessCheckResult(
                check_type=ReadinessCheckType.DISK_SPACE,
                check_name="Disk Space",
                passed=False,
                severity=ReadinessCheckSeverity.ERROR,
                message="Failed to check disk space",
                details={"error": result.stderr},
                check_duration_ms=duration_ms,
            )

        available_mb = int(result.stdout.strip())

        if available_mb < REQUIRED_SPACE_MB:
            return ReadinessCheckResult(
                check_type=ReadinessCheckType.DISK_SPACE,
                check_name="Disk Space",
                passed=False,
                severity=ReadinessCheckSeverity.ERROR,
                message=f"Insufficient disk space: {available_mb}MB available, {REQUIRED_SPACE_MB}MB required",
                details={
                    "available_mb": available_mb,
                    "required_mb": REQUIRED_SPACE_MB,
                    "remediation": "Free up disk space in /tmp directory",
                },
                check_duration_ms=duration_ms,
            )

        return ReadinessCheckResult(
            check_type=ReadinessCheckType.DISK_SPACE,
            check_name="Disk Space",
            passed=True,
            severity=ReadinessCheckSeverity.INFO,
            message=f"Sufficient disk space: {available_mb}MB available",
            details={"available_mb": available_mb, "required_mb": REQUIRED_SPACE_MB},
            check_duration_ms=duration_ms,
        )

    except Exception as e:
        duration_ms = (time.time() - start_time) * 1000
        return ReadinessCheckResult(
            check_type=ReadinessCheckType.DISK_SPACE,
            check_name="Disk Space",
            passed=False,
            severity=ReadinessCheckSeverity.ERROR,
            message=f"Error checking disk space: {str(e)}",
            details={"error": str(e)},
            check_duration_ms=duration_ms,
        )
