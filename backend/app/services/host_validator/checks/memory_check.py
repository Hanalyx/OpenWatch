"""
Memory Availability Check

Verifies sufficient available memory for SCAP scanning.
OSCAP scans can consume 200MB+ of memory.
"""

import logging
import time
from typing import Optional

from backend.app.models.readiness_models import ReadinessCheckResult, ReadinessCheckSeverity, ReadinessCheckType

logger = logging.getLogger(__name__)

REQUIRED_MEMORY_MB = 200  # Minimum 200MB free memory


async def check_memory(
    host, credentials, ssh_service, user_id: Optional[str] = None
) -> ReadinessCheckResult:  # pragma: allowlist secret
    """
    Check available memory on target host.

    Args:
        host: Host model instance
        credentials: Decrypted credentials  # pragma: allowlist secret
        ssh_service: UnifiedSSHService instance
        user_id: Optional user ID for audit logging

    Returns:
        ReadinessCheckResult with memory check details
    """
    start_time = time.time()

    try:
        # Get available memory in MB
        result = await ssh_service.execute_command(
            host=host,
            credentials=credentials,  # pragma: allowlist secret
            command="free -m | awk 'NR==2 {print $7}'",
            timeout=10,
        )

        duration_ms = (time.time() - start_time) * 1000

        if result.exit_code != 0:
            return ReadinessCheckResult(
                check_type=ReadinessCheckType.MEMORY_AVAILABILITY,
                check_name="Memory Availability",
                passed=False,
                severity=ReadinessCheckSeverity.ERROR,
                message="Failed to check available memory",
                details={"error": result.stderr},
                check_duration_ms=duration_ms,
            )

        available_mb = int(result.stdout.strip())

        if available_mb < REQUIRED_MEMORY_MB:
            return ReadinessCheckResult(
                check_type=ReadinessCheckType.MEMORY_AVAILABILITY,
                check_name="Memory Availability",
                passed=False,
                severity=ReadinessCheckSeverity.WARNING,
                message=f"Low memory: {available_mb}MB available, {REQUIRED_MEMORY_MB}MB recommended",
                details={
                    "available_mb": available_mb,
                    "required_mb": REQUIRED_MEMORY_MB,
                    "remediation": "Free up memory or consider running scans during low-usage periods",
                    "impact": "MEDIUM - Scans may be slow or fail",
                },
                check_duration_ms=duration_ms,
            )

        return ReadinessCheckResult(
            check_type=ReadinessCheckType.MEMORY_AVAILABILITY,
            check_name="Memory Availability",
            passed=True,
            severity=ReadinessCheckSeverity.INFO,
            message=f"Sufficient memory available: {available_mb}MB",
            details={"available_mb": available_mb, "required_mb": REQUIRED_MEMORY_MB},
            check_duration_ms=duration_ms,
        )

    except Exception as e:
        duration_ms = (time.time() - start_time) * 1000
        return ReadinessCheckResult(
            check_type=ReadinessCheckType.MEMORY_AVAILABILITY,
            check_name="Memory Availability",
            passed=False,
            severity=ReadinessCheckSeverity.ERROR,
            message=f"Error checking memory: {str(e)}",
            details={"error": str(e)},
            check_duration_ms=duration_ms,
        )
