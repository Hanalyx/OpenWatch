"""
Sudo Access Check

Verifies passwordless sudo access for SCAP scanning.  # pragma: allowlist secret
Many compliance checks require root privileges.
"""

import logging
import time
from typing import Optional

from backend.app.models.readiness_models import ReadinessCheckResult, ReadinessCheckSeverity, ReadinessCheckType

logger = logging.getLogger(__name__)


async def check_sudo_access(
    host, credentials, ssh_service, user_id: Optional[str] = None
) -> ReadinessCheckResult:  # pragma: allowlist secret
    """
    Check if user has passwordless sudo access.  # pragma: allowlist secret

    Args:
        host: Host model instance
        credentials: Decrypted credentials  # pragma: allowlist secret
        ssh_service: UnifiedSSHService instance
        user_id: Optional user ID for audit logging

    Returns:
        ReadinessCheckResult with pass/fail status
    """
    start_time = time.time()

    try:
        # Test sudo without password  # pragma: allowlist secret
        result = await ssh_service.execute_command(
            host=host,
            credentials=credentials,  # pragma: allowlist secret
            command="sudo -n whoami",
            timeout=10,
        )

        duration_ms = (time.time() - start_time) * 1000

        if result.exit_code != 0:
            return ReadinessCheckResult(
                check_type=ReadinessCheckType.SUDO_ACCESS,
                check_name="Sudo Access",
                passed=False,
                severity=ReadinessCheckSeverity.WARNING,
                message="Passwordless sudo not configured",  # pragma: allowlist secret
                details={
                    "remediation": "Configure passwordless sudo:\n"  # pragma: allowlist secret
                    "  1. Run: sudo visudo\n"
                    "  2. Add: username ALL=(ALL) NOPASSWD:ALL\n"
                    "  3. Or use specific commands only",
                    "impact": "MEDIUM - Some compliance checks may fail without sudo",
                },
                check_duration_ms=duration_ms,
            )

        return ReadinessCheckResult(
            check_type=ReadinessCheckType.SUDO_ACCESS,
            check_name="Sudo Access",
            passed=True,
            severity=ReadinessCheckSeverity.INFO,
            message="Passwordless sudo access configured",  # pragma: allowlist secret
            details={"sudo_user": result.stdout.strip()},
            check_duration_ms=duration_ms,
        )

    except Exception as e:
        duration_ms = (time.time() - start_time) * 1000
        return ReadinessCheckResult(
            check_type=ReadinessCheckType.SUDO_ACCESS,
            check_name="Sudo Access",
            passed=False,
            severity=ReadinessCheckSeverity.ERROR,
            message=f"Error checking sudo access: {str(e)}",
            details={"error": str(e)},
            check_duration_ms=duration_ms,
        )
