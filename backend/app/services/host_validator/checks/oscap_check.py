"""
OSCAP Installation Check

Verifies that OpenSCAP scanner is installed and accessible on target host.
This is a CRITICAL check - without oscap, compliance scans cannot run.

Security: Uses SSHConnectionContext for efficient SSH connection reuse.
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


async def check_oscap_installation(
    host, ssh_context: "SSHConnectionContext", user_id: Optional[str] = None
) -> ReadinessCheckResult:
    """
    Check if oscap command is installed and get version.

    This is the MOST CRITICAL readiness check. Without oscap, SCAP scans
    cannot execute on the target host.

    Args:
        host: Host model instance
        ssh_context: Active SSH connection context (reuses existing connection)
        user_id: Optional user ID for audit logging

    Returns:
        ReadinessCheckResult with pass/fail status and details

    Example:
        >>> async with SSHConnectionContext(...) as ssh_ctx:
        ...     result = await check_oscap_installation(host, ssh_ctx)
        ...     if not result.passed:
        ...         print(f"OSCAP missing: {result.message}")
        ...         print(f"Remediation: {result.details['remediation']}")
    """
    start_time = time.time()

    try:
        # Execute command using existing SSH connection (NO new connection created)
        result = await ssh_context.execute_command(
            command="which oscap && oscap --version | head -1",
            timeout=10,
        )

        duration_ms = (time.time() - start_time) * 1000

        # Check if command succeeded
        if result.exit_code != 0 or not result.stdout:
            logger.warning(
                f"OSCAP check failed for host {host.hostname}: not installed or not in PATH",
                extra={"host_id": str(host.id), "user_id": user_id},
            )

            return ReadinessCheckResult(
                check_type=ReadinessCheckType.OSCAP_INSTALLATION,
                check_name="OSCAP Installation",
                passed=False,
                severity=ReadinessCheckSeverity.ERROR,
                message="OSCAP scanner is not installed or not in PATH",
                details={
                    "exit_code": result.exit_code,
                    "stderr": result.stderr[:500] if result.stderr else None,
                    "remediation": "Install openscap-scanner package:\n"
                    "  RHEL/CentOS: sudo yum install openscap-scanner\n"
                    "  Ubuntu/Debian: sudo apt-get install libopenscap8\n"
                    "  Then verify: oscap --version",
                    "impact": "CRITICAL - Cannot run compliance scans without oscap",
                },
                check_duration_ms=duration_ms,
            )

        # Parse oscap version from output
        oscap_path = result.stdout.split("\n")[0].strip() if result.stdout else "unknown"
        oscap_version = (
            result.stdout.split("\n")[1].strip()
            if len(result.stdout.split("\n")) > 1
            else "unknown"
        )

        logger.info(
            f"OSCAP check passed for host {host.hostname}: {oscap_version}",
            extra={
                "host_id": str(host.id),
                "user_id": user_id,
                "oscap_version": oscap_version,
            },
        )

        return ReadinessCheckResult(
            check_type=ReadinessCheckType.OSCAP_INSTALLATION,
            check_name="OSCAP Installation",
            passed=True,
            severity=ReadinessCheckSeverity.INFO,
            message=f"OSCAP scanner is installed: {oscap_version}",
            details={
                "oscap_path": oscap_path,
                "oscap_version": oscap_version,
                "command_output": result.stdout[:500],
            },
            check_duration_ms=duration_ms,
        )

    except Exception as e:
        duration_ms = (time.time() - start_time) * 1000
        logger.error(
            f"OSCAP check error for host {host.hostname}: {str(e)}",
            extra={"host_id": str(host.id), "user_id": user_id},
            exc_info=True,
        )

        return ReadinessCheckResult(
            check_type=ReadinessCheckType.OSCAP_INSTALLATION,
            check_name="OSCAP Installation",
            passed=False,
            severity=ReadinessCheckSeverity.ERROR,
            message=f"Error checking OSCAP installation: {str(e)}",
            details={
                "error": str(e),
                "remediation": "Verify SSH connectivity and try again",
            },
            check_duration_ms=duration_ms,
        )
