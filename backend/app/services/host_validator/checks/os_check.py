"""
Operating System Check

Detects OS type and version to ensure compatibility with SCAP content.
"""

import logging
import time
from typing import TYPE_CHECKING, Optional

from backend.app.models.readiness_models import ReadinessCheckResult, ReadinessCheckSeverity, ReadinessCheckType

if TYPE_CHECKING:
    from backend.app.services.ssh_connection_context import SSHConnectionContext

logger = logging.getLogger(__name__)

# Supported OS families
SUPPORTED_OS = ["rhel", "centos", "ubuntu", "debian", "fedora", "rocky", "almalinux"]


async def check_operating_system(
    host, ssh_context: "SSHConnectionContext", user_id: Optional[str] = None
) -> ReadinessCheckResult:
    """
    Detect operating system type and version.

    Args:
        host: Host model instance
        ssh_context: Active SSH connection context (reuses existing connection)
        user_id: Optional user ID for audit logging

    Returns:
        ReadinessCheckResult with OS details
    """
    start_time = time.time()

    try:
        # Read /etc/os-release for OS detection using existing SSH connection
        result = await ssh_context.execute_command(
            command='cat /etc/os-release | grep -E "^(ID=|VERSION_ID=)" | tr "\\n" " "',
            timeout=10,
        )

        duration_ms = (time.time() - start_time) * 1000

        if result.exit_code != 0:
            return ReadinessCheckResult(
                check_type=ReadinessCheckType.OPERATING_SYSTEM,
                check_name="Operating System",
                passed=False,
                severity=ReadinessCheckSeverity.ERROR,
                message="Failed to detect operating system",
                details={"error": result.stderr},
                check_duration_ms=duration_ms,
            )

        # Parse OS info
        os_info = {}
        for line in result.stdout.split():
            if "=" in line:
                key, value = line.split("=", 1)
                os_info[key] = value.strip('"')

        os_id = os_info.get("ID", "unknown").lower()
        os_version = os_info.get("VERSION_ID", "unknown")

        # Check if OS is supported
        is_supported = any(supported in os_id for supported in SUPPORTED_OS)

        if not is_supported:
            return ReadinessCheckResult(
                check_type=ReadinessCheckType.OPERATING_SYSTEM,
                check_name="Operating System",
                passed=False,
                severity=ReadinessCheckSeverity.WARNING,
                message=f"Unsupported OS: {os_id} {os_version}",
                details={
                    "os_id": os_id,
                    "os_version": os_version,
                    "supported_os": SUPPORTED_OS,
                    "remediation": "SCAP content may not be available for this OS",
                },
                check_duration_ms=duration_ms,
            )

        return ReadinessCheckResult(
            check_type=ReadinessCheckType.OPERATING_SYSTEM,
            check_name="Operating System",
            passed=True,
            severity=ReadinessCheckSeverity.INFO,
            message=f"Detected OS: {os_id} {os_version}",
            details={"os_id": os_id, "os_version": os_version, "is_supported": True},
            check_duration_ms=duration_ms,
        )

    except Exception as e:
        duration_ms = (time.time() - start_time) * 1000
        return ReadinessCheckResult(
            check_type=ReadinessCheckType.OPERATING_SYSTEM,
            check_name="Operating System",
            passed=False,
            severity=ReadinessCheckSeverity.ERROR,
            message=f"Error detecting OS: {str(e)}",
            details={"error": str(e)},
            check_duration_ms=duration_ms,
        )
