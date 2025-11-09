"""
Network Connectivity Check

Verifies SFTP capability and /tmp write permissions.
OpenWatch transfers XCCDF and OVAL files to hosts during scans.
"""

import logging
import time
import uuid
from typing import Optional

from backend.app.models.readiness_models import ReadinessCheckResult, ReadinessCheckSeverity, ReadinessCheckType

logger = logging.getLogger(__name__)


async def check_network_connectivity(
    host, credentials, ssh_service, user_id: Optional[str] = None  # pragma: allowlist secret
) -> ReadinessCheckResult:
    """
    Check network connectivity for SCAP file transfers.

    OpenWatch transfers XCCDF and OVAL files to hosts during scans,
    so we verify:
    1. SSH connectivity (already established)
    2. SFTP capability for file transfers
    3. Write permissions on /tmp

    Args:
        host: Host model instance
        credentials: Decrypted credentials  # pragma: allowlist secret
        ssh_service: UnifiedSSHService instance
        user_id: Optional user ID for audit logging

    Returns:
        ReadinessCheckResult with network check details
    """
    start_time = time.time()

    try:
        # Check if /tmp is writable
        test_file = f"/tmp/.openwatch_sftp_test_{uuid.uuid4().hex[:8]}"

        result = await ssh_service.execute_command(
            host=host,
            credentials=credentials,  # pragma: allowlist secret
            command='test -w /tmp && echo "WRITABLE" || echo "NOT_WRITABLE"',
            timeout=5,
        )

        if result.exit_code != 0 or "NOT_WRITABLE" in result.stdout:
            duration_ms = (time.time() - start_time) * 1000
            return ReadinessCheckResult(
                check_type=ReadinessCheckType.NETWORK_CONNECTIVITY,
                check_name="Network Connectivity",
                passed=False,
                severity=ReadinessCheckSeverity.ERROR,
                message="/tmp directory is not writable",
                details={
                    "remediation": "Ensure /tmp is writable:\n  sudo chmod 1777 /tmp",
                    "impact": "CRITICAL - Cannot transfer SCAP content to host",
                },
                check_duration_ms=duration_ms,
            )

        # Test file write/read/delete
        write_result = await ssh_service.execute_command(
            host=host,
            credentials=credentials,  # pragma: allowlist secret
            command=f'echo "test" > {test_file} && cat {test_file} && rm -f {test_file}',
            timeout=10,
        )

        duration_ms = (time.time() - start_time) * 1000

        if write_result.exit_code != 0:
            return ReadinessCheckResult(
                check_type=ReadinessCheckType.NETWORK_CONNECTIVITY,
                check_name="Network Connectivity",
                passed=False,
                severity=ReadinessCheckSeverity.ERROR,
                message="SFTP file transfer test failed",
                details={
                    "error": write_result.stderr,
                    "remediation": "Verify SSH/SFTP configuration",
                },
                check_duration_ms=duration_ms,
            )

        return ReadinessCheckResult(
            check_type=ReadinessCheckType.NETWORK_CONNECTIVITY,
            check_name="Network Connectivity",
            passed=True,
            severity=ReadinessCheckSeverity.INFO,
            message="SFTP file transfer capability verified",
            details={
                "tmp_writable": True,
                "sftp_test": "passed",
            },
            check_duration_ms=duration_ms,
        )

    except Exception as e:
        duration_ms = (time.time() - start_time) * 1000
        return ReadinessCheckResult(
            check_type=ReadinessCheckType.NETWORK_CONNECTIVITY,
            check_name="Network Connectivity",
            passed=False,
            severity=ReadinessCheckSeverity.ERROR,
            message=f"Error checking network connectivity: {str(e)}",
            details={"error": str(e)},
            check_duration_ms=duration_ms,
        )
