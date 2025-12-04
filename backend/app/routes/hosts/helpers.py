"""
Host Management Helper Functions

This module contains utility functions for the hosts package,
including UUID validation, security helpers, and common operations.
"""

import logging
import uuid
from typing import Any, Dict, List

from fastapi import HTTPException, status

from ...utils.logging_security import sanitize_id_for_log

logger = logging.getLogger(__name__)


# =============================================================================
# UUID VALIDATION
# =============================================================================


def validate_host_uuid(host_id: str) -> uuid.UUID:
    """
    Validate and convert host ID string to UUID.

    This helper eliminates duplicate validation logic that was repeated across
    multiple endpoints. Follows DRY (Don't Repeat Yourself) principle from
    CLAUDE.md coding standards.

    Why this helper exists:
    - Reduces code duplication across all host-related endpoints
    - Ensures consistent error handling
    - Centralizes security logging for invalid UUIDs
    - Makes code more maintainable (one place to update logic)

    Args:
        host_id: String representation of host UUID from API request

    Returns:
        uuid.UUID: Validated UUID object

    Raises:
        HTTPException: 400 Bad Request if host_id is not a valid UUID format

    Example:
        >>> host_uuid = validate_host_uuid("550e8400-e29b-41d4-a716-446655440000")
        >>> assert isinstance(host_uuid, uuid.UUID)

        >>> validate_host_uuid("invalid-uuid")  # Raises HTTPException 400

    Security:
        - Logs sanitized ID for audit trail (uses sanitize_id_for_log)
        - Returns generic error message to client (no information disclosure)
        - Detailed error logged server-side for debugging
    """
    try:
        return uuid.UUID(host_id)
    except (ValueError, TypeError) as e:
        # Log detailed error server-side for debugging
        logger.error(f"Invalid host ID format: {sanitize_id_for_log(host_id)} - {type(e).__name__}")
        # Return generic error to client (security best practice)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid host ID format"
        )


# =============================================================================
# NETWORK DISCOVERY HELPERS
# =============================================================================


def calculate_connectivity_score(connectivity_tests: Dict[str, Any]) -> float:
    """
    Calculate connectivity score based on test results.

    Args:
        connectivity_tests: Dictionary of connectivity test results

    Returns:
        Float score between 0.0 and 1.0
    """
    if not connectivity_tests:
        return 0.0

    total_tests = len(connectivity_tests)
    successful_tests = sum(
        1 for test in connectivity_tests.values() if test.get("ping_success", False)
    )

    return successful_tests / total_tests if total_tests > 0 else 0.0


# =============================================================================
# COMPLIANCE ASSESSMENT HELPERS
# =============================================================================


def assess_scap_capability(openscap_tools: Dict[str, Any]) -> str:
    """
    Assess SCAP capability based on OpenSCAP tools availability.

    Args:
        openscap_tools: Dictionary of OpenSCAP tool discovery results

    Returns:
        Capability level: "full", "limited", or "none"
    """
    if any(tool.get("available") for tool in openscap_tools.values()):
        return "full"
    return "none"


def assess_python_capability(python_envs: Dict[str, Any]) -> str:
    """
    Assess Python capability based on discovered environments.

    Args:
        python_envs: Dictionary of Python environment discovery results

    Returns:
        Capability level: "available" or "none"
    """
    if python_envs:
        return "available"
    return "none"


def assess_privilege_escalation(privilege_tools: Dict[str, Any]) -> str:
    """
    Assess privilege escalation capability.

    Args:
        privilege_tools: Dictionary of privilege escalation tool discovery results

    Returns:
        Capability level: "available", "limited", or "none"
    """
    if privilege_tools.get("sudo", {}).get("available"):
        return "available"
    elif privilege_tools.get("su", {}).get("available"):
        return "limited"
    return "none"


def assess_audit_capability(audit_tools: Dict[str, Any]) -> str:
    """
    Assess audit capability based on available tools.

    Args:
        audit_tools: Dictionary of audit tool discovery results

    Returns:
        Capability level: "full", "partial", or "none"
    """
    audit_count = sum(1 for tool in audit_tools.values() if tool.get("available"))
    if audit_count >= 3:
        return "full"
    elif audit_count >= 1:
        return "partial"
    return "none"


def calculate_compliance_readiness_score(
    scap_capability: str,
    python_capability: str,
    privilege_escalation: str,
    audit_capability: str,
) -> float:
    """
    Calculate overall compliance readiness score.

    Args:
        scap_capability: SCAP capability level
        python_capability: Python capability level
        privilege_escalation: Privilege escalation capability level
        audit_capability: Audit capability level

    Returns:
        Float score between 0.0 and 1.0
    """
    score = 0.0

    if scap_capability == "full":
        score += 0.4
    if python_capability == "available":
        score += 0.2
    if privilege_escalation == "available":
        score += 0.2
    elif privilege_escalation == "limited":
        score += 0.1
    if audit_capability == "full":
        score += 0.2
    elif audit_capability == "partial":
        score += 0.1

    return score


def get_recommended_frameworks(scap_capability: str, audit_capability: str) -> List[str]:
    """
    Get recommended compliance frameworks based on capabilities.

    Args:
        scap_capability: SCAP capability level
        audit_capability: Audit capability level

    Returns:
        List of recommended framework names
    """
    recommended = []
    if scap_capability == "full":
        recommended.extend(["NIST 800-53", "DISA STIG", "CIS Controls"])
    if audit_capability in ["full", "partial"]:
        recommended.extend(["SOX", "HIPAA", "FISMA"])
    return list(set(recommended))


def get_missing_tools(
    scap_capability: str,
    python_capability: str,
    privilege_escalation: str,
    audit_capability: str,
) -> List[str]:
    """
    Get list of missing tools based on capabilities.

    Args:
        scap_capability: SCAP capability level
        python_capability: Python capability level
        privilege_escalation: Privilege escalation capability level
        audit_capability: Audit capability level

    Returns:
        List of missing tool names
    """
    missing = []
    if scap_capability == "none":
        missing.append("OpenSCAP")
    if python_capability == "none":
        missing.append("Python")
    if privilege_escalation == "none":
        missing.append("Sudo/Privilege Escalation")
    if audit_capability == "none":
        missing.append("Audit Tools")
    return missing
