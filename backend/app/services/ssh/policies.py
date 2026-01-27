"""
SSH Host Key Policies

Provides configurable host key verification policies for different security
requirements and automation environments. These policies control how OpenWatch
handles unknown or changed SSH host keys when connecting to target systems.

Available Policies:
- SecurityWarningPolicy: Logs warnings but allows connections (recommended)
- Strict (RejectPolicy): Rejects unknown hosts (high security)
- AutoAdd (AutoAddPolicy): Silently accepts all hosts (development only)

Security Considerations:
- SecurityWarningPolicy balances automation needs with security auditing
- All policy decisions are logged for audit trail compliance
- Host key fingerprints are recorded for later verification
- Production environments should use SecurityWarningPolicy or stricter

Usage:
    from backend.app.services.ssh.policies import SecurityWarningPolicy

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(SecurityWarningPolicy())
    client.connect(hostname, username=user, password=passwd)

References:
- NIST SP 800-53 SC-8: Transmission Confidentiality and Integrity
- NIST SP 800-53 SC-23: Session Authenticity
- Ansible host key checking: https://docs.ansible.com/ansible/latest/reference_appendices/config.html#host-key-checking
"""

import logging
from typing import Callable, Optional

import paramiko
from paramiko import SSHClient

logger = logging.getLogger(__name__)


class SecurityWarningPolicy(paramiko.MissingHostKeyPolicy):
    """
    Secure middle-ground SSH host key policy for automation environments.

    This policy logs security warnings for unknown hosts but allows connections
    to proceed. It balances security (full audit trail) with operational
    requirements (automation doesn't fail on new hosts).

    This approach is similar to Ansible's default behavior and is appropriate
    for environments where:
    - Hosts are dynamically provisioned
    - Strict host key verification would break automation
    - Audit logging is required for compliance

    Attributes:
        audit_callback: Optional function to call for custom audit logging

    Security Features:
        - Logs host key fingerprint for every unknown host
        - Records key type (RSA, Ed25519, etc.) for security analysis
        - Stores key in session for consistent verification during session
        - Supports custom audit callbacks for SIEM integration

    Example:
        >>> def my_audit_callback(hostname, key_type, fingerprint):
        ...     siem.log_event("ssh_unknown_host", hostname=hostname)
        ...
        >>> policy = SecurityWarningPolicy(audit_callback=my_audit_callback)
        >>> client.set_missing_host_key_policy(policy)
    """

    def __init__(self, audit_callback: Optional[Callable[[str, str, str], None]] = None) -> None:
        """
        Initialize policy with optional audit callback.

        Args:
            audit_callback: Optional function called with (hostname, key_type, fingerprint)
                           when an unknown host key is encountered. Use this to integrate
                           with external audit/SIEM systems.
        """
        self.audit_callback = audit_callback

    def missing_host_key(self, client: SSHClient, hostname: str, key: paramiko.PKey) -> None:
        """
        Handle missing host key by logging warning and storing key.

        This method is called by paramiko when connecting to a host whose
        key is not in the known_hosts file. Instead of rejecting the
        connection (like RejectPolicy) or silently accepting (like
        AutoAddPolicy), we log a warning and allow the connection.

        Args:
            client: The paramiko SSHClient instance
            hostname: Target hostname or IP address
            key: The SSH host key presented by the remote server

        Security Notes:
            - Warning is logged to 'openwatch.audit' for compliance
            - Key fingerprint is included for forensic analysis
            - Key is stored in session to detect mid-session key changes
        """
        # Extract key fingerprint and type with defensive error handling
        # Paramiko key operations can fail in edge cases (malformed keys)
        try:
            fingerprint = key.get_fingerprint().hex()
            key_type = key.get_name()
        except Exception:
            # If we cannot get key details, use placeholder values
            # This should rarely happen but prevents connection failures
            fingerprint = "unknown"
            key_type = "unknown"

        # Log security warning with audit-friendly format
        # Using structured format for log parsing and SIEM ingestion
        try:
            logger.warning(
                "SSH_SECURITY_WARNING: Unknown host key for %s "
                "(type: %s, fingerprint: %s). "
                "Connection allowed but logged for audit.",
                hostname,
                key_type,
                fingerprint,
            )
        except Exception:
            # Logging failures should never prevent connections
            # This handles edge cases like log file permission issues
            pass

        # Call custom audit callback if provided
        # This allows integration with external security monitoring
        if self.audit_callback:
            try:
                self.audit_callback(hostname, key_type, fingerprint)
            except Exception:
                # Callback failures should not prevent connections
                # The warning log above provides the audit trail
                pass

        # Store key for this session to detect mid-session key changes
        # This provides defense-in-depth against MITM attacks
        try:
            client.get_host_keys().add(hostname, key.get_name(), key)
        except Exception:
            # Host key storage failures should not prevent connections
            # The connection will still work, just without session key caching
            pass


class StrictHostKeyPolicy(paramiko.RejectPolicy):
    """
    Strict host key policy that rejects unknown hosts with logging.

    Extends paramiko's RejectPolicy to add audit logging before rejection.
    Use this policy in high-security environments where unknown hosts
    should never be connected to automatically.

    Example:
        >>> client.set_missing_host_key_policy(StrictHostKeyPolicy())
        >>> try:
        ...     client.connect(hostname)  # Will fail if host unknown
        ... except paramiko.SSHException:
        ...     print("Unknown host rejected")
    """

    def missing_host_key(self, client: SSHClient, hostname: str, key: paramiko.PKey) -> None:
        """
        Reject unknown host key with audit logging.

        Args:
            client: The paramiko SSHClient instance
            hostname: Target hostname or IP address
            key: The SSH host key presented by the remote server

        Raises:
            paramiko.SSHException: Always raised to reject the connection
        """
        # Extract key details for logging before rejection
        try:
            fingerprint = key.get_fingerprint().hex()
            key_type = key.get_name()
        except Exception:
            fingerprint = "unknown"
            key_type = "unknown"

        # Log the rejection for audit compliance
        logger.warning(
            "SSH_STRICT_REJECTION: Rejecting unknown host key for %s "
            "(type: %s, fingerprint: %s). Connection denied by policy.",
            hostname,
            key_type,
            fingerprint,
        )

        # Call parent to raise the rejection exception
        super().missing_host_key(client, hostname, key)


def create_host_key_policy(
    policy_type: str,
    audit_callback: Optional[Callable[[str, str, str], None]] = None,
) -> paramiko.MissingHostKeyPolicy:
    """
    Factory function to create host key policy by name.

    This function provides a consistent interface for creating host key
    policies based on configuration settings.

    Args:
        policy_type: Policy type name. One of:
            - "strict": Reject unknown hosts (StrictHostKeyPolicy)
            - "auto_add": Accept all hosts silently (AutoAddPolicy)
            - "auto_add_warning": Accept with warning (SecurityWarningPolicy)
            - "warning": Alias for "auto_add_warning"
        audit_callback: Optional callback for SecurityWarningPolicy

    Returns:
        Configured paramiko.MissingHostKeyPolicy instance

    Raises:
        ValueError: If policy_type is not recognized

    Example:
        >>> policy = create_host_key_policy("auto_add_warning")
        >>> client.set_missing_host_key_policy(policy)
    """
    policy_type_lower = policy_type.lower().strip()

    if policy_type_lower == "strict":
        return StrictHostKeyPolicy()

    elif policy_type_lower == "auto_add":
        return paramiko.AutoAddPolicy()

    elif policy_type_lower in ("auto_add_warning", "warning"):
        return SecurityWarningPolicy(audit_callback=audit_callback)

    else:
        # Provide helpful error message with valid options
        valid_options = ["strict", "auto_add", "auto_add_warning", "warning"]
        raise ValueError(f"Unknown host key policy type: {policy_type!r}. " f"Valid options: {valid_options}")


__all__ = [
    "SecurityWarningPolicy",
    "StrictHostKeyPolicy",
    "create_host_key_policy",
]
