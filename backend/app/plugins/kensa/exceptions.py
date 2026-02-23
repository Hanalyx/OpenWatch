"""
Kensa Plugin Exceptions

Defines exception hierarchy for Kensa plugin operations.
All exceptions inherit from KensaError for easy catching.
"""

from typing import Any, Dict, List, Optional


class KensaError(Exception):
    """
    Base exception for all Kensa plugin errors.

    All Kensa-specific exceptions inherit from this class,
    allowing callers to catch all Kensa errors with a single handler.
    """

    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Initialize Kensa error.

        Args:
            message: Human-readable error message.
            details: Optional dictionary of additional error details.
        """
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for JSON serialization."""
        return {
            "error_type": self.__class__.__name__,
            "message": self.message,
            "details": self.details,
        }


class KensaRuleLoadError(KensaError):
    """
    Error loading Kensa rules from YAML files.

    Raised when rule files are missing, malformed, or fail validation.
    """

    def __init__(
        self,
        path: str,
        detail: str,
        rule_id: Optional[str] = None,
    ) -> None:
        """
        Initialize rule load error.

        Args:
            path: Path to the rule file that failed to load.
            detail: Description of the error.
            rule_id: Optional rule ID if known.
        """
        self.path = path
        self.rule_id = rule_id

        message = f"Failed to load rule from {path}: {detail}"
        super().__init__(
            message=message,
            details={
                "path": path,
                "detail": detail,
                "rule_id": rule_id,
            },
        )


class KensaConnectionError(KensaError):
    """
    Error connecting to target host via SSH.

    Raised when SSH connection fails due to network issues,
    authentication failures, or host key problems.
    """

    def __init__(
        self,
        host: str,
        detail: str,
        port: int = 22,
        username: Optional[str] = None,
    ) -> None:
        """
        Initialize connection error.

        Args:
            host: Target hostname or IP.
            detail: Description of the connection failure.
            port: SSH port (default 22).
            username: SSH username if available.
        """
        self.host = host
        self.port = port
        self.username = username

        message = f"Cannot connect to {host}:{port}: {detail}"
        super().__init__(
            message=message,
            details={
                "host": host,
                "port": port,
                "username": username,
                "detail": detail,
            },
        )


class KensaCapabilityError(KensaError):
    """
    Error detecting host capabilities.

    Raised when capability detection fails or returns unexpected results.
    """

    def __init__(
        self,
        host: str,
        detail: str,
        failed_probes: Optional[List[str]] = None,
    ) -> None:
        """
        Initialize capability error.

        Args:
            host: Target hostname.
            detail: Description of the capability detection failure.
            failed_probes: List of capability probes that failed.
        """
        self.host = host
        self.failed_probes = failed_probes or []

        message = f"Capability detection failed for {host}: {detail}"
        super().__init__(
            message=message,
            details={
                "host": host,
                "detail": detail,
                "failed_probes": self.failed_probes,
            },
        )


class KensaExecutionError(KensaError):
    """
    Error during rule check or remediation execution.

    Raised when a check or remediation command fails on the target host.
    """

    def __init__(
        self,
        rule_id: str,
        operation: str,
        detail: str,
        exit_code: Optional[int] = None,
        stdout: Optional[str] = None,
        stderr: Optional[str] = None,
    ) -> None:
        """
        Initialize execution error.

        Args:
            rule_id: Rule being executed.
            operation: Operation type ("check" or "remediate").
            detail: Description of the failure.
            exit_code: Command exit code if available.
            stdout: Command stdout if available.
            stderr: Command stderr if available.
        """
        self.rule_id = rule_id
        self.operation = operation
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr

        message = f"Rule {rule_id} {operation} failed: {detail}"
        super().__init__(
            message=message,
            details={
                "rule_id": rule_id,
                "operation": operation,
                "detail": detail,
                "exit_code": exit_code,
                "stdout": stdout,
                "stderr": stderr,
            },
        )


class KensaLicenseError(KensaError):
    """
    Error due to missing or invalid license.

    Raised when attempting to use licensed features (remediation, rollback)
    without a valid OpenWatch+ subscription.
    """

    def __init__(
        self,
        feature: str,
        detail: Optional[str] = None,
    ) -> None:
        """
        Initialize license error.

        Args:
            feature: Feature requiring license (e.g., "remediation", "rollback").
            detail: Additional detail about the license requirement.
        """
        self.feature = feature

        message = f"Feature '{feature}' requires OpenWatch+ subscription"
        if detail:
            message = f"{message}: {detail}"

        super().__init__(
            message=message,
            details={
                "feature": feature,
                "detail": detail,
                "upgrade_url": "/settings/license/upgrade",
            },
        )


class KensaConflictError(KensaError):
    """
    Conflicting rules detected.

    Raised when rules with conflicting requirements are selected together.
    """

    def __init__(
        self,
        conflicts: List[Dict[str, str]],
    ) -> None:
        """
        Initialize conflict error.

        Args:
            conflicts: List of conflict descriptions with rule IDs.
        """
        self.conflicts = conflicts

        conflict_strs = [f"{c.get('rule_a')} conflicts with {c.get('rule_b')}" for c in conflicts]
        message = f"Conflicting rules detected: {', '.join(conflict_strs)}"

        super().__init__(
            message=message,
            details={"conflicts": conflicts},
        )


class KensaRollbackError(KensaError):
    """
    Error during rollback operation.

    Raised when rollback of a remediation fails.
    """

    def __init__(
        self,
        job_id: str,
        detail: str,
        partial_rollback: bool = False,
        rolled_back_rules: Optional[List[str]] = None,
        failed_rules: Optional[List[str]] = None,
    ) -> None:
        """
        Initialize rollback error.

        Args:
            job_id: Remediation job ID being rolled back.
            detail: Description of the rollback failure.
            partial_rollback: True if some rules were rolled back.
            rolled_back_rules: Rules successfully rolled back.
            failed_rules: Rules that failed to roll back.
        """
        self.job_id = job_id
        self.partial_rollback = partial_rollback
        self.rolled_back_rules = rolled_back_rules or []
        self.failed_rules = failed_rules or []

        message = f"Rollback failed for job {job_id}: {detail}"
        if partial_rollback:
            succeeded = len(self.rolled_back_rules)
            failed = len(self.failed_rules)
            message = f"{message} (partial rollback: {succeeded} succeeded, {failed} failed)"

        super().__init__(
            message=message,
            details={
                "job_id": job_id,
                "detail": detail,
                "partial_rollback": partial_rollback,
                "rolled_back_rules": self.rolled_back_rules,
                "failed_rules": self.failed_rules,
            },
        )


class KensaUpdateError(KensaError):
    """
    Error during Kensa update.

    Raised when checking for or applying Kensa updates fails.
    """

    def __init__(
        self,
        operation: str,
        detail: str,
        current_version: Optional[str] = None,
        target_version: Optional[str] = None,
    ) -> None:
        """
        Initialize update error.

        Args:
            operation: Update operation that failed.
            detail: Description of the failure.
            current_version: Current Kensa version if known.
            target_version: Target version being updated to.
        """
        self.operation = operation
        self.current_version = current_version
        self.target_version = target_version

        message = f"Kensa update {operation} failed: {detail}"

        super().__init__(
            message=message,
            details={
                "operation": operation,
                "detail": detail,
                "current_version": current_version,
                "target_version": target_version,
            },
        )
