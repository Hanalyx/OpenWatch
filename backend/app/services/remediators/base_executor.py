"""
Base remediation executor interface for ORSA plugin architecture.

Defines the abstract interface that all remediation executors must implement.
Executors are responsible for executing remediation content (Ansible playbooks,
Bash scripts, Terraform modules, etc.) against target systems.
"""

from abc import ABC, abstractmethod
from typing import Dict, Optional, List
from enum import Enum
import logging

from backend.app.models.remediation_models import (
    RemediationTarget,
    RemediationExecutionResult,
)


logger = logging.getLogger(__name__)


class ExecutorCapability(str, Enum):
    """Capabilities that an executor may support."""

    DRY_RUN = "dry_run"
    ROLLBACK = "rollback"
    IDEMPOTENT = "idempotent"
    VARIABLE_SUBSTITUTION = "variable_substitution"
    REMOTE_EXECUTION = "remote_execution"
    PARALLEL_EXECUTION = "parallel_execution"


class RemediationExecutorError(Exception):
    """Base exception for remediation executor errors."""

    pass


class ExecutorNotAvailableError(RemediationExecutorError):
    """Executor binary/tool not available on system."""

    pass


class ExecutorValidationError(RemediationExecutorError):
    """Remediation content failed validation."""

    pass


class ExecutorExecutionError(RemediationExecutorError):
    """Error during remediation execution."""

    pass


class UnsupportedTargetError(RemediationExecutorError):
    """Target type not supported by this executor."""

    pass


class BaseRemediationExecutor(ABC):
    """
    Abstract base class for remediation executors.

    All remediation executors (Ansible, Bash, Terraform, etc.) must inherit
    from this class and implement the abstract methods.

    Attributes:
        executor_name: Name of the executor (e.g., 'ansible', 'bash')
        version: Version of the underlying tool
        capabilities: Set of capabilities this executor supports
    """

    def __init__(self, executor_name: str):
        """
        Initialize base executor.

        Args:
            executor_name: Name identifier for this executor
        """
        self.executor_name = executor_name
        self.version = self._get_version()
        self.capabilities = self._get_capabilities()
        self.logger = logging.getLogger(f"{__name__}.{executor_name}")

    @abstractmethod
    def _get_version(self) -> str:
        """
        Get version of the underlying tool.

        Returns:
            Version string (e.g., '2.14.3' for Ansible)

        Raises:
            ExecutorNotAvailableError: If tool not installed
        """
        pass

    @abstractmethod
    def _get_capabilities(self) -> set[ExecutorCapability]:
        """
        Get set of capabilities this executor supports.

        Returns:
            Set of ExecutorCapability enum values
        """
        pass

    @abstractmethod
    async def execute(
        self,
        content: str,
        target: RemediationTarget,
        variables: Dict[str, str],
        dry_run: bool = False,
        timeout_seconds: int = 300,
    ) -> RemediationExecutionResult:
        """
        Execute remediation content against target.

        Args:
            content: Remediation content (playbook YAML, bash script, etc.)
            target: Target system to remediate
            variables: Variable values to substitute/apply
            dry_run: If True, preview changes without applying
            timeout_seconds: Execution timeout

        Returns:
            RemediationExecutionResult with execution details

        Raises:
            ExecutorValidationError: Content validation failed
            ExecutorExecutionError: Execution failed
            UnsupportedTargetError: Target type not supported
            TimeoutError: Execution exceeded timeout
        """
        pass

    @abstractmethod
    async def rollback(
        self,
        remediation_id: str,
        rollback_content: str,
        target: RemediationTarget,
        timeout_seconds: int = 300,
    ) -> RemediationExecutionResult:
        """
        Execute rollback remediation.

        Args:
            remediation_id: ID of original remediation to rollback
            rollback_content: Rollback remediation content
            target: Target system (must match original)
            timeout_seconds: Execution timeout

        Returns:
            RemediationExecutionResult with rollback details

        Raises:
            ExecutorValidationError: Rollback content invalid
            ExecutorExecutionError: Rollback execution failed
        """
        pass

    @abstractmethod
    def validate_content(self, content: str) -> bool:
        """
        Validate remediation content syntax/structure.

        Args:
            content: Remediation content to validate

        Returns:
            True if valid

        Raises:
            ExecutorValidationError: Content validation failed
        """
        pass

    @abstractmethod
    def supports_target(self, target_type: str) -> bool:
        """
        Check if this executor supports the target type.

        Args:
            target_type: ScanTargetType value

        Returns:
            True if target type supported
        """
        pass

    def has_capability(self, capability: ExecutorCapability) -> bool:
        """
        Check if executor has a specific capability.

        Args:
            capability: Capability to check

        Returns:
            True if capability supported
        """
        return capability in self.capabilities

    def _substitute_variables(self, content: str, variables: Dict[str, str]) -> str:
        """
        Perform variable substitution in content.

        Default implementation replaces {{variable_name}} patterns.
        Executors may override for custom substitution logic.

        Args:
            content: Content with variable placeholders
            variables: Variable name -> value mapping

        Returns:
            Content with variables substituted
        """
        result = content
        for var_name, var_value in variables.items():
            # Replace {{var_name}} and ${var_name} patterns
            result = result.replace(f"{{{{{var_name}}}}}", var_value)
            result = result.replace(f"${{{var_name}}}", var_value)
        return result

    def _extract_changes(self, stdout: str) -> List[str]:
        """
        Extract list of changes from execution output.

        Used for rollback tracking. Executors should override with
        executor-specific parsing logic.

        Args:
            stdout: Execution stdout

        Returns:
            List of change descriptions
        """
        # Default: return empty list
        # Subclasses override to parse executor-specific output
        return []

    def _generate_rollback_content(
        self, original_content: str, execution_result: RemediationExecutionResult
    ) -> Optional[str]:
        """
        Generate rollback content from original remediation and execution result.

        Args:
            original_content: Original remediation content
            execution_result: Result of executing original remediation

        Returns:
            Rollback content, or None if rollback not possible
        """
        # Default: no automatic rollback generation
        # Executors may override to implement intelligent rollback
        return None

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit - cleanup resources."""
        pass


class ExecutorMetadata:
    """
    Metadata about a remediation executor.

    Used for executor discovery and capability reporting.
    """

    def __init__(
        self,
        name: str,
        display_name: str,
        description: str,
        capabilities: set[ExecutorCapability],
        supported_targets: List[str],
        version: str,
        available: bool = True,
    ):
        self.name = name
        self.display_name = display_name
        self.description = description
        self.capabilities = capabilities
        self.supported_targets = supported_targets
        self.version = version
        self.available = available

    def to_dict(self) -> Dict:
        """Convert to dictionary for API responses."""
        return {
            "name": self.name,
            "display_name": self.display_name,
            "description": self.description,
            "capabilities": [cap.value for cap in self.capabilities],
            "supported_targets": self.supported_targets,
            "version": self.version,
            "available": self.available,
        }
