"""
ORSA (OpenWatch Remediation and Security Automation) remediation executor factory.

Provides factory pattern for instantiating remediation executors and discovering
available executor capabilities.
"""

from typing import Dict, List, Type

from .ansible_executor import AnsibleExecutor
from .base_executor import BaseRemediationExecutor, ExecutorMetadata, ExecutorNotAvailableError
from .bash_executor import BashExecutor


class RemediationExecutorFactory:
    """
    Factory for creating remediation executors.

    Manages executor registry and provides methods for:
    - Instantiating executors by type
    - Discovering available executors
    - Querying executor capabilities
    """

    # Registry of executor types
    _executors: Dict[str, Type[BaseRemediationExecutor]] = {
        "ansible": AnsibleExecutor,
        "bash": BashExecutor,
        # Future executors:
        # 'terraform': TerraformExecutor,
        # 'kubernetes': KubernetesExecutor,
        # 'python': PythonExecutor,
    }

    @classmethod
    def get_executor(cls, executor_type: str) -> BaseRemediationExecutor:
        """
        Get executor instance by type.

        Args:
            executor_type: Executor type name (ansible, bash, etc.)

        Returns:
            Executor instance

        Raises:
            ValueError: Unknown executor type
            ExecutorNotAvailableError: Executor tool not available
        """
        executor_class = cls._executors.get(executor_type)

        if not executor_class:
            raise ValueError(
                f"Unknown executor type: {executor_type}. " f"Available: {', '.join(cls._executors.keys())}"
            )

        # Instantiate executor (may raise ExecutorNotAvailableError)
        return executor_class()

    @classmethod
    def register_executor(cls, executor_type: str, executor_class: Type[BaseRemediationExecutor]):
        """
        Register a custom executor type.

        Allows runtime registration of new executor types (e.g., plugins).

        Args:
            executor_type: Executor type name
            executor_class: Executor class (must inherit from BaseRemediationExecutor)

        Raises:
            TypeError: executor_class not a BaseRemediationExecutor subclass
        """
        if not issubclass(executor_class, BaseRemediationExecutor):
            raise TypeError("Executor class must inherit from BaseRemediationExecutor")

        cls._executors[executor_type] = executor_class

    @classmethod
    def list_executors(cls, available_only: bool = False) -> List[str]:
        """
        List registered executor types.

        Args:
            available_only: If True, only return executors with available tools

        Returns:
            List of executor type names
        """
        if not available_only:
            return list(cls._executors.keys())

        # Check availability
        available = []
        for executor_type in cls._executors.keys():
            try:
                cls.get_executor(executor_type)
                available.append(executor_type)
            except ExecutorNotAvailableError:
                pass

        return available

    @classmethod
    def get_executor_metadata(cls, executor_type: str) -> ExecutorMetadata:
        """
        Get metadata about an executor.

        Args:
            executor_type: Executor type name

        Returns:
            ExecutorMetadata with capabilities and version info

        Raises:
            ValueError: Unknown executor type
        """
        try:
            executor = cls.get_executor(executor_type)

            # Get metadata from executor
            metadata = ExecutorMetadata(
                name=executor.executor_name,
                display_name=executor.executor_name.capitalize(),
                description=executor.__class__.__doc__ or "",
                capabilities=executor.capabilities,
                supported_targets=[],  # Executor doesn't track this by default
                version=executor.version,
                available=True,
            )

            return metadata

        except ExecutorNotAvailableError:
            # Return metadata with available=False
            executor_class = cls._executors.get(executor_type)
            return ExecutorMetadata(
                name=executor_type,
                display_name=executor_type.capitalize(),
                description=executor_class.__doc__ if executor_class else "",
                capabilities=set(),
                supported_targets=[],
                version="N/A",
                available=False,
            )

    @classmethod
    def get_all_executor_metadata(cls) -> List[ExecutorMetadata]:
        """
        Get metadata for all registered executors.

        Returns:
            List of ExecutorMetadata objects
        """
        metadata_list = []
        for executor_type in cls._executors.keys():
            metadata = cls.get_executor_metadata(executor_type)
            metadata_list.append(metadata)

        return metadata_list


# Convenience functions


def get_executor(executor_type: str) -> BaseRemediationExecutor:
    """
    Get executor instance (convenience function).

    Args:
        executor_type: Executor type name

    Returns:
        Executor instance
    """
    return RemediationExecutorFactory.get_executor(executor_type)


def list_available_executors() -> List[str]:
    """
    List available executor types (convenience function).

    Returns:
        List of executor type names
    """
    return RemediationExecutorFactory.list_executors(available_only=True)


__all__ = [
    "RemediationExecutorFactory",
    "get_executor",
    "list_available_executors",
    "BaseRemediationExecutor",
    "AnsibleExecutor",
    "BashExecutor",
    "ExecutorMetadata",
]
