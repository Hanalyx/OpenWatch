"""
Plugin Execution Subpackage

Provides secure, sandboxed execution of imported plugins across different
execution environments (shell, Python, Ansible, API).

Components:
    - PluginExecutionService: Main service for plugin execution orchestration

Security Features:
    - Isolated execution environments (temp directories per execution)
    - Command sandboxing via CommandSandbox wrapper
    - Resource limits (timeout, memory) enforcement
    - Platform validation before execution
    - Audit logging of all execution attempts

Usage:
    from app.services.plugins.execution import PluginExecutionService

    executor = PluginExecutionService()
    result = await executor.execute_plugin(request)

Example:
    >>> from app.services.plugins.execution import PluginExecutionService
    >>> executor = PluginExecutionService()
    >>> result = await executor.execute_plugin(
    ...     PluginExecutionRequest(
    ...         plugin_id="my-plugin@1.0.0",
    ...         host_id="host-123",
    ...         platform="rhel8",
    ...     )
    ... )
    >>> print(result.status)  # "success" or "failure" or "error"
"""

from .service import PluginExecutionService

__all__ = [
    "PluginExecutionService",
]
