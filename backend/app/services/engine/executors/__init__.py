"""
Engine Executors Module

This module provides execution backends for running compliance scans
across different transport mechanisms (SSH, local, agent-based).

Executors are responsible for:
- Establishing connections to target systems
- Transferring SCAP content files
- Executing scanner commands
- Retrieving result files
- Cleanup after execution

Available Executors:
- BaseExecutor: Abstract base class defining the executor interface
- SSHExecutor: Remote execution via SSH (Paramiko-based)
- LocalExecutor: Local execution on the same host

Usage:
    from app.services.engine.executors import (
        SSHExecutor,
        LocalExecutor,
        get_executor,
    )

    # Get executor based on execution mode
    executor = get_executor(ExecutionMode.SSH, db=db)

    # Execute scan
    result = executor.execute(
        context=execution_context,
        content_path=Path("/path/to/xccdf.xml"),
        profile_id="xccdf_org.ssgproject.content_profile_stig",
        credential_data=credentials
    )

Architecture Notes:
- All executors implement the same interface (BaseExecutor)
- Executors are stateless (connection state is transient)
- Credential handling is delegated to the SSH module
- Error handling produces executor-specific exception types
"""

import logging
from typing import Optional

from sqlalchemy.orm import Session

from ..models import ExecutionMode

logger = logging.getLogger(__name__)

# Import executor implementations (re-exported for public API)
# These are imported after the module docstring to avoid circular imports
from .base import BaseExecutor  # noqa: F401, E402
from .local import LocalExecutor  # noqa: F401, E402
from .ssh import SSHExecutor  # noqa: F401, E402


def get_executor(
    mode: ExecutionMode,
    db: Optional[Session] = None,
) -> BaseExecutor:
    """
    Factory function to get the appropriate executor for an execution mode.

    This is the recommended way to obtain executor instances, as it handles
    dependency injection and configuration automatically.

    Args:
        mode: The execution mode determining which executor to use.
        db: Database session (required for SSH executor).

    Returns:
        Configured executor instance ready for use.

    Raises:
        ValueError: If mode is not supported or required dependencies missing.

    Usage:
        >>> executor = get_executor(ExecutionMode.SSH, db=session)
        >>> result = executor.execute(context, content_path, profile_id, creds)

    Note:
        - SSH executor requires a database session for credential resolution
        - Local executor can work without database session
        - Agent executor is planned for future implementation
    """
    if mode == ExecutionMode.SSH:
        if db is None:
            raise ValueError("SSH executor requires a database session")
        return SSHExecutor(db)

    elif mode == ExecutionMode.LOCAL:
        return LocalExecutor()

    elif mode == ExecutionMode.AGENT:
        # Agent mode is planned for future implementation
        raise NotImplementedError("Agent executor is not yet implemented. " "Use SSH or LOCAL mode for now.")

    else:
        raise ValueError(f"Unsupported execution mode: {mode}")


# Public API exports
__all__ = [
    # Base class
    "BaseExecutor",
    # Executor implementations
    "SSHExecutor",
    "LocalExecutor",
    # Factory function
    "get_executor",
]
