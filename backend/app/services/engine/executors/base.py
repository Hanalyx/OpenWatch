"""
Base Executor Abstract Class

This module defines the abstract base class for all scan executors.
Executors are responsible for the transport and execution layer of
compliance scans, handling connection management, file transfer,
command execution, and result retrieval.

Design Philosophy:
- Single Responsibility: Executors only handle transport/execution
- Interface Segregation: Clear, minimal interface for implementations
- Dependency Injection: Dependencies passed via constructor
- Stateless Design: No persistent state between executions
- Security First: Credentials never stored, only passed transiently

Executor Lifecycle:
    1. Construction (with dependencies)
    2. validate_environment() - Verify execution prerequisites
    3. execute() - Run the scan
    4. Garbage collection (stateless, no cleanup needed)

Implementation Requirements:
- All abstract methods must be implemented
- execute() must be idempotent (safe to retry)
- Errors must use engine exception types
- Sensitive data must not be logged
"""

import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, List, Optional

from ..exceptions import ExecutorError  # noqa: F401
from ..models import ExecutionContext, ExecutionMode, FileTransferSpec, ScanResult, ScanStatus

logger = logging.getLogger(__name__)


class BaseExecutor(ABC):
    """
    Abstract base class for scan executors.

    Executors handle the transport and execution layer for compliance scans,
    abstracting away the details of how scans are run on target systems.

    Subclasses must implement:
    - execute(): Run a scan on the target system
    - validate_environment(): Check prerequisites for execution
    - get_execution_mode(): Return the executor's execution mode

    Usage:
        class MyExecutor(BaseExecutor):
            def execute(self, context, content_path, profile_id, credential_data):
                # Implementation here
                pass

        executor = MyExecutor()
        if executor.validate_environment():
            result = executor.execute(context, content_path, profile_id, creds)

    Attributes:
        name: Human-readable executor name for logging
        execution_mode: The execution mode this executor implements
    """

    def __init__(self, name: str = "BaseExecutor"):
        """
        Initialize the base executor.

        Args:
            name: Human-readable name for logging and debugging.
        """
        self.name = name
        self._logger = logging.getLogger(f"{__name__}.{name}")

    @property
    @abstractmethod
    def execution_mode(self) -> ExecutionMode:
        """
        Return the execution mode this executor implements.

        Returns:
            The ExecutionMode enum value for this executor.
        """

    @abstractmethod
    def execute(
        self,
        context: ExecutionContext,
        content_path: Path,
        profile_id: str,
        credential_data: Optional[object] = None,
        dependencies: Optional[List[object]] = None,
    ) -> ScanResult:
        """
        Execute a compliance scan on the target system.

        This is the primary method that subclasses must implement.
        It should handle the complete scan lifecycle including:
        1. Connection establishment (if remote)
        2. File transfer (if needed)
        3. Command execution
        4. Result retrieval
        5. Cleanup

        Args:
            context: Execution context with scan parameters.
            content_path: Path to the primary SCAP content file.
            profile_id: XCCDF profile ID to evaluate.
            credential_data: Credentials for authentication (executor-specific type).
            dependencies: Optional list of dependency files to transfer.

        Returns:
            ScanResult with execution outcome and file paths.

        Raises:
            ExecutorError: If execution fails for any reason.

        Note:
            - This method must be idempotent (safe to retry on failure)
            - Credentials must not be stored or logged
            - All exceptions should be wrapped in ExecutorError subclasses
        """

    @abstractmethod
    def validate_environment(self) -> bool:
        """
        Validate that the execution environment is ready.

        Checks prerequisites such as:
        - Required tools installed (oscap, ssh, etc.)
        - Network connectivity (for remote executors)
        - File system permissions
        - Configuration validity

        Returns:
            True if environment is valid, False otherwise.

        Note:
            This method should not raise exceptions. Instead, it should
            log warnings about specific validation failures and return False.
        """

    def build_result_paths(self, working_dir: Path, scan_id: str) -> Dict[str, Path]:
        """
        Build standardized file paths for scan results.

        Creates a consistent naming convention for result files:
        - {scan_id}_results.xml: XCCDF result file
        - {scan_id}_report.html: Human-readable HTML report
        - {scan_id}_arf.xml: Asset Reporting Format (optional)

        Args:
            working_dir: Directory where results will be stored.
            scan_id: Unique scan identifier.

        Returns:
            Dictionary mapping result type to file path.

        Usage:
            >>> paths = executor.build_result_paths(Path("/results"), "scan-123")
            >>> paths["xml"]
            Path('/results/scan-123_results.xml')
        """
        return {
            "xml": working_dir / f"{scan_id}_results.xml",
            "html": working_dir / f"{scan_id}_report.html",
            "arf": working_dir / f"{scan_id}_arf.xml",
        }

    def create_failed_result(
        self,
        context: ExecutionContext,
        error: Exception,
        execution_time: float = 0.0,
    ) -> ScanResult:
        """
        Create a ScanResult for a failed execution.

        Helper method to construct consistent failure results across
        all executor implementations.

        Args:
            context: Execution context for the failed scan.
            error: Exception that caused the failure.
            execution_time: Time elapsed before failure.

        Returns:
            ScanResult with failure status and error details.

        Usage:
            try:
                # Scan logic
            except Exception as e:
                return self.create_failed_result(context, e, elapsed_time)
        """
        error_message = str(error)

        # Truncate error message to prevent log bloat (security consideration)
        if len(error_message) > 1000:
            error_message = error_message[:997] + "..."

        return ScanResult(
            success=False,
            scan_id=context.scan_id,
            status=ScanStatus.FAILED,
            exit_code=-1,
            stdout="",
            stderr=error_message,
            execution_time_seconds=execution_time,
            error_message=error_message,
        )

    def log_execution_start(self, context: ExecutionContext) -> None:
        """
        Log the start of scan execution.

        Standardized logging for execution start across all executors.
        Does not log sensitive information.

        Args:
            context: Execution context being started.
        """
        self._logger.info(
            "Starting scan execution: scan_id=%s, type=%s, host=%s, mode=%s",
            context.scan_id,
            context.scan_type.value,
            context.hostname,
            self.execution_mode.value,
        )

    def log_execution_complete(self, context: ExecutionContext, result: ScanResult) -> None:
        """
        Log the completion of scan execution.

        Standardized logging for execution completion across all executors.

        Args:
            context: Execution context that completed.
            result: Result from the execution.
        """
        if result.success:
            self._logger.info(
                "Scan execution completed: scan_id=%s, status=%s, " "exit_code=%d, time=%.1fs",
                context.scan_id,
                result.status.value,
                result.exit_code,
                result.execution_time_seconds,
            )
        else:
            self._logger.error(
                "Scan execution failed: scan_id=%s, status=%s, error=%s",
                context.scan_id,
                result.status.value,
                result.error_message[:200] if result.error_message else "Unknown",
            )

    def prepare_file_transfers(
        self,
        content_path: Path,
        dependencies: Optional[List[object]] = None,
        remote_dir: str = "/tmp",
    ) -> List[FileTransferSpec]:
        """
        Prepare file transfer specifications for remote execution.

        Creates FileTransferSpec objects for the primary content file
        and all dependencies that need to be uploaded.

        Args:
            content_path: Path to the primary SCAP content file.
            dependencies: Optional list of dependency objects with file_path attribute.
            remote_dir: Remote directory for file uploads.

        Returns:
            List of FileTransferSpec objects ready for transfer.

        Note:
            This is a helper for remote executors. Local executors
            may not need file transfers.
        """
        transfers = []

        # Primary content file
        transfers.append(
            FileTransferSpec(
                local_path=content_path,
                remote_path=f"{remote_dir}/{content_path.name}",
                direction="upload",
                required=True,
                verify_size=True,
            )
        )

        # Dependencies (if any)
        if dependencies:
            for dep in dependencies:
                # Dependencies should have a file_path attribute
                if hasattr(dep, "file_path"):
                    dep_path = dep.file_path
                    transfers.append(
                        FileTransferSpec(
                            local_path=dep_path,
                            remote_path=f"{remote_dir}/{dep_path.name}",
                            direction="upload",
                            required=True,
                            verify_size=True,
                        )
                    )

        return transfers

    def build_oscap_command(
        self,
        profile_id: str,
        content_path: str,
        result_xml: str,
        result_html: str,
        result_arf: Optional[str] = None,
        rule_id: Optional[str] = None,
    ) -> List[str]:
        """
        Build the oscap command line for scan execution.

        Creates a properly formatted oscap command with all required
        and optional arguments.

        Args:
            profile_id: XCCDF profile ID to evaluate.
            content_path: Path to SCAP content file (local or remote).
            result_xml: Path for XCCDF result output.
            result_html: Path for HTML report output.
            result_arf: Optional path for ARF result output.
            rule_id: Optional rule ID for single-rule evaluation.

        Returns:
            List of command arguments for subprocess or SSH execution.

        Usage:
            >>> cmd = executor.build_oscap_command(
            ...     profile_id="xccdf_org.ssgproject.content_profile_stig",
            ...     content_path="/tmp/ssg-rhel8-ds.xml",
            ...     result_xml="/tmp/results.xml",
            ...     result_html="/tmp/report.html"
            ... )
            >>> subprocess.run(cmd)
        """
        cmd = [
            "oscap",
            "xccdf",
            "eval",
            "--profile",
            profile_id,
            "--results",
            result_xml,
            "--report",
            result_html,
        ]

        # Optional ARF output
        if result_arf:
            cmd.extend(["--results-arf", result_arf])

        # Optional single-rule evaluation
        if rule_id:
            cmd.extend(["--rule", rule_id])
            self._logger.debug("Single-rule scan mode: rule_id=%s", rule_id)

        # Content file must be last
        cmd.append(content_path)

        return cmd
