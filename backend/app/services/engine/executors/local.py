"""
Local Executor - Local Scan Execution

This module provides the LocalExecutor class for executing compliance scans
on the local host (the same system where OpenWatch is running). This is
useful for container-based scanning and self-assessment scenarios.

Key Features:
- Direct subprocess execution of oscap commands
- No network overhead or credential requirements
- Suitable for container scanning and self-assessment
- Simplified execution path with minimal dependencies

Design Philosophy:
- Simplicity: Direct execution without SSH overhead
- Security: No credential handling required
- Isolation: Uses working directories to isolate scan files
- Compatibility: Same result format as SSH executor

Usage:
    from backend.app.services.engine.executors import LocalExecutor

    executor = LocalExecutor()
    result = executor.execute(
        context=execution_context,
        content_path=Path("/path/to/xccdf.xml"),
        profile_id="xccdf_org.ssgproject.content_profile_stig"
    )

Security Notes:
- Runs with the permissions of the OpenWatch process
- Content paths should be validated before execution
- Results are written to the configured working directory
- No credential handling required for local execution
"""

import logging
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..exceptions import ContentValidationError, ScanExecutionError, ScanTimeoutError
from ..models import ExecutionContext, ExecutionMode, LocalScanResult, ScanStatus
from .base import BaseExecutor

logger = logging.getLogger(__name__)


class LocalExecutor(BaseExecutor):
    """
    Executes SCAP scans on the local host.

    This executor runs oscap directly via subprocess on the same system
    where OpenWatch is running. It does not require SSH connections or
    credentials, making it suitable for container-based scanning.

    The executor validates the environment before execution and
    provides consistent result formatting compatible with remote scanning.

    Attributes:
        oscap_path: Path to the oscap binary (auto-detected or configured)

    Usage:
        executor = LocalExecutor()
        if executor.validate_environment():
            result = executor.execute(context, content_path, profile_id)
    """

    def __init__(self, oscap_path: Optional[str] = None):
        """
        Initialize the local executor.

        Args:
            oscap_path: Optional path to oscap binary. If not provided,
                       the executor will attempt to find it in PATH.
        """
        super().__init__(name="LocalExecutor")
        self.oscap_path = oscap_path or self._find_oscap()

    @property
    def execution_mode(self) -> ExecutionMode:
        """Return LOCAL execution mode."""
        return ExecutionMode.LOCAL

    def _find_oscap(self) -> str:
        """
        Find the oscap binary in the system PATH.

        Returns:
            Path to oscap binary.

        Raises:
            LocalExecutionError: If oscap is not found.
        """
        try:
            result = subprocess.run(
                ["which", "oscap"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                oscap_path = result.stdout.strip()
                self._logger.debug("Found oscap at: %s", oscap_path)
                return oscap_path
        except subprocess.TimeoutExpired:
            self._logger.warning("Timeout searching for oscap binary")
        except Exception as e:
            self._logger.warning("Error searching for oscap: %s", e)

        # Default fallback
        return "oscap"

    def validate_environment(self) -> bool:
        """
        Validate that the local execution environment is ready.

        Checks:
        - oscap binary is available and executable
        - oscap version is retrievable
        - Working directory is writable

        Returns:
            True if environment is valid for local execution.
        """
        try:
            # Check oscap is available
            result = subprocess.run(
                [self.oscap_path, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode != 0:
                self._logger.warning("oscap --version failed: %s", result.stderr)
                return False

            oscap_version = result.stdout.strip().split("\n")[0]
            self._logger.info("oscap available: %s", oscap_version)

            return True

        except FileNotFoundError:
            self._logger.warning("oscap binary not found at: %s", self.oscap_path)
            return False
        except subprocess.TimeoutExpired:
            self._logger.warning("oscap --version timed out")
            return False
        except Exception as e:
            self._logger.error("Environment validation failed: %s", e)
            return False

    def execute(
        self,
        context: ExecutionContext,
        content_path: Path,
        profile_id: str,
        credential_data: Optional[object] = None,
        dependencies: Optional[List[object]] = None,
    ) -> LocalScanResult:
        """
        Execute SCAP scan on the local host.

        This method handles the complete local scan execution lifecycle:
        1. Validate content file exists
        2. Prepare working directory and result paths
        3. Build and execute oscap command
        4. Parse execution results
        5. Return LocalScanResult

        Args:
            context: Execution context with scan parameters.
            content_path: Path to the SCAP content file.
            profile_id: XCCDF profile ID to evaluate.
            credential_data: Ignored for local execution.
            dependencies: Ignored for local execution (files already local).

        Returns:
            LocalScanResult with scan outcome and file paths.

        Raises:
            LocalExecutionError: If execution fails.
            ContentValidationError: If content file is invalid.
            ScanTimeoutError: If execution exceeds timeout.
        """
        self.log_execution_start(context)
        start_time = datetime.utcnow()

        try:
            # Step 1: Validate content file exists
            if not content_path.exists():
                raise ContentValidationError(
                    message=f"Content file not found: {content_path}",
                    content_path=str(content_path),
                )

            # Step 2: Prepare working directory and result paths
            working_dir = context.working_dir
            working_dir.mkdir(parents=True, exist_ok=True)

            result_paths = self.build_result_paths(working_dir, context.scan_id)

            # Step 3: Build oscap command
            cmd = self.build_oscap_command(
                profile_id=profile_id,
                content_path=str(content_path),
                result_xml=str(result_paths["xml"]),
                result_html=str(result_paths["html"]),
                result_arf=str(result_paths["arf"]),
            )

            self._logger.info("Executing local command: %s", " ".join(cmd))

            # Step 4: Execute oscap command
            exit_code, stdout, stderr = self._run_oscap(
                cmd=cmd,
                timeout=context.timeout,
                working_dir=working_dir,
            )

            # Calculate execution time
            end_time = datetime.utcnow()
            execution_time = (end_time - start_time).total_seconds()

            # Step 5: Build result
            # Exit codes: 0 = all passed, 2 = some failed (findings exist)
            success = exit_code in [0, 2]

            # Verify result files were created
            created_files: Dict[str, Path] = {}
            for file_type, file_path in result_paths.items():
                if file_path.exists():
                    created_files[file_type] = file_path
                else:
                    self._logger.warning("Expected result file not created: %s", file_path)

            result = LocalScanResult(
                success=success,
                scan_id=context.scan_id,
                status=ScanStatus.COMPLETED if success else ScanStatus.FAILED,
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                start_time=start_time,
                end_time=end_time,
                execution_time_seconds=execution_time,
                content_path=content_path,
                result_files=created_files,
                profile_id=profile_id,
            )

            self.log_execution_complete(context, result)
            return result

        except (ContentValidationError, ScanTimeoutError, ScanExecutionError):
            raise  # Re-raise known exceptions
        except Exception as e:
            self._logger.error(
                "Local execution failed for scan %s: %s",
                context.scan_id,
                str(e),
                exc_info=True,
            )
            return self._create_failed_local_result(context, content_path, profile_id, str(e), start_time)

    def _run_oscap(
        self,
        cmd: List[str],
        timeout: int,
        working_dir: Path,
    ) -> tuple:
        """
        Run oscap command via subprocess.

        Args:
            cmd: Command and arguments as list.
            timeout: Maximum execution time in seconds.
            working_dir: Working directory for execution.

        Returns:
            Tuple of (exit_code, stdout, stderr).

        Raises:
            ScanTimeoutError: If execution exceeds timeout.
            ScanExecutionError: If subprocess execution fails.
        """
        try:
            # Security note: Using list of arguments prevents shell injection
            # Never use shell=True with user-provided input
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(working_dir),
            )

            exit_code = result.returncode
            stdout = result.stdout
            stderr = result.stderr

            self._logger.info("oscap completed with exit code: %d", exit_code)

            # Log warnings for unexpected exit codes
            if exit_code not in [0, 2]:
                self._logger.warning(
                    "Unexpected oscap exit code %d: %s",
                    exit_code,
                    stderr[:500],
                )

            return exit_code, stdout, stderr

        except subprocess.TimeoutExpired:
            raise ScanTimeoutError(
                message=f"Local oscap execution timed out after {timeout}s",
                timeout_seconds=timeout,
                elapsed_seconds=float(timeout),
            )
        except Exception as e:
            raise ScanExecutionError(
                message=f"Local oscap execution failed: {e}",
                cause=e,
            )

    def _create_failed_local_result(
        self,
        context: ExecutionContext,
        content_path: Path,
        profile_id: str,
        error_message: str,
        start_time: datetime,
    ) -> LocalScanResult:
        """
        Create a LocalScanResult for failed execution.

        Args:
            context: Execution context.
            content_path: Path to SCAP content.
            profile_id: Profile ID attempted.
            error_message: Error description.
            start_time: When execution started.

        Returns:
            LocalScanResult with failure status.
        """
        end_time = datetime.utcnow()
        execution_time = (end_time - start_time).total_seconds()

        return LocalScanResult(
            success=False,
            scan_id=context.scan_id,
            status=ScanStatus.FAILED,
            exit_code=-1,
            stdout="",
            stderr=error_message,
            start_time=start_time,
            end_time=end_time,
            execution_time_seconds=execution_time,
            content_path=content_path,
            result_files={},
            profile_id=profile_id,
            error_message=error_message,
        )

    def get_oscap_info(self, content_path: Path) -> Dict[str, Any]:
        """
        Get information about SCAP content using oscap info.

        Useful for validating content before scan execution.

        Args:
            content_path: Path to SCAP content file.

        Returns:
            Dictionary with content metadata.

        Raises:
            ContentValidationError: If content is invalid.
        """
        try:
            result = subprocess.run(
                [self.oscap_path, "info", str(content_path)],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                raise ContentValidationError(
                    message=f"Invalid SCAP content: {result.stderr}",
                    content_path=str(content_path),
                )

            # Parse oscap info output
            info = self._parse_oscap_info(result.stdout)
            self._logger.debug("SCAP content info: %s", info)

            return {
                "valid": True,
                "info": info,
                "message": "SCAP content validated successfully",
            }

        except subprocess.TimeoutExpired:
            raise ContentValidationError(
                message="Timeout validating SCAP content",
                content_path=str(content_path),
            )

    def _parse_oscap_info(self, info_output: str) -> Dict[str, str]:
        """
        Parse oscap info command output.

        Args:
            info_output: Raw output from oscap info.

        Returns:
            Dictionary with parsed key-value pairs.
        """
        info: Dict[str, str] = {}
        lines = info_output.split("\n")

        for line in lines:
            line = line.strip()
            if ":" in line:
                key, value = line.split(":", 1)
                key = key.strip().lower().replace(" ", "_")
                value = value.strip()
                info[key] = value

        return info
