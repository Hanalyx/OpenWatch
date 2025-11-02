"""
Bash script executor for ORSA remediation engine.

Executes bash scripts from string content against local or remote (SSH) targets.
Supports variable expansion, script validation, and basic error handling.
"""

import asyncio
import re
import tempfile
from pathlib import Path
from typing import Dict, Optional, List
from datetime import datetime

from backend.app.services.remediators.base_executor import (
    BaseRemediationExecutor,
    ExecutorCapability,
    ExecutorNotAvailableError,
    ExecutorValidationError,
    ExecutorExecutionError,
    UnsupportedTargetError,
)
from backend.app.models.remediation_models import (
    RemediationTarget,
    RemediationExecutionResult,
    ScanTargetType,
)


class BashExecutor(BaseRemediationExecutor):
    """
    Bash script executor.

    Features:
    - Execute bash scripts from string content
    - Variable expansion (export before script)
    - Syntax validation via bash -n
    - SSH-based remote execution
    - Timeout support
    - Limited dry-run (syntax check only)
    """

    def __init__(self):
        """Initialize Bash executor."""
        super().__init__("bash")

    def _get_version(self) -> str:
        """Get Bash version."""
        try:
            result = asyncio.run(self._run_command(["bash", "--version"]))
            # Parse version from output (first line: "GNU bash, version 5.1.16(1)-release")
            first_line = result["stdout"].split("\n")[0]
            if "version" in first_line:
                # Extract version number
                match = re.search(r"version\s+(\d+\.\d+\.\d+)", first_line)
                if match:
                    return match.group(1)
            return "unknown"
        except Exception as e:
            raise ExecutorNotAvailableError(f"Bash not available: {e}")

    def _get_capabilities(self) -> set[ExecutorCapability]:
        """Get Bash executor capabilities."""
        return {
            ExecutorCapability.VARIABLE_SUBSTITUTION,
            ExecutorCapability.REMOTE_EXECUTION,
            # Note: Bash scripts are NOT inherently idempotent
            # Dry-run limited to syntax checking
        }

    def supports_target(self, target_type: str) -> bool:
        """Check if target type supported."""
        supported = {ScanTargetType.SSH_HOST, ScanTargetType.LOCAL}
        return target_type in [t.value for t in supported]

    def validate_content(self, content: str) -> bool:
        """
        Validate bash script syntax.

        Uses bash -n (noexec mode) to check syntax without executing.

        Args:
            content: Bash script content

        Returns:
            True if valid

        Raises:
            ExecutorValidationError: Syntax errors found
        """
        try:
            # Write script to temp file
            with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
                f.write(content)
                script_file = f.name

            try:
                # Run bash -n (syntax check)
                result = asyncio.run(
                    self._run_command(["bash", "-n", script_file], timeout_seconds=10)
                )

                if result["exit_code"] != 0:
                    raise ExecutorValidationError(
                        f"Script syntax error: {result['stderr']}"
                    )

                return True

            finally:
                # Cleanup
                Path(script_file).unlink(missing_ok=True)

        except Exception as e:
            if isinstance(e, ExecutorValidationError):
                raise
            raise ExecutorValidationError(f"Validation failed: {e}")

    async def execute(
        self,
        content: str,
        target: RemediationTarget,
        variables: Dict[str, str],
        dry_run: bool = False,
        timeout_seconds: int = 300,
    ) -> RemediationExecutionResult:
        """
        Execute bash script.

        Args:
            content: Bash script content
            target: Target system
            variables: Environment variables to set
            dry_run: If True, only validate syntax (no execution)
            timeout_seconds: Execution timeout

        Returns:
            RemediationExecutionResult

        Raises:
            ExecutorValidationError: Invalid script
            UnsupportedTargetError: Target type not supported
            ExecutorExecutionError: Execution failed
        """
        start_time = datetime.utcnow()

        # Validate syntax
        self.validate_content(content)

        # Check target type
        if not self.supports_target(target.type):
            raise UnsupportedTargetError(
                f"Bash executor does not support target type: {target.type}"
            )

        # Dry-run: only syntax validation
        if dry_run:
            duration = (datetime.utcnow() - start_time).total_seconds()
            return RemediationExecutionResult(
                success=True,
                stdout="Dry-run: Syntax validation passed",
                stderr="",
                exit_code=0,
                duration_seconds=duration,
                changes_made=["Dry-run: No changes made"],
                error_message=None,
            )

        # Prepare script with variable exports
        script_with_vars = self._prepare_script(content, variables)

        # Execute based on target type
        if target.type == ScanTargetType.LOCAL:
            result = await self._execute_local(script_with_vars, timeout_seconds)
        else:  # SSH_HOST
            result = await self._execute_remote(
                target, script_with_vars, timeout_seconds
            )

        return result

    async def rollback(
        self,
        remediation_id: str,
        rollback_content: str,
        target: RemediationTarget,
        timeout_seconds: int = 300,
    ) -> RemediationExecutionResult:
        """
        Execute rollback script.

        Args:
            remediation_id: Original remediation ID
            rollback_content: Rollback script
            target: Target system
            timeout_seconds: Execution timeout

        Returns:
            RemediationExecutionResult
        """
        self.logger.info(f"Executing rollback for remediation {remediation_id}")

        # Execute rollback script (no dry-run)
        return await self.execute(
            content=rollback_content,
            target=target,
            variables={},
            dry_run=False,
            timeout_seconds=timeout_seconds,
        )

    def _prepare_script(self, content: str, variables: Dict[str, str]) -> str:
        """
        Prepare script with variable exports.

        Args:
            content: Original script
            variables: Environment variables

        Returns:
            Script with variable exports prepended
        """
        # Start with shebang
        script_lines = ["#!/bin/bash", "set -e  # Exit on error", ""]

        # Export variables
        if variables:
            script_lines.append("# Environment variables")
            for var_name, var_value in variables.items():
                # Escape single quotes in value
                escaped_value = var_value.replace("'", "'\\''")
                script_lines.append(f"export {var_name}='{escaped_value}'")
            script_lines.append("")

        # Add original content
        script_lines.append("# Remediation script")
        script_lines.append(content)

        return "\n".join(script_lines)

    async def _execute_local(
        self, script: str, timeout_seconds: int
    ) -> RemediationExecutionResult:
        """
        Execute script locally.

        Args:
            script: Script content
            timeout_seconds: Timeout

        Returns:
            RemediationExecutionResult
        """
        start_time = datetime.utcnow()

        try:
            # Write script to temp file
            with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
                f.write(script)
                script_file = f.name

            # Make executable
            Path(script_file).chmod(0o700)

            try:
                # Execute
                result = await self._run_command(
                    ["bash", script_file], timeout_seconds=timeout_seconds
                )

                duration = (datetime.utcnow() - start_time).total_seconds()

                return RemediationExecutionResult(
                    success=result["exit_code"] == 0,
                    stdout=result["stdout"],
                    stderr=result["stderr"],
                    exit_code=result["exit_code"],
                    duration_seconds=duration,
                    changes_made=self._extract_changes(result["stdout"]),
                    error_message=(
                        None
                        if result["exit_code"] == 0
                        else f"Script failed with exit code {result['exit_code']}"
                    ),
                )

            finally:
                # Cleanup
                Path(script_file).unlink(missing_ok=True)

        except asyncio.TimeoutError:
            raise ExecutorExecutionError(
                f"Script execution exceeded timeout of {timeout_seconds}s"
            )
        except Exception as e:
            self.logger.error(f"Local execution failed: {e}")
            raise ExecutorExecutionError(f"Local execution failed: {e}")

    async def _execute_remote(
        self, target: RemediationTarget, script: str, timeout_seconds: int
    ) -> RemediationExecutionResult:
        """
        Execute script on remote host via SSH.

        Args:
            target: Remote target
            script: Script content
            timeout_seconds: Timeout

        Returns:
            RemediationExecutionResult
        """
        start_time = datetime.utcnow()

        # Get SSH credentials
        if not target.credentials:
            raise ExecutorExecutionError(
                "SSH credentials required for remote execution"
            )

        username = target.credentials.get("username", "root")
        ssh_key = target.credentials.get("ssh_key")
        password = target.credentials.get("password")

        try:
            # Write SSH key to temp file if provided
            ssh_key_file = None
            if ssh_key:
                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".pem", delete=False
                ) as f:
                    f.write(ssh_key)
                    ssh_key_file = f.name
                Path(ssh_key_file).chmod(0o600)

            # Write script to temp file
            with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
                f.write(script)
                script_file = f.name

            try:
                # Build SSH command
                ssh_cmd = ["ssh"]

                # SSH options
                ssh_cmd.extend(
                    [
                        "-o",
                        "StrictHostKeyChecking=no",
                        "-o",
                        "UserKnownHostsFile=/dev/null",
                        "-o",
                        "LogLevel=ERROR",
                    ]
                )

                # SSH key auth
                if ssh_key_file:
                    ssh_cmd.extend(["-i", ssh_key_file])

                # Target
                ssh_cmd.append(f"{username}@{target.identifier}")

                # Command: read script from stdin and execute
                ssh_cmd.append("bash -s")

                # Execute with script as stdin
                result = await self._run_command_with_stdin(
                    ssh_cmd, stdin=script, timeout_seconds=timeout_seconds
                )

                duration = (datetime.utcnow() - start_time).total_seconds()

                return RemediationExecutionResult(
                    success=result["exit_code"] == 0,
                    stdout=result["stdout"],
                    stderr=result["stderr"],
                    exit_code=result["exit_code"],
                    duration_seconds=duration,
                    changes_made=self._extract_changes(result["stdout"]),
                    error_message=(
                        None
                        if result["exit_code"] == 0
                        else f"Remote script failed with exit code {result['exit_code']}"
                    ),
                )

            finally:
                # Cleanup
                Path(script_file).unlink(missing_ok=True)
                if ssh_key_file:
                    Path(ssh_key_file).unlink(missing_ok=True)

        except asyncio.TimeoutError:
            raise ExecutorExecutionError(
                f"Remote execution exceeded timeout of {timeout_seconds}s"
            )
        except Exception as e:
            self.logger.error(f"Remote execution failed: {e}")
            raise ExecutorExecutionError(f"Remote execution failed: {e}")

    def _extract_changes(self, stdout: str) -> List[str]:
        """
        Extract changes from script output.

        Looks for common patterns like:
        - "Changed: ..."
        - "Modified: ..."
        - "Created: ..."
        - "Updated: ..."

        Args:
            stdout: Script output

        Returns:
            List of change descriptions
        """
        changes = []
        change_patterns = [
            r"^Changed:\s*(.+)$",
            r"^Modified:\s*(.+)$",
            r"^Created:\s*(.+)$",
            r"^Updated:\s*(.+)$",
            r"^Configured:\s*(.+)$",
        ]

        for line in stdout.split("\n"):
            for pattern in change_patterns:
                match = re.match(pattern, line.strip(), re.IGNORECASE)
                if match:
                    changes.append(match.group(0))
                    break

        return changes

    async def _run_command(
        self, cmd: List[str], timeout_seconds: int = 300
    ) -> Dict[str, any]:
        """
        Run command asynchronously.

        Args:
            cmd: Command and arguments
            timeout_seconds: Execution timeout

        Returns:
            Dict with stdout, stderr, exit_code

        Raises:
            asyncio.TimeoutError: Command exceeded timeout
        """
        process = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=timeout_seconds
            )

            return {
                "stdout": stdout.decode("utf-8", errors="replace"),
                "stderr": stderr.decode("utf-8", errors="replace"),
                "exit_code": process.returncode,
            }

        except asyncio.TimeoutError:
            # Kill process
            process.kill()
            await process.wait()
            raise

    async def _run_command_with_stdin(
        self, cmd: List[str], stdin: str, timeout_seconds: int = 300
    ) -> Dict[str, any]:
        """
        Run command with stdin input.

        Args:
            cmd: Command and arguments
            stdin: Input to send to stdin
            timeout_seconds: Execution timeout

        Returns:
            Dict with stdout, stderr, exit_code
        """
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(input=stdin.encode("utf-8")),
                timeout=timeout_seconds,
            )

            return {
                "stdout": stdout.decode("utf-8", errors="replace"),
                "stderr": stderr.decode("utf-8", errors="replace"),
                "exit_code": process.returncode,
            }

        except asyncio.TimeoutError:
            # Kill process
            process.kill()
            await process.wait()
            raise
