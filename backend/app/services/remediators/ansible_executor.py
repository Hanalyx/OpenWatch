"""
Ansible playbook executor for ORSA remediation engine.

Executes Ansible playbooks from string content against target systems.
Supports remote execution, variable substitution, dry-run mode, and idempotent operations.
"""

import asyncio
import json
import os
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import yaml

from backend.app.models.remediation_models import (
    RemediationExecutionResult,
    RemediationTarget,
    ScanTargetType,
)
from backend.app.services.remediators.base_executor import (
    BaseRemediationExecutor,
    ExecutorCapability,
    ExecutorExecutionError,
    ExecutorNotAvailableError,
    ExecutorValidationError,
    UnsupportedTargetError,
)


class AnsibleExecutor(BaseRemediationExecutor):
    """
    Ansible playbook executor.

    Features:
    - Execute playbooks from string content
    - Dynamic inventory generation
    - Variable substitution via extra-vars
    - Check mode (dry-run) support
    - Idempotent operations via Ansible modules
    - SSH-based remote execution
    - JSON callback for structured output parsing
    """

    def __init__(self):
        """Initialize Ansible executor."""
        super().__init__("ansible")

    def _get_version(self) -> str:
        """Get Ansible version."""
        try:
            result = asyncio.run(self._run_command(["ansible-playbook", "--version"]))
            # Parse version from output (first line: "ansible-playbook [core 2.14.3]")
            first_line = result["stdout"].split("\n")[0]
            if "[core" in first_line:
                version = first_line.split("[core")[1].split("]")[0].strip()
                return version
            return "unknown"
        except Exception as e:
            raise ExecutorNotAvailableError(f"Ansible not available: {e}. Install with: pip install ansible-core")

    def _get_capabilities(self) -> set[ExecutorCapability]:
        """Get Ansible executor capabilities."""
        return {
            ExecutorCapability.DRY_RUN,
            ExecutorCapability.ROLLBACK,
            ExecutorCapability.IDEMPOTENT,
            ExecutorCapability.VARIABLE_SUBSTITUTION,
            ExecutorCapability.REMOTE_EXECUTION,
        }

    def supports_target(self, target_type: str) -> bool:
        """Check if target type supported."""
        supported = {ScanTargetType.SSH_HOST, ScanTargetType.LOCAL}
        return target_type in [t.value for t in supported]

    def validate_content(self, content: str) -> bool:
        """
        Validate Ansible playbook YAML syntax.

        Args:
            content: Playbook YAML content

        Returns:
            True if valid

        Raises:
            ExecutorValidationError: Invalid YAML or playbook structure
        """
        try:
            # Parse YAML
            playbook = yaml.safe_load(content)

            # Basic structure validation
            if not isinstance(playbook, list):
                raise ExecutorValidationError("Playbook must be a YAML list")

            if len(playbook) == 0:
                raise ExecutorValidationError("Playbook is empty")

            # Check first play has required fields
            first_play = playbook[0]
            if not isinstance(first_play, dict):
                raise ExecutorValidationError("Play must be a dictionary")

            if "tasks" not in first_play and "roles" not in first_play:
                raise ExecutorValidationError("Play must have 'tasks' or 'roles'")

            return True

        except yaml.YAMLError as e:
            raise ExecutorValidationError(f"Invalid YAML syntax: {e}")

    async def execute(
        self,
        content: str,
        target: RemediationTarget,
        variables: Dict[str, str],
        dry_run: bool = False,
        timeout_seconds: int = 300,
    ) -> RemediationExecutionResult:
        """
        Execute Ansible playbook.

        Args:
            content: Playbook YAML content
            target: Target system
            variables: Extra vars to pass to playbook
            dry_run: Run in check mode (no changes)
            timeout_seconds: Execution timeout

        Returns:
            RemediationExecutionResult

        Raises:
            ExecutorValidationError: Invalid playbook
            UnsupportedTargetError: Target type not supported
            ExecutorExecutionError: Execution failed
        """
        start_time = datetime.utcnow()

        # Validate content
        self.validate_content(content)

        # Check target type
        if not self.supports_target(target.type):
            raise UnsupportedTargetError(f"Ansible executor does not support target type: {target.type}")

        # Create temporary files for playbook, inventory, SSH key
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)

                # Write playbook
                playbook_file = temp_path / "playbook.yml"
                playbook_file.write_text(content)

                # Generate inventory
                inventory_file = temp_path / "inventory.ini"
                self._generate_inventory(target, inventory_file)

                # Write SSH key if provided
                ssh_key_file = None
                if target.credentials and "ssh_key" in target.credentials:
                    ssh_key_file = temp_path / "ssh_key"
                    ssh_key_file.write_text(target.credentials["ssh_key"])
                    ssh_key_file.chmod(0o600)

                # Build ansible-playbook command
                cmd = self._build_playbook_command(
                    playbook_file=playbook_file,
                    inventory_file=inventory_file,
                    variables=variables,
                    dry_run=dry_run,
                    ssh_key_file=ssh_key_file,
                )

                # Execute
                result = await self._run_command(cmd, timeout_seconds=timeout_seconds)

                # Parse results
                execution_result = self._parse_ansible_output(
                    stdout=result["stdout"],
                    stderr=result["stderr"],
                    exit_code=result["exit_code"],
                    start_time=start_time,
                )

                return execution_result

        except asyncio.TimeoutError:
            raise ExecutorExecutionError(f"Ansible execution exceeded timeout of {timeout_seconds}s")
        except Exception as e:
            self.logger.error(f"Ansible execution failed: {e}")
            raise ExecutorExecutionError(f"Ansible execution failed: {e}")

    async def rollback(
        self,
        remediation_id: str,
        rollback_content: str,
        target: RemediationTarget,
        timeout_seconds: int = 300,
    ) -> RemediationExecutionResult:
        """
        Execute rollback playbook.

        Args:
            remediation_id: Original remediation ID
            rollback_content: Rollback playbook YAML
            target: Target system
            timeout_seconds: Execution timeout

        Returns:
            RemediationExecutionResult
        """
        self.logger.info(f"Executing rollback for remediation {remediation_id}")

        # Execute rollback playbook (no dry-run for rollback)
        return await self.execute(
            content=rollback_content,
            target=target,
            variables={},
            dry_run=False,
            timeout_seconds=timeout_seconds,
        )

    def _generate_inventory(self, target: RemediationTarget, inventory_file: Path):
        """
        Generate Ansible inventory file.

        Args:
            target: Target system
            inventory_file: Path to write inventory
        """
        if target.type == ScanTargetType.LOCAL:
            # Local execution
            inventory_content = "[local]\nlocalhost ansible_connection=local\n"
        else:
            # SSH remote execution
            username = target.credentials.get("username", "root") if target.credentials else "root"
            inventory_content = f"[targets]\n{target.identifier} ansible_user={username}\n"

        inventory_file.write_text(inventory_content)

    def _build_playbook_command(
        self,
        playbook_file: Path,
        inventory_file: Path,
        variables: Dict[str, str],
        dry_run: bool,
        ssh_key_file: Optional[Path] = None,
    ) -> List[str]:
        """
        Build ansible-playbook command.

        Args:
            playbook_file: Path to playbook
            inventory_file: Path to inventory
            variables: Extra vars
            dry_run: Check mode flag
            ssh_key_file: Path to SSH private key

        Returns:
            Command as list of arguments
        """
        cmd = [
            "ansible-playbook",
            str(playbook_file),
            "-i",
            str(inventory_file),
            "-v",  # Verbose output
        ]

        # Add extra vars
        if variables:
            cmd.extend(["--extra-vars", json.dumps(variables)])

        # Check mode for dry-run
        if dry_run:
            cmd.append("--check")

        # SSH key
        if ssh_key_file:
            cmd.extend(["--private-key", str(ssh_key_file)])

        # Disable host key checking (security consideration: should be configurable)
        cmd.extend(
            [
                "-e",
                "ansible_host_key_checking=False",
                "-e",
                "ansible_ssh_common_args='-o StrictHostKeyChecking=no'",
            ]
        )

        return cmd

    def _parse_ansible_output(
        self, stdout: str, stderr: str, exit_code: int, start_time: datetime
    ) -> RemediationExecutionResult:
        """
        Parse Ansible execution output.

        Args:
            stdout: Command stdout
            stderr: Command stderr
            exit_code: Exit code
            start_time: Execution start time

        Returns:
            RemediationExecutionResult
        """
        duration = (datetime.utcnow() - start_time).total_seconds()

        # Determine success
        success = exit_code == 0

        # Extract changes from output
        changes = self._extract_changes(stdout)

        # Check for specific failure patterns
        error_message = None
        if not success:
            if "UNREACHABLE" in stdout:
                error_message = "Target host unreachable"
            elif "FAILED" in stdout:
                error_message = "One or more tasks failed"
            else:
                error_message = f"Ansible exited with code {exit_code}"

        return RemediationExecutionResult(
            success=success,
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            duration_seconds=duration,
            changes_made=changes,
            error_message=error_message,
        )

    def _extract_changes(self, stdout: str) -> List[str]:
        """
        Extract list of changes from Ansible output.

        Parses Ansible task output to identify changed resources.

        Args:
            stdout: Ansible stdout

        Returns:
            List of change descriptions
        """
        changes = []

        # Look for "changed:" lines in output
        for line in stdout.split("\n"):
            if "changed:" in line.lower():
                # Extract task name if available
                if "TASK" in line:
                    task_name = line.split("[")[1].split("]")[0] if "[" in line else "unknown"
                    changes.append(f"Changed: {task_name}")
                else:
                    changes.append(line.strip())

        # Alternative: parse PLAY RECAP for change counts
        if "PLAY RECAP" in stdout:
            recap_section = stdout.split("PLAY RECAP")[1]
            for line in recap_section.split("\n"):
                if "changed=" in line:
                    # Extract host and change count
                    parts = line.split()
                    if parts:
                        host = parts[0]
                        changed_count = next((p.split("=")[1] for p in parts if "changed=" in p), "0")
                        if int(changed_count) > 0:
                            changes.append(f"{host}: {changed_count} changes")

        return changes

    async def _run_command(self, cmd: List[str], timeout_seconds: int = 300) -> Dict[str, any]:
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
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout_seconds)

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
