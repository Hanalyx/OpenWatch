"""
SSH Executor - Remote Scan Execution via SSH

This module provides the SSHExecutor class for executing compliance scans
on remote hosts via SSH connections. It is the primary executor for
production scanning in OpenWatch.

Key Features:
- Paramiko-based SSH connections with full credential support
- Intelligent SCAP dependency resolution and transfer
- Atomic file transfer with integrity verification
- Real-time scan progress monitoring
- Comprehensive error handling and recovery
- Full security audit trail integration

Migrated from: backend/app/services/remote_scap_executor.py

Design Philosophy:
- Security first: Credentials never stored, only passed transiently
- Modular: Uses SSHConnectionManager for all SSH operations
- Testable: Clear separation of concerns enables unit testing
- Defensive: Comprehensive error handling with graceful degradation

Usage:
    from backend.app.services.engine.executors import SSHExecutor

    executor = SSHExecutor(db=session)
    result = executor.execute(
        context=execution_context,
        content_path=Path("/path/to/xccdf.xml"),
        profile_id="xccdf_org.ssgproject.content_profile_stig",
        credential_data=credentials,
        dependencies=resolved_dependencies
    )

Security Notes:
- SSH connections use SSHConnectionManager for consistent security policies
- Credentials are validated but never logged or stored
- Remote directories use unique scan IDs to prevent collision
- File transfers are verified with size checks
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional

import paramiko
from sqlalchemy.orm import Session

from backend.app.services.ssh import SSHConnectionManager

if TYPE_CHECKING:
    from backend.app.services.auth_service import CredentialData

from ..dependency_resolver import SCAPDependency, SCAPDependencyResolver
from ..exceptions import DependencyError, FileTransferError, ScanExecutionError, ScanTimeoutError, SSHExecutionError
from ..models import ExecutionContext, ExecutionMode, RemoteScanResult, ScanStatus
from .base import BaseExecutor

logger = logging.getLogger(__name__)


class SSHExecutor(BaseExecutor):
    """
    Executes SCAP scans on remote hosts via SSH.

    This executor handles the complete lifecycle of remote scan execution:
    1. SSH connection establishment via SSHConnectionManager
    2. SCAP content dependency resolution
    3. File transfer to remote host
    4. oscap command execution
    5. Result file retrieval
    6. Remote cleanup (optional)

    The executor is stateless - each execute() call is independent.
    Connection state is managed transiently within execute().

    Attributes:
        db: Database session for credential resolution
        ssh_service: SSHConnectionManager for SSH operations
        dependency_resolver: Resolver for SCAP content dependencies

    Usage:
        executor = SSHExecutor(db=session)
        result = executor.execute(context, content_path, profile_id, creds)
    """

    def __init__(self, db: Session):
        """
        Initialize the SSH executor.

        Args:
            db: Database session for SSH service and credential resolution.
        """
        super().__init__(name="SSHExecutor")
        self.db = db
        # SSHConnectionManager handles SSH connections with security policies
        self.ssh_service = SSHConnectionManager(db)
        self.dependency_resolver = SCAPDependencyResolver()

    @property
    def execution_mode(self) -> ExecutionMode:
        """Return SSH execution mode."""
        return ExecutionMode.SSH

    def validate_environment(self) -> bool:
        """
        Validate that the SSH execution environment is ready.

        Checks:
        - Database connection is valid
        - SSH service is properly initialized
        - Dependency resolver is available

        Returns:
            True if environment is valid for SSH execution.
        """
        try:
            # Check database session
            if self.db is None:
                self._logger.warning("Database session is not available")
                return False

            # Check SSH service
            if self.ssh_service is None:
                self._logger.warning("SSH connection manager is not initialized")
                return False

            # Check dependency resolver
            if self.dependency_resolver is None:
                self._logger.warning("SCAP dependency resolver is not initialized")
                return False

            return True

        except Exception as e:
            self._logger.error("Environment validation failed: %s", str(e))
            return False

    def execute(
        self,
        context: ExecutionContext,
        content_path: Path,
        profile_id: str,
        credential_data: Optional[object] = None,
        dependencies: Optional[List[object]] = None,
    ) -> RemoteScanResult:
        """
        Execute SCAP scan on remote host via SSH.

        This method handles the complete scan execution lifecycle:
        1. Validate credentials and establish SSH connection
        2. Resolve SCAP dependencies (if not provided)
        3. Create remote working directory
        4. Transfer SCAP content bundle
        5. Execute oscap on remote host
        6. Download result files
        7. Cleanup remote directory (optional)

        Args:
            context: Execution context with scan parameters.
            content_path: Path to the primary XCCDF file.
            profile_id: XCCDF profile ID to evaluate.
            credential_data: CredentialData object with decrypted credentials.
            dependencies: Optional pre-resolved dependencies (resolved if None).

        Returns:
            RemoteScanResult with scan outcome and file paths.

        Raises:
            SSHExecutionError: If SSH connection or execution fails.
            DependencyError: If dependency resolution fails.
            FileTransferError: If file transfer fails.
            ScanExecutionError: If oscap execution fails.
        """
        self.log_execution_start(context)
        start_time = datetime.utcnow()

        # Validate credentials are provided
        if credential_data is None:
            error_msg = "Credentials required for SSH execution"
            self._logger.error(error_msg)
            return self._create_failed_remote_result(context, error_msg, start_time)

        ssh: Optional[paramiko.SSHClient] = None

        try:
            # Step 1: Resolve SCAP dependencies if not provided
            if dependencies is None:
                dependencies = self._resolve_dependencies(content_path)
            self._logger.info("Processing %d SCAP dependencies for transfer", len(dependencies))

            # Step 2: Establish SSH connection
            ssh = self._establish_connection(context, credential_data)

            # Step 3: Create remote working directory
            remote_dir = f"/tmp/openwatch_scap_{context.scan_id}"
            self._create_remote_directory(ssh, remote_dir)

            # Step 4: Transfer SCAP content bundle
            file_mapping = self._transfer_scap_bundle(ssh, dependencies, remote_dir)

            # Step 5: Build result paths and execute oscap
            remote_xccdf = file_mapping[content_path.name]
            remote_result_paths = self._build_remote_result_paths(remote_dir)

            exit_code, stdout, stderr = self._execute_remote_oscap(
                ssh=ssh,
                remote_xccdf=remote_xccdf,
                profile_id=profile_id,
                result_files=remote_result_paths,
                timeout=context.timeout,
            )

            # Step 6: Download result files
            local_result_paths = self._download_results(
                ssh=ssh,
                remote_results=remote_result_paths,
                local_dir=context.working_dir,
                scan_id=context.scan_id,
            )

            # Step 7: Cleanup remote directory (optional - can be disabled for debugging)
            # self._cleanup_remote_directory(ssh, remote_dir)
            self._logger.debug("Preserved remote directory for inspection: %s", remote_dir)

            # Calculate execution time
            end_time = datetime.utcnow()
            execution_time = (end_time - start_time).total_seconds()

            # Build successful result
            # Exit codes: 0 = all passed, 2 = some failed (findings exist)
            success = exit_code in [0, 2]

            result = RemoteScanResult(
                success=success,
                scan_id=context.scan_id,
                status=ScanStatus.COMPLETED if success else ScanStatus.FAILED,
                hostname=context.hostname,
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                start_time=start_time,
                end_time=end_time,
                execution_time_seconds=execution_time,
                result_files=local_result_paths,
                files_transferred=len(dependencies),
                remote_dir=remote_dir,
            )

            self.log_execution_complete(context, result)
            return result

        except Exception as e:
            self._logger.error(
                "SSH execution failed for scan %s: %s",
                context.scan_id,
                str(e),
                exc_info=True,
            )
            return self._create_failed_remote_result(context, str(e), start_time)

        finally:
            # Always close SSH connection
            if ssh:
                try:
                    ssh.close()
                    self._logger.debug("Closed SSH connection to %s", context.hostname)
                except Exception:
                    pass  # Ignore cleanup errors

    def _resolve_dependencies(self, content_path: Path) -> List[SCAPDependency]:
        """
        Resolve all SCAP file dependencies for content transfer.

        Uses the SCAPDependencyResolver to identify all files that must
        be transferred to the remote host for scan execution.

        Args:
            content_path: Path to the primary XCCDF file.

        Returns:
            List of SCAPDependency objects representing files to transfer.

        Raises:
            DependencyError: If resolution fails or dependencies are invalid.
        """
        try:
            dependencies = self.dependency_resolver.resolve(content_path)

            # Validate dependencies
            errors = self.dependency_resolver.validate_dependencies()
            if errors:
                error_msg = "Dependency validation failed:\n" + "\n".join(errors)
                raise DependencyError(
                    message=error_msg,
                    primary_file=str(content_path),
                    missing_files=errors,
                )

            return dependencies

        except DependencyError:
            raise  # Re-raise DependencyError as-is
        except Exception as e:
            raise DependencyError(
                message=f"Dependency resolution failed: {e}",
                primary_file=str(content_path),
                cause=e,
            )

    def _establish_connection(self, context: ExecutionContext, credential_data: "CredentialData") -> paramiko.SSHClient:
        """
        Establish SSH connection to the target host.

        Uses SSHConnectionManager for consistent security policies
        and credential handling.

        Args:
            context: Execution context with connection parameters.
            credential_data: Decrypted credentials for authentication.

        Returns:
            Connected paramiko.SSHClient instance.

        Raises:
            SSHExecutionError: If connection fails.
        """
        # Extract credential value based on auth method
        auth_method = credential_data.auth_method.value
        credential_value = self._get_credential_value(credential_data, auth_method)

        if not credential_value:
            raise SSHExecutionError(
                message=f"No credential available for auth method: {auth_method}",
                hostname=context.hostname,
                port=context.port,
                auth_method=auth_method,
            )

        self._logger.info(
            "Connecting to %s:%d as %s via %s",
            context.hostname,
            context.port,
            credential_data.username,
            auth_method,
        )

        # Use SSHConnectionManager for connection
        connection_result = self.ssh_service.connect_with_credentials(
            hostname=context.hostname,
            port=context.port,
            username=credential_data.username,
            auth_method=auth_method,
            credential=credential_value,
            service_name="Remote_SCAP_Scan",
            timeout=30,
        )

        if not connection_result.success:
            raise SSHExecutionError(
                message=f"SSH connection failed: {connection_result.error_message}",
                hostname=context.hostname,
                port=context.port,
                auth_method=auth_method,
            )

        self._logger.info("SSH connection established successfully")
        return connection_result.connection

    def _get_credential_value(self, credential_data: "CredentialData", auth_method: str) -> Optional[str]:
        """
        Extract the credential value based on authentication method.

        Args:
            credential_data: CredentialData object with credentials.
            auth_method: Authentication method string.

        Returns:
            Decrypted credential value or None if not available.
        """
        if auth_method in ["ssh_key", "ssh-key", "key"]:
            return credential_data.private_key
        elif auth_method == "password":
            return credential_data.password
        elif auth_method == "both":
            return credential_data.private_key or credential_data.password
        return None

    def _create_remote_directory(self, ssh: paramiko.SSHClient, remote_dir: str) -> None:
        """
        Create working directory on remote host.

        Args:
            ssh: Connected SSH client.
            remote_dir: Path to create on remote host.

        Raises:
            SSHExecutionError: If directory creation fails.
        """
        try:
            _, stdout, stderr = ssh.exec_command(f"mkdir -p {remote_dir}")
            exit_code = stdout.channel.recv_exit_status()

            if exit_code != 0:
                error = stderr.read().decode()
                raise SSHExecutionError(
                    message=f"Failed to create remote directory: {error}",
                    context={"remote_dir": remote_dir},
                )

            self._logger.debug("Created remote directory: %s", remote_dir)

        except SSHExecutionError:
            raise
        except Exception as e:
            raise SSHExecutionError(
                message=f"Failed to create remote directory: {e}",
                context={"remote_dir": remote_dir},
                cause=e,
            )

    def _transfer_scap_bundle(
        self,
        ssh: paramiko.SSHClient,
        dependencies: List[SCAPDependency],
        remote_dir: str,
    ) -> Dict[str, str]:
        """
        Transfer all SCAP files to remote host via SFTP.

        Transfers each file and verifies integrity using file size comparison.

        Args:
            ssh: Connected SSH client.
            dependencies: List of dependencies to transfer.
            remote_dir: Remote directory for file uploads.

        Returns:
            Dictionary mapping local filename to remote path.

        Raises:
            FileTransferError: If any transfer fails or verification fails.
        """
        file_mapping: Dict[str, str] = {}

        try:
            sftp = ssh.open_sftp()

            for dep in dependencies:
                local_path = dep.file_path
                remote_path = f"{remote_dir}/{local_path.name}"

                # Transfer file
                local_size = local_path.stat().st_size
                self._logger.debug("Transferring %s (%d bytes)", local_path.name, local_size)
                sftp.put(str(local_path), remote_path)

                # Verify transfer with file size check
                remote_stat = sftp.stat(remote_path)
                if remote_stat.st_size != local_size:
                    raise FileTransferError(
                        message="File transfer verification failed: size mismatch",
                        local_path=str(local_path),
                        remote_path=remote_path,
                        direction="upload",
                        context={
                            "local_size": local_size,
                            "remote_size": remote_stat.st_size,
                        },
                    )

                file_mapping[local_path.name] = remote_path
                self._logger.debug("Transferred: %s -> %s", local_path.name, remote_path)

            sftp.close()
            self._logger.info("Successfully transferred %d files", len(file_mapping))

            return file_mapping

        except FileTransferError:
            raise
        except Exception as e:
            raise FileTransferError(
                message=f"File transfer failed: {e}",
                direction="upload",
                cause=e,
            )

    def _build_remote_result_paths(self, remote_dir: str) -> Dict[str, str]:
        """
        Build remote paths for scan result files.

        Args:
            remote_dir: Remote working directory.

        Returns:
            Dictionary mapping result type to remote path.
        """
        return {
            "xml": f"{remote_dir}/results.xml",
            "html": f"{remote_dir}/report.html",
        }

    def _execute_remote_oscap(
        self,
        ssh: paramiko.SSHClient,
        remote_xccdf: str,
        profile_id: str,
        result_files: Dict[str, str],
        timeout: int,
    ) -> tuple:
        """
        Execute oscap command on remote host.

        Args:
            ssh: Connected SSH client.
            remote_xccdf: Remote path to XCCDF file.
            profile_id: XCCDF profile ID to evaluate.
            result_files: Dictionary of result type to remote path.
            timeout: Maximum execution time in seconds.

        Returns:
            Tuple of (exit_code, stdout, stderr).

        Raises:
            ScanExecutionError: If oscap execution fails.
            ScanTimeoutError: If execution exceeds timeout.
        """
        try:
            # Build oscap command
            cmd = (
                f"oscap xccdf eval "
                f"--profile {profile_id} "
                f"--results {result_files['xml']} "
                f"--report {result_files['html']} "
                f"{remote_xccdf}"
            )

            self._logger.info("Executing remote command: %s", cmd)

            # Execute command with timeout
            _, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)

            # Wait for completion and get exit code
            exit_code = stdout.channel.recv_exit_status()
            stdout_data = stdout.read().decode("utf-8", errors="replace")
            stderr_data = stderr.read().decode("utf-8", errors="replace")

            self._logger.info("oscap completed with exit code: %d", exit_code)

            # Log warnings for unexpected exit codes
            # Exit codes: 0 = pass, 2 = some rules failed (normal)
            if exit_code not in [0, 2]:
                self._logger.warning(
                    "Unexpected oscap exit code %d: %s",
                    exit_code,
                    stderr_data[:500],
                )

            return exit_code, stdout_data, stderr_data

        except paramiko.SSHException as e:
            if "timeout" in str(e).lower():
                raise ScanTimeoutError(
                    message=f"Remote oscap execution timed out after {timeout}s",
                    timeout_seconds=timeout,
                )
            raise ScanExecutionError(
                message=f"Remote oscap execution failed: {e}",
                profile_id=profile_id,
                cause=e,
            )
        except Exception as e:
            raise ScanExecutionError(
                message=f"Remote oscap execution failed: {e}",
                profile_id=profile_id,
                cause=e,
            )

    def _download_results(
        self,
        ssh: paramiko.SSHClient,
        remote_results: Dict[str, str],
        local_dir: Path,
        scan_id: str,
    ) -> Dict[str, Path]:
        """
        Download result files from remote host.

        Args:
            ssh: Connected SSH client.
            remote_results: Dictionary of result type to remote path.
            local_dir: Local directory for downloaded files.
            scan_id: Scan identifier for filename prefix.

        Returns:
            Dictionary mapping result type to local Path.
        """
        local_results: Dict[str, Path] = {}

        try:
            sftp = ssh.open_sftp()

            for result_type, remote_path in remote_results.items():
                # Build local path with scan ID prefix
                extension = "xml" if result_type == "xml" else "html"
                local_path = local_dir / f"{scan_id}_results.{extension}"

                try:
                    sftp.get(remote_path, str(local_path))
                    local_results[result_type] = local_path
                    self._logger.debug("Downloaded %s: %s", result_type, local_path)
                except FileNotFoundError:
                    self._logger.warning("Result file not found on remote: %s", remote_path)

            sftp.close()
            self._logger.info("Downloaded %d result files", len(local_results))

            return local_results

        except Exception as e:
            self._logger.error("Failed to download results: %s", e)
            return local_results  # Return partial results

    def _cleanup_remote_directory(self, ssh: paramiko.SSHClient, remote_dir: str) -> None:
        """
        Clean up remote working directory.

        Args:
            ssh: Connected SSH client.
            remote_dir: Remote directory to remove.

        Note:
            Cleanup failures are logged but do not raise exceptions,
            as they should not fail the overall scan execution.
        """
        try:
            _, stdout, stderr = ssh.exec_command(f"rm -rf {remote_dir}")
            exit_code = stdout.channel.recv_exit_status()

            if exit_code == 0:
                self._logger.debug("Cleaned up remote directory: %s", remote_dir)
            else:
                self._logger.warning(
                    "Failed to cleanup remote directory: %s",
                    stderr.read().decode(),
                )

        except Exception as e:
            self._logger.warning("Remote cleanup failed: %s", e)

    def _create_failed_remote_result(
        self,
        context: ExecutionContext,
        error_message: str,
        start_time: datetime,
    ) -> RemoteScanResult:
        """
        Create a RemoteScanResult for failed execution.

        Args:
            context: Execution context.
            error_message: Error description.
            start_time: When execution started.

        Returns:
            RemoteScanResult with failure status.
        """
        end_time = datetime.utcnow()
        execution_time = (end_time - start_time).total_seconds()

        return RemoteScanResult(
            success=False,
            scan_id=context.scan_id,
            status=ScanStatus.FAILED,
            hostname=context.hostname,
            exit_code=-1,
            stdout="",
            stderr=error_message,
            start_time=start_time,
            end_time=end_time,
            execution_time_seconds=execution_time,
            result_files={},
            files_transferred=0,
            error_message=error_message,
        )
