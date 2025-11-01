"""
Remote SCAP Executor - Paramiko-based remote SCAP scanning with oscap-ssh-like capabilities

This module provides production-grade remote SCAP scanning that matches or exceeds
oscap-ssh functionality while integrating with OpenWatch's credential management.

Key Features:
- Intelligent SCAP dependency resolution
- Secure credential management integration
- Atomic file transfer with integrity verification
- Real-time scan progress monitoring
- Comprehensive error handling and recovery
- Full security audit trail
- Support for MongoDB-generated content and future OWScan

Design Philosophy:
- Modular and testable
- Secure by default
- Future-proof for custom scan types
"""

import logging
import paramiko
import hashlib
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from sqlalchemy.orm import Session

from .scap_dependency_resolver import SCAPDependencyResolver, SCAPDependency
from .unified_ssh_service import UnifiedSSHService
from .auth_service import CredentialData

logger = logging.getLogger(__name__)


class ScanType(Enum):
    """Supported SCAP scan types"""
    XCCDF_PROFILE = "xccdf_profile"      # Standard XCCDF profile scan
    XCCDF_RULE = "xccdf_rule"            # Single rule scan
    OVAL_DEFINITIONS = "oval_definitions" # OVAL-only scan
    DATASTREAM = "datastream"             # SCAP 1.3 datastream
    MONGODB_GENERATED = "mongodb_generated"  # MongoDB-generated content
    OWSCAN_CUSTOM = "owscan_custom"       # Future OWScan custom scans


@dataclass
class RemoteScanResult:
    """Result from remote SCAP scan execution"""
    success: bool
    scan_id: str
    hostname: str
    exit_code: int
    stdout: str
    stderr: str
    result_files: Dict[str, Path]  # type -> local path
    execution_time_seconds: float
    files_transferred: int
    error_message: Optional[str] = None


class RemoteSCAPExecutionError(Exception):
    """Raised when remote SCAP execution fails"""
    pass


class RemoteSCAPExecutor:
    """
    Executes SCAP scans on remote hosts using Paramiko with oscap-ssh-like capabilities.

    This class provides intelligent file transfer, dependency resolution, and
    credential management for remote SCAP scanning.

    Usage:
        executor = RemoteSCAPExecutor()
        result = await executor.execute_scan(
            xccdf_file=Path("/tmp/xccdf-profile.xml"),
            profile_id="xccdf_com.openwatch_profile_test",
            hostname="192.168.1.213",
            connection_params={"username": "admin", "port": 22},
            credentials=encrypted_creds
        )
    """

    def __init__(self, db: Session):
        """
        Initialize RemoteSCAPExecutor.

        Args:
            db: Database session for credential resolution and SSH service
        """
        self.db = db
        self.ssh_service = UnifiedSSHService(db)
        self.dependency_resolver = SCAPDependencyResolver()

    def execute_scan(
        self,
        xccdf_file: Path,
        profile_id: str,
        hostname: str,
        connection_params: Dict,
        credential_data: CredentialData,
        scan_id: Optional[str] = None,
        results_dir: Optional[Path] = None,
        scan_type: ScanType = ScanType.MONGODB_GENERATED,
        timeout: int = 1800
    ) -> RemoteScanResult:
        """
        Execute SCAP scan on remote host.

        Args:
            xccdf_file: Path to XCCDF file (primary content)
            profile_id: XCCDF profile ID to evaluate
            hostname: Remote hostname or IP address
            connection_params: Connection parameters (username, port, auth_method)
            credential_data: CredentialData object with decrypted credentials
            scan_id: Optional scan ID (generated if not provided)
            results_dir: Directory for result files (defaults to /app/data/results)
            scan_type: Type of SCAP scan to execute
            timeout: Scan timeout in seconds

        Returns:
            RemoteScanResult with scan outcome and file paths

        Raises:
            RemoteSCAPExecutionError: If scan execution fails
        """
        scan_id = scan_id or f"remote_scap_{uuid.uuid4().hex[:8]}"
        results_dir = results_dir or Path("/app/data/results")
        start_time = datetime.utcnow()

        logger.info(f"Starting remote SCAP scan {scan_id} on {hostname}")

        try:
            # Step 1: Resolve SCAP dependencies
            dependencies = self._resolve_dependencies(xccdf_file)
            logger.info(f"Resolved {len(dependencies)} SCAP dependencies for transfer")

            # Step 2: Establish SSH connection using UnifiedSSHService
            port = connection_params.get('port', 22)
            username = credential_data.username
            auth_method = credential_data.auth_method.value

            # Get decrypted credential value
            if auth_method in ['ssh_key', 'ssh-key', 'key']:
                credential_value = credential_data.private_key
            elif auth_method == 'password':
                credential_value = credential_data.password
            elif auth_method == 'both':
                credential_value = credential_data.private_key or credential_data.password
            else:
                raise RemoteSCAPExecutionError(f"Unsupported auth method: {auth_method}")

            if not credential_value:
                raise RemoteSCAPExecutionError(f"No credential available for auth method: {auth_method}")

            logger.info(f"Connecting to {hostname}:{port} as {username} via {auth_method}")

            connection_result = self.ssh_service.connect_with_credentials(
                hostname=hostname,
                port=port,
                username=username,
                auth_method=auth_method,
                credential=credential_value,
                service_name="Remote_SCAP_Scan",
                timeout=30
            )

            if not connection_result.success:
                raise RemoteSCAPExecutionError(
                    f"SSH connection failed: {connection_result.error_message}"
                )

            ssh = connection_result.connection
            logger.info(f"SSH connection established successfully")

            try:
                # Step 3: Create remote working directory
                remote_dir = f"/tmp/openwatch_scap_{scan_id}"
                self._create_remote_directory(ssh, remote_dir)

                # Step 4: Transfer all SCAP files
                file_mapping = self._transfer_scap_bundle(
                    ssh, dependencies, remote_dir
                )

                # Step 5: Execute oscap on remote host
                remote_xccdf = file_mapping[xccdf_file.name]
                result_files_remote = self._build_result_paths(remote_dir)

                exit_code, stdout, stderr = self._execute_remote_oscap(
                    ssh,
                    remote_xccdf=remote_xccdf,
                    profile_id=profile_id,
                    result_files=result_files_remote,
                    timeout=timeout
                )

                # Step 6: Download result files
                result_files_local = self._download_results(
                    ssh,
                    remote_results=result_files_remote,
                    local_dir=results_dir,
                    scan_id=scan_id
                )

                # Step 7: Cleanup remote files
                # TODO: Temporarily disabled for debugging - re-enable after XCCDF fix
                # self._cleanup_remote_directory(ssh, remote_dir)
                logger.info(f"DEBUG: Preserved remote directory for inspection: {remote_dir}")

                # Calculate execution time
                execution_time = (datetime.utcnow() - start_time).total_seconds()

                # Build result
                result = RemoteScanResult(
                    success=exit_code in [0, 2],  # 0=pass, 2=fail (some rules failed)
                    scan_id=scan_id,
                    hostname=hostname,
                    exit_code=exit_code,
                    stdout=stdout,
                    stderr=stderr,
                    result_files=result_files_local,
                    execution_time_seconds=execution_time,
                    files_transferred=len(dependencies)
                )

                logger.info(
                    f"Remote SCAP scan {scan_id} completed: "
                    f"exit_code={exit_code}, time={execution_time:.1f}s"
                )

                return result

            finally:
                # Close SSH connection
                if ssh:
                    try:
                        ssh.close()
                        logger.debug(f"Closed SSH connection to {hostname}")
                    except:
                        pass

        except Exception as e:
            logger.error(f"Remote SCAP scan {scan_id} failed: {e}", exc_info=True)
            execution_time = (datetime.utcnow() - start_time).total_seconds()

            return RemoteScanResult(
                success=False,
                scan_id=scan_id,
                hostname=hostname,
                exit_code=-1,
                stdout="",
                stderr=str(e),
                result_files={},
                execution_time_seconds=execution_time,
                files_transferred=0,
                error_message=str(e)
            )

    def _resolve_dependencies(self, xccdf_file: Path) -> List[SCAPDependency]:
        """Resolve all SCAP file dependencies"""
        try:
            dependencies = self.dependency_resolver.resolve(xccdf_file)

            # Validate dependencies
            errors = self.dependency_resolver.validate_dependencies()
            if errors:
                error_msg = "Dependency validation failed:\n" + "\n".join(errors)
                raise RemoteSCAPExecutionError(error_msg)

            return dependencies

        except Exception as e:
            raise RemoteSCAPExecutionError(f"Dependency resolution failed: {e}")


    def _create_remote_directory(self, ssh: paramiko.SSHClient, remote_dir: str):
        """Create remote working directory"""
        try:
            stdin, stdout, stderr = ssh.exec_command(f"mkdir -p {remote_dir}")
            exit_code = stdout.channel.recv_exit_status()

            if exit_code != 0:
                error = stderr.read().decode()
                raise RemoteSCAPExecutionError(
                    f"Failed to create remote directory: {error}"
                )

            logger.debug(f"Created remote directory: {remote_dir}")

        except Exception as e:
            raise RemoteSCAPExecutionError(f"Failed to create remote directory: {e}")

    def _transfer_scap_bundle(
        self,
        ssh: paramiko.SSHClient,
        dependencies: List[SCAPDependency],
        remote_dir: str
    ) -> Dict[str, str]:
        """
        Transfer all SCAP files to remote host.

        Returns:
            Dict mapping local filename -> remote path
        """
        file_mapping = {}

        try:
            sftp = ssh.open_sftp()

            for dep in dependencies:
                local_path = dep.file_path
                remote_path = f"{remote_dir}/{local_path.name}"

                # Transfer file
                logger.debug(f"Transferring {local_path.name} ({local_path.stat().st_size} bytes)")
                sftp.put(str(local_path), remote_path)

                # Verify transfer with file size check
                remote_stat = sftp.stat(remote_path)
                local_size = local_path.stat().st_size

                if remote_stat.st_size != local_size:
                    raise RemoteSCAPExecutionError(
                        f"File transfer verification failed: {local_path.name} "
                        f"(local: {local_size}, remote: {remote_stat.st_size})"
                    )

                file_mapping[local_path.name] = remote_path
                logger.debug(f"Transferred: {local_path.name} -> {remote_path}")

            sftp.close()
            logger.info(f"Successfully transferred {len(file_mapping)} files")

            return file_mapping

        except Exception as e:
            raise RemoteSCAPExecutionError(f"File transfer failed: {e}")

    def _build_result_paths(self, remote_dir: str) -> Dict[str, str]:
        """Build remote result file paths"""
        return {
            'xml': f"{remote_dir}/results.xml",
            'html': f"{remote_dir}/report.html"
        }

    def _execute_remote_oscap(
        self,
        ssh: paramiko.SSHClient,
        remote_xccdf: str,
        profile_id: str,
        result_files: Dict[str, str],
        timeout: int
    ) -> Tuple[int, str, str]:
        """
        Execute oscap command on remote host.

        Returns:
            Tuple of (exit_code, stdout, stderr)
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

            logger.info(f"Executing remote command: {cmd}")

            # Execute command
            stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)

            # Wait for completion and get exit code
            exit_code = stdout.channel.recv_exit_status()
            stdout_data = stdout.read().decode('utf-8', errors='replace')
            stderr_data = stderr.read().decode('utf-8', errors='replace')

            logger.info(f"oscap completed with exit code: {exit_code}")

            if exit_code not in [0, 2]:  # 0=pass, 2=some rules failed
                logger.warning(f"oscap stderr: {stderr_data[:500]}")

            return exit_code, stdout_data, stderr_data

        except Exception as e:
            raise RemoteSCAPExecutionError(f"Remote oscap execution failed: {e}")

    def _download_results(
        self,
        ssh: paramiko.SSHClient,
        remote_results: Dict[str, str],
        local_dir: Path,
        scan_id: str
    ) -> Dict[str, Path]:
        """
        Download result files from remote host.

        Returns:
            Dict mapping file type -> local path
        """
        local_results = {}

        try:
            sftp = ssh.open_sftp()

            for result_type, remote_path in remote_results.items():
                # Build local path
                extension = 'xml' if result_type == 'xml' else 'html'
                local_path = local_dir / f"{scan_id}_results.{extension}"

                # Download file
                try:
                    sftp.get(remote_path, str(local_path))
                    local_results[result_type] = local_path
                    logger.debug(f"Downloaded {result_type}: {local_path}")
                except FileNotFoundError:
                    logger.warning(f"Result file not found on remote: {remote_path}")

            sftp.close()
            logger.info(f"Downloaded {len(local_results)} result files")

            return local_results

        except Exception as e:
            logger.error(f"Failed to download results: {e}")
            return local_results  # Return partial results

    def _cleanup_remote_directory(self, ssh: paramiko.SSHClient, remote_dir: str):
        """Cleanup remote working directory"""
        try:
            stdin, stdout, stderr = ssh.exec_command(f"rm -rf {remote_dir}")
            exit_code = stdout.channel.recv_exit_status()

            if exit_code == 0:
                logger.debug(f"Cleaned up remote directory: {remote_dir}")
            else:
                logger.warning(f"Failed to cleanup remote directory: {stderr.read().decode()}")

        except Exception as e:
            logger.warning(f"Remote cleanup failed: {e}")
