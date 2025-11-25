"""
Base SCAP Scanner Service

Provides shared functionality for SCAP scanning operations including SSH connection
management, SCAP validation, and result processing. This base class eliminates
code duplication between SCAPScanner and SCAPCLIScanner classes.
"""

import logging
import os
import subprocess
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import paramiko
from paramiko.ssh_exception import SSHException

from ..config import get_settings
from .unified_ssh_service import SSHConfigService, SSHKeyError, parse_ssh_key, validate_ssh_key

logger = logging.getLogger(__name__)
settings = get_settings()


class SCAPBaseError(Exception):
    """Base exception for SCAP scanner operations"""


class SCAPConnectionManager:
    """Manages SSH connections with unified authentication and validation"""

    @staticmethod
    def validate_and_parse_key(credential: str) -> paramiko.PKey:
        """Validate and parse SSH key with comprehensive error handling"""
        try:
            # Validate SSH key first
            validation_result = validate_ssh_key(credential)
            if not validation_result.is_valid:
                logger.error(f"Invalid SSH key: {validation_result.error_message}")
                raise SSHException(f"Invalid SSH key: {validation_result.error_message}")

            # Log any warnings
            if validation_result.warnings:
                logger.warning(f"SSH key warnings: {'; '.join(validation_result.warnings)}")

            # Parse key using unified parser
            return parse_ssh_key(credential)

        except SSHKeyError as e:
            logger.error(f"SSH key parsing failed: {e}")
            raise SSHException(f"SSH key error: {str(e)}")

    @staticmethod
    def create_ssh_client(host_ip: Optional[str] = None) -> paramiko.SSHClient:
        """Create SSH client with configurable host key policy"""
        ssh = paramiko.SSHClient()

        # Use configurable SSH host key policy instead of hardcoded RejectPolicy
        ssh_config_service = SSHConfigService()
        ssh_config_service.configure_ssh_client(ssh, host_ip)

        return ssh

    @classmethod
    def test_connection(cls, hostname: str, port: int, username: str, auth_method: str, credential: str) -> Dict:
        """Test SSH connection with comprehensive validation and SCAP availability check"""
        try:
            logger.info(f"Testing SSH connection to {username}@{hostname}:{port}")

            ssh = cls.create_ssh_client(hostname)

            # Connect based on auth method
            if auth_method == "password":
                ssh.connect(
                    hostname,
                    port=port,
                    username=username,
                    password=credential,
                    timeout=10,
                )
            elif auth_method in ["ssh-key", "ssh_key"]:
                key = cls.validate_and_parse_key(credential)
                ssh.connect(hostname, port=port, username=username, pkey=key, timeout=10)
            else:
                raise SCAPBaseError(f"Unsupported auth method: {auth_method}")

            # Test basic command execution
            stdin, stdout, stderr = ssh.exec_command('echo "OpenWatch SSH Test"')
            output = stdout.read().decode()
            stderr.read().decode()

            # Check if oscap is available on remote host
            stdin, stdout, stderr = ssh.exec_command("oscap --version")
            oscap_output = stdout.read().decode()
            stderr.read().decode()

            oscap_available = stdout.channel.recv_exit_status() == 0

            ssh.close()

            result = {
                "success": True,
                "message": "SSH connection successful",
                "oscap_available": oscap_available,
                "oscap_version": oscap_output.strip() if oscap_available else None,
                "test_output": output.strip(),
            }

            if not oscap_available:
                result["warning"] = "OpenSCAP not found on remote host"

            logger.info(f"SSH test successful: {hostname}")
            return result

        except SSHException as e:
            logger.error(f"SSH connection failed: {e}")
            return {
                "success": False,
                "message": f"SSH connection failed: {str(e)}",
                "oscap_available": False,
            }
        except Exception as e:
            logger.error(f"SSH test error: {e}")
            return {
                "success": False,
                "message": f"Connection test failed: {str(e)}",
                "oscap_available": False,
            }


class SCAPContentValidator:
    """Handles SCAP content validation and profile extraction"""

    @staticmethod
    def validate_content(content_path: str) -> Dict:
        """Validate SCAP content file and extract metadata"""
        try:
            if not os.path.exists(content_path):
                raise SCAPBaseError(f"SCAP content file not found: {content_path}")

            # Validate content using oscap
            result = subprocess.run(
                ["oscap", "info", content_path],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                raise SCAPBaseError(f"Invalid SCAP content: {result.stderr}")

            # Parse basic info
            info = SCAPContentValidator._parse_oscap_info(result.stdout)

            logger.info(f"SCAP content validated: {content_path}")
            return {
                "valid": True,
                "info": info,
                "message": "SCAP content validated successfully",
            }

        except subprocess.TimeoutExpired:
            raise SCAPBaseError("Timeout validating SCAP content")
        except Exception as e:
            logger.error(f"Error validating SCAP content: {e}")
            raise SCAPBaseError(f"Content validation failed: {str(e)}")

    @staticmethod
    def extract_profiles(content_path: str) -> List[Dict]:
        """Extract available profiles from SCAP content"""
        try:
            if not os.path.exists(content_path):
                raise SCAPBaseError(f"SCAP content file not found: {content_path}")

            # Extract profiles using oscap
            result = subprocess.run(
                ["oscap", "info", "--profiles", content_path],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                raise SCAPBaseError(f"Failed to extract profiles: {result.stderr}")

            profiles = SCAPContentValidator._parse_profiles(result.stdout)
            logger.info(f"Extracted {len(profiles)} profiles from {content_path}")
            return profiles

        except subprocess.TimeoutExpired:
            raise SCAPBaseError("Timeout extracting profiles")
        except Exception as e:
            logger.error(f"Error extracting profiles: {e}")
            raise SCAPBaseError(f"Profile extraction failed: {str(e)}")

    @staticmethod
    def _parse_oscap_info(info_output: str) -> Dict:
        """Parse oscap info command output"""
        info = {}
        lines = info_output.split("\n")

        for line in lines:
            line = line.strip()
            if ":" in line:
                key, value = line.split(":", 1)
                key = key.strip().lower().replace(" ", "_")
                value = value.strip()
                info[key] = value

        return info

    @staticmethod
    def _parse_profiles(profiles_output: str) -> List[Dict]:
        """Parse profiles from oscap info --profiles output"""
        profiles = []
        lines = profiles_output.split("\n")

        current_profile = None
        for line in lines:
            line = line.strip()
            if line.startswith("Profile ID:"):
                if current_profile:
                    profiles.append(current_profile)
                current_profile = {
                    "id": line.split(":", 1)[1].strip(),
                    "title": "",
                    "description": "",
                }
            elif line.startswith("Title:") and current_profile:
                current_profile["title"] = line.split(":", 1)[1].strip()
            elif line.startswith("Description:") and current_profile:
                current_profile["description"] = line.split(":", 1)[1].strip()

        if current_profile:
            profiles.append(current_profile)

        return profiles


class BaseSCAPScanner(ABC):
    """
    Abstract base class for SCAP scanners providing common functionality

    This class eliminates code duplication between SCAPScanner and SCAPCLIScanner
    by providing shared methods for SSH connection management, SCAP validation,
    and result processing.
    """

    def __init__(self, content_dir: str = None, results_dir: str = None):
        # Use provided paths or fall back to configuration
        content_path = content_dir or settings.scap_content_dir
        results_path = results_dir or settings.scan_results_dir

        self.content_dir = Path(content_path)
        self.results_dir = Path(results_path)

        # Initialize shared components
        self.connection_manager = SCAPConnectionManager()
        self.content_validator = SCAPContentValidator()

        # Create directories if they don't exist
        try:
            self.content_dir.mkdir(parents=True, exist_ok=True)
            self.results_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"SCAP Scanner initialized - Content: {self.content_dir}, Results: {self.results_dir}")
        except Exception as e:
            logger.error(f"Failed to create SCAP directories: {e}")
            raise SCAPBaseError(f"Directory creation failed: {str(e)}")

    def validate_scap_content(self, content_path: str) -> Dict:
        """Validate SCAP content file - delegates to content validator"""
        return self.content_validator.validate_content(content_path)

    def extract_profiles(self, content_path: str) -> List[Dict]:
        """Extract profiles from SCAP content - delegates to content validator"""
        return self.content_validator.extract_profiles(content_path)

    def test_ssh_connection(self, hostname: str, port: int, username: str, auth_method: str, credential: str) -> Dict:
        """Test SSH connection - delegates to connection manager"""
        return self.connection_manager.test_connection(hostname, port, username, auth_method, credential)

    def create_scan_directory(self, scan_id: str) -> Path:
        """Create directory for scan results"""
        scan_dir = self.results_dir / scan_id
        scan_dir.mkdir(exist_ok=True)
        return scan_dir

    def get_scan_file_paths(self, scan_dir: Path) -> Tuple[Path, Path, Path]:
        """Get standardized file paths for scan results"""
        return (
            scan_dir / "results.xml",
            scan_dir / "report.html",
            scan_dir / "results.arf.xml",
        )

    def build_oscap_command(
        self,
        profile_id: str,
        xml_result: Path,
        html_report: Path,
        arf_result: Path,
        content_path: str,
        rule_id: str = None,
    ) -> List[str]:
        """Build standardized oscap command with optional rule-specific scanning"""
        cmd = [
            "oscap",
            "xccdf",
            "eval",
            "--profile",
            profile_id,
            "--results",
            str(xml_result),
            "--report",
            str(html_report),
            "--results-arf",
            str(arf_result),
        ]

        # Add rule-specific scanning if rule_id is provided
        if rule_id:
            cmd.extend(["--rule", rule_id])
            logger.info(f"Building command for specific rule: {rule_id}")

        cmd.append(content_path)
        return cmd

    @abstractmethod
    def execute_local_scan(self, content_path: str, profile_id: str, scan_id: str, rule_id: str = None) -> Dict:
        """Execute local SCAP scan - must be implemented by subclasses"""

    @abstractmethod
    def execute_remote_scan(
        self,
        hostname: str,
        port: int,
        username: str,
        auth_method: str,
        credential: str,
        content_path: str,
        profile_id: str,
        scan_id: str,
        rule_id: str = None,
    ) -> Dict:
        """Execute remote SCAP scan - must be implemented by subclasses"""

    def get_system_info(
        self,
        hostname: str = None,
        port: int = 22,
        username: str = None,
        auth_method: str = None,
        credential: str = None,
    ) -> Dict:
        """Get system information from local or remote host"""
        try:
            if hostname:
                # Remote system info
                return self._get_remote_system_info(hostname, port, username, auth_method, credential)
            else:
                # Local system info
                return self._get_local_system_info()

        except Exception as e:
            logger.error(f"Error getting system info: {e}")
            return {"error": str(e)}

    def _get_local_system_info(self) -> Dict:
        """Get local system information"""
        try:
            # Get OS info
            with open("/etc/os-release", "r") as f:
                os_info = {}
                for line in f:
                    if "=" in line:
                        key, value = line.strip().split("=", 1)
                        os_info[key] = value.strip('"')

            # Get system stats
            import psutil

            return {
                "hostname": os.uname().nodename,
                "os_name": os_info.get("NAME", "Unknown"),
                "os_version": os_info.get("VERSION", "Unknown"),
                "kernel": os.uname().release,
                "architecture": os.uname().machine,
                "cpu_count": psutil.cpu_count(),
                "memory_total": psutil.virtual_memory().total,
                "disk_usage": dict(psutil.disk_usage("/")),
                "uptime": datetime.now().isoformat(),
            }

        except Exception as e:
            logger.error(f"Error getting local system info: {e}")
            return {"error": str(e)}

    def _get_remote_system_info(
        self, hostname: str, port: int, username: str, auth_method: str, credential: str
    ) -> Dict:
        """Get remote system information via SSH"""
        try:
            ssh = self.connection_manager.create_ssh_client(hostname)

            # Connect
            if auth_method == "password":
                ssh.connect(
                    hostname,
                    port=port,
                    username=username,
                    password=credential,
                    timeout=10,
                )
            else:
                # Handle SSH key using connection manager
                key = self.connection_manager.validate_and_parse_key(credential)
                ssh.connect(hostname, port=port, username=username, pkey=key, timeout=10)

            # Execute commands to get system info
            commands = {
                "hostname": "hostname",
                "os_release": "cat /etc/os-release 2>/dev/null || echo 'ID=unknown'",
                "kernel": "uname -r",
                "architecture": "uname -m",
                "uptime": "uptime",
                "memory": "free -m | grep '^Mem:' | awk '{print $2}'",
                "cpu_info": "nproc",
            }

            results = {}
            for key, cmd in commands.items():
                stdin, stdout, stderr = ssh.exec_command(cmd)
                output = stdout.read().decode().strip()
                results[key] = output

            ssh.close()

            # Parse OS release info
            os_info = {}
            for line in results.get("os_release", "").split("\n"):
                if "=" in line:
                    key, value = line.split("=", 1)
                    os_info[key] = value.strip('"')

            return {
                "hostname": results.get("hostname", hostname),
                "os_name": os_info.get("NAME", "Unknown"),
                "os_version": os_info.get("VERSION", "Unknown"),
                "kernel": results.get("kernel", "Unknown"),
                "architecture": results.get("architecture", "Unknown"),
                "cpu_count": int(results.get("cpu_info", "0")),
                "memory_mb": int(results.get("memory", "0")),
                "uptime": results.get("uptime", "Unknown"),
            }

        except Exception as e:
            logger.error(f"Error getting remote system info: {e}")
            return {"error": str(e)}
