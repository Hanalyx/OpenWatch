"""
Platform Detector - Just-In-Time OS Detection for Scan Operations

Provides lightweight platform detection for scan-time OVAL content selection.
This module does NOT persist data - it only returns platform info for the current scan.

The detection logic mirrors host_discovery_service.py but is optimized for:
1. Single-use (no caching or persistence)
2. Scan-specific return format (platform_identifier for OVAL selection)
3. Integration with existing scanner SSH connections
"""

import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, Optional

from backend.app.services.ssh import SSHConnectionManager

logger = logging.getLogger(__name__)


@dataclass
class PlatformInfo:
    """
    Platform information detected for scan operations.

    This structure contains exactly what the scan API needs for
    platform-specific OVAL content selection.

    Attributes:
        platform: Base platform name (e.g., "rhel", "ubuntu", "debian")
        platform_version: Full version string (e.g., "9.3", "22.04")
        platform_identifier: Normalized identifier for OVAL selection (e.g., "rhel9", "ubuntu2204")
        os_name: Full OS name from /etc/os-release (e.g., "Red Hat Enterprise Linux")
        architecture: System architecture (e.g., "x86_64", "arm64")
        detection_success: Whether detection completed successfully
        detection_error: Error message if detection failed
    """

    platform: Optional[str] = None
    platform_version: Optional[str] = None
    platform_identifier: Optional[str] = None
    os_name: Optional[str] = None
    architecture: Optional[str] = None
    detection_success: bool = False
    detection_error: Optional[str] = None


class PlatformDetector:
    """
    Detects platform information from remote hosts via SSH.

    This class is designed for just-in-time platform detection during scan
    operations. It does NOT persist any data to the database.

    Usage:
        detector = PlatformDetector()
        info = await detector.detect(
            hostname="192.168.1.100",
            connection_params={"username": "root", "port": 22},
            encryption_service=enc_service,
        )
        if info.detection_success:
            print(f"Platform: {info.platform_identifier}")
    """

    # OS name mappings to standardized families (matches host_discovery_service)
    OS_FAMILY_MAPPINGS = {
        "red hat enterprise linux": "rhel",
        "rhel": "rhel",
        "redhat": "rhel",
        "red hat": "rhel",
        "centos": "centos",
        "centos linux": "centos",
        "rocky linux": "rhel",
        "almalinux": "rhel",
        "oracle linux": "rhel",
        "oracle linux server": "rhel",
        "fedora": "fedora",
        "ubuntu": "ubuntu",
        "debian": "debian",
        "debian gnu/linux": "debian",
        "suse linux enterprise": "suse",
        "sles": "suse",
        "opensuse": "opensuse",
        "opensuse leap": "opensuse",
        "opensuse tumbleweed": "opensuse",
        "amazon linux": "rhel",
        "amazon linux ami": "rhel",
    }

    def __init__(self, ssh_manager: Optional[SSHConnectionManager] = None):
        """
        Initialize the platform detector.

        Args:
            ssh_manager: Optional SSHConnectionManager instance to reuse.
                        If not provided, a new one will be created.
        """
        self.ssh_manager = ssh_manager
        self._owns_ssh_manager = ssh_manager is None

    async def detect(
        self,
        hostname: str,
        connection_params: Dict[str, Any],
        encryption_service: Any,
        host_id: Optional[str] = None,
    ) -> PlatformInfo:
        """
        Detect platform information from a remote host.

        This method connects via SSH, detects OS information, and returns
        a PlatformInfo object. It does NOT persist any data.

        Args:
            hostname: Target hostname or IP address
            connection_params: SSH connection parameters (username, port, etc.)
            encryption_service: Encryption service for credential decryption
            host_id: Optional host ID for credential resolution

        Returns:
            PlatformInfo with detected platform data, or with detection_error
            if detection failed.
        """
        result = PlatformInfo()
        ssh_client = None

        try:
            # Create SSH manager if not provided
            if self.ssh_manager is None:
                self.ssh_manager = SSHConnectionManager()
                self._owns_ssh_manager = True

            # Build connection config
            ssh_config = self._build_ssh_config(hostname, connection_params, encryption_service)

            # Determine auth method and credential
            auth_method = "password"
            credential = ssh_config.get("password", "")
            if ssh_config.get("private_key"):
                auth_method = "ssh_key"
                credential = ssh_config["private_key"]

            # Connect to host using connect_with_credentials API
            conn_result = self.ssh_manager.connect_with_credentials(
                hostname=ssh_config["hostname"],
                port=ssh_config.get("port", 22),
                username=ssh_config.get("username", "root"),
                auth_method=auth_method,
                credential=credential,
                service_name="platform_detection",
                password=ssh_config.get("password") if auth_method == "ssh_key" else None,
            )

            if not conn_result.success:
                result.detection_error = f"SSH connection failed: {conn_result.error_message}"
                return result

            ssh_client = conn_result.connection

            # Detect OS information
            os_info = self._detect_os_release(ssh_client)
            result.os_name = os_info.get("os_name")
            result.platform = os_info.get("os_family")
            result.platform_version = os_info.get("os_version")

            # Detect architecture
            result.architecture = self._detect_architecture(ssh_client)

            # Compute platform identifier for OVAL selection
            if result.platform and result.platform_version:
                result.platform_identifier = self._normalize_platform_identifier(
                    result.platform, result.platform_version
                )
                result.detection_success = True
            else:
                result.detection_error = "Could not determine platform or version"

            logger.info(
                f"Platform detection for {hostname}: "
                f"{result.platform} {result.platform_version} -> {result.platform_identifier}"
            )

        except Exception as e:
            logger.error(f"Platform detection failed for {hostname}: {e}")
            result.detection_error = str(e)

        finally:
            # Close connection if we have one
            if ssh_client:
                try:
                    ssh_client.close()
                except Exception:
                    pass

        return result

    def _build_ssh_config(
        self,
        hostname: str,
        connection_params: Dict[str, Any],
        encryption_service: Any,
    ) -> Dict[str, Any]:
        """Build SSH connection configuration from parameters."""
        config = {
            "hostname": hostname,
            "port": connection_params.get("port", 22),
            "username": connection_params.get("username"),
        }

        # Handle encrypted credentials
        if connection_params.get("encrypted_password"):
            try:
                config["password"] = encryption_service.decrypt(connection_params["encrypted_password"])
            except Exception as e:
                logger.warning(f"Failed to decrypt password: {e}")
        elif connection_params.get("password"):
            config["password"] = connection_params["password"]

        if connection_params.get("encrypted_private_key"):
            try:
                config["private_key"] = encryption_service.decrypt(connection_params["encrypted_private_key"])
            except Exception as e:
                logger.warning(f"Failed to decrypt private key: {e}")
        elif connection_params.get("private_key"):
            config["private_key"] = connection_params["private_key"]

        if connection_params.get("private_key_passphrase"):
            config["private_key_passphrase"] = connection_params["private_key_passphrase"]

        return config

    def _detect_os_release(self, ssh_client: Any) -> Dict[str, str]:
        """Detect OS information from /etc/os-release."""
        result = {"os_family": None, "os_version": None, "os_name": None}

        try:
            # Try /etc/os-release first
            stdin, stdout, stderr = ssh_client.exec_command("cat /etc/os-release", timeout=10)
            output = stdout.read().decode("utf-8", errors="ignore")
            exit_code = stdout.channel.recv_exit_status()

            if exit_code == 0 and output.strip():
                parsed = self._parse_os_release(output)
                result.update(parsed)
                return result

            # Fallback to redhat-release
            stdin, stdout, stderr = ssh_client.exec_command("cat /etc/redhat-release", timeout=5)
            output = stdout.read().decode("utf-8", errors="ignore")
            exit_code = stdout.channel.recv_exit_status()

            if exit_code == 0 and output.strip():
                content = output.strip()
                if "red hat" in content.lower() or "rhel" in content.lower():
                    result["os_family"] = "rhel"
                    result["os_name"] = content
                    version_match = re.search(r"(\d+\.?\d*)", content)
                    if version_match:
                        result["os_version"] = version_match.group(1)
                return result

            # Fallback to debian_version
            stdin, stdout, stderr = ssh_client.exec_command("cat /etc/debian_version", timeout=5)
            output = stdout.read().decode("utf-8", errors="ignore")
            exit_code = stdout.channel.recv_exit_status()

            if exit_code == 0 and output.strip():
                result["os_family"] = "debian"
                result["os_version"] = output.strip()
                result["os_name"] = "Debian GNU/Linux"
                return result

        except Exception as e:
            logger.debug(f"OS detection failed: {e}")

        return result

    def _parse_os_release(self, content: str) -> Dict[str, str]:
        """Parse /etc/os-release file content."""
        result = {"os_family": None, "os_version": None, "os_name": None}

        # Parse key-value pairs
        os_data = {}
        for line in content.split("\n"):
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                key, value = line.split("=", 1)
                os_data[key.upper()] = value.strip("\"'")

        # Extract OS name
        name = os_data.get("NAME", os_data.get("PRETTY_NAME", ""))
        result["os_name"] = name if name else None

        # Extract version
        version = os_data.get("VERSION_ID", os_data.get("VERSION", ""))
        result["os_version"] = version if version else None

        # Map to standardized OS family
        if name:
            name_lower = name.lower()
            for key, family in self.OS_FAMILY_MAPPINGS.items():
                if key in name_lower:
                    result["os_family"] = family
                    break

        return result

    def _detect_architecture(self, ssh_client: Any) -> Optional[str]:
        """Detect system architecture."""
        try:
            stdin, stdout, stderr = ssh_client.exec_command("uname -m", timeout=10)
            output = stdout.read().decode("utf-8", errors="ignore").strip()
            exit_code = stdout.channel.recv_exit_status()

            if exit_code == 0 and output:
                return self._normalize_architecture(output)
        except Exception as e:
            logger.debug(f"Architecture detection failed: {e}")

        return None

    def _normalize_architecture(self, arch: str) -> str:
        """Normalize architecture name to standard format."""
        arch_mappings = {
            "x86_64": "x86_64",
            "amd64": "x86_64",
            "i686": "i386",
            "i386": "i386",
            "aarch64": "arm64",
            "arm64": "arm64",
            "armv7l": "armv7",
            "armv6l": "armv6",
            "s390x": "s390x",
            "ppc64le": "ppc64le",
            "ppc64": "ppc64",
        }
        return arch_mappings.get(arch.lower(), arch)

    def _normalize_platform_identifier(self, os_family: str, os_version: str) -> Optional[str]:
        """
        Normalize OS family and version into a platform identifier for OVAL selection.

        This matches the logic in os_discovery_tasks._normalize_platform_identifier()
        to ensure consistency between JIT detection and scheduled discovery.

        Args:
            os_family: Detected OS family (e.g., "rhel", "ubuntu", "debian")
            os_version: Detected OS version (e.g., "9.3", "22.04", "12")

        Returns:
            Normalized platform identifier (e.g., "rhel9", "ubuntu2204") or None
        """
        if not os_family or not os_version:
            return None

        os_family_lower = os_family.lower()

        try:
            # Ubuntu uses YY.MM format - keep both parts without dot
            if os_family_lower == "ubuntu":
                version_parts = os_version.split(".")
                if len(version_parts) >= 2:
                    major = version_parts[0]
                    minor = version_parts[1]
                    return f"ubuntu{major}{minor}"
                else:
                    return f"ubuntu{version_parts[0]}"

            # For RHEL-compatible distros, use major version only
            elif os_family_lower in ["rhel", "centos", "rocky", "alma", "oracle"]:
                major_version = os_version.split(".")[0]
                return f"rhel{major_version}"

            # For other distros, use major version only
            else:
                major_version = os_version.split(".")[0]
                return f"{os_family_lower}{major_version}"

        except (IndexError, ValueError) as e:
            logger.warning(f"Failed to normalize platform identifier for {os_family} {os_version}: {e}")
            return None


async def detect_platform_for_scan(
    hostname: str,
    connection_params: Dict[str, Any],
    encryption_service: Any,
    host_id: Optional[str] = None,
) -> PlatformInfo:
    """
    Factory function for quick platform detection during scan operations.

    This is the recommended entry point for scan-time platform detection.
    It creates a PlatformDetector, performs detection, and returns the result.

    Args:
        hostname: Target hostname or IP address
        connection_params: SSH connection parameters
        encryption_service: Encryption service for credential decryption
        host_id: Optional host ID for logging/correlation

    Returns:
        PlatformInfo with detected platform data

    Example:
        info = await detect_platform_for_scan(
            hostname="192.168.1.100",
            connection_params={"username": "root", "port": 22},
            encryption_service=enc_service,
        )
        if info.detection_success:
            platform_identifier = info.platform_identifier  # e.g., "rhel9"
    """
    detector = PlatformDetector()
    return await detector.detect(
        hostname=hostname,
        connection_params=connection_params,
        encryption_service=encryption_service,
        host_id=host_id,
    )
