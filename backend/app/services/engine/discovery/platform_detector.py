"""
Platform Detector - Just-In-Time OS Detection for Scan Operations

Provides lightweight platform detection for scan-time OVAL content selection.
This module does NOT persist data - it only returns platform info for the current scan.

The detection logic mirrors host_discovery_service.py but is optimized for:
1. Single-use (no caching or persistence)
2. Scan-specific return format (platform_identifier for OVAL selection)
3. Integration with existing scanner SSH connections

SSH Connection Pattern:
    This module follows the SSH Connection Best Practices documented in CLAUDE.md.
    It accepts CredentialData objects with pre-decrypted values - it does NOT
    handle encryption/decryption internally.

Usage:
    from app.services.auth import CentralizedAuthService, CredentialData
    from app.services.engine.discovery import PlatformDetector

    # Step 1: Resolve credentials at the entry point (API/task)
    auth_service = CentralizedAuthService(db, encryption_service)
    credential_data = auth_service.resolve_credential(target_id=str(host.id))

    # Step 2: Pass CredentialData to detector
    detector = PlatformDetector(db)
    info = await detector.detect(
        hostname="192.168.1.100",
        port=22,
        credential_data=credential_data,
    )
    if info.detection_success:
        print(f"Platform: {info.platform_identifier}")
"""

import logging
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Dict, Optional

from sqlalchemy.orm import Session

from app.services.ssh import SSHConnectionManager

if TYPE_CHECKING:
    from app.services.auth import CredentialData

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

    SSH Connection Pattern:
        This detector follows the SSH Connection Best Practices from CLAUDE.md.
        It accepts CredentialData objects with pre-decrypted values.
        Credential resolution and decryption must happen at the calling layer
        (API endpoint or task).

    Usage:
        from app.services.auth import CentralizedAuthService
        from app.services.engine.discovery import PlatformDetector

        # At API endpoint - resolve credentials
        auth_service = CentralizedAuthService(db, encryption_service)
        credential_data = auth_service.resolve_credential(target_id=str(host.id))

        # Pass CredentialData to detector
        detector = PlatformDetector(db)
        info = await detector.detect(
            hostname="192.168.1.100",
            port=22,
            credential_data=credential_data,
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

    def __init__(self, db: Optional[Session] = None):
        """
        Initialize the platform detector.

        Args:
            db: Optional database session for SSHConnectionManager.
        """
        self.db = db
        self.ssh_manager = SSHConnectionManager(db) if db else SSHConnectionManager()

    async def detect(
        self,
        hostname: str,
        port: int,
        credential_data: "CredentialData",
    ) -> PlatformInfo:
        """
        Detect platform information from a remote host.

        This method connects via SSH using pre-resolved CredentialData,
        detects OS information, and returns a PlatformInfo object.
        It does NOT persist any data.

        SSH Connection Pattern:
            This method follows the SSH Connection Best Practices from CLAUDE.md.
            The credential_data parameter must contain DECRYPTED values.
            Credential resolution must happen at the calling layer.

        Args:
            hostname: Target hostname or IP address
            port: SSH port number
            credential_data: CredentialData object with DECRYPTED credentials

        Returns:
            PlatformInfo with detected platform data, or with detection_error
            if detection failed.

        Raises:
            ValueError: If credential_data is None
        """
        result = PlatformInfo()
        ssh_client = None

        # Validate credential_data is provided
        if credential_data is None:
            result.detection_error = "No credentials provided for platform detection"
            logger.error(result.detection_error)
            return result

        try:
            # Extract credential value based on auth method
            auth_method = credential_data.auth_method.value
            credential_value = self._get_credential_value(credential_data, auth_method)

            if not credential_value:
                result.detection_error = f"No credential value available for auth method: {auth_method}"
                logger.error(result.detection_error)
                return result

            # Connect to host using SSHConnectionManager with pre-decrypted credentials
            logger.info(f"Connecting to {hostname}:{port} as {credential_data.username} via {auth_method}")

            conn_result = self.ssh_manager.connect_with_credentials(
                hostname=hostname,
                port=port,
                username=credential_data.username,
                auth_method=auth_method,
                credential=credential_value,
                service_name="platform_detection",
                timeout=30,
            )

            if not conn_result.success:
                result.detection_error = f"SSH connection failed: {conn_result.error_message}"
                logger.error(result.detection_error)
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

    def _get_credential_value(self, credential_data: "CredentialData", auth_method: str) -> Optional[str]:
        """
        Extract the appropriate credential value based on auth method.

        This method follows the pattern from SSHExecutor._get_credential_value().

        Args:
            credential_data: CredentialData object with decrypted credentials
            auth_method: Authentication method string

        Returns:
            Decrypted credential value (private_key or password), or None
        """
        if auth_method in ["ssh_key", "ssh-key", "key"]:
            return credential_data.private_key
        elif auth_method == "password":
            return credential_data.password
        elif auth_method == "both":
            # Prefer SSH key, fallback to password
            return credential_data.private_key or credential_data.password
        return None

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
    port: int,
    credential_data: "CredentialData",
    db: Optional[Session] = None,
) -> PlatformInfo:
    """
    Factory function for quick platform detection during scan operations.

    This is the recommended entry point for scan-time platform detection.
    It creates a PlatformDetector, performs detection, and returns the result.

    SSH Connection Pattern:
        This function follows the SSH Connection Best Practices from CLAUDE.md.
        The credential_data parameter must contain pre-resolved, DECRYPTED
        credentials from CentralizedAuthService.resolve_credential().

    Args:
        hostname: Target hostname or IP address
        port: SSH port number
        credential_data: CredentialData with DECRYPTED credentials
        db: Optional database session for SSHConnectionManager

    Returns:
        PlatformInfo with detected platform data

    Example:
        from app.services.auth import CentralizedAuthService

        # At API endpoint - resolve credentials first
        auth_service = CentralizedAuthService(db, encryption_service)
        credential_data = auth_service.resolve_credential(target_id=str(host.id))

        # Pass to detector
        info = await detect_platform_for_scan(
            hostname="192.168.1.100",
            port=22,
            credential_data=credential_data,
            db=db,
        )
        if info.detection_success:
            platform_identifier = info.platform_identifier  # e.g., "rhel9"
    """
    detector = PlatformDetector(db)
    return await detector.detect(
        hostname=hostname,
        port=port,
        credential_data=credential_data,
    )
