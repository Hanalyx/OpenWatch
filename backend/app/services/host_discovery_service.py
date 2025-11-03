"""
Host Discovery Service
Implements comprehensive host system discovery functionality
"""

import re
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime

from ..database import Host
from ..services.unified_ssh_service import UnifiedSSHService as SSHService

logger = logging.getLogger(__name__)


class HostBasicDiscoveryService:
    """
    Service for discovering basic system information from hosts via SSH
    """

    # OS name mappings to standardized families
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
        "amazon linux": "rhel",  # Amazon Linux is RHEL-compatible
        "amazon linux ami": "rhel",
    }

    def __init__(self, ssh_service: Optional[SSHService] = None):
        """Initialize the discovery service"""
        self.ssh_service = ssh_service or SSHService()

    def discover_basic_system_info(self, host: Host) -> Dict[str, Any]:
        """
        Discover basic system information from a host

        Args:
            host: Host object to discover information for

        Returns:
            Dictionary containing discovered system information
        """
        logger.info(f"Starting basic system discovery for host: {host.hostname}")

        discovery_results = {
            "hostname": "Unknown",
            "os_family": "Unknown",
            "os_version": "Unknown",
            "os_name": "Unknown",
            "architecture": "Unknown",
            "kernel_version": "Unknown",
            "discovery_timestamp": datetime.utcnow(),
            "discovery_success": False,
            "discovery_errors": [],
        }

        try:
            # Establish SSH connection
            if not self.ssh_service.connect(host):
                discovery_results["discovery_errors"].append("Failed to establish SSH connection")
                return discovery_results

            # 1. Get hostname
            hostname_info = self._discover_hostname(host)
            discovery_results.update(hostname_info)

            # 2. Get OS information from /etc/os-release
            os_info = self._discover_os_information(host)
            discovery_results.update(os_info)

            # 3. Get architecture
            arch_info = self._discover_architecture(host)
            discovery_results.update(arch_info)

            # 4. Get kernel version
            kernel_info = self._discover_kernel_version(host)
            discovery_results.update(kernel_info)

            # Update discovery success status
            discovery_results["discovery_success"] = len(discovery_results["discovery_errors"]) == 0

            # Update host object with discovered information
            self._update_host_with_discovery(host, discovery_results)

            logger.info(
                f"Basic system discovery completed for {host.hostname}: "
                f"OS={discovery_results['os_family']} {discovery_results['os_version']}, "
                f"Arch={discovery_results['architecture']}"
            )

        except Exception as e:
            logger.error(f"System discovery failed for {host.hostname}: {str(e)}")
            discovery_results["discovery_errors"].append(f"Discovery exception: {str(e)}")

        finally:
            self.ssh_service.disconnect()

        return discovery_results

    def _discover_hostname(self, host: Host) -> Dict[str, Any]:
        """Discover system hostname"""
        result = {"hostname": "Unknown"}

        try:
            output = self.ssh_service.execute_command("hostname", timeout=10)
            if output and output["success"]:
                hostname = output["stdout"].strip()
                if hostname:
                    result["hostname"] = hostname
                    logger.debug(f"Discovered hostname: {hostname}")
            else:
                result["discovery_errors"] = [
                    f"Hostname command failed: {output.get('stderr', 'Unknown error')}"
                ]

        except Exception as e:
            logger.warning(f"Failed to discover hostname for {host.hostname}: {str(e)}")
            result["discovery_errors"] = [f"Hostname discovery error: {str(e)}"]

        return result

    def _discover_os_information(self, host: Host) -> Dict[str, Any]:
        """Discover OS family, version, and name from /etc/os-release"""
        result = {"os_family": "Unknown", "os_version": "Unknown", "os_name": "Unknown"}

        try:
            output = self.ssh_service.execute_command("cat /etc/os-release", timeout=10)
            if output and output["success"]:
                os_release_content = output["stdout"]

                # Parse os-release content
                parsed_info = self._parse_os_release(os_release_content)
                result.update(parsed_info)

                logger.debug(
                    f"Discovered OS info: {result['os_name']} "
                    f"(family: {result['os_family']}, version: {result['os_version']})"
                )
            else:
                # Fallback: try other methods
                fallback_info = self._discover_os_fallback(host)
                result.update(fallback_info)

        except Exception as e:
            logger.warning(f"Failed to discover OS info for {host.hostname}: {str(e)}")
            result["discovery_errors"] = [f"OS discovery error: {str(e)}"]

        return result

    def _parse_os_release(self, content: str) -> Dict[str, str]:
        """Parse /etc/os-release file content"""
        result = {"os_family": "Unknown", "os_version": "Unknown", "os_name": "Unknown"}

        # Parse key-value pairs
        os_data = {}
        for line in content.split("\n"):
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                key, value = line.split("=", 1)
                # Remove quotes
                value = value.strip("\"'")
                os_data[key.upper()] = value

        # Extract OS name
        name = os_data.get("NAME", os_data.get("PRETTY_NAME", "Unknown"))
        result["os_name"] = name

        # Extract version ID
        version = os_data.get("VERSION_ID", os_data.get("VERSION", "Unknown"))
        result["os_version"] = version

        # Map to standardized OS family
        name_lower = name.lower()
        for key, family in self.OS_FAMILY_MAPPINGS.items():
            if key in name_lower:
                result["os_family"] = family
                break

        return result

    def _discover_os_fallback(self, host: Host) -> Dict[str, str]:
        """Fallback OS discovery using alternative methods"""
        result = {"os_family": "Unknown", "os_version": "Unknown", "os_name": "Unknown"}

        try:
            # Try /etc/redhat-release for RHEL-based systems
            output = self.ssh_service.execute_command("cat /etc/redhat-release", timeout=5)
            if output and output["success"]:
                content = output["stdout"].strip()
                if "red hat" in content.lower() or "rhel" in content.lower():
                    result["os_family"] = "rhel"
                    result["os_name"] = content
                    # Extract version
                    version_match = re.search(r"(\d+\.?\d*)", content)
                    if version_match:
                        result["os_version"] = version_match.group(1)
                return result

            # Try /etc/debian_version for Debian-based systems
            output = self.ssh_service.execute_command("cat /etc/debian_version", timeout=5)
            if output and output["success"]:
                version = output["stdout"].strip()
                result["os_family"] = "debian"
                result["os_version"] = version
                result["os_name"] = "Debian GNU/Linux"
                return result

        except Exception as e:
            logger.debug(f"OS fallback discovery failed: {str(e)}")

        return result

    def _discover_architecture(self, host: Host) -> Dict[str, Any]:
        """Discover system architecture"""
        result = {"architecture": "Unknown"}

        try:
            output = self.ssh_service.execute_command("uname -m", timeout=10)
            if output and output["success"]:
                arch = output["stdout"].strip()
                if arch:
                    # Normalize architecture names
                    arch_normalized = self._normalize_architecture(arch)
                    result["architecture"] = arch_normalized
                    logger.debug(f"Discovered architecture: {arch_normalized}")
            else:
                result["discovery_errors"] = [
                    f"Architecture command failed: {output.get('stderr', 'Unknown error')}"
                ]

        except Exception as e:
            logger.warning(f"Failed to discover architecture for {host.hostname}: {str(e)}")
            result["discovery_errors"] = [f"Architecture discovery error: {str(e)}"]

        return result

    def _normalize_architecture(self, arch: str) -> str:
        """Normalize architecture name to standard format"""
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

    def _discover_kernel_version(self, host: Host) -> Dict[str, Any]:
        """Discover kernel version"""
        result = {"kernel_version": "Unknown"}

        try:
            output = self.ssh_service.execute_command("uname -r", timeout=10)
            if output and output["success"]:
                kernel = output["stdout"].strip()
                if kernel:
                    result["kernel_version"] = kernel
                    logger.debug(f"Discovered kernel version: {kernel}")
            else:
                result["discovery_errors"] = [
                    f"Kernel version command failed: {output.get('stderr', 'Unknown error')}"
                ]

        except Exception as e:
            logger.warning(f"Failed to discover kernel version for {host.hostname}: {str(e)}")
            result["discovery_errors"] = [f"Kernel discovery error: {str(e)}"]

        return result

    def _update_host_with_discovery(self, host: Host, discovery_results: Dict[str, Any]):
        """Update host object with discovered information"""
        try:
            # Update host fields with discovered data
            if discovery_results.get("os_family") != "Unknown":
                host.os_family = discovery_results["os_family"]

            if discovery_results.get("os_version") != "Unknown":
                host.os_version = discovery_results["os_version"]

            if discovery_results.get("architecture") != "Unknown":
                host.architecture = discovery_results["architecture"]

            # Update the operating_system field with full OS name
            if discovery_results.get("os_name") != "Unknown":
                host.operating_system = discovery_results["os_name"]

            # Update discovery timestamp
            host.last_os_detection = discovery_results["discovery_timestamp"]

            logger.info(f"Updated host {host.hostname} with discovered system information")

        except Exception as e:
            logger.error(f"Failed to update host {host.hostname} with discovery results: {str(e)}")
