"""
Platform Capability Detection Service for OpenWatch
Detects and manages platform capabilities for rule applicability
"""

import asyncio
import json
import logging
import re
import subprocess
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class PlatformType(Enum):
    """Supported platform types"""

    RHEL = "rhel"
    UBUNTU = "ubuntu"
    CENTOS = "centos"
    DEBIAN = "debian"
    WINDOWS = "windows"
    SUSE = "suse"


class CapabilityType(Enum):
    """Types of capabilities to detect"""

    PACKAGE = "package"
    SERVICE = "service"
    FILE = "file"
    KERNEL_MODULE = "kernel_module"
    SYSTEMD = "systemd"
    NETWORK = "network"
    SECURITY = "security"


class PlatformCapabilityService:
    """Service for detecting platform capabilities"""

    def __init__(self):
        self.capability_cache = {}
        self.cache_ttl = timedelta(hours=1)  # Cache for 1 hour

        # Capability detection commands by platform
        self.detection_commands = {
            PlatformType.RHEL: {
                CapabilityType.PACKAGE: "rpm -qa --qf '%{NAME}:%{VERSION}\\n'",
                CapabilityType.SERVICE: "systemctl list-unit-files --type=service --no-legend",
                CapabilityType.SYSTEMD: "systemctl --version | head -1",
                CapabilityType.KERNEL_MODULE: "lsmod",
                CapabilityType.SECURITY: self._get_security_commands_rhel,
                CapabilityType.NETWORK: "ss -tuln",
                CapabilityType.FILE: "ls -la /etc/os-release",
            },
            PlatformType.UBUNTU: {
                CapabilityType.PACKAGE: "dpkg-query -W -f='${Package}:${Version}\\n'",
                CapabilityType.SERVICE: "systemctl list-unit-files --type=service --no-legend",
                CapabilityType.SYSTEMD: "systemctl --version | head -1",
                CapabilityType.KERNEL_MODULE: "lsmod",
                CapabilityType.SECURITY: self._get_security_commands_ubuntu,
                CapabilityType.NETWORK: "ss -tuln",
                CapabilityType.FILE: "ls -la /etc/os-release",
            },
        }

    async def initialize(self):
        """Initialize the capability service"""
        logger.info("PlatformCapabilityService initialized")

    async def detect_capabilities(
        self, platform: str, platform_version: str, target_host: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Detect platform capabilities

        Args:
            platform: Platform type (rhel, ubuntu, etc.)
            platform_version: Platform version
            target_host: Optional remote host for capability detection

        Returns:
            Dictionary of detected capabilities
        """
        cache_key = f"{platform}:{platform_version}:{target_host or 'local'}"

        # Check cache
        if cache_key in self.capability_cache:
            cached_data = self.capability_cache[cache_key]
            if datetime.utcnow() - cached_data["timestamp"] < self.cache_ttl:
                logger.debug(f"Using cached capabilities for {cache_key}")
                return cached_data["capabilities"]

        logger.info(f"Detecting capabilities for {platform} {platform_version}")

        try:
            # Convert platform string to enum
            platform_enum = PlatformType(platform.lower())
        except ValueError:
            raise ValueError(f"Unsupported platform: {platform}")

        capabilities = {
            "platform": platform,
            "platform_version": platform_version,
            "detection_timestamp": datetime.utcnow().isoformat(),
            "target_host": target_host,
            "capabilities": {},
        }

        # Detect each capability type
        for capability_type in CapabilityType:
            try:
                capability_data = await self._detect_capability_type(platform_enum, capability_type, target_host)
                capabilities["capabilities"][capability_type.value] = capability_data
            except Exception as e:
                logger.error(f"Failed to detect {capability_type.value}: {str(e)}")
                capabilities["capabilities"][capability_type.value] = {
                    "error": str(e),
                    "detected": False,
                }

        # Cache the result
        self.capability_cache[cache_key] = {
            "capabilities": capabilities,
            "timestamp": datetime.utcnow(),
        }

        logger.info(f"Capability detection completed for {platform} {platform_version}")
        return capabilities

    async def _detect_capability_type(
        self,
        platform: PlatformType,
        capability_type: CapabilityType,
        target_host: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Detect specific capability type"""

        if platform not in self.detection_commands:
            return {
                "detected": False,
                "reason": f"Unsupported platform: {platform.value}",
            }

        commands = self.detection_commands[platform]
        if capability_type not in commands:
            return {
                "detected": False,
                "reason": f"No detection method for {capability_type.value}",
            }

        command_spec = commands[capability_type]

        # Handle callable command generators
        if callable(command_spec):
            command_spec = command_spec()

        # Execute command(s)
        if isinstance(command_spec, str):
            return await self._execute_single_command(command_spec, target_host)
        elif isinstance(command_spec, list):
            return await self._execute_multiple_commands(command_spec, target_host)
        elif isinstance(command_spec, dict):
            return await self._execute_command_dict(command_spec, target_host)
        else:
            return {"detected": False, "reason": "Invalid command specification"}

    async def _execute_single_command(self, command: str, target_host: Optional[str] = None) -> Dict[str, Any]:
        """Execute a single command"""
        try:
            # Prepare command for remote execution if needed
            if target_host:
                command = f"ssh {target_host} '{command}'"

            # Execute command
            process = await asyncio.create_subprocess_shell(
                command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            return {
                "detected": True,
                "exit_code": process.returncode,
                "stdout": stdout.decode("utf-8", errors="ignore"),
                "stderr": stderr.decode("utf-8", errors="ignore"),
                "command": command,
            }

        except Exception as e:
            return {"detected": False, "error": str(e), "command": command}

    async def _execute_multiple_commands(
        self, commands: List[str], target_host: Optional[str] = None
    ) -> Dict[str, Any]:
        """Execute multiple commands"""
        results = []

        for cmd in commands:
            result = await self._execute_single_command(cmd, target_host)
            results.append(result)

        return {"detected": True, "results": results, "command_count": len(commands)}

    async def _execute_command_dict(
        self, command_dict: Dict[str, str], target_host: Optional[str] = None
    ) -> Dict[str, Any]:
        """Execute commands specified in dictionary"""
        results = {}

        for key, cmd in command_dict.items():
            result = await self._execute_single_command(cmd, target_host)
            results[key] = result

        return {"detected": True, "results": results}

    def _get_security_commands_rhel(self) -> Dict[str, str]:
        """Get security-related detection commands for RHEL"""
        return {
            "selinux": "getenforce",
            "firewall": "firewall-cmd --state",
            "auditd": "systemctl is-active auditd",
            "aide": "rpm -q aide",
            "fapolicyd": "systemctl is-active fapolicyd",
            "crypto_policies": "update-crypto-policies --show",
        }

    def _get_security_commands_ubuntu(self) -> Dict[str, str]:
        """Get security-related detection commands for Ubuntu"""
        return {
            "apparmor": "aa-status --enabled",
            "ufw": "ufw status",
            "auditd": "systemctl is-active auditd",
            "aide": "dpkg -l | grep aide",
            "fail2ban": "systemctl is-active fail2ban",
            "unattended_upgrades": "systemctl is-active unattended-upgrades",
        }

    async def parse_package_capabilities(self, raw_output: str, platform: PlatformType) -> Dict[str, Dict[str, str]]:
        """Parse package information from raw command output"""
        packages = {}

        lines = raw_output.strip().split("\n")
        for line in lines:
            if ":" in line:
                try:
                    name, version = line.split(":", 1)
                    packages[name.strip()] = {
                        "version": version.strip(),
                        "installed": True,
                    }
                except ValueError:
                    continue

        return packages

    async def parse_service_capabilities(self, raw_output: str, platform: PlatformType) -> Dict[str, Dict[str, str]]:
        """Parse service information from raw command output"""
        services = {}

        lines = raw_output.strip().split("\n")
        for line in lines:
            parts = line.split()
            if len(parts) >= 2:
                service_name = parts[0].replace(".service", "")
                service_state = parts[1]
                services[service_name] = {
                    "state": service_state,
                    "enabled": service_state in ["enabled", "static"],
                }

        return services

    async def detect_specific_capabilities(
        self,
        platform: str,
        platform_version: str,
        capability_list: List[str],
        target_host: Optional[str] = None,
    ) -> Dict[str, bool]:
        """
        Detect specific capabilities by name

        Args:
            platform: Platform type
            platform_version: Platform version
            capability_list: List of specific capabilities to check
            target_host: Optional remote host

        Returns:
            Dictionary mapping capability names to detection results
        """
        # Get full capability data
        full_capabilities = await self.detect_capabilities(platform, platform_version, target_host)

        results = {}

        for capability in capability_list:
            detected = False

            # Check in packages
            packages = full_capabilities["capabilities"].get("package", {}).get("results", {})
            if isinstance(packages, dict) and capability in packages:
                detected = True

            # Check in services
            services = full_capabilities["capabilities"].get("service", {}).get("results", {})
            if isinstance(services, dict) and capability in services:
                detected = True

            # Check in kernel modules
            modules = full_capabilities["capabilities"].get("kernel_module", {}).get("stdout", "")
            if capability in modules:
                detected = True

            results[capability] = detected

        return results

    async def get_platform_baseline(self, platform: str, platform_version: str) -> Dict[str, Any]:
        """
        Get expected baseline capabilities for a platform/version

        Returns known good baseline for comparison
        """
        baselines = {
            "rhel": {
                "8": {
                    "expected_packages": [
                        "systemd",
                        "kernel",
                        "glibc",
                        "bash",
                        "coreutils",
                        "rpm",
                        "yum",
                        "dnf",
                        "firewalld",
                        "openssh-server",
                    ],
                    "expected_services": ["systemd", "dbus", "NetworkManager", "sshd"],
                    "security_features": ["selinux", "firewall", "crypto_policies"],
                },
                "9": {
                    "expected_packages": [
                        "systemd",
                        "kernel",
                        "glibc",
                        "bash",
                        "coreutils",
                        "rpm",
                        "dnf",
                        "firewalld",
                        "openssh-server",
                    ],
                    "expected_services": ["systemd", "dbus", "NetworkManager", "sshd"],
                    "security_features": ["selinux", "firewall", "crypto_policies"],
                },
            },
            "ubuntu": {
                "20.04": {
                    "expected_packages": [
                        "systemd",
                        "linux-image",
                        "libc6",
                        "bash",
                        "coreutils",
                        "dpkg",
                        "apt",
                        "ufw",
                        "openssh-server",
                    ],
                    "expected_services": ["systemd", "dbus", "NetworkManager", "sshd"],
                    "security_features": ["apparmor", "ufw", "unattended_upgrades"],
                },
                "22.04": {
                    "expected_packages": [
                        "systemd",
                        "linux-image",
                        "libc6",
                        "bash",
                        "coreutils",
                        "dpkg",
                        "apt",
                        "ufw",
                        "openssh-server",
                    ],
                    "expected_services": ["systemd", "dbus", "NetworkManager", "sshd"],
                    "security_features": ["apparmor", "ufw", "unattended_upgrades"],
                },
            },
        }

        return baselines.get(platform, {}).get(platform_version, {})

    async def compare_with_baseline(
        self, detected_capabilities: Dict[str, Any], baseline: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Compare detected capabilities with baseline

        Returns analysis of missing, extra, and matched capabilities
        """
        comparison = {"missing": [], "extra": [], "matched": [], "analysis": {}}

        # Get detected package names
        detected_packages = set()
        package_data = detected_capabilities.get("capabilities", {}).get("package", {})
        if isinstance(package_data, dict) and "results" in package_data:
            detected_packages = set(package_data["results"].keys())

        # Compare packages
        expected_packages = set(baseline.get("expected_packages", []))
        comparison["missing"].extend(expected_packages - detected_packages)
        comparison["matched"].extend(expected_packages & detected_packages)

        # Get detected service names
        detected_services = set()
        service_data = detected_capabilities.get("capabilities", {}).get("service", {})
        if isinstance(service_data, dict) and "results" in service_data:
            detected_services = set(service_data["results"].keys())

        # Compare services
        expected_services = set(baseline.get("expected_services", []))
        comparison["missing"].extend(expected_services - detected_services)
        comparison["matched"].extend(expected_services & detected_services)

        # Analysis
        comparison["analysis"] = {
            "baseline_coverage": len(comparison["matched"]) / max(1, len(expected_packages) + len(expected_services)),
            "total_expected": len(expected_packages) + len(expected_services),
            "total_detected": len(detected_packages) + len(detected_services),
            "missing_critical": [item for item in comparison["missing"] if item in ["systemd", "kernel", "sshd"]],
            "platform_health": "good" if len(comparison["missing"]) < 3 else "degraded",
        }

        return comparison

    def clear_cache(self, platform: Optional[str] = None):
        """Clear capability cache"""
        if platform:
            keys_to_remove = [k for k in self.capability_cache.keys() if k.startswith(f"{platform}:")]
            for key in keys_to_remove:
                del self.capability_cache[key]
        else:
            self.capability_cache.clear()

        logger.info(f"Cleared capability cache{' for ' + platform if platform else ''}")
