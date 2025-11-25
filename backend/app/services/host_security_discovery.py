"""
Host Security Infrastructure Discovery Service
Identifies security tools, configurations, and enforcement mechanisms on target hosts
"""

import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..database import Host
from ..services.unified_ssh_service import UnifiedSSHService as SSHService

logger = logging.getLogger(__name__)


class HostSecurityDiscoveryService:
    """
    Service for discovering security infrastructure and configurations on hosts
    """

    def __init__(self, ssh_service: Optional[SSHService] = None):
        """Initialize the security discovery service"""
        self.ssh_service = ssh_service or SSHService()

    def discover_security_infrastructure(self, host: Host) -> Dict[str, Any]:
        """
        Discover security infrastructure and configurations on a host

        Args:
            host: Host object to discover security information for

        Returns:
            Dictionary containing discovered security information
        """
        logger.info(f"Starting security infrastructure discovery for host: {host.hostname}")

        discovery_results = {
            "package_managers": {},
            "service_manager": "Unknown",
            "selinux_status": "Unknown",
            "apparmor_status": "Unknown",
            "firewall_services": {},
            "security_tools": [],
            "discovery_timestamp": datetime.utcnow(),
            "discovery_success": False,
            "discovery_errors": [],
        }

        try:
            # Establish SSH connection
            if not self.ssh_service.connect(host):
                discovery_results["discovery_errors"].append("Failed to establish SSH connection")
                return discovery_results

            # 1. Discover package managers
            pkg_mgr_info = self._discover_package_managers(host)
            discovery_results["package_managers"] = pkg_mgr_info.get("package_managers", {})
            discovery_results["discovery_errors"].extend(pkg_mgr_info.get("errors", []))

            # 2. Discover service manager
            service_mgr_info = self._discover_service_manager(host)
            discovery_results["service_manager"] = service_mgr_info.get("service_manager", "Unknown")
            discovery_results["discovery_errors"].extend(service_mgr_info.get("errors", []))

            # 3. Discover SELinux status
            selinux_info = self._discover_selinux_status(host)
            discovery_results["selinux_status"] = selinux_info.get("selinux_status", "Unknown")
            discovery_results["discovery_errors"].extend(selinux_info.get("errors", []))

            # 4. Discover AppArmor status
            apparmor_info = self._discover_apparmor_status(host)
            discovery_results["apparmor_status"] = apparmor_info.get("apparmor_status", "Unknown")
            discovery_results["discovery_errors"].extend(apparmor_info.get("errors", []))

            # 5. Discover active firewall services
            firewall_info = self._discover_firewall_services(host)
            discovery_results["firewall_services"] = firewall_info.get("firewall_services", {})
            discovery_results["discovery_errors"].extend(firewall_info.get("errors", []))

            # 6. Compile security tools list
            discovery_results["security_tools"] = self._compile_security_tools(discovery_results)

            # Update discovery success status
            discovery_results["discovery_success"] = len(discovery_results["discovery_errors"]) == 0

            logger.info(
                f"Security infrastructure discovery completed for {host.hostname}: "
                f"PM={list(discovery_results['package_managers'].keys())}, "
                f"SM={discovery_results['service_manager']}, "
                f"SEL={discovery_results['selinux_status']}, "
                f"AA={discovery_results['apparmor_status']}"
            )

        except Exception as e:
            logger.error(f"Security discovery failed for {host.hostname}: {str(e)}")
            discovery_results["discovery_errors"].append(f"Discovery exception: {str(e)}")

        finally:
            self.ssh_service.disconnect()

        return discovery_results

    def _discover_package_managers(self, host: Host) -> Dict[str, Any]:
        """Discover available package managers"""
        result = {"package_managers": {}, "errors": []}

        # Package managers to check
        package_managers = {
            "dnf": "DNF (Fedora/RHEL 8+)",
            "yum": "YUM (RHEL/CentOS 7)",
            "apt": "APT (Debian/Ubuntu)",
            "zypper": "Zypper (SUSE)",
            "pacman": "Pacman (Arch)",
            "pkg": "PKG (FreeBSD)",
            "apk": "APK (Alpine)",
        }

        try:
            for pm_cmd, pm_name in package_managers.items():
                output = self.ssh_service.execute_command(f"which {pm_cmd}", timeout=5)
                if output and output["success"] and output["stdout"].strip():
                    # Get version if possible
                    version_output = self.ssh_service.execute_command(f"{pm_cmd} --version", timeout=5)
                    version = "Unknown"
                    if version_output and version_output["success"]:
                        version_text = version_output["stdout"].strip()
                        # Extract version number from output
                        version_match = re.search(r"(\d+\.\d+[\.\d]*)", version_text)
                        if version_match:
                            version = version_match.group(1)

                    result["package_managers"][pm_cmd] = {
                        "name": pm_name,
                        "path": output["stdout"].strip(),
                        "version": version,
                        "available": True,
                    }

                    logger.debug(f"Found package manager: {pm_name} at {output['stdout'].strip()}")

        except Exception as e:
            logger.warning(f"Error discovering package managers for {host.hostname}: {str(e)}")
            result["errors"].append(f"Package manager discovery error: {str(e)}")

        return result

    def _discover_service_manager(self, host: Host) -> Dict[str, Any]:
        """Discover service manager (systemd vs init)"""
        result = {"service_manager": "Unknown", "errors": []}

        try:
            # Check for systemd first (most common)
            output = self.ssh_service.execute_command("systemctl --version", timeout=10)
            if output and output["success"]:
                version_text = output["stdout"].strip()
                version_match = re.search(r"systemd (\d+)", version_text)
                if version_match:
                    version = version_match.group(1)
                    result["service_manager"] = f"systemd (version {version})"
                    logger.debug(f"Found systemd version {version}")
                    return result

            # Check for traditional init systems
            output = self.ssh_service.execute_command("ps -p 1 -o comm=", timeout=10)
            if output and output["success"]:
                init_process = output["stdout"].strip()
                if "systemd" in init_process:
                    result["service_manager"] = "systemd"
                elif "init" in init_process:
                    result["service_manager"] = "SysV init"
                elif "upstart" in init_process:
                    result["service_manager"] = "Upstart"
                else:
                    result["service_manager"] = f"Unknown ({init_process})"

                logger.debug(f"Detected service manager: {result['service_manager']}")

        except Exception as e:
            logger.warning(f"Error discovering service manager for {host.hostname}: {str(e)}")
            result["errors"].append(f"Service manager discovery error: {str(e)}")

        return result

    def _discover_selinux_status(self, host: Host) -> Dict[str, Any]:
        """Discover SELinux status and enforcement mode"""
        result = {"selinux_status": "Unknown", "errors": []}

        try:
            # Try getenforce command first
            output = self.ssh_service.execute_command("getenforce", timeout=10)
            if output and output["success"]:
                enforcement_mode = output["stdout"].strip()
                if enforcement_mode:
                    # Get additional details with sestatus
                    status_output = self.ssh_service.execute_command("sestatus", timeout=10)
                    if status_output and status_output["success"]:
                        status_text = status_output["stdout"]
                        # Parse sestatus output for more details
                        policy_match = re.search(r"Current mode:\s*(\w+)", status_text)
                        policy_type_match = re.search(r"Policy from config file:\s*(\w+)", status_text)

                        selinux_info = {
                            "enforcement_mode": enforcement_mode,
                            "status": ("enabled" if enforcement_mode != "Disabled" else "disabled"),
                        }

                        if policy_match:
                            selinux_info["current_mode"] = policy_match.group(1)
                        if policy_type_match:
                            selinux_info["policy_type"] = policy_type_match.group(1)

                        result["selinux_status"] = selinux_info
                        logger.debug(f"SELinux status: {enforcement_mode}")
                    else:
                        result["selinux_status"] = {
                            "enforcement_mode": enforcement_mode,
                            "status": ("enabled" if enforcement_mode != "Disabled" else "disabled"),
                        }
                    return result

            # Check if SELinux is installed but not active
            output = self.ssh_service.execute_command("ls /etc/selinux/config", timeout=5)
            if output and output["success"]:
                result["selinux_status"] = {
                    "status": "installed_but_inactive",
                    "enforcement_mode": "Disabled",
                }
            else:
                result["selinux_status"] = {
                    "status": "not_installed",
                    "enforcement_mode": "N/A",
                }

        except Exception as e:
            logger.warning(f"Error discovering SELinux status for {host.hostname}: {str(e)}")
            result["errors"].append(f"SELinux discovery error: {str(e)}")

        return result

    def _discover_apparmor_status(self, host: Host) -> Dict[str, Any]:
        """Discover AppArmor status and profiles"""
        result = {"apparmor_status": "Unknown", "errors": []}

        try:
            # Check AppArmor status
            output = self.ssh_service.execute_command("aa-status", timeout=10)
            if output and output["success"]:
                status_text = output["stdout"]

                # Parse aa-status output
                apparmor_info = {"status": "enabled"}

                # Extract profile counts
                profiles_loaded_match = re.search(r"(\d+) profiles are loaded", status_text)
                profiles_enforce_match = re.search(r"(\d+) profiles are in enforce mode", status_text)
                profiles_complain_match = re.search(r"(\d+) profiles are in complain mode", status_text)

                if profiles_loaded_match:
                    apparmor_info["profiles_loaded"] = int(profiles_loaded_match.group(1))
                if profiles_enforce_match:
                    apparmor_info["profiles_enforce"] = int(profiles_enforce_match.group(1))
                if profiles_complain_match:
                    apparmor_info["profiles_complain"] = int(profiles_complain_match.group(1))

                result["apparmor_status"] = apparmor_info
                logger.debug(f"AppArmor status: enabled with {apparmor_info.get('profiles_loaded', 0)} profiles")
                return result

            # Check if AppArmor is installed but not running
            output = self.ssh_service.execute_command("which apparmor_status", timeout=5)
            if output and output["success"]:
                result["apparmor_status"] = {"status": "installed_but_inactive"}
            else:
                result["apparmor_status"] = {"status": "not_installed"}

        except Exception as e:
            logger.warning(f"Error discovering AppArmor status for {host.hostname}: {str(e)}")
            result["errors"].append(f"AppArmor discovery error: {str(e)}")

        return result

    def _discover_firewall_services(self, host: Host) -> Dict[str, Any]:
        """Discover active firewall services"""
        result = {"firewall_services": {}, "errors": []}

        firewall_services = {
            "firewalld": "FirewallD (RHEL/Fedora)",
            "ufw": "UFW (Ubuntu)",
            "iptables": "iptables",
            "nftables": "nftables",
            "pf": "Packet Filter (BSD)",
        }

        try:
            for fw_service, fw_name in firewall_services.items():
                # Check if service is active using systemctl
                output = self.ssh_service.execute_command(f"systemctl is-active {fw_service}", timeout=5)
                if output and output["success"] and "active" in output["stdout"].strip():
                    # Get additional status info
                    status_output = self.ssh_service.execute_command(
                        f"systemctl status {fw_service} --no-pager -l", timeout=10
                    )

                    fw_info = {
                        "name": fw_name,
                        "status": "active",
                        "service": fw_service,
                    }

                    if status_output and status_output["success"]:
                        status_text = status_output["stdout"]
                        # Extract useful information
                        if "enabled" in status_text:
                            fw_info["enabled"] = True
                        loaded_match = re.search(r"Loaded: ([^;]+)", status_text)
                        if loaded_match:
                            fw_info["loaded_status"] = loaded_match.group(1).strip()

                    result["firewall_services"][fw_service] = fw_info
                    logger.debug(f"Found active firewall: {fw_name}")

                # Special handling for iptables - check if rules exist
                elif fw_service == "iptables":
                    output = self.ssh_service.execute_command("iptables -L -n | wc -l", timeout=10)
                    if output and output["success"]:
                        rule_count = int(output["stdout"].strip()) if output["stdout"].strip().isdigit() else 0
                        if rule_count > 8:  # More than default empty chains
                            result["firewall_services"]["iptables"] = {
                                "name": fw_name,
                                "status": "active_with_rules",
                                "rule_count": rule_count,
                            }
                            logger.debug(f"Found iptables with {rule_count} rules")

        except Exception as e:
            logger.warning(f"Error discovering firewall services for {host.hostname}: {str(e)}")
            result["errors"].append(f"Firewall discovery error: {str(e)}")

        return result

    def _compile_security_tools(self, discovery_results: Dict[str, Any]) -> List[str]:
        """Compile a list of detected security tools"""
        tools = []

        # Add package managers
        if discovery_results.get("package_managers"):
            tools.extend([f"Package Manager: {pm['name']}" for pm in discovery_results["package_managers"].values()])

        # Add service manager
        if discovery_results.get("service_manager") and discovery_results["service_manager"] != "Unknown":
            tools.append(f"Service Manager: {discovery_results['service_manager']}")

        # Add SELinux if enabled
        selinux_status = discovery_results.get("selinux_status")
        if isinstance(selinux_status, dict) and selinux_status.get("status") == "enabled":
            mode = selinux_status.get("enforcement_mode", "Unknown")
            tools.append(f"SELinux: {mode}")

        # Add AppArmor if enabled
        apparmor_status = discovery_results.get("apparmor_status")
        if isinstance(apparmor_status, dict) and apparmor_status.get("status") == "enabled":
            profiles = apparmor_status.get("profiles_loaded", 0)
            tools.append(f"AppArmor: {profiles} profiles loaded")

        # Add active firewalls
        if discovery_results.get("firewall_services"):
            for fw_name, fw_info in discovery_results["firewall_services"].items():
                tools.append(f"Firewall: {fw_info['name']}")

        return tools
