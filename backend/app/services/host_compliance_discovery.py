"""
Host Compliance Infrastructure Discovery Service
Identifies compliance tools, SCAP capabilities, and security scanners on target hosts
"""

import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..database import Host
from ..services.unified_ssh_service import UnifiedSSHService as SSHService

logger = logging.getLogger(__name__)


class HostComplianceDiscoveryService:
    """
    Service for discovering compliance infrastructure and tooling on hosts
    """

    def __init__(self, ssh_service: Optional[SSHService] = None):
        """Initialize the compliance discovery service"""
        self.ssh_service = ssh_service or SSHService()

    def discover_compliance_infrastructure(self, host: Host) -> Dict[str, Any]:
        """
        Discover compliance infrastructure and tooling on a host

        Args:
            host: Host object to discover compliance information for

        Returns:
            Dictionary containing discovered compliance information
        """
        logger.info(f"Starting compliance infrastructure discovery for host: {host.hostname}")

        discovery_results = {
            "python_environments": {},
            "openscap_tools": {},
            "privilege_escalation": {},
            "compliance_scanners": {},
            "filesystem_capabilities": {},
            "audit_tools": {},
            "compliance_frameworks": [],
            "discovery_timestamp": datetime.utcnow(),
            "discovery_success": False,
            "discovery_errors": [],
        }

        try:
            # Establish SSH connection
            if not self.ssh_service.connect(host):
                discovery_results["discovery_errors"].append("Failed to establish SSH connection")
                return discovery_results

            # 1. Discover Python environments and versions
            python_info = self._discover_python_environments(host)
            discovery_results["python_environments"] = python_info.get("python_environments", {})
            discovery_results["discovery_errors"].extend(python_info.get("errors", []))

            # 2. Discover OpenSCAP tools and capabilities
            openscap_info = self._discover_openscap_tools(host)
            discovery_results["openscap_tools"] = openscap_info.get("openscap_tools", {})
            discovery_results["discovery_errors"].extend(openscap_info.get("errors", []))

            # 3. Discover privilege escalation capabilities
            privilege_info = self._discover_privilege_escalation(host)
            discovery_results["privilege_escalation"] = privilege_info.get(
                "privilege_escalation", {}
            )
            discovery_results["discovery_errors"].extend(privilege_info.get("errors", []))

            # 4. Discover other compliance scanners
            scanner_info = self._discover_compliance_scanners(host)
            discovery_results["compliance_scanners"] = scanner_info.get("compliance_scanners", {})
            discovery_results["discovery_errors"].extend(scanner_info.get("errors", []))

            # 5. Discover filesystem capabilities
            filesystem_info = self._discover_filesystem_capabilities(host)
            discovery_results["filesystem_capabilities"] = filesystem_info.get(
                "filesystem_capabilities", {}
            )
            discovery_results["discovery_errors"].extend(filesystem_info.get("errors", []))

            # 6. Discover audit and logging tools
            audit_info = self._discover_audit_tools(host)
            discovery_results["audit_tools"] = audit_info.get("audit_tools", {})
            discovery_results["discovery_errors"].extend(audit_info.get("errors", []))

            # 7. Compile compliance frameworks list
            discovery_results["compliance_frameworks"] = self._compile_compliance_frameworks(
                discovery_results
            )

            # Update discovery success status
            discovery_results["discovery_success"] = len(discovery_results["discovery_errors"]) == 0

            logger.info(
                f"Compliance infrastructure discovery completed for {host.hostname}: "
                f"Python={len(discovery_results['python_environments'])}, "
                f"SCAP={len(discovery_results['openscap_tools'])}, "
                f"Sudo={'yes' if discovery_results['privilege_escalation'].get('sudo') else 'no'}"
            )

        except Exception as e:
            logger.error(f"Compliance discovery failed for {host.hostname}: {str(e)}")
            discovery_results["discovery_errors"].append(f"Discovery exception: {str(e)}")

        finally:
            self.ssh_service.disconnect()

        return discovery_results

    def _discover_python_environments(self, host: Host) -> Dict[str, Any]:
        """Discover Python installations and versions"""
        result = {"python_environments": {}, "errors": []}

        # Python executables to check
        python_executables = [
            "python",
            "python3",
            "python2",
            "python3.8",
            "python3.9",
            "python3.10",
            "python3.11",
            "python3.12",
        ]

        try:
            for py_exec in python_executables:
                output = self.ssh_service.execute_command(f"which {py_exec}", timeout=5)
                if output and output["success"] and output["stdout"].strip():
                    # Get Python version
                    version_output = self.ssh_service.execute_command(
                        f"{py_exec} --version", timeout=5
                    )
                    version = "Unknown"
                    if version_output and version_output["success"]:
                        version_text = (
                            version_output["stdout"].strip()
                            or version_output.get("stderr", "").strip()
                        )
                        version_match = re.search(r"Python (\\d+\\.\\d+\\.\\d+)", version_text)
                        if version_match:
                            version = version_match.group(1)

                    # Check for pip availability
                    pip_available = False
                    pip_output = self.ssh_service.execute_command(
                        f"{py_exec} -m pip --version", timeout=5
                    )
                    if pip_output and pip_output["success"]:
                        pip_available = True

                    # Check for virtual environment support
                    venv_available = False
                    venv_output = self.ssh_service.execute_command(
                        f"{py_exec} -m venv --help", timeout=5
                    )
                    if venv_output and venv_output["success"]:
                        venv_available = True

                    result["python_environments"][py_exec] = {
                        "path": output["stdout"].strip(),
                        "version": version,
                        "pip_available": pip_available,
                        "venv_available": venv_available,
                        "executable": py_exec,
                    }

                    logger.debug(
                        f"Found Python: {py_exec} version {version} at {output['stdout'].strip()}"
                    )

        except Exception as e:
            logger.warning(f"Error discovering Python environments for {host.hostname}: {str(e)}")
            result["errors"].append(f"Python discovery error: {str(e)}")

        return result

    def _discover_openscap_tools(self, host: Host) -> Dict[str, Any]:
        """Discover OpenSCAP tools and capabilities"""
        result = {"openscap_tools": {}, "errors": []}

        # OpenSCAP tools to check
        openscap_tools = {
            "oscap": "OpenSCAP Scanner",
            "scap-workbench": "SCAP Workbench GUI",
            "oscap-docker": "OpenSCAP Docker Scanner",
            "oscap-chroot": "OpenSCAP Chroot Scanner",
            "oscap-vm": "OpenSCAP VM Scanner",
        }

        try:
            for tool_cmd, tool_name in openscap_tools.items():
                output = self.ssh_service.execute_command(f"which {tool_cmd}", timeout=5)
                if output and output["success"] and output["stdout"].strip():
                    # Get version if possible
                    version_output = self.ssh_service.execute_command(
                        f"{tool_cmd} --version", timeout=10
                    )
                    version = "Unknown"
                    capabilities = []

                    if version_output and version_output["success"]:
                        version_text = version_output["stdout"].strip()
                        # Extract version number
                        version_match = re.search(r"(\\d+\\.\\d+[\\.\\d]*)", version_text)
                        if version_match:
                            version = version_match.group(1)

                    # Check tool-specific capabilities
                    if tool_cmd == "oscap":
                        # Check for XCCDF support
                        xccdf_output = self.ssh_service.execute_command(
                            "oscap xccdf --help", timeout=5
                        )
                        if xccdf_output and xccdf_output["success"]:
                            capabilities.append("XCCDF")

                        # Check for OVAL support
                        oval_output = self.ssh_service.execute_command(
                            "oscap oval --help", timeout=5
                        )
                        if oval_output and oval_output["success"]:
                            capabilities.append("OVAL")

                        # Check for CVE support
                        cve_output = self.ssh_service.execute_command("oscap cve --help", timeout=5)
                        if cve_output and cve_output["success"]:
                            capabilities.append("CVE")

                        # Check for CPE support
                        cpe_output = self.ssh_service.execute_command("oscap cpe --help", timeout=5)
                        if cpe_output and cpe_output["success"]:
                            capabilities.append("CPE")

                    result["openscap_tools"][tool_cmd] = {
                        "name": tool_name,
                        "path": output["stdout"].strip(),
                        "version": version,
                        "capabilities": capabilities,
                        "available": True,
                    }

                    logger.debug(f"Found OpenSCAP tool: {tool_name} version {version}")

            # Check for SCAP content directories
            scap_content_dirs = [
                "/usr/share/scap-security-guide/",
                "/usr/share/xml/scap/",
                "/var/lib/scap/",
                "/opt/scap-content/",
            ]

            available_content = []
            for content_dir in scap_content_dirs:
                dir_check = self.ssh_service.execute_command(f"ls -la {content_dir}", timeout=5)
                if dir_check and dir_check["success"]:
                    available_content.append(content_dir)

            if available_content:
                result["openscap_tools"]["scap_content_directories"] = {
                    "name": "SCAP Content Directories",
                    "directories": available_content,
                    "available": True,
                }

        except Exception as e:
            logger.warning(f"Error discovering OpenSCAP tools for {host.hostname}: {str(e)}")
            result["errors"].append(f"OpenSCAP discovery error: {str(e)}")

        return result

    def _discover_privilege_escalation(self, host: Host) -> Dict[str, Any]:
        """Discover privilege escalation capabilities (sudo, su, etc.)"""
        result = {"privilege_escalation": {}, "errors": []}

        try:
            # Check for sudo
            sudo_output = self.ssh_service.execute_command("which sudo", timeout=5)
            if sudo_output and sudo_output["success"] and sudo_output["stdout"].strip():
                # Get sudo version
                sudo_version_output = self.ssh_service.execute_command("sudo --version", timeout=5)
                sudo_version = "Unknown"
                if sudo_version_output and sudo_version_output["success"]:
                    version_text = sudo_version_output["stdout"].strip()
                    version_match = re.search(r"version (\\d+\\.\\d+[\\.\\d]*)", version_text)
                    if version_match:
                        sudo_version = version_match.group(1)

                # Check sudo configuration (basic check)
                sudoers_check = self.ssh_service.execute_command("sudo -l", timeout=10)
                sudo_configured = sudoers_check and sudoers_check["success"]

                result["privilege_escalation"]["sudo"] = {
                    "available": True,
                    "path": sudo_output["stdout"].strip(),
                    "version": sudo_version,
                    "configured": sudo_configured,
                }

                logger.debug(f"Found sudo version {sudo_version}")
            else:
                result["privilege_escalation"]["sudo"] = {"available": False}

            # Check for su
            su_output = self.ssh_service.execute_command("which su", timeout=5)
            if su_output and su_output["success"] and su_output["stdout"].strip():
                result["privilege_escalation"]["su"] = {
                    "available": True,
                    "path": su_output["stdout"].strip(),
                }
            else:
                result["privilege_escalation"]["su"] = {"available": False}

            # Check for doas (OpenBSD alternative to sudo)
            doas_output = self.ssh_service.execute_command("which doas", timeout=5)
            if doas_output and doas_output["success"] and doas_output["stdout"].strip():
                result["privilege_escalation"]["doas"] = {
                    "available": True,
                    "path": doas_output["stdout"].strip(),
                }
            else:
                result["privilege_escalation"]["doas"] = {"available": False}

        except Exception as e:
            logger.warning(f"Error discovering privilege escalation for {host.hostname}: {str(e)}")
            result["errors"].append(f"Privilege escalation discovery error: {str(e)}")

        return result

    def _discover_compliance_scanners(self, host: Host) -> Dict[str, Any]:
        """Discover other compliance and security scanners"""
        result = {"compliance_scanners": {}, "errors": []}

        # Compliance scanners to check
        scanners = {
            "nessus": "Tenable Nessus",
            "openvas": "OpenVAS Scanner",
            "lynis": "Lynis Security Auditor",
            "inspec": "Chef InSpec",
            "compliance-tools": "ComplianceAsCode Tools",
            "scapval": "SCAP Validation Tool",
            "aide": "AIDE File Integrity Monitor",
            "tripwire": "Tripwire File Integrity Monitor",
            "samhain": "Samhain File Integrity Monitor",
            "chkrootkit": "Rootkit Checker",
            "rkhunter": "Rootkit Hunter",
            "clamav": "ClamAV Antivirus",
        }

        try:
            for scanner_cmd, scanner_name in scanners.items():
                output = self.ssh_service.execute_command(f"which {scanner_cmd}", timeout=5)
                if output and output["success"] and output["stdout"].strip():
                    # Get version if possible
                    version_output = self.ssh_service.execute_command(
                        f"{scanner_cmd} --version", timeout=10
                    )
                    version = "Unknown"
                    if version_output and version_output["success"]:
                        version_text = version_output["stdout"].strip()
                        # Extract version number from output
                        version_match = re.search(r"(\\d+\\.\\d+[\\.\\d]*)", version_text)
                        if version_match:
                            version = version_match.group(1)

                    result["compliance_scanners"][scanner_cmd] = {
                        "name": scanner_name,
                        "path": output["stdout"].strip(),
                        "version": version,
                        "available": True,
                    }

                    logger.debug(f"Found compliance scanner: {scanner_name} version {version}")

        except Exception as e:
            logger.warning(f"Error discovering compliance scanners for {host.hostname}: {str(e)}")
            result["errors"].append(f"Compliance scanner discovery error: {str(e)}")

        return result

    def _discover_filesystem_capabilities(self, host: Host) -> Dict[str, Any]:
        """Discover filesystem capabilities relevant to compliance"""
        result = {"filesystem_capabilities": {}, "errors": []}

        try:
            # Check mounted filesystems and their properties
            mount_output = self.ssh_service.execute_command(
                'mount | grep -E "ext[234]|xfs|btrfs|zfs"', timeout=10
            )
            if mount_output and mount_output["success"]:
                filesystems = []
                for line in mount_output["stdout"].strip().split("\\n"):
                    if line.strip():
                        # Parse mount line
                        parts = line.split()
                        if len(parts) >= 3:
                            device = parts[0]
                            mountpoint = parts[2]
                            fs_type = parts[4] if len(parts) > 4 else "unknown"
                            options = parts[5] if len(parts) > 5 else ""

                            filesystems.append(
                                {
                                    "device": device,
                                    "mountpoint": mountpoint,
                                    "type": fs_type,
                                    "options": options,
                                }
                            )

                result["filesystem_capabilities"]["mounted_filesystems"] = filesystems

            # Check for extended attribute support
            xattr_output = self.ssh_service.execute_command("which getfattr", timeout=5)
            result["filesystem_capabilities"]["extended_attributes"] = {
                "available": xattr_output
                and xattr_output["success"]
                and xattr_output["stdout"].strip()
            }

            # Check for SELinux filesystem labels (if SELinux is available)
            selinux_labels = self.ssh_service.execute_command("which restorecon", timeout=5)
            result["filesystem_capabilities"]["selinux_labels"] = {
                "available": selinux_labels
                and selinux_labels["success"]
                and selinux_labels["stdout"].strip()
            }

            # Check for file capabilities
            getcap_output = self.ssh_service.execute_command("which getcap", timeout=5)
            result["filesystem_capabilities"]["file_capabilities"] = {
                "available": getcap_output
                and getcap_output["success"]
                and getcap_output["stdout"].strip()
            }

        except Exception as e:
            logger.warning(
                f"Error discovering filesystem capabilities for {host.hostname}: {str(e)}"
            )
            result["errors"].append(f"Filesystem capability discovery error: {str(e)}")

        return result

    def _discover_audit_tools(self, host: Host) -> Dict[str, Any]:
        """Discover audit and logging tools"""
        result = {"audit_tools": {}, "errors": []}

        # Audit tools to check
        audit_tools = {
            "auditd": "Linux Audit Daemon",
            "auditctl": "Audit Control Program",
            "ausearch": "Audit Log Search",
            "aureport": "Audit Report Generator",
            "rsyslog": "RSyslog Daemon",
            "syslog-ng": "Syslog-NG Daemon",
            "journalctl": "SystemD Journal Control",
            "logrotate": "Log Rotation Tool",
            "logwatch": "Log Analysis System",
        }

        try:
            for tool_cmd, tool_name in audit_tools.items():
                output = self.ssh_service.execute_command(f"which {tool_cmd}", timeout=5)
                if output and output["success"] and output["stdout"].strip():
                    # Get version if possible
                    version_output = None
                    if tool_cmd in ["auditctl", "ausearch", "aureport"]:
                        version_output = self.ssh_service.execute_command(
                            f"{tool_cmd} --version", timeout=5
                        )
                    elif tool_cmd == "journalctl":
                        version_output = self.ssh_service.execute_command(
                            "systemctl --version", timeout=5
                        )
                    elif tool_cmd == "rsyslog":
                        version_output = self.ssh_service.execute_command("rsyslogd -v", timeout=5)

                    version = "Unknown"
                    if version_output and version_output["success"]:
                        version_text = version_output["stdout"].strip()
                        version_match = re.search(r"(\\d+\\.\\d+[\\.\\d]*)", version_text)
                        if version_match:
                            version = version_match.group(1)

                    # Check if service is running (for daemons)
                    running = False
                    if tool_cmd in ["auditd", "rsyslog", "syslog-ng"]:
                        service_check = self.ssh_service.execute_command(
                            f"systemctl is-active {tool_cmd}", timeout=5
                        )
                        if (
                            service_check
                            and service_check["success"]
                            and "active" in service_check["stdout"]
                        ):
                            running = True

                    result["audit_tools"][tool_cmd] = {
                        "name": tool_name,
                        "path": output["stdout"].strip(),
                        "version": version,
                        "running": running,
                        "available": True,
                    }

                    logger.debug(f"Found audit tool: {tool_name} version {version}")

        except Exception as e:
            logger.warning(f"Error discovering audit tools for {host.hostname}: {str(e)}")
            result["errors"].append(f"Audit tool discovery error: {str(e)}")

        return result

    def _compile_compliance_frameworks(self, discovery_results: Dict[str, Any]) -> List[str]:
        """Compile a list of supported compliance frameworks based on discovered tools"""
        frameworks = []

        # Check for OpenSCAP tools (supports multiple frameworks)
        if discovery_results.get("openscap_tools"):
            oscap_tools = discovery_results["openscap_tools"]
            if any(tool.get("available") for tool in oscap_tools.values()):
                frameworks.extend(
                    [
                        "NIST 800-53",
                        "DISA STIG",
                        "CIS Controls",
                        "PCI DSS",
                        "FISMA",
                        "HIPAA",
                        "SOX",
                    ]
                )

        # Check for Chef InSpec
        if discovery_results.get("compliance_scanners", {}).get("inspec", {}).get("available"):
            frameworks.extend(["CIS Benchmarks", "DevSec Hardening Framework"])

        # Check for Lynis
        if discovery_results.get("compliance_scanners", {}).get("lynis", {}).get("available"):
            frameworks.extend(["System Hardening", "Security Benchmarks"])

        # Check for audit tools (supports various compliance requirements)
        audit_tools = discovery_results.get("audit_tools", {})
        if any(tool.get("available") for tool in audit_tools.values()):
            frameworks.extend(["SOX Compliance", "GDPR Compliance", "FISMA Compliance"])

        # Check for file integrity monitors
        fim_tools = ["aide", "tripwire", "samhain"]
        if any(
            discovery_results.get("compliance_scanners", {}).get(tool, {}).get("available")
            for tool in fim_tools
        ):
            frameworks.extend(["File Integrity Monitoring", "Change Detection"])

        return list(set(frameworks))  # Remove duplicates
