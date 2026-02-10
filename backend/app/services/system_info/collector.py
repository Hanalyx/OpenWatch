"""
System Information Collector Service

Collects detailed system information from remote hosts via SSH.
Used during compliance scans to gather rich system data.

Part of OpenWatch OS Transformation - Server Intelligence.
"""

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


@dataclass
class SystemInfo:
    """Collected system information from a host."""

    # OS Information
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    os_version_full: Optional[str] = None
    os_pretty_name: Optional[str] = None
    os_id: Optional[str] = None
    os_id_like: Optional[str] = None

    # Kernel Information
    kernel_version: Optional[str] = None
    kernel_release: Optional[str] = None
    kernel_name: Optional[str] = None

    # Hardware Information
    architecture: Optional[str] = None
    cpu_model: Optional[str] = None
    cpu_cores: Optional[int] = None
    cpu_threads: Optional[int] = None
    memory_total_mb: Optional[int] = None
    memory_available_mb: Optional[int] = None
    swap_total_mb: Optional[int] = None

    # Disk Information
    disk_total_gb: Optional[float] = None
    disk_used_gb: Optional[float] = None
    disk_free_gb: Optional[float] = None

    # Security Status
    selinux_status: Optional[str] = None
    selinux_mode: Optional[str] = None
    firewall_status: Optional[str] = None
    firewall_service: Optional[str] = None

    # Network Information
    hostname: Optional[str] = None
    fqdn: Optional[str] = None
    primary_ip: Optional[str] = None

    # System Uptime
    uptime_seconds: Optional[int] = None
    boot_time: Optional[datetime] = None


@dataclass
class PackageInfo:
    """Information about an installed package."""

    name: str
    version: Optional[str] = None
    release: Optional[str] = None
    arch: Optional[str] = None
    source_repo: Optional[str] = None
    installed_at: Optional[datetime] = None


@dataclass
class ServiceInfo:
    """Information about a system service."""

    name: str
    display_name: Optional[str] = None
    status: Optional[str] = None  # running, stopped, failed
    enabled: Optional[bool] = None
    service_type: Optional[str] = None  # simple, forking, oneshot
    run_as_user: Optional[str] = None
    listening_ports: List[Dict[str, Any]] = field(default_factory=list)


class SystemInfoCollector:
    """Collects system information from remote hosts via SSH."""

    def __init__(self, ssh_session: Any):
        """
        Initialize with an SSH session.

        Args:
            ssh_session: An SSH session object with run() method (Aegis SSHSession or similar)
        """
        self.ssh = ssh_session

    def _run_command(self, command: str) -> Optional[str]:
        """Run a command and return stdout, or None on error."""
        try:
            result = self.ssh.run(command)
            if result.returncode == 0:
                return result.stdout.strip()
            return None
        except Exception as e:
            logger.debug(f"Command '{command}' failed: {e}")
            return None

    def collect(self) -> SystemInfo:
        """
        Collect all system information from the remote host.

        Returns:
            SystemInfo dataclass with collected data
        """
        info = SystemInfo()

        # Collect OS information from /etc/os-release
        self._collect_os_info(info)

        # Collect kernel information
        self._collect_kernel_info(info)

        # Collect hardware information
        self._collect_hardware_info(info)

        # Collect disk information
        self._collect_disk_info(info)

        # Collect security status
        self._collect_security_status(info)

        # Collect network information
        self._collect_network_info(info)

        # Collect uptime
        self._collect_uptime(info)

        return info

    def _collect_os_info(self, info: SystemInfo) -> None:
        """Collect OS information from /etc/os-release."""
        os_release = self._run_command("cat /etc/os-release 2>/dev/null")
        if os_release:
            # Parse key=value pairs
            for line in os_release.split("\n"):
                if "=" in line:
                    key, value = line.split("=", 1)
                    value = value.strip('"').strip("'")

                    if key == "NAME":
                        info.os_name = value
                    elif key == "VERSION":
                        info.os_version_full = value
                    elif key == "VERSION_ID":
                        info.os_version = value
                    elif key == "PRETTY_NAME":
                        info.os_pretty_name = value
                    elif key == "ID":
                        info.os_id = value
                    elif key == "ID_LIKE":
                        info.os_id_like = value

    def _collect_kernel_info(self, info: SystemInfo) -> None:
        """Collect kernel information using uname."""
        info.kernel_name = self._run_command("uname -s")
        info.kernel_release = self._run_command("uname -r")
        info.kernel_version = self._run_command("uname -v")
        info.architecture = self._run_command("uname -m")

    def _collect_hardware_info(self, info: SystemInfo) -> None:
        """Collect CPU and memory information."""
        # CPU model from /proc/cpuinfo
        cpu_info = self._run_command("grep 'model name' /proc/cpuinfo | head -1")
        if cpu_info:
            match = re.search(r"model name\s*:\s*(.+)", cpu_info)
            if match:
                info.cpu_model = match.group(1).strip()

        # CPU cores (physical)
        cores = self._run_command("grep -c '^processor' /proc/cpuinfo")
        if cores:
            try:
                info.cpu_threads = int(cores)
            except ValueError:
                pass

        # Physical cores (may be different from threads)
        physical_cores = self._run_command("grep 'cpu cores' /proc/cpuinfo | head -1 | awk '{print $4}'")
        if physical_cores:
            try:
                info.cpu_cores = int(physical_cores)
            except ValueError:
                # Fall back to threads count
                info.cpu_cores = info.cpu_threads

        # Memory information from /proc/meminfo
        meminfo = self._run_command("cat /proc/meminfo")
        if meminfo:
            for line in meminfo.split("\n"):
                if line.startswith("MemTotal:"):
                    match = re.search(r"(\d+)", line)
                    if match:
                        info.memory_total_mb = int(match.group(1)) // 1024
                elif line.startswith("MemAvailable:"):
                    match = re.search(r"(\d+)", line)
                    if match:
                        info.memory_available_mb = int(match.group(1)) // 1024
                elif line.startswith("SwapTotal:"):
                    match = re.search(r"(\d+)", line)
                    if match:
                        info.swap_total_mb = int(match.group(1)) // 1024

    def _collect_disk_info(self, info: SystemInfo) -> None:
        """Collect disk usage for root filesystem."""
        # Get disk usage for root partition
        df_output = self._run_command("df -BG / | tail -1")
        if df_output:
            # Format: Filesystem Size Used Avail Use% Mounted
            parts = df_output.split()
            if len(parts) >= 4:
                try:
                    # Remove 'G' suffix and convert to float
                    info.disk_total_gb = float(parts[1].rstrip("G"))
                    info.disk_used_gb = float(parts[2].rstrip("G"))
                    info.disk_free_gb = float(parts[3].rstrip("G"))
                except (ValueError, IndexError):
                    pass

    def _collect_security_status(self, info: SystemInfo) -> None:
        """Collect SELinux and firewall status."""
        # SELinux status
        selinux_status = self._run_command("getenforce 2>/dev/null")
        if selinux_status:
            info.selinux_status = selinux_status.lower()

        # SELinux mode (targeted, mls, etc.)
        selinux_config = self._run_command("grep '^SELINUXTYPE=' /etc/selinux/config 2>/dev/null")
        if selinux_config:
            match = re.search(r"SELINUXTYPE=(\w+)", selinux_config)
            if match:
                info.selinux_mode = match.group(1)

        # Firewall status - try firewalld first
        firewalld_status = self._run_command("systemctl is-active firewalld 2>/dev/null")
        if firewalld_status == "active":
            info.firewall_status = "active"
            info.firewall_service = "firewalld"
        else:
            # Try iptables
            iptables_rules = self._run_command("iptables -L -n 2>/dev/null | grep -c '^[A-Z]'")
            if iptables_rules and int(iptables_rules) > 3:  # More than default chains
                info.firewall_status = "active"
                info.firewall_service = "iptables"
            else:
                # Try nftables
                nft_rules = self._run_command("nft list tables 2>/dev/null | wc -l")
                if nft_rules and int(nft_rules) > 0:
                    info.firewall_status = "active"
                    info.firewall_service = "nftables"
                else:
                    # Try ufw (Ubuntu)
                    ufw_status = self._run_command("ufw status 2>/dev/null | head -1")
                    if ufw_status and "active" in ufw_status.lower():
                        info.firewall_status = "active"
                        info.firewall_service = "ufw"
                    else:
                        info.firewall_status = "inactive"

    def _collect_network_info(self, info: SystemInfo) -> None:
        """Collect hostname and network information."""
        info.hostname = self._run_command("hostname")
        info.fqdn = self._run_command("hostname -f 2>/dev/null")

        # Get primary IP (default route interface)
        primary_ip = self._run_command("ip route get 1 2>/dev/null | head -1 | awk '{print $7}'")
        if primary_ip:
            info.primary_ip = primary_ip

    def _collect_uptime(self, info: SystemInfo) -> None:
        """Collect system uptime."""
        uptime = self._run_command("cat /proc/uptime | awk '{print $1}'")
        if uptime:
            try:
                info.uptime_seconds = int(float(uptime))
                # Calculate boot time
                info.boot_time = datetime.now(timezone.utc) - __import__("datetime").timedelta(
                    seconds=info.uptime_seconds
                )
            except ValueError:
                pass

    def collect_packages(self) -> List[PackageInfo]:
        """
        Collect installed packages from the remote host.

        Returns:
            List of PackageInfo dataclasses with package details
        """
        packages: List[PackageInfo] = []

        # Try RPM first (RHEL, CentOS, Fedora)
        rpm_output = self._run_command(
            "rpm -qa --queryformat '%{NAME}|%{VERSION}|%{RELEASE}|%{ARCH}|%{INSTALLTIME}\\n'"
        )
        if rpm_output:
            for line in rpm_output.split("\n"):
                if "|" in line:
                    parts = line.strip().split("|")
                    if len(parts) >= 4:
                        installed_at = None
                        if len(parts) >= 5 and parts[4]:
                            try:
                                installed_at = datetime.fromtimestamp(int(parts[4]), tz=timezone.utc)
                            except (ValueError, OSError):
                                pass

                        packages.append(
                            PackageInfo(
                                name=parts[0],
                                version=parts[1] if parts[1] else None,
                                release=parts[2] if parts[2] else None,
                                arch=parts[3] if parts[3] else None,
                                installed_at=installed_at,
                            )
                        )
            logger.info(f"Collected {len(packages)} RPM packages")
            return packages

        # Try dpkg for Debian/Ubuntu
        dpkg_output = self._run_command("dpkg-query -W -f='${Package}|${Version}|${Architecture}|${Status}\\n'")
        if dpkg_output:
            for line in dpkg_output.split("\n"):
                if "|" in line:
                    parts = line.strip().split("|")
                    if len(parts) >= 3:
                        # Only include installed packages
                        status = parts[3] if len(parts) >= 4 else ""
                        if "installed" in status.lower():
                            # Parse Debian version format (version-release)
                            version = parts[1]
                            release = None
                            if "-" in version:
                                version, release = version.rsplit("-", 1)

                            packages.append(
                                PackageInfo(
                                    name=parts[0],
                                    version=version,
                                    release=release,
                                    arch=parts[2] if parts[2] else None,
                                )
                            )
            logger.info(f"Collected {len(packages)} DEB packages")
            return packages

        logger.warning("Could not collect packages - neither RPM nor dpkg available")
        return packages

    def collect_services(self) -> List[ServiceInfo]:
        """
        Collect running services from the remote host.

        Returns:
            List of ServiceInfo dataclasses with service details
        """
        services: List[ServiceInfo] = []

        # Get systemd services
        systemctl_output = self._run_command(
            "systemctl list-units --type=service --all --no-legend --no-pager "
            "--output=json 2>/dev/null || "
            "systemctl list-units --type=service --all --no-legend --no-pager"
        )

        if not systemctl_output:
            logger.warning("Could not collect services - systemctl not available")
            return services

        # Try to parse JSON output first (newer systemd)
        try:
            service_data = json.loads(systemctl_output)
            for svc in service_data:
                services.append(
                    ServiceInfo(
                        name=svc.get("unit", "").replace(".service", ""),
                        display_name=svc.get("description"),
                        status=svc.get("sub", "unknown"),
                        enabled=None,  # Need separate query
                    )
                )
        except json.JSONDecodeError:
            # Fall back to text parsing
            for line in systemctl_output.split("\n"):
                parts = line.split()
                if len(parts) >= 4:
                    name = parts[0].replace(".service", "")
                    # Format: UNIT LOAD ACTIVE SUB DESCRIPTION...
                    status = parts[3] if len(parts) > 3 else "unknown"
                    description = " ".join(parts[4:]) if len(parts) > 4 else None

                    services.append(
                        ServiceInfo(
                            name=name,
                            display_name=description,
                            status=status,
                        )
                    )

        # Get enabled status for services
        enabled_output = self._run_command("systemctl list-unit-files --type=service --no-legend --no-pager")
        if enabled_output:
            enabled_map: Dict[str, bool] = {}
            for line in enabled_output.split("\n"):
                parts = line.split()
                if len(parts) >= 2:
                    name = parts[0].replace(".service", "")
                    state = parts[1].lower()
                    enabled_map[name] = state in ("enabled", "static")

            for svc in services:
                if svc.name in enabled_map:
                    svc.enabled = enabled_map[svc.name]

        # Get listening ports via ss
        ports_output = self._run_command("ss -tlnp 2>/dev/null")
        if ports_output:
            # Parse ss output to map ports to processes
            port_map: Dict[str, List[Dict[str, Any]]] = {}
            for line in ports_output.split("\n")[1:]:  # Skip header
                parts = line.split()
                if len(parts) >= 6:
                    # Format: State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
                    local_addr = parts[3]
                    process_info = parts[-1] if len(parts) > 6 else ""

                    # Parse address and port
                    if ":" in local_addr:
                        addr, port = local_addr.rsplit(":", 1)
                        # Extract service name from process info
                        # Format: users:(("sshd",pid=1234,fd=3))
                        match = re.search(r'\("([^"]+)"', process_info)
                        if match:
                            service_name = match.group(1)
                            if service_name not in port_map:
                                port_map[service_name] = []
                            port_map[service_name].append(
                                {
                                    "port": int(port) if port.isdigit() else port,
                                    "protocol": "tcp",
                                    "address": addr if addr != "*" else "0.0.0.0",
                                }
                            )

            # Map ports to services
            for svc in services:
                if svc.name in port_map:
                    svc.listening_ports = port_map[svc.name]

        logger.info(f"Collected {len(services)} services")
        return services


class SystemInfoService:
    """Service for managing host system information in the database."""

    def __init__(self, db: Session):
        """Initialize with database session."""
        self.db = db

    def save_system_info(self, host_id: UUID, info: SystemInfo) -> None:
        """
        Save or update system information for a host.

        Args:
            host_id: The host UUID
            info: SystemInfo dataclass with collected data
        """
        now = datetime.now(timezone.utc)

        # Check if record exists
        result = self.db.execute(
            text("SELECT id FROM host_system_info WHERE host_id = :host_id"),
            {"host_id": str(host_id)},
        )
        existing = result.fetchone()

        if existing:
            # Update existing record
            self.db.execute(
                text(
                    """
                    UPDATE host_system_info SET
                        os_name = :os_name,
                        os_version = :os_version,
                        os_version_full = :os_version_full,
                        os_pretty_name = :os_pretty_name,
                        os_id = :os_id,
                        os_id_like = :os_id_like,
                        kernel_version = :kernel_version,
                        kernel_release = :kernel_release,
                        kernel_name = :kernel_name,
                        architecture = :architecture,
                        cpu_model = :cpu_model,
                        cpu_cores = :cpu_cores,
                        cpu_threads = :cpu_threads,
                        memory_total_mb = :memory_total_mb,
                        memory_available_mb = :memory_available_mb,
                        swap_total_mb = :swap_total_mb,
                        disk_total_gb = :disk_total_gb,
                        disk_used_gb = :disk_used_gb,
                        disk_free_gb = :disk_free_gb,
                        selinux_status = :selinux_status,
                        selinux_mode = :selinux_mode,
                        firewall_status = :firewall_status,
                        firewall_service = :firewall_service,
                        hostname = :hostname,
                        fqdn = :fqdn,
                        primary_ip = :primary_ip,
                        uptime_seconds = :uptime_seconds,
                        boot_time = :boot_time,
                        collected_at = :now,
                        updated_at = :now
                    WHERE host_id = :host_id
                """
                ),
                {
                    "host_id": str(host_id),
                    "os_name": info.os_name,
                    "os_version": info.os_version,
                    "os_version_full": info.os_version_full,
                    "os_pretty_name": info.os_pretty_name,
                    "os_id": info.os_id,
                    "os_id_like": info.os_id_like,
                    "kernel_version": info.kernel_version,
                    "kernel_release": info.kernel_release,
                    "kernel_name": info.kernel_name,
                    "architecture": info.architecture,
                    "cpu_model": info.cpu_model,
                    "cpu_cores": info.cpu_cores,
                    "cpu_threads": info.cpu_threads,
                    "memory_total_mb": info.memory_total_mb,
                    "memory_available_mb": info.memory_available_mb,
                    "swap_total_mb": info.swap_total_mb,
                    "disk_total_gb": info.disk_total_gb,
                    "disk_used_gb": info.disk_used_gb,
                    "disk_free_gb": info.disk_free_gb,
                    "selinux_status": info.selinux_status,
                    "selinux_mode": info.selinux_mode,
                    "firewall_status": info.firewall_status,
                    "firewall_service": info.firewall_service,
                    "hostname": info.hostname,
                    "fqdn": info.fqdn,
                    "primary_ip": info.primary_ip,
                    "uptime_seconds": info.uptime_seconds,
                    "boot_time": info.boot_time,
                    "now": now,
                },
            )
        else:
            # Insert new record
            self.db.execute(
                text(
                    """
                    INSERT INTO host_system_info (
                        host_id, os_name, os_version, os_version_full, os_pretty_name,
                        os_id, os_id_like, kernel_version, kernel_release, kernel_name,
                        architecture, cpu_model, cpu_cores, cpu_threads,
                        memory_total_mb, memory_available_mb, swap_total_mb,
                        disk_total_gb, disk_used_gb, disk_free_gb,
                        selinux_status, selinux_mode, firewall_status, firewall_service,
                        hostname, fqdn, primary_ip, uptime_seconds, boot_time,
                        collected_at, updated_at
                    ) VALUES (
                        :host_id, :os_name, :os_version, :os_version_full, :os_pretty_name,
                        :os_id, :os_id_like, :kernel_version, :kernel_release, :kernel_name,
                        :architecture, :cpu_model, :cpu_cores, :cpu_threads,
                        :memory_total_mb, :memory_available_mb, :swap_total_mb,
                        :disk_total_gb, :disk_used_gb, :disk_free_gb,
                        :selinux_status, :selinux_mode, :firewall_status, :firewall_service,
                        :hostname, :fqdn, :primary_ip, :uptime_seconds, :boot_time,
                        :now, :now
                    )
                """
                ),
                {
                    "host_id": str(host_id),
                    "os_name": info.os_name,
                    "os_version": info.os_version,
                    "os_version_full": info.os_version_full,
                    "os_pretty_name": info.os_pretty_name,
                    "os_id": info.os_id,
                    "os_id_like": info.os_id_like,
                    "kernel_version": info.kernel_version,
                    "kernel_release": info.kernel_release,
                    "kernel_name": info.kernel_name,
                    "architecture": info.architecture,
                    "cpu_model": info.cpu_model,
                    "cpu_cores": info.cpu_cores,
                    "cpu_threads": info.cpu_threads,
                    "memory_total_mb": info.memory_total_mb,
                    "memory_available_mb": info.memory_available_mb,
                    "swap_total_mb": info.swap_total_mb,
                    "disk_total_gb": info.disk_total_gb,
                    "disk_used_gb": info.disk_used_gb,
                    "disk_free_gb": info.disk_free_gb,
                    "selinux_status": info.selinux_status,
                    "selinux_mode": info.selinux_mode,
                    "firewall_status": info.firewall_status,
                    "firewall_service": info.firewall_service,
                    "hostname": info.hostname,
                    "fqdn": info.fqdn,
                    "primary_ip": info.primary_ip,
                    "uptime_seconds": info.uptime_seconds,
                    "boot_time": info.boot_time,
                    "now": now,
                },
            )

        self.db.commit()
        logger.info(f"Saved system info for host {host_id}")

    def get_system_info(self, host_id: UUID) -> Optional[Dict[str, Any]]:
        """
        Get system information for a host.

        Args:
            host_id: The host UUID

        Returns:
            Dictionary with system info or None if not found
        """
        result = self.db.execute(
            text(
                """
                SELECT
                    os_name, os_version, os_version_full, os_pretty_name,
                    os_id, os_id_like, kernel_version, kernel_release, kernel_name,
                    architecture, cpu_model, cpu_cores, cpu_threads,
                    memory_total_mb, memory_available_mb, swap_total_mb,
                    disk_total_gb, disk_used_gb, disk_free_gb,
                    selinux_status, selinux_mode, firewall_status, firewall_service,
                    hostname, fqdn, primary_ip, uptime_seconds, boot_time,
                    collected_at, updated_at
                FROM host_system_info
                WHERE host_id = :host_id
            """
            ),
            {"host_id": str(host_id)},
        )
        row = result.fetchone()
        if not row:
            return None

        return {
            "os_name": row.os_name,
            "os_version": row.os_version,
            "os_version_full": row.os_version_full,
            "os_pretty_name": row.os_pretty_name,
            "os_id": row.os_id,
            "os_id_like": row.os_id_like,
            "kernel_version": row.kernel_version,
            "kernel_release": row.kernel_release,
            "kernel_name": row.kernel_name,
            "architecture": row.architecture,
            "cpu_model": row.cpu_model,
            "cpu_cores": row.cpu_cores,
            "cpu_threads": row.cpu_threads,
            "memory_total_mb": row.memory_total_mb,
            "memory_available_mb": row.memory_available_mb,
            "swap_total_mb": row.swap_total_mb,
            "disk_total_gb": row.disk_total_gb,
            "disk_used_gb": row.disk_used_gb,
            "disk_free_gb": row.disk_free_gb,
            "selinux_status": row.selinux_status,
            "selinux_mode": row.selinux_mode,
            "firewall_status": row.firewall_status,
            "firewall_service": row.firewall_service,
            "hostname": row.hostname,
            "fqdn": row.fqdn,
            "primary_ip": row.primary_ip,
            "uptime_seconds": row.uptime_seconds,
            "boot_time": row.boot_time.isoformat() if row.boot_time else None,
            "collected_at": row.collected_at.isoformat() if row.collected_at else None,
            "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        }

    def save_packages(self, host_id: UUID, packages: List[PackageInfo]) -> int:
        """
        Save or update packages for a host.

        Uses upsert pattern - existing packages are updated, new ones are inserted.

        Args:
            host_id: The host UUID
            packages: List of PackageInfo dataclasses

        Returns:
            Number of packages saved
        """
        if not packages:
            return 0

        now = datetime.now(timezone.utc)

        # Delete existing packages for this host (full refresh)
        self.db.execute(
            text("DELETE FROM host_packages WHERE host_id = :host_id"),
            {"host_id": str(host_id)},
        )

        # Batch insert packages
        for pkg in packages:
            self.db.execute(
                text(
                    """
                    INSERT INTO host_packages (
                        host_id, name, version, release, arch,
                        source_repo, installed_at, collected_at
                    ) VALUES (
                        :host_id, :name, :version, :release, :arch,
                        :source_repo, :installed_at, :collected_at
                    )
                    ON CONFLICT (host_id, name, arch)
                    DO UPDATE SET
                        version = EXCLUDED.version,
                        release = EXCLUDED.release,
                        source_repo = EXCLUDED.source_repo,
                        installed_at = EXCLUDED.installed_at,
                        collected_at = EXCLUDED.collected_at
                    """
                ),
                {
                    "host_id": str(host_id),
                    "name": pkg.name,
                    "version": pkg.version,
                    "release": pkg.release,
                    "arch": pkg.arch,
                    "source_repo": pkg.source_repo,
                    "installed_at": pkg.installed_at,
                    "collected_at": now,
                },
            )

        self.db.commit()
        logger.info(f"Saved {len(packages)} packages for host {host_id}")
        return len(packages)

    def save_services(self, host_id: UUID, services: List[ServiceInfo]) -> int:
        """
        Save or update services for a host.

        Uses upsert pattern - existing services are updated, new ones are inserted.

        Args:
            host_id: The host UUID
            services: List of ServiceInfo dataclasses

        Returns:
            Number of services saved
        """
        if not services:
            return 0

        now = datetime.now(timezone.utc)

        # Delete existing services for this host (full refresh)
        self.db.execute(
            text("DELETE FROM host_services WHERE host_id = :host_id"),
            {"host_id": str(host_id)},
        )

        # Batch insert services
        for svc in services:
            self.db.execute(
                text(
                    """
                    INSERT INTO host_services (
                        host_id, name, display_name, status, enabled,
                        service_type, run_as_user, listening_ports, collected_at
                    ) VALUES (
                        :host_id, :name, :display_name, :status, :enabled,
                        :service_type, :run_as_user, :listening_ports, :collected_at
                    )
                    ON CONFLICT (host_id, name)
                    DO UPDATE SET
                        display_name = EXCLUDED.display_name,
                        status = EXCLUDED.status,
                        enabled = EXCLUDED.enabled,
                        service_type = EXCLUDED.service_type,
                        run_as_user = EXCLUDED.run_as_user,
                        listening_ports = EXCLUDED.listening_ports,
                        collected_at = EXCLUDED.collected_at
                    """
                ),
                {
                    "host_id": str(host_id),
                    "name": svc.name,
                    "display_name": svc.display_name,
                    "status": svc.status,
                    "enabled": svc.enabled,
                    "service_type": svc.service_type,
                    "run_as_user": svc.run_as_user,
                    "listening_ports": json.dumps(svc.listening_ports) if svc.listening_ports else None,
                    "collected_at": now,
                },
            )

        self.db.commit()
        logger.info(f"Saved {len(services)} services for host {host_id}")
        return len(services)

    def get_packages(
        self, host_id: UUID, search: Optional[str] = None, limit: int = 100, offset: int = 0
    ) -> Dict[str, Any]:
        """
        Get packages for a host with pagination and search.

        Args:
            host_id: The host UUID
            search: Optional package name search filter
            limit: Maximum packages to return
            offset: Offset for pagination

        Returns:
            Dictionary with packages list and total count
        """
        # Build query
        where_clause = "WHERE host_id = :host_id"
        params: Dict[str, Any] = {"host_id": str(host_id), "limit": limit, "offset": offset}

        if search:
            where_clause += " AND name ILIKE :search"
            params["search"] = f"%{search}%"

        # Get total count
        count_result = self.db.execute(
            text(f"SELECT COUNT(*) FROM host_packages {where_clause}"),
            params,
        )
        total = count_result.scalar() or 0

        # Get packages
        result = self.db.execute(
            text(
                f"""
                SELECT name, version, release, arch, source_repo,
                       installed_at, collected_at
                FROM host_packages
                {where_clause}
                ORDER BY name ASC
                LIMIT :limit OFFSET :offset
                """
            ),
            params,
        )

        packages = []
        for row in result.fetchall():
            packages.append(
                {
                    "name": row.name,
                    "version": row.version,
                    "release": row.release,
                    "arch": row.arch,
                    "source_repo": row.source_repo,
                    "installed_at": row.installed_at.isoformat() if row.installed_at else None,
                    "collected_at": row.collected_at.isoformat() if row.collected_at else None,
                }
            )

        return {"items": packages, "total": total, "limit": limit, "offset": offset}

    def get_services(
        self,
        host_id: UUID,
        search: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """
        Get services for a host with pagination and filtering.

        Args:
            host_id: The host UUID
            search: Optional service name search filter
            status: Optional status filter (running, stopped, failed)
            limit: Maximum services to return
            offset: Offset for pagination

        Returns:
            Dictionary with services list and total count
        """
        # Build query
        where_clause = "WHERE host_id = :host_id"
        params: Dict[str, Any] = {"host_id": str(host_id), "limit": limit, "offset": offset}

        if search:
            where_clause += " AND (name ILIKE :search OR display_name ILIKE :search)"
            params["search"] = f"%{search}%"

        if status:
            where_clause += " AND status = :status"
            params["status"] = status

        # Get total count
        count_result = self.db.execute(
            text(f"SELECT COUNT(*) FROM host_services {where_clause}"),
            params,
        )
        total = count_result.scalar() or 0

        # Get services
        result = self.db.execute(
            text(
                f"""
                SELECT name, display_name, status, enabled, service_type,
                       run_as_user, listening_ports, collected_at
                FROM host_services
                {where_clause}
                ORDER BY name ASC
                LIMIT :limit OFFSET :offset
                """
            ),
            params,
        )

        services = []
        for row in result.fetchall():
            services.append(
                {
                    "name": row.name,
                    "display_name": row.display_name,
                    "status": row.status,
                    "enabled": row.enabled,
                    "service_type": row.service_type,
                    "run_as_user": row.run_as_user,
                    "listening_ports": row.listening_ports,
                    "collected_at": row.collected_at.isoformat() if row.collected_at else None,
                }
            )

        return {"items": services, "total": total, "limit": limit, "offset": offset}
