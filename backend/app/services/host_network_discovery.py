"""
Host Network Topology Discovery Service
Identifies network interfaces, routing, DNS, NTP, and connectivity configuration on target hosts
"""

import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..database import Host
from ..services.unified_ssh_service import UnifiedSSHService as SSHService

logger = logging.getLogger(__name__)


class HostNetworkDiscoveryService:
    """
    Service for discovering network topology and configuration on hosts
    """

    def __init__(self, ssh_service: Optional[SSHService] = None):
        """Initialize the network discovery service"""
        self.ssh_service = ssh_service or SSHService()

    def discover_network_topology(self, host: Host) -> Dict[str, Any]:
        """
        Discover network topology and configuration on a host

        Args:
            host: Host object to discover network information for

        Returns:
            Dictionary containing discovered network information
        """
        logger.info(f"Starting network topology discovery for host: {host.hostname}")

        # Initialize typed collections for mypy compatibility
        discovery_errors: List[str] = []
        network_interfaces: Dict[str, Any] = {}
        routing_table: List[Dict[str, Any]] = []
        dns_configuration: Dict[str, Any] = {}
        ntp_configuration: Dict[str, Any] = {}
        network_services: Dict[str, Any] = {}
        connectivity_tests: Dict[str, Any] = {}
        network_security: Dict[str, Any] = {}

        discovery_results: Dict[str, Any] = {
            "network_interfaces": network_interfaces,
            "routing_table": routing_table,
            "dns_configuration": dns_configuration,
            "ntp_configuration": ntp_configuration,
            "network_services": network_services,
            "connectivity_tests": connectivity_tests,
            "network_security": network_security,
            "discovery_timestamp": datetime.utcnow(),
            "discovery_success": False,
            "discovery_errors": discovery_errors,
        }

        try:
            # Establish SSH connection
            if not self.ssh_service.connect(host):
                discovery_errors.append("Failed to establish SSH connection")
                return discovery_results

            # 1. Discover network interfaces
            interface_info = self._discover_network_interfaces(host)
            network_interfaces.update(interface_info.get("network_interfaces", {}))
            discovery_errors.extend(interface_info.get("errors", []))

            # 2. Discover routing table
            routing_info = self._discover_routing_table(host)
            routing_table.extend(routing_info.get("routing_table", []))
            discovery_errors.extend(routing_info.get("errors", []))

            # 3. Discover DNS configuration
            dns_info = self._discover_dns_configuration(host)
            dns_configuration.update(dns_info.get("dns_configuration", {}))
            discovery_errors.extend(dns_info.get("errors", []))

            # 4. Discover NTP configuration
            ntp_info = self._discover_ntp_configuration(host)
            ntp_configuration.update(ntp_info.get("ntp_configuration", {}))
            discovery_errors.extend(ntp_info.get("errors", []))

            # 5. Discover network services
            service_info = self._discover_network_services(host)
            network_services.update(service_info.get("network_services", {}))
            discovery_errors.extend(service_info.get("errors", []))

            # 6. Perform connectivity tests
            connectivity_info = self._perform_connectivity_tests(host)
            connectivity_tests.update(connectivity_info.get("connectivity_tests", {}))
            discovery_errors.extend(connectivity_info.get("errors", []))

            # 7. Assess network security
            security_info = self._assess_network_security(host)
            network_security.update(security_info.get("network_security", {}))
            discovery_errors.extend(security_info.get("errors", []))

            # Update discovery success status
            discovery_results["discovery_success"] = len(discovery_errors) == 0

            interface_count = len(network_interfaces)
            route_count = len(routing_table)
            logger.info(
                f"Network topology discovery completed for {host.hostname}: "
                f"Found {interface_count} interfaces, {route_count} routes"
            )

        except Exception as e:
            logger.error(f"Network discovery failed for {host.hostname}: {str(e)}")
            discovery_errors.append(f"Discovery exception: {str(e)}")

        finally:
            self.ssh_service.disconnect()

        return discovery_results

    def _discover_network_interfaces(self, host: Host) -> Dict[str, Any]:
        """Discover network interfaces and their configuration"""
        interfaces: Dict[str, Any] = {}
        errors: List[str] = []
        result: Dict[str, Any] = {"network_interfaces": interfaces, "errors": errors}

        try:
            # Use ip command (preferred on modern systems)
            ip_output = self.ssh_service.execute_command("ip addr show", timeout=15)
            if ip_output and ip_output["success"]:
                parsed_interfaces = self._parse_ip_addr_output(ip_output["stdout"])
                interfaces.update(parsed_interfaces)
            else:
                # Fallback to ifconfig if ip command fails
                ifconfig_output = self.ssh_service.execute_command("ifconfig -a", timeout=15)
                if ifconfig_output and ifconfig_output["success"]:
                    parsed_interfaces = self._parse_ifconfig_output(ifconfig_output["stdout"])
                    interfaces.update(parsed_interfaces)
                else:
                    errors.append("Failed to retrieve network interface information")

            # Get additional interface statistics
            for interface_name in interfaces.keys():
                # Get interface statistics
                stats_output = self.ssh_service.execute_command(
                    f"cat /sys/class/net/{interface_name}/statistics/rx_bytes "
                    f"/sys/class/net/{interface_name}/statistics/tx_bytes 2>/dev/null",
                    timeout=5,
                )
                if stats_output and stats_output["success"]:
                    lines = stats_output["stdout"].strip().split("\\n")
                    if len(lines) >= 2:
                        interfaces[interface_name]["rx_bytes"] = (
                            int(lines[0]) if lines[0].isdigit() else 0
                        )
                        interfaces[interface_name]["tx_bytes"] = (
                            int(lines[1]) if lines[1].isdigit() else 0
                        )

                # Get interface speed and duplex
                speed_output = self.ssh_service.execute_command(
                    f'ethtool {interface_name} 2>/dev/null | grep -E "Speed|Duplex"',
                    timeout=5,
                )
                if speed_output and speed_output["success"]:
                    for line in speed_output["stdout"].split("\\n"):
                        if "Speed:" in line:
                            interfaces[interface_name]["speed"] = line.split("Speed:")[1].strip()
                        elif "Duplex:" in line:
                            interfaces[interface_name]["duplex"] = line.split("Duplex:")[1].strip()

        except Exception as e:
            logger.warning(f"Error discovering network interfaces for {host.hostname}: {str(e)}")
            errors.append(f"Network interface discovery error: {str(e)}")

        return result

    def _discover_routing_table(self, host: Host) -> Dict[str, Any]:
        """Discover routing table information"""
        routing_table: List[Dict[str, Any]] = []
        errors: List[str] = []
        result: Dict[str, Any] = {"routing_table": routing_table, "errors": errors}

        try:
            # Get IPv4 routing table
            route_output = self.ssh_service.execute_command("ip route show", timeout=10)
            if route_output and route_output["success"]:
                ipv4_routes = self._parse_ip_route_output(route_output["stdout"], "ipv4")
                routing_table.extend(ipv4_routes)

            # Get IPv6 routing table
            route6_output = self.ssh_service.execute_command("ip -6 route show", timeout=10)
            if route6_output and route6_output["success"]:
                ipv6_routes = self._parse_ip_route_output(route6_output["stdout"], "ipv6")
                routing_table.extend(ipv6_routes)

            # If ip command fails, try route command
            if not routing_table:
                fallback_output = self.ssh_service.execute_command("route -n", timeout=10)
                if fallback_output and fallback_output["success"]:
                    fallback_routes = self._parse_route_n_output(fallback_output["stdout"])
                    routing_table.extend(fallback_routes)

        except Exception as e:
            logger.warning(f"Error discovering routing table for {host.hostname}: {str(e)}")
            errors.append(f"Routing table discovery error: {str(e)}")

        return result

    def _discover_dns_configuration(self, host: Host) -> Dict[str, Any]:
        """Discover DNS configuration"""
        dns_configuration: Dict[str, Any] = {}
        errors: List[str] = []
        result: Dict[str, Any] = {"dns_configuration": dns_configuration, "errors": errors}

        try:
            # Read /etc/resolv.conf
            resolv_output = self.ssh_service.execute_command("cat /etc/resolv.conf", timeout=5)
            if resolv_output and resolv_output["success"]:
                dns_config = self._parse_resolv_conf(resolv_output["stdout"])
                dns_configuration.update(dns_config)

            # Check systemd-resolved status (if available)
            systemd_resolved = self.ssh_service.execute_command(
                "systemctl is-active systemd-resolved", timeout=5
            )
            if (
                systemd_resolved
                and systemd_resolved["success"]
                and "active" in systemd_resolved["stdout"]
            ):
                dns_configuration["resolver"] = "systemd-resolved"

                # Get resolved status
                resolved_status = self.ssh_service.execute_command(
                    "systemd-resolve --status", timeout=10
                )
                if resolved_status and resolved_status["success"]:
                    resolved_info = self._parse_systemd_resolved_status(resolved_status["stdout"])
                    dns_configuration["resolved_info"] = resolved_info

            # Test DNS resolution
            dns_test = self.ssh_service.execute_command("nslookup google.com", timeout=10)
            if dns_test and dns_test["success"]:
                dns_configuration["resolution_test"] = "passed"
            else:
                dns_configuration["resolution_test"] = "failed"
                errors.append("DNS resolution test failed")

        except Exception as e:
            logger.warning(f"Error discovering DNS configuration for {host.hostname}: {str(e)}")
            errors.append(f"DNS configuration discovery error: {str(e)}")

        return result

    def _discover_ntp_configuration(self, host: Host) -> Dict[str, Any]:
        """Discover NTP configuration"""
        ntp_configuration: Dict[str, Any] = {}
        errors: List[str] = []
        result: Dict[str, Any] = {"ntp_configuration": ntp_configuration, "errors": errors}

        try:
            # Check for different NTP implementations
            ntp_services = ["ntp", "ntpd", "chronyd", "systemd-timesyncd"]
            active_service = None

            for service in ntp_services:
                service_check = self.ssh_service.execute_command(
                    f"systemctl is-active {service}", timeout=5
                )
                if (
                    service_check
                    and service_check["success"]
                    and "active" in service_check["stdout"]
                ):
                    active_service = service
                    break

            ntp_configuration["active_service"] = active_service

            # Get NTP configuration based on active service
            if active_service == "chronyd":
                # Chrony configuration
                chrony_config = self.ssh_service.execute_command("cat /etc/chrony.conf", timeout=5)
                if chrony_config and chrony_config["success"]:
                    ntp_servers = self._parse_chrony_config(chrony_config["stdout"])
                    ntp_configuration["servers"] = ntp_servers

                # Chrony sources
                chrony_sources = self.ssh_service.execute_command("chronyc sources", timeout=10)
                if chrony_sources and chrony_sources["success"]:
                    ntp_configuration["sources_status"] = chrony_sources["stdout"]

            elif active_service in ["ntp", "ntpd"]:
                # NTP configuration
                ntp_config = self.ssh_service.execute_command("cat /etc/ntp.conf", timeout=5)
                if ntp_config and ntp_config["success"]:
                    ntp_servers = self._parse_ntp_config(ntp_config["stdout"])
                    ntp_configuration["servers"] = ntp_servers

                # NTP status
                ntpq_output = self.ssh_service.execute_command("ntpq -p", timeout=10)
                if ntpq_output and ntpq_output["success"]:
                    ntp_configuration["peers_status"] = ntpq_output["stdout"]

            elif active_service == "systemd-timesyncd":
                # systemd-timesyncd configuration
                timesyncd_config = self.ssh_service.execute_command(
                    "cat /etc/systemd/timesyncd.conf", timeout=5
                )
                if timesyncd_config and timesyncd_config["success"]:
                    ntp_servers = self._parse_timesyncd_config(timesyncd_config["stdout"])
                    ntp_configuration["servers"] = ntp_servers

                # Timesyncd status
                timesyncd_status = self.ssh_service.execute_command(
                    "timedatectl show-timesync", timeout=10
                )
                if timesyncd_status and timesyncd_status["success"]:
                    ntp_configuration["timesyncd_status"] = timesyncd_status["stdout"]

            # General time synchronization status
            timedatectl_output = self.ssh_service.execute_command("timedatectl status", timeout=5)
            if timedatectl_output and timedatectl_output["success"]:
                ntp_configuration["time_status"] = self._parse_timedatectl_status(
                    timedatectl_output["stdout"]
                )

        except Exception as e:
            logger.warning(f"Error discovering NTP configuration for {host.hostname}: {str(e)}")
            errors.append(f"NTP configuration discovery error: {str(e)}")

        return result

    def _discover_network_services(self, host: Host) -> Dict[str, Any]:
        """Discover network services and listening ports"""
        network_services: Dict[str, Any] = {}
        errors: List[str] = []
        result: Dict[str, Any] = {"network_services": network_services, "errors": errors}

        try:
            # Get listening ports with ss (preferred) or netstat
            ss_output = self.ssh_service.execute_command("ss -tuln", timeout=15)
            if ss_output and ss_output["success"]:
                services = self._parse_ss_output(ss_output["stdout"])
                network_services["listening_ports"] = services
            else:
                # Fallback to netstat
                netstat_output = self.ssh_service.execute_command("netstat -tuln", timeout=15)
                if netstat_output and netstat_output["success"]:
                    services = self._parse_netstat_output(netstat_output["stdout"])
                    network_services["listening_ports"] = services

            # Check for common network services
            common_services = ["ssh", "http", "https", "dns", "dhcp", "snmp", "ntp"]
            running_services: Dict[str, str] = {}

            for service in common_services:
                service_check = self.ssh_service.execute_command(
                    f"systemctl is-active {service}*", timeout=5
                )
                if (
                    service_check
                    and service_check["success"]
                    and "active" in service_check["stdout"]
                ):
                    running_services[service] = "active"
                else:
                    running_services[service] = "inactive"

            network_services["system_services"] = running_services

        except Exception as e:
            logger.warning(f"Error discovering network services for {host.hostname}: {str(e)}")
            errors.append(f"Network services discovery error: {str(e)}")

        return result

    def _perform_connectivity_tests(self, host: Host) -> Dict[str, Any]:
        """Perform basic connectivity tests"""
        connectivity_tests: Dict[str, Any] = {}
        errors: List[str] = []
        result: Dict[str, Any] = {"connectivity_tests": connectivity_tests, "errors": errors}

        try:
            # Test connectivity to common destinations
            test_destinations = [
                {"name": "Google DNS", "target": "8.8.8.8"},
                {"name": "Cloudflare DNS", "target": "1.1.1.1"},
                {"name": "Google.com", "target": "google.com"},
            ]

            for destination in test_destinations:
                # Ping test
                ping_output = self.ssh_service.execute_command(
                    f'ping -c 3 -W 5 {destination["target"]}', timeout=20
                )
                ping_success = (
                    ping_output
                    and ping_output["success"]
                    and "0% packet loss" in ping_output["stdout"]
                )

                # Extract ping statistics
                ping_stats: Dict[str, Any] = {}
                if ping_output and ping_output["success"]:
                    ping_stats = self._parse_ping_output(ping_output["stdout"])

                connectivity_tests[destination["name"]] = {
                    "target": destination["target"],
                    "ping_success": ping_success,
                    "ping_stats": ping_stats,
                }

                # For domain names, also test HTTP/HTTPS connectivity
                if (
                    "." in destination["target"]
                    and not destination["target"].replace(".", "").isdigit()
                ):
                    curl_test = self.ssh_service.execute_command(
                        f'curl -I --connect-timeout 10 https://{destination["target"]}',
                        timeout=15,
                    )
                    https_success = curl_test and curl_test["success"]
                    connectivity_tests[destination["name"]]["https_success"] = https_success

        except Exception as e:
            logger.warning(f"Error performing connectivity tests for {host.hostname}: {str(e)}")
            errors.append(f"Connectivity test error: {str(e)}")

        return result

    def _assess_network_security(self, host: Host) -> Dict[str, Any]:
        """Assess network security configuration"""
        network_security: Dict[str, Any] = {}
        errors: List[str] = []
        result: Dict[str, Any] = {"network_security": network_security, "errors": errors}

        try:
            # Check IP forwarding status
            ip_forward_output = self.ssh_service.execute_command(
                "sysctl net.ipv4.ip_forward", timeout=5
            )
            if ip_forward_output and ip_forward_output["success"]:
                ip_forward = "1" in ip_forward_output["stdout"]
                network_security["ip_forwarding"] = ip_forward

            # Check for open ports and potential security issues
            if hasattr(self, "_network_services") and "listening_ports" in result.get(
                "network_services", {}
            ):
                net_services = result.get("network_services", {})
                listening_ports = (
                    net_services.get("listening_ports", [])
                    if isinstance(net_services, dict)
                    else []
                )

                # Identify potentially risky open ports
                risky_ports: List[Dict[str, Any]] = []
                common_risky_ports = [
                    23,
                    135,
                    139,
                    445,
                    1433,
                    1521,
                    3389,
                    5432,
                    5900,
                    6379,
                ]

                for port_info in listening_ports:
                    port = port_info.get("port")
                    if port and int(port) in common_risky_ports:
                        risky_ports.append(port_info)

                network_security["risky_open_ports"] = risky_ports

            # Check for network security tools
            security_tools = ["iptables", "ufw", "firewalld", "fail2ban"]
            active_security_tools: List[str] = []

            for tool in security_tools:
                tool_check = self.ssh_service.execute_command(f"which {tool}", timeout=5)
                if tool_check and tool_check["success"] and tool_check["stdout"].strip():
                    active_security_tools.append(tool)

            network_security["security_tools"] = active_security_tools

            # Check TCP/IP stack hardening
            hardening_checks = [
                ("net.ipv4.tcp_syncookies", "TCP SYN Cookies"),
                ("net.ipv4.icmp_echo_ignore_broadcasts", "ICMP Broadcast Ignore"),
                ("net.ipv4.conf.all.accept_redirects", "Accept Redirects"),
                ("net.ipv4.conf.all.send_redirects", "Send Redirects"),
            ]

            hardening_status: Dict[str, str] = {}
            for param, description in hardening_checks:
                param_output = self.ssh_service.execute_command(f"sysctl {param}", timeout=5)
                if param_output and param_output["success"]:
                    value = param_output["stdout"].split("=")[-1].strip()
                    hardening_status[description] = value

            network_security["hardening_status"] = hardening_status

        except Exception as e:
            logger.warning(f"Error assessing network security for {host.hostname}: {str(e)}")
            errors.append(f"Network security assessment error: {str(e)}")

        return result

    # Helper methods for parsing command outputs

    def _parse_ip_addr_output(self, output: str) -> Dict[str, Any]:
        """Parse 'ip addr show' output"""
        interfaces: Dict[str, Any] = {}
        current_interface: Optional[str] = None

        for line in output.split("\\n"):
            line = line.strip()
            if not line:
                continue

            # Interface line (e.g., "1: lo: <LOOPBACK,UP,LOWER_UP>")
            if re.match(r"^\\d+:", line):
                parts = line.split(":")
                if len(parts) >= 2:
                    interface_name = parts[1].strip()
                    current_interface = interface_name

                    # Extract flags
                    flags_match = re.search(r"<([^>]+)>", line)
                    flags = flags_match.group(1).split(",") if flags_match else []

                    # Extract state
                    state_match = re.search(r"state (\\w+)", line)
                    state = state_match.group(1) if state_match else "UNKNOWN"

                    interfaces[interface_name] = {
                        "name": interface_name,
                        "flags": flags,
                        "state": state,
                        "addresses": [],
                    }

            # Address line (e.g., "inet 127.0.0.1/8 scope host lo")
            elif current_interface and ("inet " in line or "inet6 " in line):
                addr_match = re.search(r"inet6? ([\\w:.]+/\\d+)", line)
                if addr_match:
                    address = addr_match.group(1)
                    addr_type = "ipv6" if "inet6" in line else "ipv4"
                    interfaces[current_interface]["addresses"].append(
                        {"address": address, "type": addr_type}
                    )

        return interfaces

    def _parse_ifconfig_output(self, output: str) -> Dict[str, Any]:
        """Parse ifconfig output (fallback)"""
        interfaces: Dict[str, Any] = {}
        current_interface: Optional[str] = None

        for line in output.split("\\n"):
            # Interface line
            if line and not line.startswith(" ") and not line.startswith("\\t"):
                interface_match = re.match(r"^([\\w]+)", line)
                if interface_match:
                    current_interface = interface_match.group(1)
                    interfaces[current_interface] = {
                        "name": current_interface,
                        "addresses": [],
                    }

            # Address lines
            elif current_interface:
                # IPv4 address
                ipv4_match = re.search(r"inet (\\d+\\.\\d+\\.\\d+\\.\\d+)", line)
                if ipv4_match:
                    interfaces[current_interface]["addresses"].append(
                        {"address": ipv4_match.group(1), "type": "ipv4"}
                    )

                # IPv6 address
                ipv6_match = re.search(r"inet6 ([\\w:]+)", line)
                if ipv6_match:
                    interfaces[current_interface]["addresses"].append(
                        {"address": ipv6_match.group(1), "type": "ipv6"}
                    )

        return interfaces

    def _parse_ip_route_output(self, output: str, ip_version: str) -> List[Dict[str, Any]]:
        """Parse 'ip route show' output"""
        routes = []

        for line in output.split("\\n"):
            line = line.strip()
            if not line:
                continue

            route = {"ip_version": ip_version}
            parts = line.split()

            if parts:
                # Destination network
                route["destination"] = parts[0]

                # Parse route details
                for i, part in enumerate(parts):
                    if part == "via" and i + 1 < len(parts):
                        route["gateway"] = parts[i + 1]
                    elif part == "dev" and i + 1 < len(parts):
                        route["interface"] = parts[i + 1]
                    elif part == "metric" and i + 1 < len(parts):
                        route["metric"] = parts[i + 1]
                    elif part == "scope" and i + 1 < len(parts):
                        route["scope"] = parts[i + 1]

                routes.append(route)

        return routes

    def _parse_route_n_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse 'route -n' output (fallback)"""
        routes = []
        lines = output.split("\\n")

        for line in lines[2:]:  # Skip header lines
            parts = line.split()
            if len(parts) >= 8:
                routes.append(
                    {
                        "destination": parts[0],
                        "gateway": parts[1],
                        "netmask": parts[2],
                        "flags": parts[3],
                        "interface": parts[7],
                        "ip_version": "ipv4",
                    }
                )

        return routes

    def _parse_resolv_conf(self, output: str) -> Dict[str, Any]:
        """Parse /etc/resolv.conf"""
        nameservers: List[str] = []
        search_domains: List[str] = []
        domain: Optional[str] = None

        for line in output.split("\\n"):
            line = line.strip()
            if line.startswith("nameserver "):
                nameservers.append(line.split()[1])
            elif line.startswith("search "):
                search_domains = line.split()[1:]
            elif line.startswith("domain "):
                domain = line.split()[1]

        return {"nameservers": nameservers, "search_domains": search_domains, "domain": domain}

    def _parse_systemd_resolved_status(self, output: str) -> Dict[str, Any]:
        """Parse systemd-resolve --status output"""
        # Simplified parsing - would need more sophisticated parsing for full details
        info = {}
        if "DNS Servers:" in output:
            info["has_dns_servers"] = True
        return info

    def _parse_chrony_config(self, output: str) -> List[str]:
        """Parse chrony.conf for NTP servers"""
        servers = []
        for line in output.split("\\n"):
            line = line.strip()
            if line.startswith("server ") or line.startswith("pool "):
                parts = line.split()
                if len(parts) >= 2:
                    servers.append(parts[1])
        return servers

    def _parse_ntp_config(self, output: str) -> List[str]:
        """Parse ntp.conf for NTP servers"""
        servers = []
        for line in output.split("\\n"):
            line = line.strip()
            if line.startswith("server "):
                parts = line.split()
                if len(parts) >= 2:
                    servers.append(parts[1])
        return servers

    def _parse_timesyncd_config(self, output: str) -> List[str]:
        """Parse timesyncd.conf for NTP servers"""
        servers = []
        for line in output.split("\\n"):
            line = line.strip()
            if line.startswith("NTP="):
                ntp_line = line.split("=")[1]
                servers.extend(ntp_line.split())
        return servers

    def _parse_timedatectl_status(self, output: str) -> Dict[str, Any]:
        """Parse timedatectl status output"""
        status = {}
        for line in output.split("\\n"):
            line = line.strip()
            if ": " in line:
                key, value = line.split(": ", 1)
                status[key.strip()] = value.strip()
        return status

    def _parse_ss_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse ss command output"""
        services = []
        lines = output.split("\\n")

        for line in lines[1:]:  # Skip header
            parts = line.split()
            if len(parts) >= 5:
                state = parts[0]
                local_address = parts[4]

                # Parse address and port
                if ":" in local_address:
                    addr_parts = local_address.rsplit(":", 1)
                    address = addr_parts[0].strip("[]")
                    port = addr_parts[1]

                    services.append(
                        {
                            "protocol": parts[0],
                            "state": state,
                            "address": address,
                            "port": port,
                            "local_address": local_address,
                        }
                    )

        return services

    def _parse_netstat_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse netstat command output (fallback)"""
        services = []
        lines = output.split("\\n")

        for line in lines[2:]:  # Skip header lines
            parts = line.split()
            if len(parts) >= 4:
                protocol = parts[0]
                local_address = parts[3]
                state = parts[5] if len(parts) > 5 else "LISTEN"

                # Parse address and port
                if ":" in local_address:
                    addr_parts = local_address.rsplit(":", 1)
                    address = addr_parts[0]
                    port = addr_parts[1]

                    services.append(
                        {
                            "protocol": protocol,
                            "state": state,
                            "address": address,
                            "port": port,
                            "local_address": local_address,
                        }
                    )

        return services

    def _parse_ping_output(self, output: str) -> Dict[str, Any]:
        """Parse ping command output"""
        stats: Dict[str, Any] = {}

        # Extract packet loss
        loss_match = re.search(r"(\\d+)% packet loss", output)
        if loss_match:
            stats["packet_loss_percent"] = int(loss_match.group(1))

        # Extract round-trip times
        rtt_match = re.search(r"min/avg/max/mdev = ([\\d.]+)/([\\d.]+)/([\\d.]+)/([\\d.]+)", output)
        if rtt_match:
            stats["rtt_min"] = float(rtt_match.group(1))
            stats["rtt_avg"] = float(rtt_match.group(2))
            stats["rtt_max"] = float(rtt_match.group(3))
            stats["rtt_mdev"] = float(rtt_match.group(4))

        return stats
