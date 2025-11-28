"""
Host Network Discovery API Routes
Provides endpoints for discovering network topology and configuration on hosts
"""

import logging
from typing import Any, Dict, List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..database import Host, get_db
from ..rbac import check_permission
from ..services.host_network_discovery import HostNetworkDiscoveryService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/host-network-discovery", tags=["Host Network Discovery"])


class NetworkDiscoveryResponse(BaseModel):
    """Response model for network discovery results."""

    network_interfaces: Dict[str, Any]
    routing_table: List[Dict[str, Any]]
    dns_configuration: Dict[str, Any]
    ntp_configuration: Dict[str, Any]
    network_services: Dict[str, Any]
    connectivity_tests: Dict[str, Any]
    network_security: Dict[str, Any]
    discovery_timestamp: str
    discovery_success: bool
    discovery_errors: List[str]


class BulkNetworkDiscoveryRequest(BaseModel):
    """Request model for bulk network discovery."""

    host_ids: List[str]


class BulkNetworkDiscoveryResponse(BaseModel):
    """Response model for bulk network discovery results."""

    total_hosts: int
    successful_discoveries: int
    failed_discoveries: int
    results: Dict[str, NetworkDiscoveryResponse]
    errors: Dict[str, str]


class NetworkTopologyMap(BaseModel):
    """Response model for network topology map."""

    hosts: List[Dict[str, Any]]
    network_segments: List[Dict[str, Any]]
    connectivity_matrix: Dict[str, Dict[str, bool]]
    network_summary: Dict[str, Any]


class NetworkSecurityAssessment(BaseModel):
    """Response model for network security assessment."""

    host_id: str
    hostname: str
    security_score: float  # 0.0 to 1.0
    open_ports: List[Dict[str, Any]]
    risky_services: List[str]
    firewall_status: str
    hardening_recommendations: List[str]
    network_vulnerabilities: List[str]


@router.post("/hosts/{host_id}/network-discovery", response_model=NetworkDiscoveryResponse)
async def discover_host_network_topology(
    host_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> NetworkDiscoveryResponse:
    """
    Discover network topology and configuration on a specific host

    Args:
        host_id: UUID of the host to discover network information for

    Returns:
        NetworkDiscoveryResponse containing discovered network information
    """
    # Check permissions
    check_permission(current_user["role"], "hosts", "read")

    try:
        # Convert string UUID to UUID object
        host_uuid = UUID(host_id)

        # Get host from database
        host = db.query(Host).filter(Host.id == host_uuid).first()
        if not host:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Host with ID {host_id} not found",
            )

        # Perform network discovery
        network_service = HostNetworkDiscoveryService()
        discovery_results = network_service.discover_network_topology(host)

        # Convert datetime to string for JSON serialization
        discovery_results["discovery_timestamp"] = discovery_results[
            "discovery_timestamp"
        ].isoformat()

        interface_count = len(discovery_results["network_interfaces"])
        route_count = len(discovery_results["routing_table"])
        logger.info(
            f"Network discovery completed for host {host.hostname}: "
            f"Found {interface_count} interfaces, {route_count} routes"
        )

        return NetworkDiscoveryResponse(**discovery_results)

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid host ID format: {str(e)}",
        )
    except Exception as e:
        logger.error(f"Network discovery failed for host {host_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Network discovery failed: {str(e)}",
        )


@router.post("/bulk-network-discovery", response_model=BulkNetworkDiscoveryResponse)
async def bulk_discover_network_topology(
    request: BulkNetworkDiscoveryRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> BulkNetworkDiscoveryResponse:
    """
    Discover network topology for multiple hosts in bulk

    Args:
        request: BulkNetworkDiscoveryRequest containing list of host IDs

    Returns:
        BulkNetworkDiscoveryResponse with results for all hosts
    """
    # Check permissions
    check_permission(current_user["role"], "hosts", "read")

    if not request.host_ids:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No host IDs provided")

    if len(request.host_ids) > 10:  # Limit bulk operations for network discovery (most intensive)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Too many hosts requested. Maximum 10 hosts per bulk network discovery operation.",
        )

    logger.info(f"Starting bulk network discovery for {len(request.host_ids)} hosts")

    results = {}
    errors = {}
    successful_discoveries = 0
    failed_discoveries = 0

    network_service = HostNetworkDiscoveryService()

    for host_id in request.host_ids:
        try:
            # Convert string UUID to UUID object
            host_uuid = UUID(host_id)

            # Get host from database
            host = db.query(Host).filter(Host.id == host_uuid).first()
            if not host:
                errors[host_id] = f"Host with ID {host_id} not found"
                failed_discoveries += 1
                continue

            # Perform network discovery
            discovery_results = network_service.discover_network_topology(host)

            # Convert datetime to string for JSON serialization
            discovery_results["discovery_timestamp"] = discovery_results[
                "discovery_timestamp"
            ].isoformat()

            results[host_id] = NetworkDiscoveryResponse(**discovery_results)

            if discovery_results["discovery_success"]:
                successful_discoveries += 1
            else:
                failed_discoveries += 1

        except ValueError as e:
            errors[host_id] = f"Invalid host ID format: {str(e)}"
            failed_discoveries += 1
        except Exception as e:
            logger.error(f"Network discovery failed for host {host_id}: {str(e)}")
            errors[host_id] = f"Network discovery failed: {str(e)}"
            failed_discoveries += 1

    logger.info(
        f"Bulk network discovery completed: {successful_discoveries} successful, "
        f"{failed_discoveries} failed out of {len(request.host_ids)} total hosts"
    )

    return BulkNetworkDiscoveryResponse(
        total_hosts=len(request.host_ids),
        successful_discoveries=successful_discoveries,
        failed_discoveries=failed_discoveries,
        results=results,
        errors=errors,
    )


@router.get(
    "/hosts/{host_id}/network-security-assessment",
    response_model=NetworkSecurityAssessment,
)
async def assess_host_network_security(
    host_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> NetworkSecurityAssessment:
    """
    Assess network security for a specific host

    Args:
        host_id: UUID of the host to assess

    Returns:
        NetworkSecurityAssessment with security evaluation
    """
    # Check permissions
    check_permission(current_user["role"], "hosts", "read")

    try:
        # Convert string UUID to UUID object
        host_uuid = UUID(host_id)

        # Get host from database
        host = db.query(Host).filter(Host.id == host_uuid).first()
        if not host:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Host with ID {host_id} not found",
            )

        # Perform network discovery
        network_service = HostNetworkDiscoveryService()
        discovery_results = network_service.discover_network_topology(host)

        # Assess network security
        assessment = _assess_network_security(host, discovery_results)

        return assessment

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid host ID format: {str(e)}",
        )
    except Exception as e:
        logger.error(f"Network security assessment failed for host {host_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Network security assessment failed: {str(e)}",
        )


@router.post("/network-topology-map")
async def generate_network_topology_map(
    request: BulkNetworkDiscoveryRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> NetworkTopologyMap:
    """
    Generate a network topology map for multiple hosts

    Args:
        request: BulkNetworkDiscoveryRequest containing list of host IDs

    Returns:
        NetworkTopologyMap with network topology visualization data
    """
    # Check permissions
    check_permission(current_user["role"], "hosts", "read")

    if not request.host_ids:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No host IDs provided")

    if len(request.host_ids) > 20:  # Allow more hosts for topology mapping
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Too many hosts requested. Maximum 20 hosts for network topology mapping.",
        )

    try:
        # Perform bulk discovery first
        bulk_response = await bulk_discover_network_topology(request, current_user, db)

        # Generate topology map from results
        topology_map = _generate_topology_map(bulk_response.results, db)

        return topology_map

    except Exception as e:
        logger.error(f"Network topology map generation failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Network topology map generation failed: {str(e)}",
        )


@router.get("/network-discovery-capabilities")
async def get_network_discovery_capabilities(
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Get information about network discovery capabilities

    Returns:
        Dictionary of supported network discovery features
    """
    # Check permissions
    check_permission(current_user["role"], "hosts", "read")

    capabilities = {
        "network_interfaces": {
            "description": "Discovers all network interfaces with IP addresses, states, and statistics",
            "commands_used": ["ip addr show", "ifconfig -a", "ethtool"],
            "information_gathered": [
                "Interface names and states",
                "IPv4 and IPv6 addresses",
                "Interface flags and MTU",
                "TX/RX byte statistics",
                "Link speed and duplex",
            ],
        },
        "routing_table": {
            "description": "Discovers IPv4 and IPv6 routing information",
            "commands_used": ["ip route show", "ip -6 route show", "route -n"],
            "information_gathered": [
                "Destination networks",
                "Gateway addresses",
                "Interface routing",
                "Route metrics",
                "Route types and scopes",
            ],
        },
        "dns_configuration": {
            "description": "Discovers DNS resolver configuration and tests resolution",
            "commands_used": [
                "cat /etc/resolv.conf",
                "systemd-resolve --status",
                "nslookup",
            ],
            "information_gathered": [
                "DNS servers",
                "Search domains",
                "Resolution testing",
                "systemd-resolved status",
            ],
        },
        "ntp_configuration": {
            "description": "Discovers time synchronization configuration",
            "commands_used": ["timedatectl", "chronyc sources", "ntpq -p"],
            "information_gathered": [
                "Active NTP service",
                "NTP server configuration",
                "Time synchronization status",
                "NTP peer status",
            ],
        },
        "network_services": {
            "description": "Discovers listening network services and ports",
            "commands_used": ["ss -tuln", "netstat -tuln", "systemctl is-active"],
            "information_gathered": [
                "Listening ports by protocol",
                "Service binding addresses",
                "System service status",
                "Network daemon status",
            ],
        },
        "connectivity_tests": {
            "description": "Performs basic network connectivity testing",
            "commands_used": ["ping", "curl"],
            "information_gathered": [
                "Ping statistics to common destinations",
                "Packet loss measurements",
                "Round-trip time analysis",
                "HTTPS connectivity tests",
            ],
        },
        "network_security": {
            "description": "Assesses network security configuration",
            "commands_used": ["sysctl", "iptables", "systemctl"],
            "information_gathered": [
                "IP forwarding status",
                "TCP/IP stack hardening",
                "Active security tools",
                "Risky open ports identification",
            ],
        },
    }

    return capabilities


def _assess_network_security(
    host: Host, discovery_results: Dict[str, Any]
) -> NetworkSecurityAssessment:
    """Assess network security based on discovery results"""

    # Initialize assessment
    assessment = NetworkSecurityAssessment(
        host_id=str(host.id),
        hostname=host.hostname,
        security_score=1.0,
        open_ports=[],
        risky_services=[],
        firewall_status="unknown",
        hardening_recommendations=[],
        network_vulnerabilities=[],
    )

    # Analyze open ports
    network_services = discovery_results.get("network_services", {})
    listening_ports = network_services.get("listening_ports", [])

    # Identify risky ports
    risky_port_numbers = [21, 23, 135, 139, 445, 1433, 1521, 3389, 5432, 5900, 6379]
    risky_ports = []

    for port_info in listening_ports:
        try:
            port = int(port_info.get("port", 0))
            if port in risky_port_numbers:
                risky_ports.append(port_info)
                assessment.risky_services.append(
                    f"Port {port} ({port_info.get('protocol', 'unknown')})"
                )
        except (ValueError, TypeError):
            continue

    assessment.open_ports = listening_ports

    # Assess firewall status
    network_security = discovery_results.get("network_security", {})
    security_tools = network_security.get("security_tools", [])

    if any(tool in security_tools for tool in ["iptables", "ufw", "firewalld"]):
        assessment.firewall_status = "active"
    else:
        assessment.firewall_status = "inactive"
        assessment.network_vulnerabilities.append("No active firewall detected")
        assessment.security_score -= 0.3

    # Check IP forwarding
    if network_security.get("ip_forwarding"):
        assessment.network_vulnerabilities.append("IP forwarding is enabled")
        assessment.hardening_recommendations.append("Disable IP forwarding if not needed")
        assessment.security_score -= 0.1

    # Check risky ports
    if risky_ports:
        assessment.security_score -= len(risky_ports) * 0.1
        assessment.hardening_recommendations.append("Review and secure risky open ports")

    # Check hardening status
    hardening_status = network_security.get("hardening_status", {})

    # TCP SYN cookies should be enabled
    if hardening_status.get("TCP SYN Cookies") != "1":
        assessment.hardening_recommendations.append("Enable TCP SYN cookies for DDoS protection")
        assessment.security_score -= 0.05

    # Accept redirects should be disabled
    if hardening_status.get("Accept Redirects") == "1":
        assessment.hardening_recommendations.append("Disable ICMP redirect acceptance")
        assessment.security_score -= 0.05

    # Send redirects should be disabled
    if hardening_status.get("Send Redirects") == "1":
        assessment.hardening_recommendations.append("Disable ICMP redirect sending")
        assessment.security_score -= 0.05

    # Connectivity test failures might indicate network issues
    connectivity_tests = discovery_results.get("connectivity_tests", {})
    failed_tests = sum(
        1 for test in connectivity_tests.values() if not test.get("ping_success", True)
    )
    if failed_tests > 0:
        assessment.network_vulnerabilities.append(f"{failed_tests} connectivity tests failed")

    # Ensure score doesn't go below 0
    assessment.security_score = max(0.0, assessment.security_score)

    return assessment


def _generate_topology_map(
    discovery_results: Dict[str, NetworkDiscoveryResponse], db: Session
) -> NetworkTopologyMap:
    """Generate network topology map from discovery results."""
    hosts: List[Dict[str, Any]] = []
    network_segments: List[Dict[str, Any]] = []
    connectivity_matrix: Dict[str, Dict[str, bool]] = {}

    # Process each host
    for host_id, result in discovery_results.items():
        try:
            # Get host info from database
            host_uuid = UUID(host_id)
            host = db.query(Host).filter(Host.id == host_uuid).first()

            if not host:
                continue

            # Extract host network information
            host_info = {
                "host_id": host_id,
                "hostname": host.hostname,
                "ip_address": host.ip_address,
                "interfaces": list(result.network_interfaces.keys()),
                "gateway_count": len([r for r in result.routing_table if r.get("gateway")]),
                "open_ports": len(result.network_services.get("listening_ports", [])),
                "connectivity_score": _calculate_connectivity_score(result.connectivity_tests),
            }

            hosts.append(host_info)

            # Initialize connectivity matrix for this host
            connectivity_matrix[host_id] = {}

            # Extract network segments
            for interface_name, interface_info in result.network_interfaces.items():
                for addr in interface_info.get("addresses", []):
                    if addr.get("type") == "ipv4" and "/" in addr.get("address", ""):
                        network = addr["address"]
                        network_segments.append(
                            {
                                "network": network,
                                "interface": interface_name,
                                "host_id": host_id,
                                "host_name": host.hostname,
                            }
                        )

        except Exception as e:
            logger.warning(f"Error processing host {host_id} for topology map: {str(e)}")
            continue

    # Generate connectivity matrix (simplified - based on ping tests)
    for host_id in discovery_results.keys():
        for other_host_id in discovery_results.keys():
            if host_id != other_host_id:
                # Simplified connectivity assessment
                # In a real implementation, this would analyze actual connectivity tests
                connectivity_matrix.setdefault(host_id, {})[other_host_id] = True

    # Remove duplicate network segments
    unique_segments = []
    seen_networks = set()
    for segment in network_segments:
        network_key = segment["network"]
        if network_key not in seen_networks:
            seen_networks.add(network_key)
            unique_segments.append(segment)

    # Generate network summary
    total_interfaces = sum(len(h["interfaces"]) for h in hosts)
    connectivity_scores = [h["connectivity_score"] for h in hosts]
    avg_score = sum(connectivity_scores) / len(hosts) if hosts else 0.0
    hosts_with_gws = sum(1 for h in hosts if h["gateway_count"] > 0)
    total_ports = sum(h["open_ports"] for h in hosts)

    network_summary: Dict[str, Any] = {
        "total_hosts": len(hosts),
        "total_interfaces": total_interfaces,
        "network_segments": len(unique_segments),
        "average_connectivity_score": avg_score,
        "hosts_with_gateways": hosts_with_gws,
        "total_open_ports": total_ports,
    }

    return NetworkTopologyMap(
        hosts=hosts,
        network_segments=unique_segments,
        connectivity_matrix=connectivity_matrix,
        network_summary=network_summary,
    )


def _calculate_connectivity_score(connectivity_tests: Dict[str, Any]) -> float:
    """Calculate connectivity score based on test results"""
    if not connectivity_tests:
        return 0.0

    total_tests = len(connectivity_tests)
    successful_tests = sum(
        1 for test in connectivity_tests.values() if test.get("ping_success", False)
    )

    return successful_tests / total_tests if total_tests > 0 else 0.0
