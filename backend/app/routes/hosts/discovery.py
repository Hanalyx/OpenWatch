"""
Host Discovery API Endpoints

This module consolidates all host discovery operations under unified endpoints.
Part of Phase 3 API Standardization: Host Discovery Consolidation.

Endpoint Structure:
    # Basic System Discovery
    POST /{host_id}/discovery/basic    - Discover basic system info
    POST /discovery/basic/bulk         - Bulk basic system discovery
    GET  /{host_id}/discovery/status   - Get discovery status

    # Network Discovery
    POST /{host_id}/discovery/network  - Discover network topology
    POST /discovery/network/bulk       - Bulk network discovery
    GET  /{host_id}/discovery/network/security-assessment - Network security
    POST /discovery/network/topology-map - Generate topology map
    GET  /discovery/network/capabilities - Network discovery capabilities

    # Security Discovery
    POST /{host_id}/discovery/security - Discover security infrastructure
    POST /discovery/security/bulk      - Bulk security discovery
    GET  /{host_id}/discovery/security/summary - Security summary

    # Compliance Discovery
    POST /{host_id}/discovery/compliance - Discover compliance infrastructure
    POST /discovery/compliance/bulk    - Bulk compliance discovery
    GET  /{host_id}/discovery/compliance/assessment - Compliance assessment
    GET  /discovery/compliance/frameworks - Supported frameworks

Migration Status:
    - /api/host-discovery/* -> /api/hosts/{id}/discovery/basic/*
    - /api/host-network-discovery/* -> /api/hosts/{id}/discovery/network/*
    - /api/host-security-discovery/* -> /api/hosts/{id}/discovery/security/*
    - /api/host-compliance-discovery/* -> /api/hosts/{id}/discovery/compliance/*
"""

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ...auth import get_current_user
from ...database import Host, get_db
from ...rbac import check_permission
from ...services.host_compliance_discovery import HostComplianceDiscoveryService
from ...services.host_discovery_service import HostBasicDiscoveryService
from ...services.host_network_discovery import HostNetworkDiscoveryService
from ...services.host_security_discovery import HostSecurityDiscoveryService
from .helpers import (
    assess_audit_capability,
    assess_privilege_escalation,
    assess_python_capability,
    assess_scap_capability,
    calculate_compliance_readiness_score,
    calculate_connectivity_score,
    get_missing_tools,
    get_recommended_frameworks,
    validate_host_uuid,
)
from .models import (  # noqa: E501; Basic discovery models; Network discovery models; Security discovery models; Compliance discovery models
    BulkComplianceDiscoveryRequest,
    BulkComplianceDiscoveryResponse,
    BulkDiscoveryRequest,
    BulkDiscoveryResponse,
    BulkNetworkDiscoveryRequest,
    BulkNetworkDiscoveryResponse,
    BulkSecurityDiscoveryRequest,
    BulkSecurityDiscoveryResponse,
    ComplianceCapabilityAssessment,
    ComplianceDiscoveryResponse,
    HostDiscoveryResponse,
    NetworkDiscoveryResponse,
    NetworkSecurityAssessment,
    NetworkTopologyMap,
    SecurityDiscoveryResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Host Discovery"])


# =============================================================================
# BASIC SYSTEM DISCOVERY ENDPOINTS
# =============================================================================


@router.post("/{host_id}/discovery/basic", response_model=HostDiscoveryResponse)
async def discover_basic_system_info(
    host_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> HostDiscoveryResponse:
    """
    Trigger basic system information discovery for a specific host.

    Discovers OS information, architecture, kernel version, and other
    basic system attributes.
    """
    # Check permissions
    check_permission(current_user["role"], "hosts", "read")

    # Validate host exists
    host_uuid = validate_host_uuid(host_id)
    host = db.query(Host).filter(Host.id == host_uuid).first()

    if not host:
        raise HTTPException(status_code=404, detail="Host not found")

    # Check if host has necessary connection info
    if not host.username or not (host.ip_address or host.hostname):
        raise HTTPException(
            status_code=400,
            detail="Host missing required connection information (username, IP/hostname)",
        )

    # Initialize discovery service
    discovery_service = HostBasicDiscoveryService()

    try:
        # Perform discovery
        discovery_results = discovery_service.discover_basic_system_info(host)

        # Update host in database
        db.add(host)
        db.commit()
        db.refresh(host)

        # Determine discovery status
        if discovery_results["discovery_success"]:
            discovery_status = "completed"
        elif discovery_results["discovery_errors"]:
            discovery_status = "partial"
        else:
            discovery_status = "failed"

        return HostDiscoveryResponse(
            host_id=str(host.id),
            hostname=host.hostname,
            discovery_status=discovery_status,
            discovered_info=discovery_results,
            timestamp=discovery_results["discovery_timestamp"],
        )

    except Exception as e:
        logger.error(f"Host discovery failed for {host_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Discovery failed: {str(e)}")


@router.post("/discovery/basic/bulk", response_model=BulkDiscoveryResponse)
async def discover_basic_system_bulk(
    request: BulkDiscoveryRequest,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> BulkDiscoveryResponse:
    """Trigger basic system discovery for multiple hosts."""
    # Check permissions
    check_permission(current_user["role"], "hosts", "read")

    # Validate hosts exist
    valid_hosts = []
    invalid_hosts = []

    for host_id in request.host_ids:
        try:
            host_uuid = UUID(host_id)
            host = db.query(Host).filter(Host.id == host_uuid).first()

            if host:
                # Check connection requirements
                if host.username and (host.ip_address or host.hostname):
                    valid_hosts.append(host)
                else:
                    invalid_hosts.append({"host_id": host_id, "error": "Missing connection information"})
            else:
                invalid_hosts.append({"host_id": host_id, "error": "Host not found"})

        except ValueError:
            invalid_hosts.append({"host_id": host_id, "error": "Invalid host ID format"})

    if not valid_hosts:
        raise HTTPException(status_code=400, detail="No valid hosts found for discovery")

    # Schedule background discovery for valid hosts
    initiated_hosts = []

    for host in valid_hosts:
        try:
            # Dispatch discovery via Celery
            from app.tasks.background_tasks import execute_host_discovery_celery

            execute_host_discovery_celery.delay(host_id=str(host.id))
            initiated_hosts.append(str(host.id))

        except Exception as e:
            logger.error(f"Failed to schedule discovery for host {host.id}: {str(e)}")
            invalid_hosts.append({"host_id": str(host.id), "error": f"Failed to schedule: {str(e)}"})

    # Estimate completion time (assume 30 seconds per host)
    estimated_completion = datetime.utcnow()
    if valid_hosts:
        estimated_completion = datetime.utcnow() + timedelta(seconds=len(valid_hosts) * 30)

    return BulkDiscoveryResponse(
        total_hosts=len(request.host_ids),
        discovery_initiated=initiated_hosts,
        discovery_failed=invalid_hosts,
        estimated_completion=estimated_completion,
    )


@router.get("/{host_id}/discovery/status")
async def get_discovery_status(
    host_id: str,
    db: Session = Depends(get_db),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Get the current discovery status and information for a host."""
    # Check permissions
    check_permission(current_user["role"], "hosts", "read")

    # Validate and get host
    host_uuid = validate_host_uuid(host_id)
    host = db.query(Host).filter(Host.id == host_uuid).first()

    if not host:
        raise HTTPException(status_code=404, detail="Host not found")

    # Return current discovery information
    return {
        "host_id": str(host.id),
        "hostname": host.hostname,
        "os_family": host.os_family,
        "os_version": host.os_version,
        "architecture": host.architecture,
        "operating_system": host.operating_system,
        "last_discovery": host.last_os_detection,
        "discovery_complete": bool(
            host.os_family
            and host.os_family != "Unknown"
            and host.os_version
            and host.os_version != "Unknown"
            and host.architecture
            and host.architecture != "Unknown"
        ),
    }


async def _execute_background_discovery(host_id: str, db: Session) -> None:
    """Background task for executing host discovery."""
    try:
        host_uuid = UUID(host_id)
        host = db.query(Host).filter(Host.id == host_uuid).first()

        if host:
            discovery_service = HostBasicDiscoveryService()
            discovery_service.discover_basic_system_info(host)

            # Update host in database
            db.add(host)
            db.commit()

            logger.info(f"Background discovery completed for host {host_id}")

    except Exception as e:
        logger.error(f"Background discovery failed for host {host_id}: {str(e)}")


# =============================================================================
# NETWORK DISCOVERY ENDPOINTS
# =============================================================================


@router.post("/{host_id}/discovery/network", response_model=NetworkDiscoveryResponse)
async def discover_host_network_topology(
    host_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> NetworkDiscoveryResponse:
    """
    Discover network topology and configuration on a specific host.

    Returns network interfaces, routing tables, DNS/NTP configuration,
    network services, and security assessment.
    """
    # Check permissions
    check_permission(current_user["role"], "hosts", "read")

    try:
        # Convert string UUID to UUID object
        host_uuid = validate_host_uuid(host_id)

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
        discovery_results["discovery_timestamp"] = discovery_results["discovery_timestamp"].isoformat()

        interface_count = len(discovery_results["network_interfaces"])
        route_count = len(discovery_results["routing_table"])
        logger.info(
            f"Network discovery completed for host {host.hostname}: "
            f"Found {interface_count} interfaces, {route_count} routes"
        )

        return NetworkDiscoveryResponse(**discovery_results)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Network discovery failed for host {host_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Network discovery failed: {str(e)}",
        )


@router.post("/discovery/network/bulk", response_model=BulkNetworkDiscoveryResponse)
async def bulk_discover_network_topology(
    request: BulkNetworkDiscoveryRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> BulkNetworkDiscoveryResponse:
    """
    Discover network topology for multiple hosts in bulk.

    Limited to 10 hosts per request (network discovery is resource-intensive).
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
            discovery_results["discovery_timestamp"] = discovery_results["discovery_timestamp"].isoformat()

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
    "/{host_id}/discovery/network/security-assessment",
    response_model=NetworkSecurityAssessment,
)
async def assess_host_network_security(
    host_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> NetworkSecurityAssessment:
    """Assess network security for a specific host."""
    # Check permissions
    check_permission(current_user["role"], "hosts", "read")

    try:
        # Convert string UUID to UUID object
        host_uuid = validate_host_uuid(host_id)

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

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Network security assessment failed for host {host_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Network security assessment failed: {str(e)}",
        )


@router.post("/discovery/network/topology-map")
async def generate_network_topology_map(
    request: BulkNetworkDiscoveryRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> NetworkTopologyMap:
    """
    Generate a network topology map for multiple hosts.

    Limited to 20 hosts per request.
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

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Network topology map generation failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Network topology map generation failed: {str(e)}",
        )


@router.get("/discovery/network/capabilities")
async def get_network_discovery_capabilities(
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Any]:
    """Get information about network discovery capabilities."""
    # Check permissions
    check_permission(current_user["role"], "hosts", "read")

    return {
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


def _assess_network_security(host: Host, discovery_results: Dict[str, Any]) -> NetworkSecurityAssessment:
    """Assess network security based on discovery results."""

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
                assessment.risky_services.append(f"Port {port} ({port_info.get('protocol', 'unknown')})")
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
    failed_tests = sum(1 for test in connectivity_tests.values() if not test.get("ping_success", True))
    if failed_tests > 0:
        assessment.network_vulnerabilities.append(f"{failed_tests} connectivity tests failed")

    # Ensure score doesn't go below 0
    assessment.security_score = max(0.0, assessment.security_score)

    return assessment


def _generate_topology_map(discovery_results: Dict[str, NetworkDiscoveryResponse], db: Session) -> NetworkTopologyMap:
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
                "connectivity_score": calculate_connectivity_score(result.connectivity_tests),
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


# =============================================================================
# SECURITY DISCOVERY ENDPOINTS
# =============================================================================


@router.post("/{host_id}/discovery/security", response_model=SecurityDiscoveryResponse)
async def discover_host_security_infrastructure(
    host_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> SecurityDiscoveryResponse:
    """
    Discover security infrastructure and configurations on a specific host.

    Returns package managers, SELinux/AppArmor status, firewall services,
    and security tools inventory.
    """
    # Check permissions
    check_permission(current_user["role"], "hosts", "read")

    try:
        # Convert string UUID to UUID object
        host_uuid = validate_host_uuid(host_id)

        # Get host from database
        host = db.query(Host).filter(Host.id == host_uuid).first()
        if not host:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Host with ID {host_id} not found",
            )

        # Perform security discovery
        security_service = HostSecurityDiscoveryService()
        discovery_results = security_service.discover_security_infrastructure(host)

        # Convert datetime to string for JSON serialization
        discovery_results["discovery_timestamp"] = discovery_results["discovery_timestamp"].isoformat()

        logger.info(
            f"Security discovery completed for host {host.hostname}: "
            f"Found {len(discovery_results['package_managers'])} package managers, "
            f"SELinux: {discovery_results['selinux_status']}, "
            f"AppArmor: {discovery_results['apparmor_status']}"
        )

        return SecurityDiscoveryResponse(**discovery_results)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Security discovery failed for host {host_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Security discovery failed: {str(e)}",
        )


@router.post("/discovery/security/bulk", response_model=BulkSecurityDiscoveryResponse)
async def bulk_discover_security_infrastructure(
    request: BulkSecurityDiscoveryRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> BulkSecurityDiscoveryResponse:
    """
    Discover security infrastructure for multiple hosts in bulk.

    Limited to 50 hosts per request.
    """
    # Check permissions
    check_permission(current_user["role"], "hosts", "read")

    if not request.host_ids:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No host IDs provided")

    if len(request.host_ids) > 50:  # Limit bulk operations
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Too many hosts requested. Maximum 50 hosts per bulk operation.",
        )

    logger.info(f"Starting bulk security discovery for {len(request.host_ids)} hosts")

    results = {}
    errors = {}
    successful_discoveries = 0
    failed_discoveries = 0

    security_service = HostSecurityDiscoveryService()

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

            # Perform security discovery
            discovery_results = security_service.discover_security_infrastructure(host)

            # Convert datetime to string for JSON serialization
            discovery_results["discovery_timestamp"] = discovery_results["discovery_timestamp"].isoformat()

            results[host_id] = SecurityDiscoveryResponse(**discovery_results)

            if discovery_results["discovery_success"]:
                successful_discoveries += 1
            else:
                failed_discoveries += 1

        except ValueError as e:
            errors[host_id] = f"Invalid host ID format: {str(e)}"
            failed_discoveries += 1
        except Exception as e:
            logger.error(f"Security discovery failed for host {host_id}: {str(e)}")
            errors[host_id] = f"Security discovery failed: {str(e)}"
            failed_discoveries += 1

    logger.info(
        f"Bulk security discovery completed: {successful_discoveries} successful, "
        f"{failed_discoveries} failed out of {len(request.host_ids)} total hosts"
    )

    return BulkSecurityDiscoveryResponse(
        total_hosts=len(request.host_ids),
        successful_discoveries=successful_discoveries,
        failed_discoveries=failed_discoveries,
        results=results,
        errors=errors,
    )


@router.get("/{host_id}/discovery/security/summary")
async def get_host_security_summary(
    host_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Get a quick security summary for a host without running full discovery."""
    # Check permissions
    check_permission(current_user["role"], "hosts", "read")

    try:
        # Convert string UUID to UUID object
        host_uuid = validate_host_uuid(host_id)

        # Get host from database
        host = db.query(Host).filter(Host.id == host_uuid).first()
        if not host:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Host with ID {host_id} not found",
            )

        # Generate security summary based on existing host information
        security_recommendations: List[str] = []

        # Add security recommendations based on OS family
        os_family_str: Optional[str] = str(host.os_family) if host.os_family else None
        if os_family_str:
            os_family_lower = os_family_str.lower()
            if "rhel" in os_family_lower or "centos" in os_family_lower or "fedora" in os_family_lower:
                security_recommendations.extend(
                    [
                        "Consider enabling SELinux if not already active",
                        "Ensure firewalld is configured properly",
                        "Keep system updated with dnf/yum",
                    ]
                )
            elif "ubuntu" in os_family_lower or "debian" in os_family_lower:
                security_recommendations.extend(
                    [
                        "Consider configuring AppArmor profiles",
                        "Ensure UFW firewall is configured",
                        "Keep system updated with apt",
                    ]
                )
            elif "suse" in os_family_lower:
                security_recommendations.extend(
                    [
                        "Configure AppArmor or SELinux as appropriate",
                        "Ensure firewall is configured",
                        "Keep system updated with zypper",
                    ]
                )

        summary: Dict[str, Any] = {
            "host_id": str(host.id),
            "hostname": host.hostname,
            "os_family": host.os_family,
            "os_version": host.os_version,
            "architecture": host.architecture,
            "last_os_detection": (host.last_os_detection.isoformat() if host.last_os_detection else None),
            "auth_method": host.auth_method,
            "security_recommendations": security_recommendations,
        }

        return summary

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get security summary for host {host_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get security summary: {str(e)}",
        )


# =============================================================================
# COMPLIANCE DISCOVERY ENDPOINTS
# =============================================================================


@router.post("/{host_id}/discovery/compliance", response_model=ComplianceDiscoveryResponse)
async def discover_host_compliance_infrastructure(
    host_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ComplianceDiscoveryResponse:
    """
    Discover compliance infrastructure and tooling on a specific host.

    Returns Python environments, OpenSCAP tools, privilege escalation,
    compliance scanners, filesystem capabilities, and audit tools.
    """
    # Check permissions - RBAC requires role, resource, and action
    check_permission(current_user["role"], "hosts", "read")

    try:
        # Convert string UUID to UUID object
        host_uuid = validate_host_uuid(host_id)

        # Get host from database
        host = db.query(Host).filter(Host.id == host_uuid).first()
        if not host:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Host with ID {host_id} not found",
            )

        # Perform compliance discovery
        compliance_service = HostComplianceDiscoveryService()
        discovery_results: Dict[str, Any] = compliance_service.discover_compliance_infrastructure(host)

        # Convert datetime to string for JSON serialization
        discovery_results["discovery_timestamp"] = discovery_results["discovery_timestamp"].isoformat()

        logger.info(
            f"Compliance discovery completed for host {host.hostname}: "
            f"Found {len(discovery_results['python_environments'])} Python environments, "
            f"{len(discovery_results['openscap_tools'])} OpenSCAP tools, "
            f"{len(discovery_results['compliance_frameworks'])} supported frameworks"
        )

        return ComplianceDiscoveryResponse(**discovery_results)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Compliance discovery failed for host {host_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Compliance discovery failed: {str(e)}",
        )


@router.post("/discovery/compliance/bulk", response_model=BulkComplianceDiscoveryResponse)
async def bulk_discover_compliance_infrastructure(
    request: BulkComplianceDiscoveryRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> BulkComplianceDiscoveryResponse:
    """
    Discover compliance infrastructure for multiple hosts in bulk.

    Limited to 20 hosts per request (compliance discovery is resource-intensive).
    """
    # Check permissions - RBAC requires role, resource, and action
    check_permission(current_user["role"], "hosts", "read")

    if not request.host_ids:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No host IDs provided")

    if len(request.host_ids) > 20:  # Limit bulk operations for compliance (more intensive)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Too many hosts requested. Maximum 20 hosts per bulk compliance discovery operation.",
        )

    logger.info(f"Starting bulk compliance discovery for {len(request.host_ids)} hosts")

    results = {}
    errors = {}
    successful_discoveries = 0
    failed_discoveries = 0

    compliance_service = HostComplianceDiscoveryService()

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

            # Perform compliance discovery
            discovery_results = compliance_service.discover_compliance_infrastructure(host)

            # Convert datetime to string for JSON serialization
            discovery_results["discovery_timestamp"] = discovery_results["discovery_timestamp"].isoformat()

            results[host_id] = ComplianceDiscoveryResponse(**discovery_results)

            if discovery_results["discovery_success"]:
                successful_discoveries += 1
            else:
                failed_discoveries += 1

        except ValueError as e:
            errors[host_id] = f"Invalid host ID format: {str(e)}"
            failed_discoveries += 1
        except Exception as e:
            logger.error(f"Compliance discovery failed for host {host_id}: {str(e)}")
            errors[host_id] = f"Compliance discovery failed: {str(e)}"
            failed_discoveries += 1

    logger.info(
        f"Bulk compliance discovery completed: {successful_discoveries} successful, "
        f"{failed_discoveries} failed out of {len(request.host_ids)} total hosts"
    )

    return BulkComplianceDiscoveryResponse(
        total_hosts=len(request.host_ids),
        successful_discoveries=successful_discoveries,
        failed_discoveries=failed_discoveries,
        results=results,
        errors=errors,
    )


@router.get(
    "/{host_id}/discovery/compliance/assessment",
    response_model=ComplianceCapabilityAssessment,
)
async def assess_host_compliance_capability(
    host_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ComplianceCapabilityAssessment:
    """Assess a host's compliance capability and readiness."""
    # Check permissions - RBAC requires role, resource, and action
    check_permission(current_user["role"], "hosts", "read")

    try:
        # Convert string UUID to UUID object
        host_uuid = validate_host_uuid(host_id)

        # Get host from database
        host = db.query(Host).filter(Host.id == host_uuid).first()
        if not host:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Host with ID {host_id} not found",
            )

        # Perform compliance discovery
        compliance_service = HostComplianceDiscoveryService()
        discovery_results = compliance_service.discover_compliance_infrastructure(host)

        # Assess capabilities using helper functions
        scap_capability = assess_scap_capability(discovery_results.get("openscap_tools", {}))
        python_capability = assess_python_capability(discovery_results.get("python_environments", {}))
        privilege_escalation = assess_privilege_escalation(discovery_results.get("privilege_escalation", {}))
        audit_capability = assess_audit_capability(discovery_results.get("audit_tools", {}))

        # Calculate readiness score
        readiness_score = calculate_compliance_readiness_score(
            scap_capability, python_capability, privilege_escalation, audit_capability
        )

        # Determine overall readiness
        if readiness_score >= 0.8:
            overall_readiness = "ready"
        elif readiness_score >= 0.5:
            overall_readiness = "partial"
        else:
            overall_readiness = "not_ready"

        # Get recommended frameworks and missing tools
        recommended_frameworks = get_recommended_frameworks(scap_capability, audit_capability)
        missing_tools = get_missing_tools(scap_capability, python_capability, privilege_escalation, audit_capability)

        return ComplianceCapabilityAssessment(
            host_id=str(host.id),
            hostname=host.hostname,
            overall_compliance_readiness=overall_readiness,
            scap_capability=scap_capability,
            python_capability=python_capability,
            privilege_escalation=privilege_escalation,
            audit_capability=audit_capability,
            recommended_frameworks=recommended_frameworks,
            missing_tools=missing_tools,
            readiness_score=readiness_score,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Compliance assessment failed for host {host_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Compliance assessment failed: {str(e)}",
        )


@router.get("/discovery/compliance/frameworks")
async def get_supported_compliance_frameworks(
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> Dict[str, Dict[str, Any]]:
    """Get list of compliance frameworks that can be discovered and supported."""
    # Check permissions - RBAC requires role, resource, and action
    check_permission(current_user["role"], "hosts", "read")

    return {
        "NIST 800-53": {
            "name": "NIST SP 800-53",
            "description": "Security and Privacy Controls for Federal Information Systems",
            "requires": ["OpenSCAP", "Python", "Audit Tools"],
            "category": "Federal Compliance",
        },
        "DISA STIG": {
            "name": "DISA Security Technical Implementation Guides",
            "description": "DoD security configuration standards",
            "requires": ["OpenSCAP", "Privilege Escalation"],
            "category": "Military/Defense",
        },
        "CIS Controls": {
            "name": "Center for Internet Security Controls",
            "description": "Cybersecurity best practices framework",
            "requires": ["OpenSCAP", "InSpec", "Audit Tools"],
            "category": "Industry Standard",
        },
        "PCI DSS": {
            "name": "Payment Card Industry Data Security Standard",
            "description": "Security standards for payment card processing",
            "requires": ["OpenSCAP", "File Integrity Monitoring", "Audit Tools"],
            "category": "Industry Regulation",
        },
        "FISMA": {
            "name": "Federal Information Security Management Act",
            "description": "US federal security compliance framework",
            "requires": ["OpenSCAP", "Audit Tools", "Python"],
            "category": "Federal Compliance",
        },
        "HIPAA": {
            "name": "Health Insurance Portability and Accountability Act",
            "description": "Healthcare data protection regulations",
            "requires": ["Audit Tools", "File Integrity Monitoring"],
            "category": "Healthcare Regulation",
        },
        "SOX": {
            "name": "Sarbanes-Oxley Act",
            "description": "Financial reporting and corporate governance",
            "requires": ["Audit Tools", "File Integrity Monitoring"],
            "category": "Financial Regulation",
        },
    }
