"""
Host Compliance Discovery API Routes
Provides endpoints for discovering compliance infrastructure and tooling on hosts
"""
import logging
from typing import Dict, Any, List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel

from ..database import get_db, Host
from ..auth import get_current_user
from ..services.host_compliance_discovery import HostComplianceDiscoveryService
from ..rbac import check_permission

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/host-compliance-discovery", tags=["Host Compliance Discovery"])


class ComplianceDiscoveryResponse(BaseModel):
    python_environments: Dict[str, Any]
    openscap_tools: Dict[str, Any]
    privilege_escalation: Dict[str, Any]
    compliance_scanners: Dict[str, Any]
    filesystem_capabilities: Dict[str, Any]
    audit_tools: Dict[str, Any]
    compliance_frameworks: List[str]
    discovery_timestamp: str
    discovery_success: bool
    discovery_errors: List[str]


class BulkComplianceDiscoveryRequest(BaseModel):
    host_ids: List[str]


class BulkComplianceDiscoveryResponse(BaseModel):
    total_hosts: int
    successful_discoveries: int
    failed_discoveries: int
    results: Dict[str, ComplianceDiscoveryResponse]
    errors: Dict[str, str]


class ComplianceCapabilityAssessment(BaseModel):
    host_id: str
    hostname: str
    overall_compliance_readiness: str  # ready, partial, not_ready
    scap_capability: str  # full, limited, none
    python_capability: str  # available, limited, none
    privilege_escalation: str  # available, limited, none
    audit_capability: str  # full, partial, none
    recommended_frameworks: List[str]
    missing_tools: List[str]
    readiness_score: float  # 0.0 to 1.0


@router.post("/hosts/{host_id}/compliance-discovery", response_model=ComplianceDiscoveryResponse)
async def discover_host_compliance_infrastructure(
    host_id: str,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Discover compliance infrastructure and tooling on a specific host
    
    Args:
        host_id: UUID of the host to discover compliance information for
        
    Returns:
        ComplianceDiscoveryResponse containing discovered compliance information
    """
    # Check permissions
    check_permission(current_user, "hosts:read")
    
    try:
        # Convert string UUID to UUID object
        host_uuid = UUID(host_id)
        
        # Get host from database
        host = db.query(Host).filter(Host.id == host_uuid).first()
        if not host:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Host with ID {host_id} not found"
            )
        
        # Perform compliance discovery
        compliance_service = HostComplianceDiscoveryService()
        discovery_results = compliance_service.discover_compliance_infrastructure(host)
        
        # Convert datetime to string for JSON serialization
        discovery_results['discovery_timestamp'] = discovery_results['discovery_timestamp'].isoformat()
        
        logger.info(f"Compliance discovery completed for host {host.hostname}: "
                   f"Found {len(discovery_results['python_environments'])} Python environments, "
                   f"{len(discovery_results['openscap_tools'])} OpenSCAP tools, "
                   f"{len(discovery_results['compliance_frameworks'])} supported frameworks")
        
        return ComplianceDiscoveryResponse(**discovery_results)
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid host ID format: {str(e)}"
        )
    except Exception as e:
        logger.error(f"Compliance discovery failed for host {host_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Compliance discovery failed: {str(e)}"
        )


@router.post("/bulk-compliance-discovery", response_model=BulkComplianceDiscoveryResponse)
async def bulk_discover_compliance_infrastructure(
    request: BulkComplianceDiscoveryRequest,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Discover compliance infrastructure for multiple hosts in bulk
    
    Args:
        request: BulkComplianceDiscoveryRequest containing list of host IDs
        
    Returns:
        BulkComplianceDiscoveryResponse with results for all hosts
    """
    # Check permissions
    check_permission(current_user, "hosts:read")
    
    if not request.host_ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No host IDs provided"
        )
    
    if len(request.host_ids) > 20:  # Limit bulk operations for compliance (more intensive)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Too many hosts requested. Maximum 20 hosts per bulk compliance discovery operation."
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
            discovery_results['discovery_timestamp'] = discovery_results['discovery_timestamp'].isoformat()
            
            results[host_id] = ComplianceDiscoveryResponse(**discovery_results)
            
            if discovery_results['discovery_success']:
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
    
    logger.info(f"Bulk compliance discovery completed: {successful_discoveries} successful, "
               f"{failed_discoveries} failed out of {len(request.host_ids)} total hosts")
    
    return BulkComplianceDiscoveryResponse(
        total_hosts=len(request.host_ids),
        successful_discoveries=successful_discoveries,
        failed_discoveries=failed_discoveries,
        results=results,
        errors=errors
    )


@router.get("/hosts/{host_id}/compliance-assessment", response_model=ComplianceCapabilityAssessment)
async def assess_host_compliance_capability(
    host_id: str,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Assess a host's compliance capability and readiness
    
    Args:
        host_id: UUID of the host to assess
        
    Returns:
        ComplianceCapabilityAssessment with readiness evaluation
    """
    # Check permissions
    check_permission(current_user, "hosts:read")
    
    try:
        # Convert string UUID to UUID object
        host_uuid = UUID(host_id)
        
        # Get host from database
        host = db.query(Host).filter(Host.id == host_uuid).first()
        if not host:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Host with ID {host_id} not found"
            )
        
        # Perform compliance discovery
        compliance_service = HostComplianceDiscoveryService()
        discovery_results = compliance_service.discover_compliance_infrastructure(host)
        
        # Assess capabilities
        assessment = _assess_compliance_capabilities(host, discovery_results)
        
        return assessment
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid host ID format: {str(e)}"
        )
    except Exception as e:
        logger.error(f"Compliance assessment failed for host {host_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Compliance assessment failed: {str(e)}"
        )


@router.get("/compliance-frameworks")
async def get_supported_compliance_frameworks(
    current_user=Depends(get_current_user)
):
    """
    Get list of compliance frameworks that can be discovered and supported
    
    Returns:
        List of supported compliance frameworks with descriptions
    """
    # Check permissions
    check_permission(current_user, "hosts:read")
    
    frameworks = {
        "NIST 800-53": {
            "name": "NIST SP 800-53",
            "description": "Security and Privacy Controls for Federal Information Systems",
            "requires": ["OpenSCAP", "Python", "Audit Tools"],
            "category": "Federal Compliance"
        },
        "DISA STIG": {
            "name": "DISA Security Technical Implementation Guides",
            "description": "DoD security configuration standards",
            "requires": ["OpenSCAP", "Privilege Escalation"],
            "category": "Military/Defense"
        },
        "CIS Controls": {
            "name": "Center for Internet Security Controls",
            "description": "Cybersecurity best practices framework",
            "requires": ["OpenSCAP", "InSpec", "Audit Tools"],
            "category": "Industry Standard"
        },
        "PCI DSS": {
            "name": "Payment Card Industry Data Security Standard",
            "description": "Security standards for payment card processing",
            "requires": ["OpenSCAP", "File Integrity Monitoring", "Audit Tools"],
            "category": "Industry Regulation"
        },
        "FISMA": {
            "name": "Federal Information Security Management Act",
            "description": "US federal security compliance framework",
            "requires": ["OpenSCAP", "Audit Tools", "Python"],
            "category": "Federal Compliance"
        },
        "HIPAA": {
            "name": "Health Insurance Portability and Accountability Act",
            "description": "Healthcare data protection regulations",
            "requires": ["Audit Tools", "File Integrity Monitoring"],
            "category": "Healthcare Regulation"
        },
        "SOX": {
            "name": "Sarbanes-Oxley Act",
            "description": "Financial reporting and corporate governance",
            "requires": ["Audit Tools", "File Integrity Monitoring"],
            "category": "Financial Regulation"
        }
    }
    
    return frameworks


def _assess_compliance_capabilities(host: Host, discovery_results: Dict[str, Any]) -> ComplianceCapabilityAssessment:
    """Assess host's compliance capabilities based on discovery results"""
    
    # Assess SCAP capability
    openscap_tools = discovery_results.get('openscap_tools', {})
    if any(tool.get('available') for tool in openscap_tools.values()):
        scap_capability = "full"
    else:
        scap_capability = "none"
    
    # Assess Python capability
    python_envs = discovery_results.get('python_environments', {})
    if python_envs:
        python_capability = "available"
    else:
        python_capability = "none"
    
    # Assess privilege escalation
    privilege_tools = discovery_results.get('privilege_escalation', {})
    if privilege_tools.get('sudo', {}).get('available'):
        privilege_escalation = "available"
    elif privilege_tools.get('su', {}).get('available'):
        privilege_escalation = "limited"
    else:
        privilege_escalation = "none"
    
    # Assess audit capability
    audit_tools = discovery_results.get('audit_tools', {})
    audit_count = sum(1 for tool in audit_tools.values() if tool.get('available'))
    if audit_count >= 3:
        audit_capability = "full"
    elif audit_count >= 1:
        audit_capability = "partial"
    else:
        audit_capability = "none"
    
    # Calculate readiness score
    score = 0.0
    if scap_capability == "full":
        score += 0.4
    if python_capability == "available":
        score += 0.2
    if privilege_escalation == "available":
        score += 0.2
    elif privilege_escalation == "limited":
        score += 0.1
    if audit_capability == "full":
        score += 0.2
    elif audit_capability == "partial":
        score += 0.1
    
    # Determine overall readiness
    if score >= 0.8:
        overall_readiness = "ready"
    elif score >= 0.5:
        overall_readiness = "partial"
    else:
        overall_readiness = "not_ready"
    
    # Recommended frameworks based on capabilities
    recommended_frameworks = []
    if scap_capability == "full":
        recommended_frameworks.extend(["NIST 800-53", "DISA STIG", "CIS Controls"])
    if audit_capability in ["full", "partial"]:
        recommended_frameworks.extend(["SOX", "HIPAA", "FISMA"])
    
    # Missing tools
    missing_tools = []
    if scap_capability == "none":
        missing_tools.append("OpenSCAP")
    if python_capability == "none":
        missing_tools.append("Python")
    if privilege_escalation == "none":
        missing_tools.append("Sudo/Privilege Escalation")
    if audit_capability == "none":
        missing_tools.append("Audit Tools")
    
    return ComplianceCapabilityAssessment(
        host_id=str(host.id),
        hostname=host.hostname,
        overall_compliance_readiness=overall_readiness,
        scap_capability=scap_capability,
        python_capability=python_capability,
        privilege_escalation=privilege_escalation,
        audit_capability=audit_capability,
        recommended_frameworks=list(set(recommended_frameworks)),
        missing_tools=missing_tools,
        readiness_score=score
    )