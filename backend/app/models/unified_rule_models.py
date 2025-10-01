"""
Unified Rule Models
Models for executable compliance rules that map to multiple frameworks
"""
from typing import List, Dict, Any, Optional, Union
from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field
from beanie import Document

from backend.app.models.enhanced_mongo_models import FrameworkControlDefinition


class RuleType(str, Enum):
    """Types of compliance rules"""
    FILE_CHECK = "file_check"
    COMMAND_EXECUTION = "command_execution"
    SERVICE_STATUS = "service_status"
    CONFIGURATION_PARSE = "configuration_parse"
    REGISTRY_CHECK = "registry_check"
    PACKAGE_CHECK = "package_check"
    NETWORK_CHECK = "network_check"
    PERMISSION_CHECK = "permission_check"
    CONTENT_MATCH = "content_match"
    COMPOSITE = "composite"


class ComplianceStatus(str, Enum):
    """Compliance status values"""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant" 
    PARTIAL = "partial"
    EXCEEDS = "exceeds"
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"


class Platform(str, Enum):
    """Supported platforms"""
    RHEL_8 = "rhel_8"
    RHEL_9 = "rhel_9"
    UBUNTU_20_04 = "ubuntu_20_04"
    UBUNTU_22_04 = "ubuntu_22_04"
    UBUNTU_24_04 = "ubuntu_24_04"
    CENTOS_7 = "centos_7"
    CENTOS_8 = "centos_8"
    DEBIAN_11 = "debian_11"
    DEBIAN_12 = "debian_12"
    WINDOWS_2019 = "windows_2019"
    WINDOWS_2022 = "windows_2022"


class PlatformVersionRange(BaseModel):
    """Platform version range specification"""
    platform: Platform
    min_version: Optional[str] = None
    max_version: Optional[str] = None
    excluded_versions: List[str] = Field(default_factory=list)
    architecture: Optional[str] = None  # x86_64, aarch64, etc.


class RuleParameter(BaseModel):
    """Parameter for rule execution"""
    name: str
    type: str  # string, integer, boolean, list, dict
    description: str
    default_value: Optional[Any] = None
    required: bool = True
    validation_regex: Optional[str] = None
    allowed_values: Optional[List[str]] = None


class ExecutionContext(BaseModel):
    """Context for rule execution"""
    command: Optional[str] = None
    file_path: Optional[str] = None
    service_name: Optional[str] = None
    config_section: Optional[str] = None
    registry_key: Optional[str] = None
    package_name: Optional[str] = None
    expected_value: Optional[Any] = None
    comparison_operator: Optional[str] = None  # eq, ne, gt, lt, gte, lte, contains, regex
    timeout: int = 30
    working_directory: Optional[str] = None
    environment_vars: Dict[str, str] = Field(default_factory=dict)


class RemediationAction(BaseModel):
    """Remediation action for non-compliant rules"""
    type: str  # command, file_edit, service_action, package_install
    description: str
    commands: List[str] = Field(default_factory=list)
    files_to_modify: List[Dict[str, Any]] = Field(default_factory=list)
    services_to_restart: List[str] = Field(default_factory=list)
    packages_to_install: List[str] = Field(default_factory=list)
    risk_level: str = "medium"  # low, medium, high, critical
    requires_reboot: bool = False
    backup_required: bool = True


class FrameworkMapping(BaseModel):
    """Mapping to framework controls"""
    framework_id: str
    control_ids: List[str]
    compliance_status: ComplianceStatus = ComplianceStatus.COMPLIANT
    enhancement_description: Optional[str] = None
    justification: Optional[str] = None
    evidence_artifacts: List[str] = Field(default_factory=list)


class UnifiedComplianceRule(Document):
    """
    Unified compliance rule that can satisfy multiple framework requirements
    """
    
    # Core identification
    rule_id: str = Field(unique=True, description="Unique rule identifier")
    title: str = Field(description="Human-readable rule title")
    description: str = Field(description="Detailed rule description")
    version: str = Field(default="1.0", description="Rule version")
    
    # Rule execution
    rule_type: RuleType = Field(description="Type of compliance check")
    execution_context: ExecutionContext = Field(description="How to execute the rule")
    parameters: List[RuleParameter] = Field(default_factory=list, description="Rule parameters")
    
    # Platform support
    supported_platforms: List[PlatformVersionRange] = Field(description="Supported platform versions")
    
    # Framework mappings
    framework_mappings: List[FrameworkMapping] = Field(description="Framework control mappings")
    
    # Compliance logic
    pass_criteria: str = Field(description="Criteria for determining compliance")
    severity: str = Field(default="medium", description="Rule severity level")
    category: str = Field(description="Rule category")
    tags: List[str] = Field(default_factory=list, description="Rule tags for classification")
    
    # Remediation
    remediation: Optional[RemediationAction] = None
    
    # Metadata
    created_by: str = Field(description="Rule author")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    reviewed_at: Optional[datetime] = None
    reviewed_by: Optional[str] = None
    
    # Status and validation
    is_active: bool = Field(default=True, description="Whether rule is active")
    is_validated: bool = Field(default=False, description="Whether rule has been validated")
    validation_notes: Optional[str] = None
    
    class Settings:
        name = "unified_compliance_rules"
        indexes = [
            "rule_id",
            "rule_type",
            "category", 
            "severity",
            "framework_mappings.framework_id",
            "framework_mappings.control_ids",
            "supported_platforms.platform",
            "tags",
            ("rule_type", "category"),
            ("framework_mappings.framework_id", "framework_mappings.control_ids"),
            ("supported_platforms.platform", "severity")
        ]


class RuleExecution(Document):
    """
    Record of rule execution and results
    """
    
    # Execution identification
    execution_id: str = Field(unique=True, description="Unique execution identifier")
    rule_id: str = Field(description="Rule that was executed")
    host_id: str = Field(description="Host where rule was executed")
    scan_id: Optional[str] = None
    
    # Execution context
    executed_at: datetime = Field(default_factory=datetime.utcnow)
    executed_by: str = Field(description="User or system that executed the rule")
    execution_parameters: Dict[str, Any] = Field(default_factory=dict)
    
    # Platform information
    platform: Platform = Field(description="Target platform")
    platform_version: str = Field(description="Platform version")
    platform_architecture: str = Field(description="Platform architecture")
    
    # Execution results
    compliance_status: ComplianceStatus = Field(description="Overall compliance status")
    execution_success: bool = Field(description="Whether execution completed successfully")
    execution_time: float = Field(description="Execution time in seconds")
    
    # Detailed results
    raw_output: Optional[str] = None
    processed_output: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    exit_code: Optional[int] = None
    
    # Framework-specific results
    framework_results: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Results per framework mapping"
    )
    
    # Evidence and artifacts
    evidence_collected: List[str] = Field(default_factory=list)
    artifacts_paths: List[str] = Field(default_factory=list)
    
    # Compliance justification
    justification: Optional[str] = None
    enhancement_details: Optional[str] = None
    
    class Settings:
        name = "rule_executions"
        indexes = [
            "execution_id",
            "rule_id",
            "host_id",
            "scan_id",
            "executed_at",
            "compliance_status",
            "platform",
            ("rule_id", "host_id"),
            ("scan_id", "compliance_status"),
            ("executed_at", "compliance_status"),
            ("platform", "compliance_status")
        ]


class RuleSet(Document):
    """
    Collection of rules for specific compliance scenarios
    """
    
    # Identification
    ruleset_id: str = Field(unique=True, description="Unique ruleset identifier")
    name: str = Field(description="Ruleset name")
    description: str = Field(description="Ruleset description")
    version: str = Field(default="1.0", description="Ruleset version")
    
    # Rule composition
    rule_ids: List[str] = Field(description="Rules included in this set")
    
    # Framework targeting
    target_frameworks: List[str] = Field(description="Primary frameworks this ruleset addresses")
    supported_platforms: List[Platform] = Field(description="Platforms this ruleset supports")
    
    # Execution settings
    execution_order: List[str] = Field(default_factory=list, description="Preferred execution order")
    parallel_execution: bool = Field(default=True, description="Whether rules can run in parallel")
    stop_on_error: bool = Field(default=False, description="Whether to stop execution on first error")
    
    # Compliance thresholds
    minimum_compliance_percentage: float = Field(default=95.0, description="Minimum compliance percentage")
    critical_rule_ids: List[str] = Field(default_factory=list, description="Rules that must pass")
    
    # Metadata
    created_by: str = Field(description="Ruleset author")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    
    # Status
    is_active: bool = Field(default=True, description="Whether ruleset is active")
    is_validated: bool = Field(default=False, description="Whether ruleset has been validated")
    
    class Settings:
        name = "rule_sets"
        indexes = [
            "ruleset_id",
            "target_frameworks",
            "supported_platforms",
            "is_active",
            ("target_frameworks", "supported_platforms")
        ]


class ComplianceProfile(Document):
    """
    Compliance profile combining multiple rulesets for comprehensive assessment
    """
    
    # Identification
    profile_id: str = Field(unique=True, description="Unique profile identifier")
    name: str = Field(description="Profile name")
    description: str = Field(description="Profile description")
    version: str = Field(default="1.0", description="Profile version")
    
    # Profile composition
    ruleset_ids: List[str] = Field(description="Rulesets included in this profile")
    
    # Framework coverage
    framework_coverage: Dict[str, float] = Field(
        default_factory=dict,
        description="Percentage coverage per framework"
    )
    
    # Compliance requirements
    overall_compliance_threshold: float = Field(default=90.0)
    framework_compliance_thresholds: Dict[str, float] = Field(default_factory=dict)
    
    # Risk and severity
    risk_level: str = Field(default="medium", description="Overall risk level")
    business_criticality: str = Field(default="medium", description="Business criticality")
    
    # Metadata
    created_by: str = Field(description="Profile author")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    
    # Status
    is_active: bool = Field(default=True, description="Whether profile is active")
    is_approved: bool = Field(default=False, description="Whether profile is approved for use")
    
    class Settings:
        name = "compliance_profiles"
        indexes = [
            "profile_id",
            "framework_coverage",
            "risk_level",
            "business_criticality",
            "is_active",
            "is_approved"
        ]