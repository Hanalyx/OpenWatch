"""
MongoDB Models for OpenWatch Compliance Rules
Enhanced models with inheritance and multi-platform support
"""
from motor.motor_asyncio import AsyncIOMotorClient
from beanie import Document, Indexed, init_beanie
from pydantic import Field, BaseModel, validator
from typing import List, Dict, Optional, Any, Union
from datetime import datetime
from enum import Enum
import hashlib


class FrameworkVersions(BaseModel):
    """Versioned framework mappings supporting multiple compliance standards"""
    nist: Optional[Dict[str, List[str]]] = Field(
        default_factory=dict,
        description="NIST 800-53 mappings by version (e.g., {'800-53r4': ['AC-2'], '800-53r5': ['AC-2']})"
    )
    cis: Optional[Dict[str, List[str]]] = Field(
        default_factory=dict,
        description="CIS Controls mappings by version (e.g., {'rhel8_v2.0.0': ['5.1.1']})"
    )
    stig: Optional[Dict[str, str]] = Field(
        default_factory=dict,
        description="DISA STIG mappings by version (e.g., {'rhel8_v1r11': 'RHEL-08-020070'})"
    )
    pci_dss: Optional[Dict[str, List[str]]] = Field(
        default_factory=dict,
        description="PCI DSS requirements by version"
    )
    iso27001: Optional[Dict[str, List[str]]] = Field(
        default_factory=dict,
        description="ISO 27001 controls by version"
    )
    hipaa: Optional[Dict[str, List[str]]] = Field(
        default_factory=dict,
        description="HIPAA safeguards by regulation section"
    )


class PlatformImplementation(BaseModel):
    """Platform-specific implementation details"""
    versions: List[str] = Field(
        description="OS versions this implementation applies to"
    )
    service_name: Optional[str] = Field(
        default=None,
        description="System service name if applicable"
    )
    check_command: Optional[str] = Field(
        default=None,
        description="Command to check rule compliance"
    )
    check_method: Optional[str] = Field(
        default=None,
        description="Check method type (systemd, file, command, package, etc.)"
    )
    check_script: Optional[str] = Field(
        default=None,
        description="Script content for complex checks"
    )
    config_files: Optional[List[str]] = Field(
        default_factory=list,
        description="Configuration files affected by this rule"
    )
    enable_command: Optional[str] = Field(
        default=None,
        description="Command to enable/fix the rule"
    )
    disable_command: Optional[str] = Field(
        default=None,
        description="Command to disable the rule (for testing)"
    )
    validation_command: Optional[str] = Field(
        default=None,
        description="Command to validate the fix was applied"
    )
    service_dependencies: Optional[List[str]] = Field(
        default_factory=list,
        description="Required packages or services"
    )


class ConditionalLogic(BaseModel):
    """Conditional rule logic based on platform/version"""
    if_condition: Dict[str, Any] = Field(
        description="Condition to evaluate (e.g., {'platform': 'rhel', 'version': {'$gte': '8'}})"
    )
    then_action: Dict[str, Any] = Field(
        description="Action to take when condition is true"
    )
    else_action: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Action to take when condition is false"
    )


class PlatformCapability(BaseModel):
    """Platform capability detection configuration"""
    detect_command: str = Field(
        description="Command to detect the capability"
    )
    parse_version: bool = Field(
        default=False,
        description="Whether to parse version from command output"
    )
    expected_values: Optional[List[str]] = Field(
        default=None,
        description="Expected output values that indicate capability exists"
    )
    expected_exit_code: Optional[int] = Field(
        default=0,
        description="Expected exit code for successful capability detection"
    )


class CheckContent(BaseModel):
    """Enhanced check content structure"""
    check_type: str = Field(
        description="Type of check (file, command, service, package, etc.)"
    )
    file_path: Optional[str] = Field(default=None)
    parameter: Optional[str] = Field(default=None)
    pattern: Optional[str] = Field(default=None)
    expected_value: Optional[Union[str, int, float, bool]] = Field(default=None)
    comparison: Optional[str] = Field(
        default="equals",
        description="Comparison operator (equals, greater_than, less_than, etc.)"
    )
    config_format: Optional[str] = Field(
        default=None,
        description="Configuration file format (ini, json, yaml, ssh_config, etc.)"
    )
    oval_reference: Optional[Dict[str, str]] = Field(
        default=None,
        description="OVAL definition reference"
    )
    ocil_reference: Optional[Dict[str, str]] = Field(
        default=None,
        description="OCIL questionnaire reference"
    )


class FixContent(BaseModel):
    """Multi-format remediation content"""
    shell: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Shell script remediation"
    )
    ansible: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Ansible playbook remediation"
    )
    puppet: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Puppet manifest remediation"
    )
    powershell: Optional[Dict[str, Any]] = Field(
        default=None,
        description="PowerShell script remediation (for Windows)"
    )


class ComplianceRule(Document):
    """Enhanced MongoDB model for compliance rules with inheritance and multi-platform support"""
    
    # Core Identifiers
    rule_id: str = Field(
        description="Unique OpenWatch rule identifier"
    )
    scap_rule_id: Optional[str] = Field(
        default=None,
        description="Original SCAP rule identifier for traceability"
    )
    parent_rule_id: Optional[str] = Field(
        default=None,
        description="For rule families and groupings"
    )
    
    # Rich Metadata with Versioning
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Rich metadata including name, description, source provenance"
    )
    
    # Rule Type and Inheritance
    abstract: bool = Field(
        default=False,
        description="True if this is a base rule that cannot be executed directly"
    )
    inherits_from: Optional[str] = Field(
        default=None,
        description="Rule ID this rule inherits from"
    )
    derived_rules: List[str] = Field(
        default_factory=list,
        description="Auto-populated list of rules that inherit from this one"
    )
    
    # Enhanced Classification
    severity: str = Field(
        pattern="^(info|low|medium|high|critical)$",
        description="Rule severity level"
    )
    category: str = Field(
        description="Rule category (authentication, access_control, logging, etc.)"
    )
    security_function: Optional[str] = Field(
        default=None,
        description="High-level security function (network_protection, data_encryption, etc.)"
    )
    tags: List[str] = Field(
        default_factory=list,
        description="Searchable tags for categorization"
    )
    
    # Multi-Version Framework Support
    frameworks: FrameworkVersions = Field(
        default_factory=FrameworkVersions,
        description="Compliance framework mappings with version support"
    )
    
    # Platform Abstraction
    platform_implementations: Dict[str, PlatformImplementation] = Field(
        default_factory=dict,
        description="Platform-specific implementation details (key: 'rhel', 'ubuntu', 'windows')"
    )
    
    # Platform Requirements (Capability-Based)
    platform_requirements: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Required and optional platform capabilities"
    )
    
    platform_capability_detection: Optional[Dict[str, PlatformCapability]] = Field(
        default=None,
        description="Configuration for detecting platform capabilities"
    )
    
    # Conditional Logic for OS/Version-Specific Behaviors
    conditions: List[ConditionalLogic] = Field(
        default_factory=list,
        description="Conditional logic for platform/version-specific behavior"
    )
    
    # Base Rule Definition (for inheritance)
    base_parameters: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Base parameters that can be inherited and overridden"
    )
    inheritable_properties: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Properties that derived rules inherit"
    )
    
    # Platform-Specific Parameter Overrides
    parameter_overrides: Optional[Dict[str, Dict[str, Any]]] = Field(
        default=None,
        description="Platform and framework-specific parameter overrides"
    )
    
    parameter_resolution: str = Field(
        default="most_restrictive",
        pattern="^(most_restrictive|framework_specific|platform_default)$",
        description="Strategy for resolving parameter conflicts"
    )
    
    # Assessment Logic (Enhanced)
    check_type: str = Field(
        pattern="^(script|command|file|package|service|kernel|multi_parameter|oval|custom)$",
        description="Type of check to perform"
    )
    check_content: Dict[str, Any] = Field(
        description="Detailed check configuration"
    )
    
    # Advanced Dependencies
    dependencies: Dict[str, List[str]] = Field(
        default_factory=lambda: {"requires": [], "conflicts": [], "related": []},
        description="Rule dependencies and relationships"
    )
    
    # Remediation with Platform Variants  
    fix_available: bool = Field(
        default=False,
        description="Whether automated remediation is available"
    )
    fix_content: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Multi-format remediation content"
    )
    manual_remediation: Optional[str] = Field(
        default=None,
        description="Manual remediation instructions"
    )
    remediation_complexity: str = Field(
        default="medium",
        pattern="^(low|medium|high)$",
        description="Complexity of applying the remediation"
    )
    remediation_risk: str = Field(
        default="low",
        pattern="^(low|medium|high)$",
        description="Risk level of applying the remediation"
    )
    
    # Change Tracking and Provenance
    source_file: str = Field(
        description="Original source file (SCAP XML, etc.)"
    )
    source_hash: str = Field(
        description="Hash of the source content for change detection"
    )
    version: str = Field(
        default="1.0.0",
        description="Rule version"
    )
    imported_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="When the rule was imported"
    )
    updated_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="Last update timestamp"
    )
    
    @validator('rule_id')
    def validate_rule_id(cls, v):
        if not v or len(v) < 3:
            raise ValueError('Rule ID must be at least 3 characters long')
        if not v.startswith('ow-'):
            raise ValueError('Rule ID must start with "ow-"')
        return v
    
    @validator('metadata')
    def validate_metadata(cls, v):
        if not v.get('name'):
            raise ValueError('Metadata must contain a name')
        return v
    
    class Settings:
        name = "compliance_rules"
        indexes = [
            # Unique constraint on rule_id
            "rule_id",
            
            # Multi-platform queries
            [("platform_implementations.rhel.versions", 1), ("severity", -1)],
            [("platform_implementations.ubuntu.versions", 1), ("severity", -1)],
            [("platform_implementations.windows.versions", 1), ("severity", -1)],
            
            # Framework version queries
            "frameworks.nist",
            "frameworks.cis", 
            "frameworks.stig",
            
            # Inheritance and capability queries
            "inherits_from",
            [("abstract", 1), ("category", 1)],
            
            # Standard queries
            [("category", 1), ("severity", -1)],
            "tags",
            "security_function",
            [("updated_at", -1)]
        ]


class RuleIntelligence(Document):
    """Extended intelligence and context for rules"""
    
    rule_id: str = Field(
        description="Reference to compliance rule"
    )
    
    # Business Context
    business_impact: str = Field(
        description="Business impact description"
    )
    compliance_importance: int = Field(
        ge=1, le=10,
        description="Importance score for compliance (1-10)"
    )
    
    # Known Issues
    false_positive_rate: float = Field(
        ge=0.0, le=1.0, default=0.0,
        description="Historical false positive rate"
    )
    common_exceptions: List[Dict] = Field(
        default_factory=list,
        description="Common legitimate exceptions to this rule"
    )
    
    # Implementation Guidance
    implementation_notes: str = Field(
        description="Detailed implementation guidance"
    )
    testing_guidance: str = Field(
        description="How to test the rule implementation"
    )
    rollback_procedure: Optional[str] = Field(
        default=None,
        description="How to rollback if remediation causes issues"
    )
    
    # Performance Impact
    scan_duration_avg_ms: int = Field(
        default=0,
        description="Average scan duration in milliseconds"
    )
    resource_impact: str = Field(
        default="low",
        pattern="^(low|medium|high)$",
        description="System resource impact during scanning"
    )
    
    # Community Data
    success_rate: float = Field(
        ge=0.0, le=1.0, default=1.0,
        description="Success rate of remediation across environments"
    )
    usage_count: int = Field(
        default=0,
        description="How often this rule is used in scans"
    )
    last_validation: datetime = Field(
        default_factory=datetime.utcnow,
        description="Last time intelligence was validated"
    )
    
    class Settings:
        name = "rule_intelligence"
        indexes = [
            "rule_id",
            "compliance_importance",
            "success_rate",
            "last_validation"
        ]


class RemediationScript(Document):
    """Detailed remediation scripts and procedures"""
    
    rule_id: str = Field(
        description="Reference to compliance rule"
    )
    platform: str = Field(
        description="Target platform (rhel, ubuntu, windows, etc.)"
    )
    script_type: str = Field(
        pattern="^(bash|python|ansible|powershell|puppet)$",
        description="Script/automation type"
    )
    
    # Script Content
    script_content: str = Field(
        description="Complete script content"
    )
    requires_root: bool = Field(
        default=True,
        description="Whether script requires root/administrator privileges"
    )
    estimated_duration_seconds: int = Field(
        description="Estimated execution time in seconds"
    )
    
    # Validation
    validation_command: Optional[str] = Field(
        default=None,
        description="Command to validate the script worked correctly"
    )
    rollback_script: Optional[str] = Field(
        default=None,
        description="Script to undo the changes if needed"
    )
    
    # Metadata
    tested_on: List[str] = Field(
        default_factory=list,
        description="OS versions/distributions where this was tested"
    )
    contributed_by: Optional[str] = Field(
        default=None,
        description="Who contributed this script"
    )
    approved: bool = Field(
        default=False,
        description="Whether this script has been approved for use"
    )
    approval_date: Optional[datetime] = Field(
        default=None,
        description="When the script was approved"
    )
    
    class Settings:
        name = "remediation_scripts"
        indexes = [
            [("rule_id", 1), ("platform", 1)],
            "script_type",
            "approved",
            "approval_date"
        ]


# Database connection management
class MongoManager:
    """MongoDB connection and database management"""
    
    def __init__(self):
        self.client: Optional[AsyncIOMotorClient] = None
        self.database = None
        self.initialized = False
    
    async def initialize(
        self, 
        mongodb_url: str,
        database_name: str = "openwatch_rules",
        **kwargs
    ):
        """Initialize MongoDB connection and Beanie ODM"""
        
        if self.initialized:
            return
        
        # Create MongoDB client with connection pooling
        client_kwargs = {
            'minPoolSize': kwargs.get('min_pool_size', 10),
            'maxPoolSize': kwargs.get('max_pool_size', 100),
            'connectTimeoutMS': 30000,
            'serverSelectionTimeoutMS': 30000,
            'heartbeatFrequencyMS': 10000
        }
        
        # Add SSL configuration only if SSL is enabled
        if kwargs.get('ssl', False):
            client_kwargs.update({
                'tls': True,
                'tlsCertificateKeyFile': kwargs.get('ssl_cert'),
                'tlsCAFile': kwargs.get('ssl_ca'),
                'tlsAllowInvalidCertificates': kwargs.get('ssl_allow_invalid', False)
            })
        
        self.client = AsyncIOMotorClient(mongodb_url, **client_kwargs)
        
        # Get database
        self.database = self.client[database_name]
        
        # Initialize Beanie with document models
        await init_beanie(
            database=self.database,
            document_models=[ComplianceRule, RuleIntelligence, RemediationScript]
        )
        
        self.initialized = True
    
    async def health_check(self) -> Dict[str, Any]:
        """Check MongoDB connection health"""
        if not self.initialized:
            return {"status": "error", "message": "Not initialized"}
        
        try:
            # Test connection
            await self.client.admin.command('ping')
            
            # Get database stats
            stats = await self.database.command('dbStats')
            
            return {
                "status": "healthy",
                "database": self.database.name,
                "collections": await self.database.list_collection_names(),
                "document_count": {
                    "compliance_rules": await ComplianceRule.count(),
                    "rule_intelligence": await RuleIntelligence.count(),
                    "remediation_scripts": await RemediationScript.count()
                },
                "stats": {
                    "storage_size": stats.get('storageSize', 0),
                    "data_size": stats.get('dataSize', 0),
                    "index_size": stats.get('indexSize', 0)
                }
            }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }
    
    async def close(self):
        """Close MongoDB connection"""
        if self.client:
            self.client.close()
            self.initialized = False


# Global MongoDB manager instance
mongo_manager = MongoManager()


async def get_mongo_manager() -> MongoManager:
    """Get MongoDB manager instance"""
    return mongo_manager