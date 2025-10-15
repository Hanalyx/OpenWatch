"""
MongoDB Models for OpenWatch Compliance Rules
Enhanced models with inheritance and multi-platform support
"""
# Optional motor/beanie imports for test compatibility
try:
    from motor.motor_asyncio import AsyncIOMotorClient
    from beanie import Document, Indexed, init_beanie
    MOTOR_AVAILABLE = True
except ImportError:
    # Allow imports to work without motor/beanie for testing
    MOTOR_AVAILABLE = False
    AsyncIOMotorClient = type('AsyncIOMotorClient', (), {})
    Document = object
    Indexed = lambda *args, **kwargs: lambda x: x
    init_beanie = None

from pydantic import Field, BaseModel, validator
from typing import List, Dict, Optional, Any, Union
from datetime import datetime
from enum import Enum
import hashlib

# Import Phase 1 Beanie document models for registration
try:
    from .scan_config_models import ScanTemplate
    from .scan_models import ScanResult, ScanSchedule
    from .remediation_models import RemediationResult, BulkRemediationJob
    PHASE1_MODELS_AVAILABLE = True
except ImportError:
    # Fallback if Phase 1 models not available
    ScanTemplate = None
    ScanResult = None
    ScanSchedule = None
    RemediationResult = None
    BulkRemediationJob = None
    PHASE1_MODELS_AVAILABLE = False


class FrameworkVersions(BaseModel):
    """Versioned framework mappings supporting multiple compliance standards"""

    model_config = {
        # Exclude None values when serializing - critical for idempotency
        "exclude_none": True,
        # Exclude unset fields - only serialize fields that were explicitly set
        "exclude_unset": True,
        # CRITICAL: Also exclude None when converting to dict for MongoDB
        "use_enum_values": True
    }

    nist: Optional[Dict[str, List[str]]] = None
    cis: Optional[Dict[str, List[str]]] = None
    stig: Optional[Dict[str, Union[str, List[str]]]] = None
    pci_dss: Optional[Dict[str, List[str]]] = None
    iso27001: Optional[Dict[str, List[str]]] = None
    hipaa: Optional[Dict[str, List[str]]] = None

    def model_dump(self, **kwargs):
        """Override to ensure None values are excluded for MongoDB storage"""
        # Force exclude_none=True for all dumps
        kwargs['exclude_none'] = True
        return super().model_dump(**kwargs)


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


class XCCDFVariable(BaseModel):
    """
    XCCDF variable definition for scan-time customization

    XCCDF variables allow users to customize compliance checks at scan time.
    Examples: session timeout values, login banner text, password policies.

    Supports Solution A (XCCDF Variables) for hybrid scanning architecture.
    See: /docs/REMEDIATION_WITH_XCCDF_VARIABLES.md
    """

    model_config = {
        "exclude_none": True,
        "exclude_unset": True
    }

    id: str = Field(
        description="Variable identifier (e.g., 'var_accounts_tmout', 'login_banner_text')"
    )
    title: str = Field(
        description="Human-readable variable title"
    )
    description: Optional[str] = Field(
        default=None,
        description="Detailed description of what this variable controls"
    )
    type: str = Field(
        pattern="^(string|number|boolean)$",
        description="Variable data type: string, number, or boolean"
    )
    default_value: str = Field(
        description="Default value if user doesn't provide custom value"
    )
    interactive: bool = Field(
        default=True,
        description="Whether this variable can be customized via UI/API (set to False for system variables)"
    )
    sensitive: bool = Field(
        default=False,
        description="Whether this variable contains sensitive data (passwords, keys, etc.). Encrypted in storage, masked in UI."
    )
    constraints: Optional[Dict[str, Any]] = Field(
        default=None,
        description="""
        Validation constraints for variable values:
        - min_value/max_value: For numeric types
        - min_length/max_length: For string types
        - choices: List of allowed values (enum-like)
        - pattern: Regex pattern for validation (string types)

        Examples:
        - {"min_value": 60, "max_value": 3600} # Session timeout 1-60 mins
        - {"choices": ["300", "600", "900"]} # Predefined timeout options
        - {"pattern": "^grub\\.pbkdf2\\.sha512\\."} # GRUB password hash format
        """
    )

    @validator('type')
    def validate_type(cls, v):
        """Ensure type is one of the supported XCCDF types"""
        valid_types = ['string', 'number', 'boolean']
        if v not in valid_types:
            raise ValueError(f"Invalid type '{v}'. Must be one of: {', '.join(valid_types)}")
        return v

    @validator('constraints')
    def validate_constraints(cls, v, values):
        """Validate constraints match the variable type"""
        if not v:
            return v

        var_type = values.get('type')

        if var_type == 'number':
            # Validate numeric constraints
            if 'min_value' in v and 'max_value' in v:
                if v['min_value'] > v['max_value']:
                    raise ValueError("min_value cannot be greater than max_value")

        elif var_type == 'string':
            # Validate string constraints
            if 'min_length' in v and 'max_length' in v:
                if v['min_length'] > v['max_length']:
                    raise ValueError("min_length cannot be greater than max_length")

            # Validate pattern if provided
            if 'pattern' in v:
                import re
                try:
                    re.compile(v['pattern'])
                except re.error as e:
                    raise ValueError(f"Invalid regex pattern: {e}")

        return v


class ComplianceRule(Document):
    """Enhanced MongoDB model for compliance rules with inheritance and multi-platform support"""

    class Settings:
        name = "compliance_rules"
        use_state_management = True
        validate_on_save = True
        indexes = [
            "rule_id",  # Primary lookup
            "scanner_type",  # Phase 1: Route rules to appropriate scanner
            "version",  # Version queries
            "is_latest",  # Current version queries
            [("rule_id", 1), ("version", -1)],  # Compound: rule + version
            [("scanner_type", 1), ("is_latest", 1)],  # Phase 1: Latest rules by scanner type
        ]

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
        pattern="^(info|low|medium|high|critical|unknown)$",
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

    # Cross-Reference Identifiers (CCE, CVE, OVAL, etc.)
    identifiers: Optional[Dict[str, str]] = Field(
        default=None,
        description="External identifiers for cross-referencing (cce, cve, oval_id, etc.)"
    )

    # Multi-Version Framework Support
    # CRITICAL: Use Dict instead of FrameworkVersions to prevent Pydantic from
    # auto-initializing None values for unset framework fields (breaks idempotency)
    frameworks: Dict[str, Any] = Field(
        default_factory=dict,
        description="Compliance framework mappings with version support (nist, cis, stig, pci_dss, iso27001, hipaa)"
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
        default="custom",
        pattern="^(script|command|file|package|service|kernel|multi_parameter|oval|custom|scap|template)$",
        description="Type of check to perform"
    )
    check_content: Dict[str, Any] = Field(
        default_factory=dict,
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
        default="unknown",
        description="Original source file (SCAP XML, etc.)"
    )
    source_hash: str = Field(
        default="unknown",
        description="Hash of the source content for change detection"
    )

    # Immutable Versioning (FISMA/FedRAMP/HIPAA Compliance)
    version: int = Field(
        default=1,
        description="Monotonically increasing version number (immutable versioning)"
    )
    version_hash: Optional[str] = Field(
        default=None,
        description="SHA-256 hash of rule content for integrity verification"
    )
    is_latest: bool = Field(
        default=True,
        description="Denormalized flag for query performance - true if this is the current version"
    )
    supersedes_version: Optional[int] = Field(
        default=None,
        description="Previous version number that this version replaces (null for v1)"
    )
    superseded_by: Optional[int] = Field(
        default=None,
        description="Next version number that replaces this version (null if is_latest)"
    )

    # Temporal Tracking (Audit Trail)
    effective_from: datetime = Field(
        default_factory=datetime.utcnow,
        description="When this version became the active version"
    )
    effective_until: Optional[datetime] = Field(
        default=None,
        description="When this version was superseded (null if still active)"
    )
    imported_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="When the rule was imported into the system"
    )
    updated_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="Last update timestamp (for this specific version document)"
    )
    created_by: Optional[str] = Field(
        default=None,
        description="User or system that created this version"
    )

    # Source Bundle Tracking
    source_bundle: Optional[str] = Field(
        default=None,
        description="Bundle filename this version was imported from"
    )
    source_bundle_hash: Optional[str] = Field(
        default=None,
        description="SHA-512 hash of source bundle for traceability"
    )
    import_id: Optional[str] = Field(
        default=None,
        description="UUID of the import operation that created this version"
    )

    # Change Metadata (Audit Information)
    change_summary: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Summary of what changed from previous version"
    )
    deprecated: bool = Field(
        default=False,
        description="True if this rule has been deprecated (for audit trail)"
    )
    deprecation_reason: Optional[str] = Field(
        default=None,
        description="Reason for deprecation if deprecated=True"
    )
    replacement_rule_id: Optional[str] = Field(
        default=None,
        description="Rule ID that replaces this deprecated rule"
    )

    # ============================================================================
    # Phase 1: Hybrid Scanning Architecture (XCCDF Variables + Native Scanners)
    # ============================================================================

    # XCCDF Variables for Scan-Time Customization (Solution A)
    xccdf_variables: Optional[Dict[str, XCCDFVariable]] = Field(
        default=None,
        description="""
        XCCDF variables that can be customized at scan time.

        Enables user customization of compliance checks without modifying rules:
        - Session timeouts (var_accounts_tmout)
        - Login banners (login_banner_text)
        - Password policies (var_password_pam_minlen)
        - GRUB credentials (grub2_bootloader_password)
        - etc.

        Maps variable IDs to XCCDFVariable definitions.

        Example:
        {
            "var_accounts_tmout": XCCDFVariable(
                id="var_accounts_tmout",
                title="Account Inactivity Timeout",
                type="number",
                default_value="600",
                constraints={"min_value": 60, "max_value": 3600}
            )
        }

        See: /docs/REMEDIATION_WITH_XCCDF_VARIABLES.md
        """
    )

    # Scanner Type Routing (Polyglot Scanner Architecture)
    scanner_type: str = Field(
        default="oscap",
        pattern="^(oscap|inspec|python|bash|aws_api|azure_api|gcp_api|kubernetes|docker|sql|mongodb|elasticsearch|opa_rego|custom)$",
        description="""
        Scanner engine to use for this rule.

        OpenWatch Native Scanning Engine uses domain-specific scanners:
        - oscap: Traditional OSCAP/OVAL checks (Linux/Unix)
        - inspec: Chef Inspec DSL checks
        - python: Custom Python scripts (sandboxed)
        - bash: Simple shell checks
        - aws_api: AWS cloud resources (S3, IAM, VPC, etc.)
        - azure_api: Azure cloud resources
        - gcp_api: GCP cloud resources
        - kubernetes: K8s resource compliance (kube-bench, OPA)
        - docker: Container image scanning (Trivy, Falco)
        - sql: Database configuration (PostgreSQL, MySQL, etc.)
        - mongodb: MongoDB configuration checks
        - elasticsearch: Elasticsearch settings
        - opa_rego: Open Policy Agent / Rego policies
        - custom: Organization-specific custom scanner

        See: /docs/ADVANCED_SCANNING_ARCHITECTURE.md
        """
    )

    # Remediation Content for ORSA (Open Remediation Standard Adapter)
    remediation: Optional[Dict[str, Any]] = Field(
        default=None,
        description="""
        Remediation content for ORSA (Open Remediation Standard Adapter) plugins.

        Supports multiple remediation formats extracted from XCCDF or custom-defined:
        - ansible: Ansible tasks with variable bindings
        - bash: Bash scripts with variable substitution
        - puppet: Puppet manifests
        - chef: Chef recipes
        - powershell: PowerShell scripts (Windows)
        - terraform: Terraform configuration changes (cloud)
        - kubectl: Kubernetes manifest updates

        Example:
        {
            "ansible": {
                "tasks": "- name: Set timeout\\n  lineinfile:\\n    path: /etc/profile\\n    line: 'TMOUT={{ var_accounts_tmout }}'",
                "variables": ["var_accounts_tmout"],
                "complexity": "low",
                "disruption": "low"
            },
            "bash": {
                "script": "echo 'TMOUT=$XCCDF_VALUE_VAR_ACCOUNTS_TMOUT' >> /etc/profile",
                "variables": ["var_accounts_tmout"]
            }
        }

        ORSA plugins extract remediation from this field and execute via appropriate tool.

        See: /docs/PLUGIN_ARCHITECTURE.md (ORSA section)
        """
    )

    # ============================================================================
    # End Phase 1 Fields
    # ============================================================================

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
            # Immutable versioning - composite index for uniqueness
            [("rule_id", 1), ("version", -1)],  # Replaced simple rule_id index

            # Fast "latest version" queries (most common pattern)
            [("rule_id", 1), ("is_latest", 1)],
            [("is_latest", 1), ("severity", -1)],
            [("is_latest", 1), ("category", 1)],

            # Temporal queries (audit/compliance)
            [("rule_id", 1), ("effective_from", 1)],
            [("effective_from", 1), ("effective_until", 1)],

            # Content integrity and source tracking
            "version_hash",  # For integrity verification
            "source_bundle",  # Track rules by bundle
            [("source_bundle", 1), ("is_latest", 1)],

            # Multi-platform queries (updated to include is_latest filter)
            [("is_latest", 1), ("platform_implementations.rhel.versions", 1), ("severity", -1)],
            [("is_latest", 1), ("platform_implementations.ubuntu.versions", 1), ("severity", -1)],
            [("is_latest", 1), ("platform_implementations.windows.versions", 1), ("severity", -1)],

            # Framework version queries (updated to include is_latest filter)
            [("is_latest", 1), ("frameworks.nist", 1)],
            [("is_latest", 1), ("frameworks.cis", 1)],
            [("is_latest", 1), ("frameworks.stig", 1)],

            # Inheritance and capability queries
            "inherits_from",
            [("abstract", 1), ("category", 1)],

            # Standard queries (kept for backwards compatibility)
            [("category", 1), ("severity", -1)],
            "tags",
            "security_function",
            [("updated_at", -1)],

            # Deprecation tracking
            [("deprecated", 1), ("is_latest", 1)]
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
        
        # Import health models
        from .health_models import (
            ServiceHealthDocument,
            ContentHealthDocument,
            HealthSummaryDocument
        )
        
        # Initialize Beanie with all document models
        import logging
        logger = logging.getLogger(__name__)
        logger.info("About to initialize Beanie ODM...")

        # Build document models list
        document_models = [
            ComplianceRule,
            RuleIntelligence,
            RemediationScript,
            ServiceHealthDocument,
            ContentHealthDocument,
            HealthSummaryDocument
        ]

        # Add Phase 1 models if available
        if PHASE1_MODELS_AVAILABLE:
            if ScanTemplate:
                document_models.append(ScanTemplate)
            if ScanResult:
                document_models.append(ScanResult)
            if ScanSchedule:
                document_models.append(ScanSchedule)
            if RemediationResult:
                document_models.append(RemediationResult)
            if BulkRemediationJob:
                document_models.append(BulkRemediationJob)
            logger.info(f"Registered {len(document_models)} Beanie document models (including Phase 1)")
        else:
            logger.info(f"Registered {len(document_models)} Beanie document models (Phase 1 models not available)")

        try:
            await init_beanie(
                database=self.database,
                document_models=document_models
            )
            logger.info("Beanie ODM initialized successfully")
        except Exception as beanie_error:
            logger.error(f"Beanie initialization failed: {type(beanie_error).__name__}: {beanie_error}")
            raise
        
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