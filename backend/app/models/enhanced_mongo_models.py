"""
Enhanced MongoDB Models for OpenWatch Unified Compliance Architecture
Supports cross-framework intelligence and multi-platform implementations
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from beanie import Document
from pydantic import BaseModel, Field, validator


class FrameworkMapping(BaseModel):
    """Individual framework mapping with enhanced metadata"""

    controls: List[str] = Field(description="Control IDs for this framework")
    implementation_status: str = Field(
        default="compliant",
        pattern="^(compliant|exceeds|partial|not_applicable)$",
        description="How this rule relates to framework requirements",
    )
    enhancement_level: Optional[str] = Field(
        default=None, description="Level of enhancement over baseline requirements"
    )
    enhancement_details: Optional[str] = Field(
        default=None, description="Specific details about how requirements are exceeded"
    )
    gap_analysis: Optional[str] = Field(
        default=None, description="Analysis of gaps when status is partial"
    )
    justification: Optional[str] = Field(
        default=None, description="Justification for implementation status"
    )
    last_validated: Optional[datetime] = Field(
        default=None, description="When this mapping was last validated"
    )


class FrameworkVersions(BaseModel):
    """Enhanced framework mappings with multi-dimensional intelligence"""

    nist_800_53_r5: Optional[FrameworkMapping] = Field(
        default=None, description="NIST 800-53 Revision 5 mappings"
    )
    nist_800_53_r4: Optional[FrameworkMapping] = Field(
        default=None, description="NIST 800-53 Revision 4 mappings (legacy)"
    )
    cis_v8: Optional[FrameworkMapping] = Field(default=None, description="CIS Controls v8 mappings")
    cis_v7: Optional[FrameworkMapping] = Field(
        default=None, description="CIS Controls v7 mappings (legacy)"
    )
    stig_rhel9: Optional[FrameworkMapping] = Field(
        default=None, description="DISA STIG RHEL 9 mappings"
    )
    stig_rhel8: Optional[FrameworkMapping] = Field(
        default=None, description="DISA STIG RHEL 8 mappings"
    )
    stig_ubuntu2204: Optional[FrameworkMapping] = Field(
        default=None, description="DISA STIG Ubuntu 22.04 mappings"
    )
    stig_ubuntu2404: Optional[FrameworkMapping] = Field(
        default=None, description="DISA STIG Ubuntu 24.04 mappings"
    )
    srg_os: Optional[FrameworkMapping] = Field(
        default=None, description="SRG Operating System requirements"
    )
    srg_app: Optional[FrameworkMapping] = Field(
        default=None, description="SRG Application requirements"
    )
    pci_dss_v4: Optional[FrameworkMapping] = Field(
        default=None, description="PCI DSS v4.0 requirements"
    )
    pci_dss_v3: Optional[FrameworkMapping] = Field(
        default=None, description="PCI DSS v3.2.1 requirements (legacy)"
    )
    iso_27001_2022: Optional[FrameworkMapping] = Field(
        default=None, description="ISO 27001:2022 controls"
    )
    iso_27001_2013: Optional[FrameworkMapping] = Field(
        default=None, description="ISO 27001:2013 controls (legacy)"
    )
    hipaa: Optional[FrameworkMapping] = Field(default=None, description="HIPAA safeguards")
    ccm_v4: Optional[FrameworkMapping] = Field(default=None, description="Cloud Control Matrix v4")
    fedramp_high: Optional[FrameworkMapping] = Field(
        default=None, description="FedRAMP High baseline"
    )
    fedramp_moderate: Optional[FrameworkMapping] = Field(
        default=None, description="FedRAMP Moderate baseline"
    )


class PlatformImplementation(BaseModel):
    """Enhanced platform-specific implementation with version ranges"""

    version_ranges: List[str] = Field(
        description="OS version ranges this implementation applies to (e.g., ['8.0-8.9', '9.0-9.4'])"
    )
    conditional_logic: Optional[Dict[str, str]] = Field(
        default_factory=dict,
        description="Version-specific commands (e.g., {'rhel8': 'cmd1', 'rhel9': 'cmd2'})",
    )
    service_name: Optional[str] = Field(
        default=None, description="System service name if applicable"
    )
    check_command: Optional[str] = Field(
        default=None, description="Base command to check rule compliance"
    )
    check_method: str = Field(
        default="command",
        pattern="^(systemd|file|command|package|kernel|registry|api)$",
        description="Check method type",
    )
    check_script: Optional[str] = Field(
        default=None, description="Script content for complex checks"
    )
    config_files: List[str] = Field(
        default_factory=list, description="Configuration files affected by this rule"
    )
    enable_command: Optional[str] = Field(
        default=None, description="Command to enable/fix the rule"
    )
    disable_command: Optional[str] = Field(
        default=None, description="Command to disable the rule (for testing)"
    )
    validation_command: Optional[str] = Field(
        default=None, description="Command to validate the fix was applied"
    )
    service_dependencies: List[str] = Field(
        default_factory=list, description="Required packages or services"
    )
    package_dependencies: List[str] = Field(
        default_factory=list, description="Required system packages"
    )
    kernel_parameters: Optional[Dict[str, Any]] = Field(
        default=None, description="Required kernel parameters"
    )
    environment_variables: Optional[Dict[str, str]] = Field(
        default=None, description="Required environment variables"
    )
    restart_required: bool = Field(
        default=False,
        description="Whether system restart is required after remediation",
    )
    reboot_required: bool = Field(
        default=False, description="Whether full reboot is required after remediation"
    )


class RuleIntelligence(BaseModel):
    """Enhanced rule intelligence and analytics"""

    business_impact: str = Field(
        default="medium",
        pattern="^(low|medium|high|critical)$",
        description="Business impact of this control",
    )
    implementation_complexity: str = Field(
        default="medium",
        pattern="^(low|medium|high)$",
        description="Complexity of implementing this control",
    )
    cross_framework_coverage: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Percentage of frameworks covered by this rule",
    )
    false_positive_rate: float = Field(
        default=0.0, ge=0.0, le=1.0, description="Historical false positive rate"
    )
    remediation_success_rate: float = Field(
        default=1.0, ge=0.0, le=1.0, description="Success rate of automated remediation"
    )
    scan_duration_avg_ms: int = Field(
        default=1000, description="Average scan duration in milliseconds"
    )
    conflict_detection: List[str] = Field(
        default_factory=list, description="Rules that conflict with this one"
    )
    enhancement_opportunities: List[str] = Field(
        default_factory=list, description="Opportunities to enhance this rule"
    )
    usage_frequency: int = Field(default=0, description="How often this rule is used in scans")
    last_intelligence_update: datetime = Field(
        default_factory=datetime.utcnow,
        description="When intelligence was last updated",
    )


class CheckContent(BaseModel):
    """Enhanced check content structure"""

    check_type: str = Field(description="Type of check (file, command, service, package, etc.)")
    file_path: Optional[str] = Field(default=None)
    parameter: Optional[str] = Field(default=None)
    pattern: Optional[str] = Field(default=None)
    expected_value: Optional[Union[str, int, float, bool]] = Field(default=None)
    comparison: Optional[str] = Field(
        default="equals",
        description="Comparison operator (equals, greater_than, less_than, etc.)",
    )
    config_format: Optional[str] = Field(
        default=None,
        description="Configuration file format (ini, json, yaml, ssh_config, etc.)",
    )
    oval_reference: Optional[Dict[str, str]] = Field(
        default=None, description="OVAL definition reference"
    )
    ocil_reference: Optional[Dict[str, str]] = Field(
        default=None, description="OCIL questionnaire reference"
    )


class FixContent(BaseModel):
    """Multi-format remediation content"""

    shell: Optional[Dict[str, Any]] = Field(default=None, description="Shell script remediation")
    ansible: Optional[Dict[str, Any]] = Field(
        default=None, description="Ansible playbook remediation"
    )
    puppet: Optional[Dict[str, Any]] = Field(
        default=None, description="Puppet manifest remediation"
    )
    powershell: Optional[Dict[str, Any]] = Field(
        default=None, description="PowerShell script remediation (for Windows)"
    )


class UnifiedComplianceRule(Document):
    """Unified compliance rule with cross-framework intelligence"""

    # Core Identifiers
    rule_id: str = Field(
        description="Unique OpenWatch rule identifier (e.g., ow-password-complexity)"
    )
    scap_rule_id: Optional[str] = Field(
        default=None, description="Original SCAP rule identifier for traceability"
    )
    parent_rule_id: Optional[str] = Field(
        default=None, description="For rule inheritance and families"
    )

    # Rich Metadata with Versioning
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Rich metadata including name, description, source provenance",
    )

    # Rule Type and Inheritance
    abstract: bool = Field(
        default=False,
        description="True if this is a base rule that cannot be executed directly",
    )
    inherits_from: Optional[str] = Field(
        default=None, description="Rule ID this rule inherits from"
    )
    derived_rules: List[str] = Field(
        default_factory=list,
        description="Auto-populated list of rules that inherit from this one",
    )

    # Enhanced Classification
    severity: str = Field(
        pattern="^(info|low|medium|high|critical)$", description="Rule severity level"
    )
    category: str = Field(
        description="Rule category (authentication, access_control, logging, etc.)"
    )
    security_function: Optional[str] = Field(
        default=None,
        description="High-level security function (network_protection, data_encryption, etc.)",
    )
    security_domain: str = Field(
        default="system",
        description="Security domain (access_control, crypto, audit, network, etc.)",
    )
    control_family: str = Field(
        default="general",
        description="Control family (password, encryption, logging, etc.)",
    )
    tags: List[str] = Field(default_factory=list, description="Searchable tags for categorization")

    # Cross-Framework Intelligence
    frameworks: FrameworkVersions = Field(
        default_factory=FrameworkVersions,
        description="Multi-dimensional framework mappings with intelligence",
    )

    # Rule Intelligence Layer
    rule_intelligence: RuleIntelligence = Field(
        default_factory=RuleIntelligence,
        description="Enhanced rule analytics and intelligence",
    )

    # Platform Abstraction with Version Support
    platform_implementations: Dict[str, PlatformImplementation] = Field(
        default_factory=dict,
        description="Platform-specific implementations with version ranges",
    )

    # Enhanced Dependencies
    dependencies: Dict[str, List[str]] = Field(
        default_factory=lambda: {"requires": [], "conflicts": [], "related": []},
        description="Rule dependencies and relationships",
    )

    # Assessment Logic (Enhanced)
    check_type: str = Field(
        default="custom",
        pattern="^(script|command|file|package|service|kernel|multi_parameter|oval|custom)$",
        description="Type of check to perform",
    )
    check_content: Dict[str, Any] = Field(
        default_factory=dict, description="Detailed check configuration"
    )

    # Remediation with Platform Variants
    fix_available: bool = Field(
        default=False, description="Whether automated remediation is available"
    )
    fix_content: Optional[Dict[str, Any]] = Field(
        default=None, description="Multi-format remediation content"
    )
    manual_remediation: Optional[str] = Field(
        default=None, description="Manual remediation instructions"
    )
    remediation_complexity: str = Field(
        default="medium",
        pattern="^(low|medium|high)$",
        description="Complexity of applying the remediation",
    )
    remediation_risk: str = Field(
        default="low",
        pattern="^(low|medium|high)$",
        description="Risk level of applying the remediation",
    )

    # Change Tracking and Provenance
    source_file: str = Field(default="unknown", description="Original source file (SCAP XML, etc.)")
    source_hash: str = Field(
        default="unknown", description="Hash of the source content for change detection"
    )
    version: str = Field(default="1.0.0", description="Rule version")
    imported_at: datetime = Field(
        default_factory=datetime.utcnow, description="When the rule was imported"
    )
    updated_at: datetime = Field(
        default_factory=datetime.utcnow, description="Last update timestamp"
    )

    @validator("rule_id")
    def validate_rule_id(cls, v):
        if not v or len(v) < 3:
            raise ValueError("Rule ID must be at least 3 characters long")
        if not v.startswith("ow-"):
            raise ValueError('Rule ID must start with "ow-"')
        return v

    @validator("metadata")
    def validate_metadata(cls, v):
        if not v.get("name"):
            raise ValueError("Metadata must contain a name")
        return v

    class Settings:
        name = "unified_compliance_rules"
        indexes = [
            # Unique constraint on rule_id
            "rule_id",
            # Multi-platform version range queries
            [("platform_implementations.rhel.version_ranges", 1), ("severity", -1)],
            [("platform_implementations.ubuntu.version_ranges", 1), ("severity", -1)],
            [("platform_implementations.windows.version_ranges", 1), ("severity", -1)],
            [("platform_implementations.suse.version_ranges", 1), ("severity", -1)],
            # Framework-specific queries for unified scanning
            "frameworks.nist_800_53_r5.controls",
            "frameworks.cis_v8.controls",
            "frameworks.stig_rhel9.controls",
            "frameworks.stig_rhel8.controls",
            "frameworks.stig_ubuntu2204.controls",
            "frameworks.stig_ubuntu2404.controls",
            "frameworks.pci_dss_v4.controls",
            "frameworks.iso_27001_2022.controls",
            "frameworks.hipaa.controls",
            # Cross-framework intelligence queries
            "rule_intelligence.cross_framework_coverage",
            "rule_intelligence.business_impact",
            "rule_intelligence.implementation_complexity",
            # Implementation status queries
            "frameworks.nist_800_53_r5.implementation_status",
            "frameworks.cis_v8.implementation_status",
            "frameworks.stig_rhel9.implementation_status",
            # Multi-framework scanning optimization
            [
                ("frameworks.nist_800_53_r5.controls", 1),
                ("frameworks.cis_v8.controls", 1),
            ],
            [("frameworks.stig_rhel9.controls", 1), ("severity", -1)],
            # Inheritance and rule relationships
            "inherits_from",
            "derived_rules",
            [("abstract", 1), ("category", 1)],
            # Security domain and function queries
            [("security_domain", 1), ("control_family", 1)],
            # Performance optimization
            [("category", 1), ("security_function", 1), ("severity", -1)],
            "tags",
            [("updated_at", -1)],
            # Text search for rule discovery
            [
                ("metadata.name", "text"),
                ("metadata.description", "text"),
                ("tags", "text"),
            ],
        ]


class FrameworkControlDefinition(Document):
    """Framework control definitions for cross-referencing"""

    framework_id: str = Field(description="Framework identifier (e.g., nist_800_53_r5, cis_v8)")
    control_id: str = Field(description="Control ID within the framework")
    title: str = Field(description="Control title")
    description: str = Field(description="Control description")
    family: Optional[str] = Field(default=None, description="Control family or category")
    priority: Optional[str] = Field(default=None, description="Control priority or baseline")
    supplemental_guidance: Optional[str] = Field(default=None, description="Additional guidance")
    related_controls: List[str] = Field(
        default_factory=list, description="Related controls within the same framework"
    )
    external_references: Optional[Dict[str, str]] = Field(
        default=None, description="References to external standards"
    )

    class Settings:
        name = "framework_control_definitions"
        indexes = [
            [("framework_id", 1), ("control_id", 1)],
            "framework_id",
            "control_id",
            "family",
            "priority",
            [("title", "text"), ("description", "text")],
        ]
