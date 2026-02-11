"""
Rule Reference API Schemas

Pydantic models for the Rule Reference API endpoints that power the
frontend Rule Browser / Rule Reference page.

These schemas provide a user-friendly view of Aegis compliance rules
for Auditors, System Administrators, and Aegis developers.
"""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

# =============================================================================
# Framework Reference Models
# =============================================================================


class CISReference(BaseModel):
    """CIS Benchmark reference."""

    section: str = Field(..., description="CIS section number (e.g., '5.1.20')")
    level: str = Field(..., description="CIS level ('L1' or 'L2')")
    type: str = Field("Automated", description="Check type ('Automated' or 'Manual')")


class STIGReference(BaseModel):
    """DISA STIG reference."""

    vuln_id: str = Field(..., description="Vulnerability ID (e.g., 'V-257947')")
    stig_id: str = Field(..., description="STIG rule ID (e.g., 'RHEL-09-255045')")
    severity: str = Field(..., description="CAT severity ('CAT I', 'CAT II', 'CAT III')")
    cci: List[str] = Field(default_factory=list, description="CCI numbers")


class FrameworkReferences(BaseModel):
    """All framework references for a rule."""

    cis: Dict[str, CISReference] = Field(
        default_factory=dict, description="CIS references by version (e.g., 'rhel9_v2')"
    )
    stig: Dict[str, STIGReference] = Field(
        default_factory=dict, description="STIG references by version (e.g., 'rhel9_v2r7')"
    )
    nist_800_53: List[str] = Field(default_factory=list, description="NIST 800-53 control IDs")
    pci_dss_4: List[str] = Field(default_factory=list, description="PCI DSS 4.0 requirements")
    srg: List[str] = Field(default_factory=list, description="SRG IDs")


# =============================================================================
# Check and Remediation Models
# =============================================================================


class CheckDefinition(BaseModel):
    """How a rule is checked."""

    method: str = Field(..., description="Check method (config_value, audit_rule_exists, etc.)")
    path: Optional[str] = Field(None, description="File path being checked")
    key: Optional[str] = Field(None, description="Configuration key")
    expected: Optional[str] = Field(None, description="Expected value")
    comparator: Optional[str] = Field(None, description="Comparison operator (>=, ==, etc.)")
    rule: Optional[str] = Field(None, description="Audit rule pattern (for audit checks)")


class RemediationDefinition(BaseModel):
    """How to fix a failing rule."""

    mechanism: str = Field(..., description="Remediation type (config_set, audit_rule_set, etc.)")
    path: Optional[str] = Field(None, description="File to modify")
    key: Optional[str] = Field(None, description="Key to set")
    value: Optional[str] = Field(None, description="Value to set")
    reload: Optional[str] = Field(None, description="Service to reload after change")
    command: Optional[str] = Field(None, description="Command to run (if applicable)")


class Implementation(BaseModel):
    """A capability-gated implementation of a rule."""

    capability_required: Optional[str] = Field(None, description="Required capability probe (e.g., 'sshd_config_d')")
    is_default: bool = Field(False, description="Whether this is the default implementation")
    check: CheckDefinition = Field(..., description="How to check compliance")
    remediation: Optional[RemediationDefinition] = Field(None, description="How to remediate")


# =============================================================================
# Rule Models
# =============================================================================


class RuleSummary(BaseModel):
    """Summary view of a rule (for list display)."""

    id: str = Field(..., description="Rule ID (e.g., 'ssh-disable-root-login')")
    title: str = Field(..., description="Human-readable title")
    severity: str = Field(..., description="Severity level (critical, high, medium, low)")
    category: str = Field(..., description="Category (access-control, audit, etc.)")
    tags: List[str] = Field(default_factory=list, description="Searchable tags")
    platforms: List[str] = Field(default_factory=list, description="Supported platforms")
    framework_count: int = Field(0, description="Number of framework mappings")
    has_remediation: bool = Field(False, description="Whether remediation is available")


class RuleDetail(BaseModel):
    """Full detail view of a rule."""

    id: str = Field(..., description="Rule ID")
    title: str = Field(..., description="Human-readable title")
    description: str = Field(..., description="What this rule checks")
    rationale: str = Field(..., description="Why this rule matters (key for auditors)")
    severity: str = Field(..., description="Severity level")
    category: str = Field(..., description="Category")
    tags: List[str] = Field(default_factory=list, description="Searchable tags")

    # Platform support
    platforms: List[Dict[str, Any]] = Field(default_factory=list, description="Supported platforms with min versions")

    # Framework references
    references: FrameworkReferences = Field(default_factory=FrameworkReferences, description="Framework mappings")

    # Implementations (capability-gated)
    implementations: List[Implementation] = Field(default_factory=list, description="Check/remediation implementations")

    # Dependencies
    depends_on: List[str] = Field(default_factory=list, description="Rules this depends on")
    conflicts_with: List[str] = Field(default_factory=list, description="Conflicting rules")


# =============================================================================
# List/Search Response Models
# =============================================================================


class RuleListResponse(BaseModel):
    """Paginated list of rules."""

    rules: List[RuleSummary] = Field(..., description="List of rule summaries")
    total: int = Field(..., description="Total number of rules matching filters")
    page: int = Field(..., description="Current page number")
    per_page: int = Field(..., description="Items per page")
    total_pages: int = Field(..., description="Total number of pages")


class RuleDetailResponse(BaseModel):
    """Single rule detail response."""

    rule: RuleDetail = Field(..., description="Full rule details")


# =============================================================================
# Framework and Category Models
# =============================================================================


class FrameworkInfo(BaseModel):
    """Information about a compliance framework."""

    id: str = Field(..., description="Framework ID (e.g., 'cis', 'stig')")
    name: str = Field(..., description="Framework display name")
    description: str = Field(..., description="Framework description")
    versions: List[str] = Field(default_factory=list, description="Available versions")
    rule_count: int = Field(0, description="Number of rules with this framework mapping")


class FrameworkListResponse(BaseModel):
    """List of available frameworks."""

    frameworks: List[FrameworkInfo] = Field(..., description="Available frameworks")
    total: int = Field(..., description="Total frameworks")


class CategoryInfo(BaseModel):
    """Information about a rule category."""

    id: str = Field(..., description="Category ID (e.g., 'access-control')")
    name: str = Field(..., description="Category display name")
    description: str = Field(..., description="Category description")
    rule_count: int = Field(0, description="Number of rules in this category")


class CategoryListResponse(BaseModel):
    """List of rule categories."""

    categories: List[CategoryInfo] = Field(..., description="Available categories")
    total: int = Field(..., description="Total categories")


# =============================================================================
# Variable Models
# =============================================================================


class VariableDefinition(BaseModel):
    """A configurable variable with framework-specific overrides."""

    name: str = Field(..., description="Variable name (e.g., 'pam_pwquality_minlen')")
    default_value: Any = Field(..., description="Default value")
    description: Optional[str] = Field(None, description="What this variable controls")
    framework_overrides: Dict[str, Any] = Field(
        default_factory=dict, description="Framework-specific values (cis, stig, nist)"
    )
    used_by_rules: List[str] = Field(default_factory=list, description="Rule IDs that use this variable")


class VariableListResponse(BaseModel):
    """List of configurable variables."""

    variables: List[VariableDefinition] = Field(..., description="Available variables")
    total: int = Field(..., description="Total variables")


# =============================================================================
# Capability Probe Models
# =============================================================================


class CapabilityProbe(BaseModel):
    """A host capability detection probe."""

    id: str = Field(..., description="Capability ID (e.g., 'sshd_config_d')")
    name: str = Field(..., description="Human-readable name")
    description: str = Field(..., description="What this capability detects")
    detection_method: str = Field(..., description="How the capability is detected")
    rules_requiring: int = Field(0, description="Number of rules requiring this capability")


class CapabilityListResponse(BaseModel):
    """List of capability probes."""

    capabilities: List[CapabilityProbe] = Field(..., description="Available capability probes")
    total: int = Field(..., description="Total probes")


# =============================================================================
# Search/Filter Models
# =============================================================================


class RuleSearchParams(BaseModel):
    """Search parameters for rule listing."""

    search: Optional[str] = Field(None, description="Search in title, description, tags")
    framework: Optional[str] = Field(None, description="Filter by framework (cis, stig, nist)")
    category: Optional[str] = Field(None, description="Filter by category")
    severity: Optional[str] = Field(None, description="Filter by severity")
    capability: Optional[str] = Field(None, description="Filter by required capability")
    tags: Optional[List[str]] = Field(None, description="Filter by tags")
    platform: Optional[str] = Field(None, description="Filter by platform (rhel8, rhel9)")
    has_remediation: Optional[bool] = Field(None, description="Filter by remediation availability")


__all__ = [
    # Framework references
    "CISReference",
    "STIGReference",
    "FrameworkReferences",
    # Check/Remediation
    "CheckDefinition",
    "RemediationDefinition",
    "Implementation",
    # Rules
    "RuleSummary",
    "RuleDetail",
    "RuleListResponse",
    "RuleDetailResponse",
    # Frameworks & Categories
    "FrameworkInfo",
    "FrameworkListResponse",
    "CategoryInfo",
    "CategoryListResponse",
    # Variables
    "VariableDefinition",
    "VariableListResponse",
    # Capabilities
    "CapabilityProbe",
    "CapabilityListResponse",
    # Search
    "RuleSearchParams",
]
