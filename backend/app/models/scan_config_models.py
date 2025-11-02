"""
MongoDB models for scan configuration and templates.

This module defines data structures for managing scan configurations,
templates, and framework metadata for the OpenWatch compliance platform.
"""

from datetime import datetime
from enum import Enum
from typing import Optional, Dict, List, Any
from pydantic import BaseModel, Field
from beanie import Document


class ScanTargetType(str, Enum):
    """Type of scan target (matches scan_models.py)."""

    SSH_HOST = "ssh_host"
    LOCAL = "local"
    KUBERNETES = "kubernetes"
    AWS_ACCOUNT = "aws_account"
    AZURE_SUBSCRIPTION = "azure_subscription"
    GCP_PROJECT = "gcp_project"


class ScanTemplate(Document):
    """
    Saved scan configuration template.

    Templates allow users to save and reuse scan configurations with
    specific framework, variable overrides, and rule filters.
    """

    # Identifiers
    template_id: str = Field(..., description="Unique template ID (UUID)")
    name: str = Field(..., description="Template name")
    description: Optional[str] = Field(default=None, description="Template description")

    # Configuration
    framework: str = Field(
        ..., description="Compliance framework (e.g., 'nist', 'cis')"
    )
    framework_version: str = Field(
        ..., description="Framework version (e.g., 'rev5', '1.0.0')"
    )
    target_type: ScanTargetType = Field(..., description="Target system type")

    variable_overrides: Dict[str, str] = Field(
        default_factory=dict, description="Variable values overriding defaults"
    )

    rule_filter: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Filter criteria for rule selection (e.g., {'severity': ['high']})",
    )

    # Metadata
    created_by: str = Field(..., description="Username of creator")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    is_default: bool = Field(
        default=False, description="Default template for this framework/user"
    )

    tags: List[str] = Field(
        default_factory=list, description="User-defined tags for organization"
    )

    version: int = Field(default=1, description="Template version number")

    # Sharing
    shared_with: List[str] = Field(
        default_factory=list, description="Usernames with read access"
    )

    is_public: bool = Field(default=False, description="Template visible to all users")

    class Settings:
        name = "scan_templates"
        indexes = [
            "template_id",
            "created_by",
            "framework",
            "is_default",
            "is_public",
            [("created_by", 1), ("framework", 1)],
            [("tags", 1), ("created_by", 1)],
        ]


class VariableConstraint(BaseModel):
    """XCCDF variable constraints."""

    # Range constraints (numbers)
    lower_bound: Optional[float] = Field(
        default=None, description="Minimum value (inclusive)"
    )
    upper_bound: Optional[float] = Field(
        default=None, description="Maximum value (inclusive)"
    )

    # Choice constraints (enums)
    choices: Optional[List[str]] = Field(default=None, description="Allowed values")

    # Pattern constraint (regex)
    match: Optional[str] = Field(
        default=None, description="Regex pattern for validation"
    )


class VariableDefinition(BaseModel):
    """
    XCCDF variable definition with metadata and constraints.

    Used for presenting variable options to users and validating inputs.
    """

    id: str = Field(..., description="Variable identifier (e.g., 'var_accounts_tmout')")
    title: str = Field(..., description="Human-readable title")
    description: str = Field(..., description="Detailed description")

    type: str = Field(..., description="Variable type: string, number, boolean")
    default: Any = Field(..., description="Default value")

    constraints: Optional[VariableConstraint] = Field(
        default=None, description="Validation constraints"
    )

    interactive: bool = Field(
        default=True, description="Whether user input is required"
    )

    category: Optional[str] = Field(
        default=None, description="Variable category for UI grouping"
    )


class FrameworkMetadata(BaseModel):
    """
    Compliance framework metadata for discovery.

    Provides summary information about available frameworks and versions.
    """

    framework: str = Field(..., description="Framework identifier")
    display_name: str = Field(..., description="Human-readable name")
    versions: List[str] = Field(..., description="Available versions")
    description: str = Field(..., description="Framework description")

    rule_count: int = Field(..., description="Total rules in framework")
    variable_count: int = Field(..., description="Total variables in framework")

    categories: Optional[List[str]] = Field(
        default=None, description="Rule categories (e.g., ['access_control', 'audit'])"
    )

    severities: Optional[Dict[str, int]] = Field(
        default=None,
        description="Rule count by severity (e.g., {'high': 50, 'medium': 100})",
    )


class FrameworkVersion(BaseModel):
    """Detailed framework version information."""

    framework: str
    version: str
    display_name: str
    description: str

    rule_count: int
    variable_count: int

    variables: List[VariableDefinition] = Field(
        default_factory=list, description="All variables for this framework/version"
    )

    categories: List[str] = Field(
        default_factory=list, description="Available rule categories"
    )

    target_types: List[ScanTargetType] = Field(
        default_factory=list, description="Supported target types"
    )


# API Request/Response Schemas


class CreateTemplateRequest(BaseModel):
    """Request schema for creating scan template."""

    name: str
    description: Optional[str] = None
    framework: str
    framework_version: str
    target_type: ScanTargetType
    variable_overrides: Dict[str, str] = Field(default_factory=dict)
    rule_filter: Optional[Dict[str, Any]] = None
    tags: List[str] = Field(default_factory=list)
    is_public: bool = False


class UpdateTemplateRequest(BaseModel):
    """Request schema for updating scan template."""

    name: Optional[str] = None
    description: Optional[str] = None
    variable_overrides: Optional[Dict[str, str]] = None
    rule_filter: Optional[Dict[str, Any]] = None
    tags: Optional[List[str]] = None
    is_public: Optional[bool] = None


class ValidateVariablesRequest(BaseModel):
    """Request schema for variable validation."""

    variables: Dict[str, Any] = Field(
        ..., description="Variable ID -> value mapping to validate"
    )


class ValidationResult(BaseModel):
    """Result of variable validation."""

    valid: bool = Field(..., description="Overall validation result")
    errors: Dict[str, str] = Field(
        default_factory=dict, description="Variable ID -> error message mapping"
    )
    warnings: Dict[str, str] = Field(
        default_factory=dict, description="Variable ID -> warning message mapping"
    )


class ApplyTemplateRequest(BaseModel):
    """Request schema for applying template to target."""

    target: Dict[str, Any] = Field(..., description="Target configuration (ScanTarget)")

    variable_overrides: Optional[Dict[str, str]] = Field(
        default=None, description="Additional variable overrides beyond template"
    )


class TemplateStatistics(BaseModel):
    """Template usage statistics."""

    total_templates: int = 0
    by_framework: Dict[str, int] = Field(default_factory=dict)
    by_user: Dict[str, int] = Field(default_factory=dict)
    public_templates: int = 0
    most_used: List[Dict[str, Any]] = Field(default_factory=list)
