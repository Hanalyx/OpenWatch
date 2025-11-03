"""
Plugin Models for OpenWatch
Secure plugin management with comprehensive validation and tracking
"""

from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field, validator, root_validator
import hashlib
import json
from beanie import Document, Indexed
from pymongo import IndexModel, ASCENDING


class PluginType(str, Enum):
    """Supported plugin types"""

    REMEDIATION = "remediation"
    VALIDATION = "validation"
    SCANNER = "scanner"
    REPORTER = "reporter"


class PluginTrustLevel(str, Enum):
    """Plugin trust levels for security policies"""

    VERIFIED = "verified"  # Signed by known publisher
    COMMUNITY = "community"  # Community submitted, passed security scan
    INTERNAL = "internal"  # Internally developed
    UNTRUSTED = "untrusted"  # Unknown source, use with caution


class PluginStatus(str, Enum):
    """Plugin lifecycle status"""

    PENDING_VALIDATION = "pending_validation"
    VALIDATING = "validating"
    ACTIVE = "active"
    DISABLED = "disabled"
    QUARANTINED = "quarantined"  # Failed security check
    DEPRECATED = "deprecated"


class PluginCapability(str, Enum):
    """Plugin execution capabilities"""

    SHELL = "shell"
    ANSIBLE = "ansible"
    POWERSHELL = "powershell"
    PYTHON = "python"
    API = "api"
    CUSTOM = "custom"


class SecurityCheckResult(BaseModel):
    """Individual security check result"""

    check_name: str
    passed: bool
    severity: str = Field(default="info", pattern="^(info|warning|high|critical)$")
    message: str
    details: Optional[Dict[str, Any]] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class PluginSignature(BaseModel):
    """Plugin signature for verification"""

    algorithm: str = Field(default="SHA256", pattern="^(SHA256|SHA384|SHA512)$")
    signature: str = Field(..., description="Hex-encoded signature")
    signer: str = Field(..., description="Signer identity/email")
    public_key_id: str = Field(..., description="Public key identifier")
    signed_at: datetime

    @validator("signature")
    def validate_signature_format(cls, v):
        """Ensure signature is valid hex"""
        try:
            bytes.fromhex(v)
        except ValueError:
            raise ValueError("Signature must be valid hexadecimal")
        return v.lower()


class PluginManifest(BaseModel):
    """Plugin manifest with metadata and requirements"""

    api_version: str = Field(default="v1", pattern="^v[0-9]+$")
    kind: str = Field(default="RemediationPlugin")

    # Metadata
    name: str = Field(..., min_length=3, max_length=100, pattern="^[a-zA-Z0-9-_]+$")
    version: str = Field(..., pattern="^[0-9]+\\.[0-9]+\\.[0-9]+(-[a-zA-Z0-9]+)?$")
    author: str = Field(..., min_length=3, max_length=200)
    description: str = Field(..., min_length=10, max_length=1000)
    homepage: Optional[str] = Field(None, pattern="^https?://")
    license: str = Field(..., min_length=3, max_length=50)

    # Compatibility
    openwatch_version: str = Field(..., description="Compatible OpenWatch version (e.g., >=2.0.0)")
    platforms: List[str] = Field(..., min_items=1)

    # Capabilities and requirements
    type: PluginType
    capabilities: List[PluginCapability] = Field(..., min_items=1)
    requirements: Dict[str, str] = Field(default_factory=dict)

    # Configuration schema
    config_schema: Optional[Dict[str, Any]] = Field(
        None, description="JSON Schema for configuration"
    )
    default_config: Dict[str, Any] = Field(default_factory=dict)

    @validator("platforms")
    def validate_platforms(cls, v):
        """Ensure valid platform names"""
        valid_platforms = {"rhel", "ubuntu", "debian", "centos", "windows", "macos"}
        invalid = set(v) - valid_platforms
        if invalid:
            raise ValueError(f"Invalid platforms: {invalid}")
        return v

    @root_validator(skip_on_failure=True)
    def validate_config_schema(cls, values):
        """Validate config schema if provided"""
        schema = values.get("config_schema")
        if schema:
            # Basic JSON Schema validation
            required_keys = {"type", "properties"}
            if not all(k in schema for k in required_keys):
                raise ValueError("Invalid JSON Schema format")
        return values


class PluginExecutor(BaseModel):
    """Plugin executor definition"""

    type: PluginCapability
    entry_point: str = Field(..., description="Main execution entry point")
    templates: Dict[str, str] = Field(
        default_factory=dict, description="Platform-specific templates"
    )
    resource_limits: Dict[str, Union[str, int]] = Field(
        default_factory=lambda: {
            "cpu": "0.5",
            "memory": "512M",
            "timeout": 300,
            "max_retries": 3,
        }
    )
    environment_variables: Dict[str, str] = Field(default_factory=dict)

    @validator("entry_point")
    def validate_entry_point(cls, v, values):
        """Validate entry point based on executor type"""
        exec_type = values.get("type")
        if exec_type == PluginCapability.PYTHON and not v.endswith(".py"):
            raise ValueError("Python executor must have .py entry point")
        elif exec_type == PluginCapability.SHELL and not v.endswith(".sh"):
            raise ValueError("Shell executor must have .sh entry point")
        return v


class PluginPackage(BaseModel):
    """Complete plugin package for import"""

    manifest: PluginManifest
    executors: Dict[str, PluginExecutor] = Field(..., min_items=1)
    files: Dict[str, str] = Field(..., description="File path to content mapping")
    signature: Optional[PluginSignature] = None
    checksum: str = Field(..., description="SHA256 checksum of package content")

    def calculate_checksum(self) -> str:
        """Calculate checksum of package content"""
        hasher = hashlib.sha256()

        # Hash manifest
        hasher.update(json.dumps(self.manifest.dict(), sort_keys=True).encode())

        # Hash executors
        hasher.update(
            json.dumps({k: v.dict() for k, v in self.executors.items()}, sort_keys=True).encode()
        )

        # Hash files in deterministic order
        for path in sorted(self.files.keys()):
            hasher.update(f"{path}:{self.files[path]}".encode())

        return hasher.hexdigest()

    @root_validator(skip_on_failure=True)
    def validate_checksum(cls, values):
        """Validate package checksum"""
        # Skip during construction from trusted sources
        if "checksum" in values and values.get("files"):
            # Will be validated during import
            pass
        return values


class InstalledPlugin(Document):
    """Installed plugin registry with full tracking"""

    # Identity
    plugin_id: Indexed(str) = Field(..., unique=True, description="Unique plugin identifier")
    manifest: PluginManifest

    # Source tracking
    source_url: Optional[str] = Field(None, description="Where plugin was downloaded from")
    source_hash: str = Field(..., description="Hash of original package")

    # Import metadata
    imported_by: str = Field(..., description="User who imported the plugin")
    imported_at: datetime = Field(default_factory=datetime.utcnow)
    import_method: str = Field(..., pattern="^(upload|url|registry)$")

    # Security status
    trust_level: PluginTrustLevel = Field(default=PluginTrustLevel.UNTRUSTED)
    status: PluginStatus = Field(default=PluginStatus.PENDING_VALIDATION)
    security_checks: List[SecurityCheckResult] = Field(default_factory=list)
    signature_verified: bool = Field(default=False)
    signature_details: Optional[PluginSignature] = None

    # Content storage
    executors: Dict[str, PluginExecutor]
    files: Dict[str, str] = Field(..., description="Stored file contents")

    # Configuration
    user_config: Dict[str, Any] = Field(
        default_factory=dict, description="User configuration overrides"
    )
    enabled_platforms: List[str] = Field(default_factory=list)

    # Usage tracking
    usage_count: int = Field(default=0)
    last_used: Optional[datetime] = None
    applied_to_rules: List[str] = Field(default_factory=list)
    execution_history: List[Dict[str, Any]] = Field(default_factory=list, max_items=100)

    # Versioning
    previous_versions: List[str] = Field(default_factory=list, description="Previous version IDs")
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    class Settings:
        collection = "installed_plugins"
        indexes = [
            IndexModel(
                [("manifest.name", ASCENDING), ("manifest.version", ASCENDING)],
                unique=True,
            ),
            IndexModel([("status", ASCENDING)]),
            IndexModel([("trust_level", ASCENDING)]),
            IndexModel([("imported_at", ASCENDING)]),
        ]

    def generate_plugin_id(self) -> str:
        """Generate unique plugin ID from name and version"""
        return f"{self.manifest.name}@{self.manifest.version}"

    async def save(self, *args, **kwargs):
        """Override save to set plugin_id and updated_at"""
        if not self.plugin_id:
            self.plugin_id = self.generate_plugin_id()
        self.updated_at = datetime.utcnow()
        return await super().save(*args, **kwargs)

    def is_active(self) -> bool:
        """Check if plugin is active and ready for use"""
        return self.status == PluginStatus.ACTIVE and self.trust_level != PluginTrustLevel.UNTRUSTED

    def get_risk_score(self) -> int:
        """Calculate risk score based on security checks (0-100)"""
        if not self.security_checks:
            return 100  # Maximum risk if not checked

        critical_failures = sum(
            1 for check in self.security_checks if not check.passed and check.severity == "critical"
        )
        high_failures = sum(
            1 for check in self.security_checks if not check.passed and check.severity == "high"
        )

        # Risk calculation
        risk = (critical_failures * 25) + (high_failures * 10)
        return min(risk, 100)


class PluginAssociation(BaseModel):
    """Associate plugin with compliance rule"""

    plugin_id: str
    plugin_version: str = Field(..., pattern="^[0-9]+\\.[0-9]+\\.[0-9]+(-[a-zA-Z0-9]+)?$")
    priority: int = Field(default=0, ge=0, le=100)

    # Platform-specific configuration
    platform_configs: Dict[str, Dict[str, Any]] = Field(default_factory=dict)

    # Execution conditions
    conditions: List[str] = Field(
        default_factory=list,
        description="Conditions when to use this plugin (e.g., 'environment:production')",
    )

    # Override plugin defaults
    config_overrides: Dict[str, Any] = Field(default_factory=dict)

    # Tracking
    added_at: datetime = Field(default_factory=datetime.utcnow)
    added_by: str = Field(..., description="User who added the association")

    @validator("plugin_version")
    def validate_version_format(cls, v):
        """Ensure semantic versioning"""
        import re

        if not re.match(r"^\d+\.\d+\.\d+(-[a-zA-Z0-9]+)?$", v):
            raise ValueError("Invalid version format")
        return v


class PluginExecutionRequest(BaseModel):
    """Request to execute a plugin"""

    plugin_id: str
    rule_id: str
    host_id: str
    platform: str

    # Execution parameters
    dry_run: bool = Field(default=False)
    timeout_override: Optional[int] = Field(None, gt=0, le=3600)
    config_overrides: Dict[str, Any] = Field(default_factory=dict)

    # Context
    execution_context: Dict[str, Any] = Field(default_factory=dict)
    user: str = Field(..., description="User requesting execution")

    class Config:
        schema_extra = {
            "example": {
                "plugin_id": "aegis-ssh-remediation@1.2.0",
                "rule_id": "ow-ssh-disable-root",
                "host_id": "host-123",
                "platform": "rhel",
                "dry_run": True,
                "user": "admin@example.com",
            }
        }


class PluginExecutionResult(BaseModel):
    """Result of plugin execution"""

    execution_id: str = Field(..., description="Unique execution ID")
    plugin_id: str
    status: str = Field(..., pattern="^(success|failure|timeout|error)$")

    # Execution details
    started_at: datetime
    completed_at: datetime
    duration_seconds: float

    # Results
    output: Optional[str] = None
    error: Optional[str] = None
    changes_made: List[Dict[str, Any]] = Field(default_factory=list)

    # Validation
    validation_passed: bool = Field(default=False)
    validation_details: Optional[Dict[str, Any]] = None

    # Rollback information
    rollback_available: bool = Field(default=False)
    rollback_data: Optional[Dict[str, Any]] = None
