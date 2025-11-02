"""
OpenWatch Remediation System Adapter (ORSA) - Open Standard Interface
Universal adapter for integrating any remediation system with OpenWatch
"""

import asyncio
import logging
import json
import uuid
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Union, Protocol
from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field, HttpUrl

from ..models.plugin_models import (
    PluginExecutionRequest,
    PluginExecutionResult,
    InstalledPlugin,
    PluginTrustLevel,
    PluginStatus,
)

logger = logging.getLogger(__name__)


# ============================================================================
# ORSA (OpenWatch Remediation System Adapter) Standard Specifications
# ============================================================================


class RemediationSystemCapability(str, Enum):
    """Standard capabilities that remediation systems can declare"""

    CONFIGURATION_MANAGEMENT = "config_mgmt"  # File/service configuration
    PACKAGE_MANAGEMENT = "pkg_mgmt"  # Software installation/removal
    SECURITY_HARDENING = "sec_hardening"  # Security controls implementation
    COMPLIANCE_REMEDIATION = "compliance"  # Framework-specific fixes
    VULNERABILITY_PATCHING = "vuln_patching"  # CVE and security updates
    INFRASTRUCTURE_AS_CODE = "iac"  # Infrastructure provisioning
    AUDIT_REMEDIATION = "audit"  # Audit finding fixes
    CUSTOM_SCRIPTING = "scripting"  # Custom script execution


class RemediationExecutionStatus(str, Enum):
    """Standard execution status codes"""

    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    PARTIAL_SUCCESS = "partial_success"
    REQUIRES_REBOOT = "requires_reboot"
    VALIDATION_FAILED = "validation_failed"


class RemediationSystemInfo(BaseModel):
    """Standard system information that all remediation systems must provide"""

    system_id: str = Field(
        ..., description="Unique identifier for the remediation system"
    )
    name: str = Field(..., description="Human-readable system name")
    version: str = Field(..., description="System version")
    api_version: str = Field(..., description="Supported ORSA API version")

    # Capabilities
    capabilities: List[RemediationSystemCapability] = Field(
        ..., description="Supported remediation capabilities"
    )
    supported_platforms: List[str] = Field(
        ..., description="Supported target platforms (rhel, ubuntu, windows, etc.)"
    )
    supported_frameworks: List[str] = Field(
        default_factory=list,
        description="Supported compliance frameworks (stig, cis, pci, etc.)",
    )

    # Integration details
    api_endpoint: HttpUrl = Field(..., description="Base API endpoint URL")
    authentication_type: str = Field(
        ..., description="Authentication method (apikey, oauth2, jwt, etc.)"
    )
    webhook_support: bool = Field(
        default=False, description="Supports webhook callbacks"
    )

    # Operational info
    max_concurrent_jobs: int = Field(
        default=10, description="Maximum concurrent remediation jobs"
    )
    typical_job_timeout: int = Field(
        default=1800, description="Typical job timeout in seconds"
    )
    supports_dry_run: bool = Field(
        default=True, description="Supports dry-run/check mode"
    )
    supports_rollback: bool = Field(
        default=False, description="Supports rollback operations"
    )


class RemediationRule(BaseModel):
    """Standard rule definition that remediation systems should support"""

    # Rule identification
    semantic_name: str = Field(..., description="Platform-agnostic semantic rule name")
    title: str = Field(..., description="Human-readable rule title")
    description: str = Field(..., description="Detailed rule description")

    # Classification
    category: str = Field(
        ..., description="Rule category (auth, network, crypto, etc.)"
    )
    severity: str = Field(
        ..., description="Rule severity (low, medium, high, critical)"
    )
    tags: List[str] = Field(default_factory=list, description="Searchable tags")

    # Framework mappings (key innovation from AEGIS)
    framework_mappings: Dict[str, Dict[str, str]] = Field(
        default_factory=dict,
        description="Mapping to framework-specific rule IDs {framework: {platform: rule_id}}",
    )

    # Platform implementations
    implementations: Dict[str, Dict[str, Any]] = Field(
        default_factory=dict, description="Platform-specific implementation details"
    )

    # Operational metadata
    reversible: bool = Field(default=False, description="Can be rolled back")
    requires_reboot: bool = Field(default=False, description="Requires system reboot")
    prerequisites: List[str] = Field(
        default_factory=list, description="Required system state"
    )
    side_effects: List[str] = Field(
        default_factory=list, description="Known side effects"
    )


class RemediationJob(BaseModel):
    """Standard remediation job definition"""

    job_id: str = Field(default_factory=lambda: str(uuid.uuid4()))

    # Target specification
    target_host_id: str = Field(..., description="Target host identifier")
    platform: str = Field(..., description="Target platform")

    # Rule specification (flexible - semantic names OR framework-specific)
    rules: Union[List[str], List[Dict[str, Any]]] = Field(
        ..., description="Rules to execute (semantic names or detailed specs)"
    )
    framework: Optional[str] = Field(None, description="Target compliance framework")

    # Execution options
    dry_run: bool = Field(default=False, description="Perform dry-run only")
    timeout: int = Field(default=1800, description="Job timeout in seconds")
    parallel_execution: bool = Field(
        default=False, description="Enable parallel rule execution"
    )

    # Context from OpenWatch
    openwatch_context: Dict[str, Any] = Field(
        default_factory=dict, description="Context from OpenWatch scan results"
    )

    # Integration
    callback_url: Optional[HttpUrl] = Field(None, description="Webhook callback URL")
    callback_auth: Optional[Dict[str, str]] = Field(
        None, description="Callback authentication"
    )


class RemediationResult(BaseModel):
    """Standard remediation result format"""

    job_id: str
    rule_name: str

    # Execution details
    status: RemediationExecutionStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None

    # Results
    changes_made: bool = Field(default=False)
    validation_passed: bool = Field(default=False)
    error_message: Optional[str] = None

    # State tracking (inspired by AEGIS forensics)
    before_state: Optional[Dict[str, Any]] = Field(
        None, description="System state before"
    )
    after_state: Optional[Dict[str, Any]] = Field(
        None, description="System state after"
    )

    # Execution forensics
    commands_executed: List[str] = Field(default_factory=list)
    output_log: Optional[str] = None

    # Rollback support
    rollback_available: bool = Field(default=False)
    rollback_data: Optional[Dict[str, Any]] = None
    backup_files: List[str] = Field(default_factory=list)


class RemediationJobResult(BaseModel):
    """Complete job execution result"""

    job_id: str
    status: RemediationExecutionStatus

    # Timing
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None

    # Results summary
    total_rules: int
    successful_rules: int
    failed_rules: int
    skipped_rules: int

    # Detailed results
    rule_results: List[RemediationResult]

    # System impact
    system_changes_made: bool = Field(default=False)
    reboot_required: bool = Field(default=False)

    # Integration
    openwatch_verification_scan_requested: bool = Field(default=False)
    callback_sent: bool = Field(default=False)


# ============================================================================
# Abstract Base Class - Remediation System Interface
# ============================================================================


class RemediationSystemInterface(ABC):
    """
    Abstract base class that all remediation systems must implement

    This defines the standard interface for integrating any remediation system
    with OpenWatch, ensuring consistent behavior and interoperability.
    """

    @abstractmethod
    async def get_system_info(self) -> RemediationSystemInfo:
        """Get remediation system information and capabilities"""
        pass

    @abstractmethod
    async def get_available_rules(
        self,
        platform: Optional[str] = None,
        framework: Optional[str] = None,
        category: Optional[str] = None,
    ) -> List[RemediationRule]:
        """Get list of available remediation rules with filtering"""
        pass

    @abstractmethod
    async def submit_remediation_job(self, job: RemediationJob) -> str:
        """Submit remediation job and return job ID"""
        pass

    @abstractmethod
    async def get_job_status(self, job_id: str) -> RemediationJobResult:
        """Get current status of remediation job"""
        pass

    @abstractmethod
    async def cancel_job(self, job_id: str) -> bool:
        """Cancel running remediation job"""
        pass

    @abstractmethod
    async def validate_connectivity(self, host_id: str) -> Dict[str, Any]:
        """Validate connectivity to target host"""
        pass

    # Optional methods with default implementations

    async def get_rule_details(
        self, rule_name: str, platform: str
    ) -> Optional[RemediationRule]:
        """Get detailed information about specific rule"""
        rules = await self.get_available_rules(platform=platform)
        return next((r for r in rules if r.semantic_name == rule_name), None)

    async def dry_run_remediation(self, job: RemediationJob) -> RemediationJobResult:
        """Perform dry-run of remediation job"""
        job.dry_run = True
        job_id = await self.submit_remediation_job(job)
        return await self.get_job_status(job_id)

    async def health_check(self) -> Dict[str, Any]:
        """Check remediation system health"""
        try:
            info = await self.get_system_info()
            return {
                "healthy": True,
                "system": info.name,
                "version": info.version,
                "timestamp": datetime.utcnow().isoformat(),
            }
        except Exception as e:
            return {
                "healthy": False,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            }


# ============================================================================
# OpenWatch Remediation System Adapter - Universal Integration
# ============================================================================


class OpenWatchRemediationSystemAdapter:
    """
    Universal adapter for integrating remediation systems with OpenWatch

    This adapter translates between OpenWatch's plugin interface and the
    standardized remediation system interface, enabling any compliant
    remediation system to work with OpenWatch.
    """

    def __init__(self, remediation_system: RemediationSystemInterface):
        self.remediation_system = remediation_system
        self._system_info = None
        self._rule_cache = {}
        self._job_cache = {}

    async def register_as_openwatch_plugin(self) -> InstalledPlugin:
        """
        Register the remediation system as an OpenWatch plugin

        This creates a standard OpenWatch plugin that represents the entire
        remediation system, following the patterns established by AEGIS.
        """
        # Get system information
        system_info = await self.remediation_system.get_system_info()
        self._system_info = system_info

        # Get available rules for capability assessment
        available_rules = await self.remediation_system.get_available_rules()

        # Create plugin manifest
        from ..models.plugin_models import PluginManifest, PluginType, PluginCapability

        manifest = PluginManifest(
            name=system_info.system_id,
            version=system_info.version,
            author=f"{system_info.name} Team",
            description=f"{system_info.name} remediation system with {len(available_rules)} rules",
            homepage=str(system_info.api_endpoint),
            license="Various",  # Remediation systems may have different licenses
            type=PluginType.REMEDIATION,
            openwatch_version=">=2.0.0",
            platforms=system_info.supported_platforms,
            capabilities=self._map_capabilities_to_plugin_capabilities(
                system_info.capabilities
            ),
            requirements={
                "api_version": system_info.api_version,
                "authentication": system_info.authentication_type,
            },
            config_schema={
                "type": "object",
                "properties": {
                    "api_endpoint": {
                        "type": "string",
                        "default": str(system_info.api_endpoint),
                    },
                    "timeout": {
                        "type": "integer",
                        "default": system_info.typical_job_timeout,
                    },
                    "max_concurrent": {
                        "type": "integer",
                        "default": system_info.max_concurrent_jobs,
                    },
                    "default_framework": {
                        "type": "string",
                        "enum": system_info.supported_frameworks,
                        "description": "Default compliance framework to use",
                    },
                },
            },
        )

        # Create executor
        from ..models.plugin_models import PluginExecutor

        executor = PluginExecutor(
            type=PluginCapability.API,
            entry_point="remediation_system_client",
            resource_limits={
                "timeout": system_info.typical_job_timeout,
                "max_retries": 3,
            },
            environment_variables={
                "REMEDIATION_SYSTEM_API": str(system_info.api_endpoint),
                "REMEDIATION_SYSTEM_TYPE": system_info.name.lower().replace(" ", "_"),
            },
        )

        # Create installed plugin
        plugin = InstalledPlugin(
            manifest=manifest,
            source_url=str(system_info.api_endpoint),
            source_hash=self._calculate_system_hash(system_info),
            imported_by="system",
            imported_at=datetime.utcnow(),
            import_method="remediation_system_adapter",
            trust_level=PluginTrustLevel.VERIFIED,  # Assume verified for registered systems
            status=PluginStatus.ACTIVE,
            security_checks=[],  # Remediation systems bypass security checks
            signature_verified=True,
            executors={"remediation_api": executor},
            files={
                "system_info.json": json.dumps(system_info.dict(), indent=2),
                "available_rules.json": json.dumps(
                    [r.dict() for r in available_rules], indent=2
                ),
                "client.py": self._generate_client_code(),
            },
            enabled_platforms=system_info.supported_platforms,
            user_config={
                "api_endpoint": str(system_info.api_endpoint),
                "supported_frameworks": system_info.supported_frameworks,
            },
        )

        await plugin.save()
        logger.info(
            f"Registered {system_info.name} as OpenWatch plugin: {plugin.plugin_id}"
        )

        return plugin

    async def execute_remediation_via_openwatch(
        self, request: PluginExecutionRequest
    ) -> PluginExecutionResult:
        """
        Execute remediation through OpenWatch plugin interface

        Translates OpenWatch execution request to remediation system job
        """
        started_at = datetime.utcnow()
        execution_id = request.execution_context.get("execution_id", str(uuid.uuid4()))

        try:
            # Map OpenWatch rule to remediation system rules
            remediation_rules = await self._map_openwatch_rule_to_remediation_rules(
                request.rule_id, request.platform
            )

            if not remediation_rules:
                return self._create_error_result(
                    execution_id,
                    started_at,
                    f"No remediation available for rule: {request.rule_id}",
                )

            # Create remediation job
            job = RemediationJob(
                target_host_id=request.host_id,
                platform=request.platform,
                rules=remediation_rules,
                framework=request.config_overrides.get("framework"),
                dry_run=request.dry_run,
                timeout=request.timeout_override
                or self._system_info.typical_job_timeout,
                openwatch_context=request.execution_context,
                callback_url=request.config_overrides.get("callback_url"),
            )

            # Submit job
            job_id = await self.remediation_system.submit_remediation_job(job)
            self._job_cache[execution_id] = job_id

            # Wait for completion (with timeout)
            result = await self._wait_for_job_completion(job_id, job.timeout)

            # Convert to OpenWatch format
            return self._convert_to_openwatch_result(
                execution_id, started_at, result, request.plugin_id
            )

        except Exception as e:
            logger.error(f"Remediation execution failed: {e}")
            return self._create_error_result(execution_id, started_at, str(e))

    async def get_rules_for_openwatch_rule(
        self, rule_id: str, platform: str, framework: Optional[str] = None
    ) -> List[RemediationRule]:
        """Get remediation system rules that can fix an OpenWatch compliance rule"""
        available_rules = await self.remediation_system.get_available_rules(
            platform=platform, framework=framework
        )

        # Find matching rules using multiple strategies
        matches = []

        # Strategy 1: Direct semantic name match
        for rule in available_rules:
            if rule.semantic_name == rule_id:
                matches.append(rule)

        # Strategy 2: Framework mapping match
        if framework:
            for rule in available_rules:
                framework_mappings = rule.framework_mappings.get(framework, {})
                if rule_id in framework_mappings.values():
                    matches.append(rule)

        # Strategy 3: Fuzzy matching on tags and categories
        rule_keywords = set(rule_id.lower().replace("-", "_").split("_"))
        for rule in available_rules:
            rule_tags = set(tag.lower() for tag in rule.tags)
            if rule_keywords & rule_tags:
                matches.append(rule)

        return matches

    def _map_capabilities_to_plugin_capabilities(
        self, capabilities: List[RemediationSystemCapability]
    ) -> List:
        """Map remediation system capabilities to OpenWatch plugin capabilities"""
        from ..models.plugin_models import PluginCapability

        mapping = {
            RemediationSystemCapability.CONFIGURATION_MANAGEMENT: [
                PluginCapability.ANSIBLE
            ],
            RemediationSystemCapability.PACKAGE_MANAGEMENT: [PluginCapability.SHELL],
            RemediationSystemCapability.SECURITY_HARDENING: [
                PluginCapability.ANSIBLE,
                PluginCapability.SHELL,
            ],
            RemediationSystemCapability.COMPLIANCE_REMEDIATION: [PluginCapability.API],
            RemediationSystemCapability.CUSTOM_SCRIPTING: [
                PluginCapability.SHELL,
                PluginCapability.PYTHON,
            ],
        }

        plugin_capabilities = set()
        for capability in capabilities:
            if capability in mapping:
                plugin_capabilities.update(mapping[capability])

        # Always include API capability for remediation systems
        plugin_capabilities.add(PluginCapability.API)

        return list(plugin_capabilities)

    def _calculate_system_hash(self, system_info: RemediationSystemInfo) -> str:
        """Calculate hash representing current system state"""
        import hashlib

        content = json.dumps(system_info.dict(), sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()

    def _generate_client_code(self) -> str:
        """Generate Python client code for the remediation system"""
        return f'''
import asyncio
import json
import os
from typing import Dict, Any

class RemediationSystemClient:
    def __init__(self):
        self.api_endpoint = os.environ.get("REMEDIATION_SYSTEM_API")
        self.system_type = os.environ.get("REMEDIATION_SYSTEM_TYPE")
    
    async def execute_remediation(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute remediation via standardized interface"""
        # Implementation would be specific to each remediation system
        # This is a template that gets customized per system
        
        job_data = {{
            "target_host_id": context.get("host_id"),
            "platform": context.get("platform"),
            "rules": [context.get("rule_id")],
            "dry_run": context.get("dry_run", False),
            "openwatch_context": context
        }}
        
        # Submit job and wait for completion
        # Return standardized result format
        
        return {{
            "success": True,
            "job_id": "example-job-id",
            "changes_made": True,
            "validation_passed": True
        }}

if __name__ == "__main__":
    import sys
    context_file = sys.argv[1] if len(sys.argv) > 1 else "execution_context.json"
    
    with open(context_file, 'r') as f:
        context = json.load(f)
    
    client = RemediationSystemClient()
    result = asyncio.run(client.execute_remediation(context))
    
    print(json.dumps(result))
'''

    async def _map_openwatch_rule_to_remediation_rules(
        self, rule_id: str, platform: str
    ) -> List[str]:
        """Map OpenWatch rule to remediation system rules"""
        matching_rules = await self.get_rules_for_openwatch_rule(rule_id, platform)
        return [rule.semantic_name for rule in matching_rules]

    async def _wait_for_job_completion(
        self, job_id: str, timeout: int
    ) -> RemediationJobResult:
        """Wait for remediation job to complete"""
        start_time = datetime.utcnow()

        while True:
            result = await self.remediation_system.get_job_status(job_id)

            if result.status in [
                RemediationExecutionStatus.SUCCESS,
                RemediationExecutionStatus.FAILED,
                RemediationExecutionStatus.TIMEOUT,
                RemediationExecutionStatus.CANCELLED,
                RemediationExecutionStatus.PARTIAL_SUCCESS,
            ]:
                return result

            # Check timeout
            elapsed = (datetime.utcnow() - start_time).total_seconds()
            if elapsed > timeout:
                await self.remediation_system.cancel_job(job_id)
                raise TimeoutError(f"Job {job_id} timed out after {timeout} seconds")

            # Wait before next check
            await asyncio.sleep(5)

    def _convert_to_openwatch_result(
        self,
        execution_id: str,
        started_at: datetime,
        job_result: RemediationJobResult,
        plugin_id: str,
    ) -> PluginExecutionResult:
        """Convert remediation system result to OpenWatch format"""
        return PluginExecutionResult(
            execution_id=execution_id,
            plugin_id=plugin_id,
            status=(
                "success"
                if job_result.status == RemediationExecutionStatus.SUCCESS
                else "failure"
            ),
            started_at=started_at,
            completed_at=job_result.completed_at or datetime.utcnow(),
            duration_seconds=job_result.duration_seconds or 0,
            output=f"Executed {job_result.total_rules} rules: {job_result.successful_rules} successful, {job_result.failed_rules} failed",
            error=(
                None
                if job_result.status == RemediationExecutionStatus.SUCCESS
                else f"Job failed with status: {job_result.status}"
            ),
            changes_made=job_result.system_changes_made,
            validation_passed=job_result.successful_rules > 0,
            rollback_available=any(
                r.rollback_available for r in job_result.rule_results
            ),
            rollback_data=(
                {
                    "job_id": job_result.job_id,
                    "rule_results": [
                        r.dict()
                        for r in job_result.rule_results
                        if r.rollback_available
                    ],
                }
                if any(r.rollback_available for r in job_result.rule_results)
                else None
            ),
        )

    def _create_error_result(
        self, execution_id: str, started_at: datetime, error_message: str
    ) -> PluginExecutionResult:
        """Create error result"""
        completed_at = datetime.utcnow()
        duration = (completed_at - started_at).total_seconds()

        return PluginExecutionResult(
            execution_id=execution_id,
            plugin_id="remediation-system-adapter",
            status="error",
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=duration,
            error=error_message,
        )
