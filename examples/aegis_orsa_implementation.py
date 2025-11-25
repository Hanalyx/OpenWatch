"""
AEGIS Implementation of OpenWatch Remediation System Adapter (ORSA)
Example implementation showing how AEGIS integrates with the open standard
"""
import asyncio
import aiohttp
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime

from app.services.remediation_system_adapter import (
    RemediationSystemInterface,
    RemediationSystemInfo,
    RemediationSystemCapability,
    RemediationRule,
    RemediationJob,
    RemediationJobResult,
    RemediationResult,
    RemediationExecutionStatus,
    OpenWatchRemediationSystemAdapter
)

logger = logging.getLogger(__name__)


class AegisRemediationSystem(RemediationSystemInterface):
    """
    AEGIS implementation of the OpenWatch Remediation System Adapter standard

    This demonstrates how AEGIS integrates with OpenWatch using the open standard
    interface, making it interoperable with other remediation systems.
    """

    def __init__(self, aegis_api_base: str = "http://localhost:8001", api_key: str = None):
        self.aegis_api_base = aegis_api_base.rstrip('/')
        self.api_key = api_key
        self.session = None

    async def get_system_info(self) -> RemediationSystemInfo:
        """Get AEGIS system information"""
        try:
            system_data = await self._call_aegis_api("GET", "/api/v1/system/info")

            return RemediationSystemInfo(
                system_id="aegis-remediation-platform",
                name="AEGIS Security Remediation Platform",
                version=system_data.get("version", "1.0.0"),
                api_version="1.0",

                capabilities=[
                    RemediationSystemCapability.CONFIGURATION_MANAGEMENT,
                    RemediationSystemCapability.SECURITY_HARDENING,
                    RemediationSystemCapability.COMPLIANCE_REMEDIATION,
                    RemediationSystemCapability.VULNERABILITY_PATCHING,
                    RemediationSystemCapability.AUDIT_REMEDIATION,
                    RemediationSystemCapability.PACKAGE_MANAGEMENT
                ],

                supported_platforms=system_data.get("supported_platforms", [
                    "rhel7", "rhel8", "rhel9", "ubuntu18", "ubuntu20", "ubuntu22",
                    "debian9", "debian10", "debian11", "centos7", "centos8"
                ]),

                supported_frameworks=system_data.get("supported_frameworks", [
                    "stig", "cis", "nist", "pci", "fedramp", "custom"
                ]),

                api_endpoint=f"{self.aegis_api_base}",
                authentication_type="apikey",
                webhook_support=True,
                max_concurrent_jobs=system_data.get("max_concurrent_jobs", 20),
                typical_job_timeout=1800,
                supports_dry_run=True,
                supports_rollback=True
            )

        except Exception as e:
            logger.error(f"Failed to get AEGIS system info: {e}")
            # Return minimal fallback info
            return RemediationSystemInfo(
                system_id="aegis-remediation-platform",
                name="AEGIS Security Remediation Platform",
                version="1.0.0",
                api_version="1.0",
                capabilities=[RemediationSystemCapability.COMPLIANCE_REMEDIATION],
                supported_platforms=["rhel8", "ubuntu20"],
                supported_frameworks=["stig", "cis"],
                api_endpoint=f"{self.aegis_api_base}",
                authentication_type="apikey"
            )

    async def get_available_rules(
        self,
        platform: Optional[str] = None,
        framework: Optional[str] = None,
        category: Optional[str] = None
    ) -> List[RemediationRule]:
        """Get available AEGIS remediation rules"""
        try:
            params = {}
            if platform:
                params['platform'] = platform
            if framework:
                params['framework'] = framework
            if category:
                params['category'] = category

            rules_data = await self._call_aegis_api("GET", "/api/v1/rules", params=params)

            remediation_rules = []
            for rule_data in rules_data.get("rules", []):
                # Convert AEGIS rule format to standard format
                rule = RemediationRule(
                    semantic_name=rule_data.get("semantic_name", rule_data.get("name", "")),
                    title=rule_data.get("title", ""),
                    description=rule_data.get("description", ""),
                    category=rule_data.get("category", "uncategorized"),
                    severity=rule_data.get("severity", "medium"),
                    tags=rule_data.get("tags", []),

                    # AEGIS framework mappings (key strength)
                    framework_mappings=rule_data.get("frameworks", {}),

                    # Platform implementations
                    implementations=rule_data.get("implementations", {}),

                    # Operational metadata
                    reversible=rule_data.get("reversible", False),
                    requires_reboot=rule_data.get("requires_reboot", False),
                    prerequisites=rule_data.get("prerequisites", []),
                    side_effects=rule_data.get("impacts", [])
                )
                remediation_rules.append(rule)

            return remediation_rules

        except Exception as e:
            logger.error(f"Failed to get AEGIS rules: {e}")
            return []

    async def submit_remediation_job(self, job: RemediationJob) -> str:
        """Submit remediation job to AEGIS"""
        try:
            # Convert standard job format to AEGIS format
            aegis_job_data = {
                "host_id": job.target_host_id,
                "rules": job.rules,
                "framework": job.framework,
                "use_framework_values": bool(job.framework),
                "options": {
                    "dry_run": job.dry_run,
                    "timeout": job.timeout,
                    "parallel_execution": job.parallel_execution
                },
                "openwatch_integration": {
                    "callback_url": str(job.callback_url) if job.callback_url else None,
                    "scan_context": job.openwatch_context
                }
            }

            result = await self._call_aegis_api("POST", "/api/v1/remediation/jobs", data=aegis_job_data)
            return result.get("job_id")

        except Exception as e:
            logger.error(f"Failed to submit AEGIS job: {e}")
            raise

    async def get_job_status(self, job_id: str) -> RemediationJobResult:
        """Get AEGIS job status"""
        try:
            job_data = await self._call_aegis_api("GET", f"/api/v1/remediation/jobs/{job_id}")

            # Convert AEGIS status to standard status
            status_mapping = {
                "pending": RemediationExecutionStatus.PENDING,
                "running": RemediationExecutionStatus.RUNNING,
                "completed": RemediationExecutionStatus.SUCCESS,
                "failed": RemediationExecutionStatus.FAILED,
                "timeout": RemediationExecutionStatus.TIMEOUT,
                "cancelled": RemediationExecutionStatus.CANCELLED,
                "partial": RemediationExecutionStatus.PARTIAL_SUCCESS
            }

            aegis_status = job_data.get("status", "pending")
            standard_status = status_mapping.get(aegis_status, RemediationExecutionStatus.FAILED)

            # Convert rule execution results
            rule_results = []
            for rule_exec in job_data.get("rule_executions", []):
                result = RemediationResult(
                    job_id=job_id,
                    rule_name=rule_exec.get("rule_name", ""),
                    status=status_mapping.get(rule_exec.get("status", "failed"), RemediationExecutionStatus.FAILED),
                    started_at=self._parse_datetime(rule_exec.get("started_at")),
                    completed_at=self._parse_datetime(rule_exec.get("completed_at")),
                    duration_seconds=rule_exec.get("duration_seconds"),
                    changes_made=rule_exec.get("changes_made", False),
                    validation_passed=rule_exec.get("validation_result", False),
                    error_message=rule_exec.get("error_output"),
                    before_state=rule_exec.get("before_state"),
                    after_state=rule_exec.get("after_state"),
                    commands_executed=rule_exec.get("command_executed", "").split("\n") if rule_exec.get("command_executed") else [],
                    output_log=rule_exec.get("output"),
                    rollback_available=bool(rule_exec.get("backup_created")),
                    backup_files=[rule_exec.get("backup_created")] if rule_exec.get("backup_created") else []
                )
                rule_results.append(result)

            # Calculate summary statistics
            successful_rules = sum(1 for r in rule_results if r.status == RemediationExecutionStatus.SUCCESS)
            failed_rules = sum(1 for r in rule_results if r.status == RemediationExecutionStatus.FAILED)

            return RemediationJobResult(
                job_id=job_id,
                status=standard_status,
                started_at=self._parse_datetime(job_data.get("started_at")),
                completed_at=self._parse_datetime(job_data.get("completed_at")),
                duration_seconds=job_data.get("duration_seconds"),
                total_rules=len(rule_results),
                successful_rules=successful_rules,
                failed_rules=failed_rules,
                skipped_rules=0,  # AEGIS doesn't typically skip rules
                rule_results=rule_results,
                system_changes_made=any(r.changes_made for r in rule_results),
                reboot_required=job_data.get("reboot_required", False),
                openwatch_verification_scan_requested=job_data.get("verification_scan_requested", False),
                callback_sent=job_data.get("callback_sent", False)
            )

        except Exception as e:
            logger.error(f"Failed to get AEGIS job status: {e}")
            raise

    async def cancel_job(self, job_id: str) -> bool:
        """Cancel AEGIS remediation job"""
        try:
            result = await self._call_aegis_api("POST", f"/api/v1/remediation/jobs/{job_id}/cancel")
            return result.get("cancelled", False)

        except Exception as e:
            logger.error(f"Failed to cancel AEGIS job: {e}")
            return False

    async def validate_connectivity(self, host_id: str) -> Dict[str, Any]:
        """Validate AEGIS connectivity to target host"""
        try:
            result = await self._call_aegis_api("POST", "/api/v1/hosts/connectivity-test", data={"host_id": host_id})

            return {
                "reachable": result.get("connection_successful", False),
                "response_time_ms": result.get("response_time"),
                "ssh_available": result.get("ssh_connection_successful", False),
                "authentication_valid": result.get("authentication_successful", False),
                "platform_detected": result.get("platform_detected"),
                "error_message": result.get("error_message")
            }

        except Exception as e:
            logger.error(f"AEGIS connectivity test failed: {e}")
            return {
                "reachable": False,
                "error_message": str(e)
            }

    # AEGIS-specific extensions beyond the standard interface

    async def get_framework_specific_rules(self, framework: str, rule_id: str) -> Optional[RemediationRule]:
        """Get AEGIS rule by framework-specific ID"""
        try:
            result = await self._call_aegis_api("GET", f"/api/v1/frameworks/{framework}/rules/{rule_id}")

            if result:
                return RemediationRule(
                    semantic_name=result.get("semantic_name", ""),
                    title=result.get("title", ""),
                    description=result.get("description", ""),
                    category=result.get("category", ""),
                    severity=result.get("severity", "medium"),
                    framework_mappings=result.get("frameworks", {}),
                    implementations=result.get("implementations", {}),
                    reversible=result.get("reversible", False)
                )

            return None

        except Exception as e:
            logger.error(f"Failed to get framework-specific rule: {e}")
            return None

    async def trigger_openwatch_verification_scan(self, host_id: str, scan_profile: str = "verification") -> bool:
        """Trigger OpenWatch verification scan after remediation"""
        try:
            result = await self._call_aegis_api("POST", "/api/v1/integration/openwatch/trigger-scan", data={
                "host_id": host_id,
                "scan_type": "verification",
                "scan_profile": scan_profile
            })

            return result.get("scan_triggered", False)

        except Exception as e:
            logger.error(f"Failed to trigger verification scan: {e}")
            return False

    # Utility methods

    async def _call_aegis_api(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict] = None,
        params: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """Make authenticated API call to AEGIS"""
        if not self.session:
            self.session = aiohttp.ClientSession()

        url = f"{self.aegis_api_base}{endpoint}"
        headers = {}

        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        async with self.session.request(
            method,
            url,
            json=data,
            params=params,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=30)
        ) as response:
            if response.status == 200:
                return await response.json()
            else:
                error_text = await response.text()
                raise Exception(f"AEGIS API error {response.status}: {error_text}")

    def _parse_datetime(self, datetime_str: Optional[str]) -> Optional[datetime]:
        """Parse AEGIS datetime string"""
        if not datetime_str:
            return None

        try:
            return datetime.fromisoformat(datetime_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return None

    async def __aenter__(self):
        """Async context manager entry"""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()


# ============================================================================
# Example Usage: Integrating AEGIS with OpenWatch
# ============================================================================

async def integrate_aegis_with_openwatch():
    """
    Example of how to integrate AEGIS with OpenWatch using the open standard
    """
    # Initialize AEGIS remediation system
    aegis_system = AegisRemediationSystem(
        aegis_api_base="http://localhost:8001",
        api_key="your-aegis-api-key"
    )

    # Create universal adapter
    adapter = OpenWatchRemediationSystemAdapter(aegis_system)

    try:
        # Register AEGIS as OpenWatch plugin
        plugin = await adapter.register_as_openwatch_plugin()
        print(f"[OK] AEGIS registered as OpenWatch plugin: {plugin.plugin_id}")

        # Test connectivity
        health = await aegis_system.health_check()
        print(f"AEGIS health check: {'[OK] Healthy' if health['healthy'] else '[ERROR] Unhealthy'}")

        # Get available rules
        rules = await aegis_system.get_available_rules(platform="rhel8", framework="stig")
        print(f"Found {len(rules)} AEGIS rules for RHEL 8 STIG")

        # Example: Execute remediation through OpenWatch interface
        from app.models.plugin_models import PluginExecutionRequest

        execution_request = PluginExecutionRequest(
            plugin_id=plugin.plugin_id,
            rule_id="ow-ssh-disable-root",  # OpenWatch rule ID
            host_id="host-123",
            platform="rhel8",
            dry_run=True,
            execution_context={
                "scan_id": "scan-456",
                "compliance_framework": "stig"
            },
            config_overrides={
                "framework": "stig"
            },
            user="admin@example.com"
        )

        # Execute remediation
        result = await adapter.execute_remediation_via_openwatch(execution_request)
        print(f"Remediation result: {result.status}")
        print(f"   Changes made: {result.changes_made}")
        print(f"   Duration: {result.duration_seconds}s")

        # Get AEGIS-specific rule details
        aegis_rule = await aegis_system.get_framework_specific_rules("stig", "RHEL-08-010550")
        if aegis_rule:
            print(f"AEGIS STIG rule: {aegis_rule.title}")

        return True

    except Exception as e:
        logger.error(f"Integration failed: {e}")
        return False

    finally:
        await aegis_system.__aexit__(None, None, None)


# ============================================================================
# Additional Remediation System Examples
# ============================================================================

class AnsibleRemediationSystem(RemediationSystemInterface):
    """
    Example: Ansible implementation of the ORSA standard
    Shows how other tools can implement the same interface
    """

    async def get_system_info(self) -> RemediationSystemInfo:
        return RemediationSystemInfo(
            system_id="ansible-remediation",
            name="Ansible Configuration Management",
            version="2.14.0",
            api_version="1.0",
            capabilities=[
                RemediationSystemCapability.CONFIGURATION_MANAGEMENT,
                RemediationSystemCapability.PACKAGE_MANAGEMENT
            ],
            supported_platforms=["rhel", "ubuntu", "debian", "centos"],
            supported_frameworks=["custom"],
            api_endpoint="http://localhost:8002",
            authentication_type="ssh_key"
        )

    async def get_available_rules(self, **kwargs) -> List[RemediationRule]:
        # Would scan Ansible playbooks and roles
        return []

    async def submit_remediation_job(self, job: RemediationJob) -> str:
        # Would create and execute Ansible playbook
        return "ansible-job-123"

    async def get_job_status(self, job_id: str) -> RemediationJobResult:
        # Would check Ansible execution status
        return RemediationJobResult(
            job_id=job_id,
            status=RemediationExecutionStatus.SUCCESS,
            started_at=datetime.utcnow(),
            total_rules=1,
            successful_rules=1,
            failed_rules=0,
            skipped_rules=0,
            rule_results=[]
        )

    async def cancel_job(self, job_id: str) -> bool:
        return True

    async def validate_connectivity(self, host_id: str) -> Dict[str, Any]:
        return {"reachable": True}


if __name__ == "__main__":
    # Example usage
    asyncio.run(integrate_aegis_with_openwatch())
