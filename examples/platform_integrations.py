"""
OpenWatch Platform Integration Examples
Shows how different remediation platforms integrate with OpenWatch through ORSA
"""
import asyncio
import json
import subprocess
import yaml
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path

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


# ============================================================================
# ANSIBLE INTEGRATION
# ============================================================================

class AnsibleRemediationSystem(RemediationSystemInterface):
    """
    Ansible integration for OpenWatch
    
    This implementation wraps Ansible playbooks as OpenWatch remediation rules.
    Each Ansible role/playbook becomes a remediation that OpenWatch can execute.
    """
    
    def __init__(self, playbook_directory: str = "/etc/openwatch/ansible-remediations"):
        self.playbook_dir = Path(playbook_directory)
        self.ansible_path = self._find_ansible()
        self._rule_cache = None
    
    def _find_ansible(self) -> str:
        """Find ansible-playbook executable"""
        try:
            result = subprocess.run(['which', 'ansible-playbook'], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except:
            logger.debug("Ignoring exception during cleanup")
        return "ansible-playbook"  # Assume in PATH
    
    async def get_system_info(self) -> RemediationSystemInfo:
        """Get Ansible system information"""
        # Get Ansible version
        try:
            result = subprocess.run([self.ansible_path, '--version'], capture_output=True, text=True)
            version_line = result.stdout.split('\n')[0]
            version = version_line.split()[1] if 'ansible' in version_line else "2.9+"
        except:
            version = "unknown"
        
        return RemediationSystemInfo(
            system_id="ansible-remediation-adapter",
            name="Ansible Configuration Management",
            version=version,
            api_version="1.0",
            capabilities=[
                RemediationSystemCapability.CONFIGURATION_MANAGEMENT,
                RemediationSystemCapability.PACKAGE_MANAGEMENT,
                RemediationSystemCapability.SECURITY_HARDENING,
                RemediationSystemCapability.CUSTOM_SCRIPTING
            ],
            supported_platforms=["rhel", "ubuntu", "debian", "centos", "sles"],
            supported_frameworks=["custom", "cis", "stig"],  # If playbooks are tagged
            api_endpoint="file:///etc/openwatch/ansible-remediations",
            authentication_type="ssh_key",
            max_concurrent_jobs=5,  # Ansible parallel execution limit
            typical_job_timeout=600,
            supports_dry_run=True,  # Ansible check mode
            supports_rollback=False  # Unless playbooks implement it
        )
    
    async def get_available_rules(
        self,
        platform: Optional[str] = None,
        framework: Optional[str] = None,
        category: Optional[str] = None
    ) -> List[RemediationRule]:
        """Scan playbook directory and convert to remediation rules"""
        if self._rule_cache is None:
            self._rule_cache = await self._scan_playbooks()
        
        rules = self._rule_cache
        
        # Apply filters
        if platform:
            rules = [r for r in rules if platform in r.implementations]
        if framework:
            rules = [r for r in rules if framework in r.framework_mappings]
        if category:
            rules = [r for r in rules if r.category == category]
        
        return rules
    
    async def _scan_playbooks(self) -> List[RemediationRule]:
        """Scan Ansible playbooks and convert to remediation rules"""
        rules = []
        
        # Look for playbooks with OpenWatch metadata
        for playbook_file in self.playbook_dir.rglob("*.yml"):
            try:
                with open(playbook_file, 'r') as f:
                    playbook = yaml.safe_load(f)
                
                # Check for OpenWatch metadata in playbook
                if isinstance(playbook, list) and playbook:
                    first_play = playbook[0]
                    openwatch_meta = first_play.get('vars', {}).get('openwatch_metadata', {})
                    
                    if openwatch_meta:
                        rule = RemediationRule(
                            semantic_name=openwatch_meta.get('rule_name', playbook_file.stem),
                            title=openwatch_meta.get('title', first_play.get('name', '')),
                            description=openwatch_meta.get('description', ''),
                            category=openwatch_meta.get('category', 'configuration'),
                            severity=openwatch_meta.get('severity', 'medium'),
                            tags=openwatch_meta.get('tags', []),
                            framework_mappings=openwatch_meta.get('framework_mappings', {}),
                            implementations={
                                platform: {"playbook": str(playbook_file)}
                                for platform in openwatch_meta.get('platforms', ['linux'])
                            },
                            reversible=openwatch_meta.get('reversible', False),
                            requires_reboot=openwatch_meta.get('requires_reboot', False)
                        )
                        rules.append(rule)
            except:
                continue
        
        return rules
    
    async def submit_remediation_job(self, job: RemediationJob) -> str:
        """Execute Ansible playbook as remediation job"""
        job_id = job.job_id
        
        # For each rule, find corresponding playbook
        for rule_name in job.rules:
            rule = next((r for r in await self.get_available_rules() if r.semantic_name == rule_name), None)
            if not rule:
                continue
            
            implementation = rule.implementations.get(job.platform, {})
            playbook_path = implementation.get('playbook')
            
            if playbook_path:
                # Build ansible-playbook command
                cmd = [
                    self.ansible_path,
                    playbook_path,
                    '-i', f"{job.target_host_id},",  # Single host inventory
                    '-e', f"target_host={job.target_host_id}",
                    '-e', f"openwatch_context={json.dumps(job.openwatch_context)}"
                ]
                
                if job.dry_run:
                    cmd.append('--check')
                
                # Execute asynchronously (in production, use asyncio.create_subprocess_exec)
                # For now, store job info for status checking
                self._store_job_info(job_id, cmd, rule_name)
        
        return job_id
    
    async def get_job_status(self, job_id: str) -> RemediationJobResult:
        """Get Ansible job execution status"""
        # In production, this would check actual Ansible execution status
        # For example, could use ansible-runner or AWX API
        
        return RemediationJobResult(
            job_id=job_id,
            status=RemediationExecutionStatus.SUCCESS,
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
            duration_seconds=30.5,
            total_rules=1,
            successful_rules=1,
            failed_rules=0,
            skipped_rules=0,
            rule_results=[
                RemediationResult(
                    job_id=job_id,
                    rule_name="ssh_hardening",
                    status=RemediationExecutionStatus.SUCCESS,
                    started_at=datetime.utcnow(),
                    changes_made=True,
                    validation_passed=True,
                    commands_executed=["ansible-playbook ssh_hardening.yml"]
                )
            ],
            system_changes_made=True,
            reboot_required=False
        )
    
    async def cancel_job(self, job_id: str) -> bool:
        """Cancel running Ansible playbook"""
        # Would need to track subprocess PIDs and terminate
        return True
    
    async def validate_connectivity(self, host_id: str) -> Dict[str, Any]:
        """Test Ansible connectivity to host"""
        try:
            result = subprocess.run(
                [self.ansible_path.replace('-playbook', ''), host_id, '-m', 'ping'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            return {
                "reachable": result.returncode == 0,
                "authentication_valid": 'SUCCESS' in result.stdout,
                "error_message": result.stderr if result.returncode != 0 else None
            }
        except:
            return {"reachable": False, "error_message": "Ansible ping failed"}
    
    def _store_job_info(self, job_id: str, cmd: List[str], rule_name: str):
        """Store job information for tracking (placeholder)"""
        pass


# ============================================================================
# CHEF INTEGRATION
# ============================================================================

class ChefRemediationSystem(RemediationSystemInterface):
    """
    Chef integration for OpenWatch
    
    Wraps Chef cookbooks and recipes as remediation rules.
    Uses knife commands or Chef Server API for execution.
    """
    
    def __init__(self, chef_server_url: str = None, chef_repo: str = "/etc/openwatch/chef-remediations"):
        self.chef_server_url = chef_server_url
        self.chef_repo = Path(chef_repo)
        self.knife_path = self._find_knife()
    
    def _find_knife(self) -> str:
        """Find knife executable"""
        try:
            result = subprocess.run(['which', 'knife'], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except:
            logger.debug("Ignoring exception during cleanup")
        return "knife"
    
    async def get_system_info(self) -> RemediationSystemInfo:
        return RemediationSystemInfo(
            system_id="chef-remediation-adapter",
            name="Chef Configuration Management",
            version="17.0",  # Chef Infra Client version
            api_version="1.0",
            capabilities=[
                RemediationSystemCapability.CONFIGURATION_MANAGEMENT,
                RemediationSystemCapability.PACKAGE_MANAGEMENT,
                RemediationSystemCapability.INFRASTRUCTURE_AS_CODE
            ],
            supported_platforms=["rhel", "ubuntu", "debian", "centos", "windows"],
            supported_frameworks=["custom"],
            api_endpoint=self.chef_server_url or "file:///etc/openwatch/chef-remediations",
            authentication_type="pem_key",
            max_concurrent_jobs=10,
            typical_job_timeout=900,
            supports_dry_run=True,  # Chef why-run mode
            supports_rollback=False
        )
    
    async def get_available_rules(self, **kwargs) -> List[RemediationRule]:
        """Scan Chef cookbooks for remediation recipes"""
        rules = []
        
        # Look for cookbooks with OpenWatch metadata
        for cookbook_dir in self.chef_repo.glob("cookbooks/*"):
            metadata_file = cookbook_dir / "metadata.rb"
            if metadata_file.exists():
                # Parse cookbook metadata for OpenWatch rules
                # In practice, would parse Ruby DSL or JSON metadata
                
                # Example: security_baseline cookbook
                if cookbook_dir.name == "security_baseline":
                    rules.extend([
                        RemediationRule(
                            semantic_name="chef_ssh_hardening",
                            title="SSH Hardening via Chef",
                            description="Apply SSH security baseline using Chef",
                            category="security",
                            severity="high",
                            tags=["ssh", "baseline", "chef"],
                            implementations={
                                "rhel": {"cookbook": "security_baseline", "recipe": "ssh"},
                                "ubuntu": {"cookbook": "security_baseline", "recipe": "ssh"}
                            }
                        ),
                        RemediationRule(
                            semantic_name="chef_firewall_config",
                            title="Firewall Configuration via Chef",
                            description="Configure host firewall rules",
                            category="network",
                            severity="high",
                            tags=["firewall", "network", "chef"],
                            implementations={
                                "rhel": {"cookbook": "security_baseline", "recipe": "firewall"},
                                "ubuntu": {"cookbook": "security_baseline", "recipe": "firewall"}
                            }
                        )
                    ])
        
        return rules
    
    async def submit_remediation_job(self, job: RemediationJob) -> str:
        """Execute Chef recipes as remediation"""
        job_id = job.job_id
        
        # Build run list from requested rules
        run_list = []
        for rule_name in job.rules:
            rule = next((r for r in await self.get_available_rules() if r.semantic_name == rule_name), None)
            if rule:
                impl = rule.implementations.get(job.platform, {})
                if impl:
                    run_list.append(f"recipe[{impl['cookbook']}::{impl['recipe']}]")
        
        if run_list:
            # Execute via knife ssh or knife bootstrap
            cmd = [
                self.knife_path, 'ssh',
                f'name:{job.target_host_id}',
                f'sudo chef-client -o {",".join(run_list)}'
            ]
            
            if job.dry_run:
                cmd[-1] += ' --why-run'
            
            # Store job for tracking
            self._store_job_info(job_id, cmd)
        
        return job_id
    
    async def get_job_status(self, job_id: str) -> RemediationJobResult:
        """Check Chef run status"""
        # Would check Chef Server API or parse chef-client output
        return RemediationJobResult(
            job_id=job_id,
            status=RemediationExecutionStatus.SUCCESS,
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
            total_rules=1,
            successful_rules=1,
            failed_rules=0,
            skipped_rules=0,
            rule_results=[]
        )
    
    async def cancel_job(self, job_id: str) -> bool:
        return True
    
    async def validate_connectivity(self, host_id: str) -> Dict[str, Any]:
        """Validate Chef node connectivity"""
        try:
            result = subprocess.run(
                [self.knife_path, 'node', 'show', host_id],
                capture_output=True,
                text=True
            )
            
            return {
                "reachable": result.returncode == 0,
                "platform_detected": "chef-client installed" if result.returncode == 0 else None,
                "error_message": result.stderr if result.returncode != 0 else None
            }
        except:
            return {"reachable": False}
    
    def _store_job_info(self, job_id: str, cmd: List[str]):
        pass


# ============================================================================
# PUPPET INTEGRATION
# ============================================================================

class PuppetRemediationSystem(RemediationSystemInterface):
    """
    Puppet integration for OpenWatch
    
    Wraps Puppet modules and manifests as remediation rules.
    Uses Puppet Bolt or Puppet Enterprise API for execution.
    """
    
    def __init__(self, puppet_server: str = None, modules_path: str = "/etc/openwatch/puppet-modules"):
        self.puppet_server = puppet_server
        self.modules_path = Path(modules_path)
        self.bolt_path = self._find_bolt()
    
    def _find_bolt(self) -> str:
        """Find puppet bolt executable"""
        try:
            result = subprocess.run(['which', 'bolt'], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except:
            logger.debug("Ignoring exception during cleanup")
        return "bolt"
    
    async def get_system_info(self) -> RemediationSystemInfo:
        return RemediationSystemInfo(
            system_id="puppet-remediation-adapter",
            name="Puppet Configuration Management",
            version="7.0",
            api_version="1.0",
            capabilities=[
                RemediationSystemCapability.CONFIGURATION_MANAGEMENT,
                RemediationSystemCapability.INFRASTRUCTURE_AS_CODE
            ],
            supported_platforms=["rhel", "ubuntu", "debian", "centos", "windows"],
            supported_frameworks=["custom"],
            api_endpoint=self.puppet_server or "bolt://localhost",
            authentication_type="certificate",
            max_concurrent_jobs=20,
            typical_job_timeout=600,
            supports_dry_run=True,  # Puppet noop mode
            supports_rollback=False
        )
    
    async def get_available_rules(self, **kwargs) -> List[RemediationRule]:
        """Scan Puppet modules for remediation classes"""
        rules = []
        
        # Scan for Puppet modules with OpenWatch metadata
        for module_dir in self.modules_path.glob("*"):
            metadata_json = module_dir / "metadata.json"
            if metadata_json.exists():
                with open(metadata_json) as f:
                    metadata = json.load(f)
                
                # Look for OpenWatch tags in metadata
                if "openwatch" in metadata.get("tags", []):
                    # Parse module for remediation classes
                    manifests_dir = module_dir / "manifests"
                    if manifests_dir.exists():
                        for manifest in manifests_dir.glob("*.pp"):
                            # Simple example - in practice would parse Puppet DSL
                            rule_name = f"puppet_{module_dir.name}_{manifest.stem}"
                            
                            rules.append(RemediationRule(
                                semantic_name=rule_name,
                                title=f"{metadata.get('summary', 'Puppet remediation')}",
                                description=metadata.get('description', ''),
                                category="configuration",
                                tags=metadata.get('tags', []),
                                implementations={
                                    platform: {
                                        "module": module_dir.name,
                                        "class": manifest.stem
                                    }
                                    for platform in ["rhel", "ubuntu", "debian"]
                                }
                            ))
        
        return rules
    
    async def submit_remediation_job(self, job: RemediationJob) -> str:
        """Execute Puppet manifests via Bolt"""
        job_id = job.job_id
        
        # Build Puppet code to apply
        puppet_code_parts = []
        for rule_name in job.rules:
            rule = next((r for r in await self.get_available_rules() if r.semantic_name == rule_name), None)
            if rule:
                impl = rule.implementations.get(job.platform, {})
                if impl:
                    puppet_code_parts.append(f"include {impl['module']}::{impl['class']}")
        
        if puppet_code_parts:
            puppet_code = "; ".join(puppet_code_parts)
            
            # Execute via Bolt
            cmd = [
                self.bolt_path, 'apply',
                '--execute', puppet_code,
                '--targets', job.target_host_id
            ]
            
            if job.dry_run:
                cmd.extend(['--noop'])
            
            self._store_job_info(job_id, cmd)
        
        return job_id
    
    async def get_job_status(self, job_id: str) -> RemediationJobResult:
        """Check Puppet/Bolt execution status"""
        return RemediationJobResult(
            job_id=job_id,
            status=RemediationExecutionStatus.SUCCESS,
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
            total_rules=1,
            successful_rules=1,
            failed_rules=0,
            skipped_rules=0,
            rule_results=[]
        )
    
    async def cancel_job(self, job_id: str) -> bool:
        return True
    
    async def validate_connectivity(self, host_id: str) -> Dict[str, Any]:
        """Test Puppet/Bolt connectivity"""
        try:
            result = subprocess.run(
                [self.bolt_path, 'command', 'run', 'hostname', '--targets', host_id],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            return {
                "reachable": result.returncode == 0,
                "puppet_agent": "puppet agent installed" if result.returncode == 0 else None,
                "error_message": result.stderr if result.returncode != 0 else None
            }
        except:
            return {"reachable": False}
    
    def _store_job_info(self, job_id: str, cmd: List[str]):
        pass


# ============================================================================
# CUSTOM SCRIPT INTEGRATION
# ============================================================================

class CustomScriptRemediationSystem(RemediationSystemInterface):
    """
    Custom script integration for OpenWatch
    
    Allows organizations to use their own remediation scripts (bash, python, etc.)
    wrapped as OpenWatch plugins.
    """
    
    def __init__(self, scripts_directory: str = "/etc/openwatch/custom-scripts"):
        self.scripts_dir = Path(scripts_directory)
    
    async def get_system_info(self) -> RemediationSystemInfo:
        return RemediationSystemInfo(
            system_id="custom-script-adapter",
            name="Custom Script Remediation",
            version="1.0",
            api_version="1.0",
            capabilities=[
                RemediationSystemCapability.CUSTOM_SCRIPTING,
                RemediationSystemCapability.SECURITY_HARDENING
            ],
            supported_platforms=["linux", "unix"],
            supported_frameworks=["custom"],
            api_endpoint=f"file://{self.scripts_dir}",
            authentication_type="local",
            max_concurrent_jobs=5,
            typical_job_timeout=300,
            supports_dry_run=False,  # Unless scripts implement it
            supports_rollback=False
        )
    
    async def get_available_rules(self, **kwargs) -> List[RemediationRule]:
        """Scan script directory for remediation scripts"""
        rules = []
        
        # Look for scripts with .openwatch.yml metadata files
        for script_file in self.scripts_dir.rglob("*"):
            if script_file.is_file() and script_file.suffix in ['.sh', '.py', '.pl']:
                metadata_file = script_file.with_suffix('.openwatch.yml')
                
                if metadata_file.exists():
                    with open(metadata_file) as f:
                        metadata = yaml.safe_load(f)
                    
                    rule = RemediationRule(
                        semantic_name=metadata.get('name', script_file.stem),
                        title=metadata.get('title', ''),
                        description=metadata.get('description', ''),
                        category=metadata.get('category', 'custom'),
                        severity=metadata.get('severity', 'medium'),
                        tags=metadata.get('tags', []),
                        implementations={
                            platform: {"script": str(script_file)}
                            for platform in metadata.get('platforms', ['linux'])
                        },
                        reversible=metadata.get('reversible', False)
                    )
                    rules.append(rule)
        
        return rules
    
    async def submit_remediation_job(self, job: RemediationJob) -> str:
        """Execute custom scripts"""
        job_id = job.job_id
        
        for rule_name in job.rules:
            rule = next((r for r in await self.get_available_rules() if r.semantic_name == rule_name), None)
            if rule:
                impl = rule.implementations.get(job.platform, rule.implementations.get('linux', {}))
                script_path = impl.get('script')
                
                if script_path and Path(script_path).exists():
                    # Execute script with OpenWatch context
                    env = {
                        'OPENWATCH_HOST_ID': job.target_host_id,
                        'OPENWATCH_PLATFORM': job.platform,
                        'OPENWATCH_CONTEXT': json.dumps(job.openwatch_context)
                    }
                    
                    if job.dry_run:
                        env['OPENWATCH_DRY_RUN'] = '1'
                    
                    # In production, would execute asynchronously
                    self._store_job_info(job_id, script_path, env)
        
        return job_id
    
    async def get_job_status(self, job_id: str) -> RemediationJobResult:
        """Check script execution status"""
        return RemediationJobResult(
            job_id=job_id,
            status=RemediationExecutionStatus.SUCCESS,
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
            total_rules=1,
            successful_rules=1,
            failed_rules=0,
            skipped_rules=0,
            rule_results=[]
        )
    
    async def cancel_job(self, job_id: str) -> bool:
        return True
    
    async def validate_connectivity(self, host_id: str) -> Dict[str, Any]:
        """For custom scripts, assume local execution"""
        return {"reachable": True, "execution_method": "local"}
    
    def _store_job_info(self, job_id: str, script_path: str, env: Dict):
        pass


# ============================================================================
# EXAMPLE: Using Multiple Remediation Systems with OpenWatch
# ============================================================================

async def demonstrate_multi_platform_integration():
    """
    Show how OpenWatch can work with multiple remediation systems simultaneously
    """
    print("🔧 OpenWatch Multi-Platform Remediation Demo\n")
    
    # Initialize different remediation systems
    remediation_systems = {
        "ansible": AnsibleRemediationSystem(),
        "chef": ChefRemediationSystem(),
        "puppet": PuppetRemediationSystem(),
        "custom": CustomScriptRemediationSystem(),
        # "aegis": AegisRemediationSystem()  # From previous example
    }
    
    # Register each as OpenWatch plugin
    for name, system in remediation_systems.items():
        adapter = OpenWatchRemediationSystemAdapter(system)
        plugin = await adapter.register_as_openwatch_plugin()
        print(f"✅ {name.title()} registered as plugin: {plugin.plugin_id}")
    
    print("\n📋 Available Remediations by Platform:\n")
    
    # Show available rules from each system
    for name, system in remediation_systems.items():
        rules = await system.get_available_rules()
        print(f"{name.title()}: {len(rules)} remediation rules")
        for rule in rules[:3]:  # Show first 3
            print(f"  - {rule.semantic_name}: {rule.title}")
    
    print("\n🚀 Example: SSH Hardening Across Platforms\n")
    
    # OpenWatch detects SSH compliance failure
    openwatch_rule = "ow-ssh-disable-root"
    target_host = "web-server-01"
    platform = "rhel"
    
    # Find which remediation systems can fix this issue
    available_remediations = []
    for name, system in remediation_systems.items():
        adapter = OpenWatchRemediationSystemAdapter(system)
        matching_rules = await adapter.get_rules_for_openwatch_rule(
            openwatch_rule, platform
        )
        if matching_rules:
            available_remediations.append({
                "system": name,
                "rules": matching_rules
            })
    
    print(f"Found {len(available_remediations)} remediation options for {openwatch_rule}:")
    for option in available_remediations:
        print(f"  - {option['system']}: {len(option['rules'])} matching rules")
    
    # User/admin can choose which system to use
    # For example, organization policy might be:
    # - Use AEGIS for STIG compliance
    # - Use Ansible for custom configurations
    # - Use Chef for application deployments
    
    return True


# ============================================================================
# KEY INSIGHTS: How OpenWatch Supports Multiple Platforms
# ============================================================================

"""
1. STANDARD INTERFACE (ORSA)
   - Every remediation system implements the same interface
   - OpenWatch doesn't need platform-specific code
   - New platforms can be added without changing OpenWatch core

2. ADAPTER PATTERN
   - Each platform has an adapter that translates between its native format and ORSA
   - Adapters handle platform-specific execution (ansible-playbook, knife, bolt, etc.)
   - OpenWatch sees all platforms as "plugins" with standard behavior

3. RULE MAPPING
   - OpenWatch compliance rules (e.g., "ow-ssh-disable-root") are semantic
   - Each remediation system maps these to its own implementation
   - Multiple systems can remediate the same OpenWatch rule differently

4. EXECUTION ABSTRACTION
   - OpenWatch submits a "remediation job" 
   - Each adapter translates this to platform-specific execution
   - Results come back in standard format regardless of platform

5. FLEXIBILITY
   - Organizations can use their existing tools (Ansible, Chef, Puppet)
   - Can mix and match platforms based on use case
   - Can transition between platforms without changing OpenWatch

The key is that OpenWatch defines WHAT needs to be fixed (compliance rules),
while the remediation systems define HOW to fix it (implementation details).
"""

if __name__ == "__main__":
    asyncio.run(demonstrate_multi_platform_integration())