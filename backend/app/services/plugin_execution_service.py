"""
Plugin Execution Service
Handles secure execution of imported plugins in isolated environments
"""
import asyncio
import logging
import uuid
import json
import tempfile
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path

from ..models.plugin_models import (
    InstalledPlugin, PluginExecutionRequest, PluginExecutionResult,
    PluginCapability, PluginStatus
)
from ..models.mongo_models import Host
from .plugin_registry_service import PluginRegistryService
from .command_sandbox import CommandSandbox
from ..config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class PluginExecutionService:
    """Execute plugins safely in isolated environments"""
    
    def __init__(self):
        self.registry_service = PluginRegistryService()
        self.execution_history = {}
        self.active_executions = {}
    
    async def execute_plugin(
        self,
        request: PluginExecutionRequest
    ) -> PluginExecutionResult:
        """
        Execute a plugin with full security isolation
        
        Args:
            request: Plugin execution request with parameters
            
        Returns:
            Execution result with output and status
        """
        execution_id = str(uuid.uuid4())
        started_at = datetime.utcnow()
        
        try:
            # Get plugin
            plugin = await self.registry_service.get_plugin(request.plugin_id)
            if not plugin:
                return self._create_error_result(
                    execution_id, started_at, 
                    f"Plugin not found: {request.plugin_id}"
                )
            
            # Validate plugin status
            if plugin.status != PluginStatus.ACTIVE:
                return self._create_error_result(
                    execution_id, started_at,
                    f"Plugin not active: {plugin.status.value}"
                )
            
            # Validate platform support
            if request.platform not in plugin.enabled_platforms:
                return self._create_error_result(
                    execution_id, started_at,
                    f"Platform not supported: {request.platform}"
                )
            
            # Register active execution
            self.active_executions[execution_id] = {
                'plugin_id': request.plugin_id,
                'started_at': started_at,
                'request': request
            }
            
            logger.info(f"Starting plugin execution {execution_id}: {request.plugin_id}")
            
            # Create execution environment
            execution_env = await self._create_execution_environment(
                plugin, request, execution_id
            )
            
            # Select appropriate executor
            executor = await self._select_executor(plugin, request.platform)
            if not executor:
                return self._create_error_result(
                    execution_id, started_at,
                    f"No suitable executor for platform: {request.platform}"
                )
            
            # Execute plugin
            execution_result = await self._execute_with_sandbox(
                plugin, executor, request, execution_env, execution_id
            )
            
            # Update plugin usage statistics
            await self._update_usage_statistics(plugin, execution_result)
            
            # Clean up execution environment
            await self._cleanup_execution_environment(execution_env)
            
            # Record execution history
            await self._record_execution_history(plugin, request, execution_result)
            
            return execution_result
            
        except Exception as e:
            logger.error(f"Plugin execution {execution_id} failed: {e}")
            return self._create_error_result(
                execution_id, started_at,
                f"Execution failed: {str(e)}"
            )
        
        finally:
            # Remove from active executions
            self.active_executions.pop(execution_id, None)
    
    async def get_execution_status(self, execution_id: str) -> Optional[Dict[str, Any]]:
        """Get status of active execution"""
        return self.active_executions.get(execution_id)
    
    async def cancel_execution(self, execution_id: str) -> Dict[str, Any]:
        """Cancel an active execution"""
        if execution_id not in self.active_executions:
            return {
                'success': False,
                'error': 'Execution not found or already completed'
            }
        
        try:
            # Implementation would cancel the running process/container
            # For now, just remove from active executions
            execution_info = self.active_executions.pop(execution_id)
            
            logger.info(f"Cancelled plugin execution {execution_id}")
            
            return {
                'success': True,
                'execution_id': execution_id,
                'plugin_id': execution_info['plugin_id'],
                'cancelled_at': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to cancel execution {execution_id}: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def get_plugin_execution_history(
        self,
        plugin_id: str,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Get execution history for a plugin"""
        plugin = await self.registry_service.get_plugin(plugin_id)
        if not plugin:
            return []
        
        # Return last N executions from plugin's execution history
        history = plugin.execution_history or []
        return history[-limit:]
    
    async def _create_execution_environment(
        self,
        plugin: InstalledPlugin,
        request: PluginExecutionRequest,
        execution_id: str
    ) -> Dict[str, Any]:
        """Create isolated execution environment"""
        # Create temporary directory for execution
        temp_dir = Path(tempfile.mkdtemp(prefix=f"plugin_exec_{execution_id}_"))
        
        # Copy plugin files to execution directory
        plugin_dir = temp_dir / "plugin"
        plugin_dir.mkdir()
        
        for file_path, content in plugin.files.items():
            full_path = plugin_dir / file_path
            full_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(full_path, 'w') as f:
                f.write(content)
            
            # Set executable permissions for scripts
            if file_path.endswith(('.sh', '.py', '.pl')):
                full_path.chmod(0o755)
        
        # Create execution context file
        context = {
            'plugin_id': plugin.plugin_id,
            'execution_id': execution_id,
            'rule_context': request.execution_context,
            'host_info': {
                'host_id': request.host_id,
                'platform': request.platform
            },
            'config': {
                **plugin.manifest.default_config,
                **plugin.user_config,
                **request.config_overrides
            },
            'dry_run': request.dry_run,
            'timeout': request.timeout_override or 300
        }
        
        context_file = temp_dir / "execution_context.json"
        with open(context_file, 'w') as f:
            json.dump(context, f, indent=2)
        
        return {
            'temp_dir': temp_dir,
            'plugin_dir': plugin_dir,
            'context_file': context_file,
            'context': context
        }
    
    async def _select_executor(
        self,
        plugin: InstalledPlugin,
        platform: str
    ) -> Optional[Dict[str, Any]]:
        """Select best executor for platform"""
        # Find executors that support the target platform
        compatible_executors = []
        
        for name, executor in plugin.executors.items():
            # Check if executor templates include the platform
            if platform in executor.templates or not executor.templates:
                compatible_executors.append((name, executor))
        
        if not compatible_executors:
            return None
        
        # Prioritize by executor type (prefer safer types)
        priority_order = [
            PluginCapability.PYTHON,
            PluginCapability.ANSIBLE,
            PluginCapability.SHELL,
            PluginCapability.API,
            PluginCapability.CUSTOM
        ]
        
        for preferred_type in priority_order:
            for name, executor in compatible_executors:
                if executor.type == preferred_type:
                    return {
                        'name': name,
                        'executor': executor,
                        'type': executor.type.value
                    }
        
        # Return first available if no preference match
        name, executor = compatible_executors[0]
        return {
            'name': name,
            'executor': executor,
            'type': executor.type.value
        }
    
    async def _execute_with_sandbox(
        self,
        plugin: InstalledPlugin,
        executor_info: Dict[str, Any],
        request: PluginExecutionRequest,
        execution_env: Dict[str, Any],
        execution_id: str
    ) -> PluginExecutionResult:
        """Execute plugin in secure sandbox"""
        executor = executor_info['executor']
        started_at = datetime.utcnow()
        
        try:
            # Prepare execution command based on executor type
            if executor.type == PluginCapability.SHELL:
                result = await self._execute_shell_plugin(
                    plugin, executor, request, execution_env
                )
            elif executor.type == PluginCapability.PYTHON:
                result = await self._execute_python_plugin(
                    plugin, executor, request, execution_env
                )
            elif executor.type == PluginCapability.ANSIBLE:
                result = await self._execute_ansible_plugin(
                    plugin, executor, request, execution_env
                )
            elif executor.type == PluginCapability.API:
                result = await self._execute_api_plugin(
                    plugin, executor, request, execution_env
                )
            else:
                raise ValueError(f"Unsupported executor type: {executor.type}")
            
            completed_at = datetime.utcnow()
            duration = (completed_at - started_at).total_seconds()
            
            return PluginExecutionResult(
                execution_id=execution_id,
                plugin_id=plugin.plugin_id,
                status="success" if result['success'] else "failure",
                started_at=started_at,
                completed_at=completed_at,
                duration_seconds=duration,
                output=result.get('output'),
                error=result.get('error'),
                changes_made=result.get('changes', []),
                validation_passed=result.get('validation_passed', False),
                validation_details=result.get('validation_details'),
                rollback_available=result.get('rollback_available', False),
                rollback_data=result.get('rollback_data')
            )
            
        except Exception as e:
            completed_at = datetime.utcnow()
            duration = (completed_at - started_at).total_seconds()
            
            return PluginExecutionResult(
                execution_id=execution_id,
                plugin_id=plugin.plugin_id,
                status="error",
                started_at=started_at,
                completed_at=completed_at,
                duration_seconds=duration,
                error=str(e)
            )
    
    async def _execute_shell_plugin(
        self,
        plugin: InstalledPlugin,
        executor,
        request: PluginExecutionRequest,
        execution_env: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute shell-based plugin"""
        plugin_dir = execution_env['plugin_dir']
        entry_point = plugin_dir / executor.entry_point
        
        if not entry_point.exists():
            raise FileNotFoundError(f"Entry point not found: {executor.entry_point}")
        
        # Prepare environment variables
        env_vars = {
            **executor.environment_variables,
            'PLUGIN_CONTEXT_FILE': str(execution_env['context_file']),
            'PLUGIN_DRY_RUN': str(request.dry_run).lower(),
            'PLUGIN_HOST_ID': request.host_id,
            'PLUGIN_PLATFORM': request.platform
        }
        
        # Create sandbox for execution
        sandbox = CommandSandbox()
        
        # Execute with timeout
        timeout = request.timeout_override or executor.resource_limits.get('timeout', 300)
        
        try:
            result = await sandbox.run_command(
                str(entry_point),
                cwd=str(plugin_dir),
                env=env_vars,
                timeout=timeout,
                capture_output=True
            )
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr if result.returncode != 0 else None,
                'return_code': result.returncode
            }
            
        except asyncio.TimeoutError:
            return {
                'success': False,
                'error': f'Plugin execution timed out after {timeout} seconds'
            }
    
    async def _execute_python_plugin(
        self,
        plugin: InstalledPlugin,
        executor,
        request: PluginExecutionRequest,
        execution_env: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute Python-based plugin"""
        plugin_dir = execution_env['plugin_dir']
        entry_point = plugin_dir / executor.entry_point
        
        if not entry_point.exists():
            raise FileNotFoundError(f"Entry point not found: {executor.entry_point}")
        
        # Prepare command
        command = [
            'python3',
            str(entry_point),
            '--context-file', str(execution_env['context_file'])
        ]
        
        if request.dry_run:
            command.append('--dry-run')
        
        # Environment variables
        env_vars = {
            **executor.environment_variables,
            'PLUGIN_CONTEXT_FILE': str(execution_env['context_file']),
            'PYTHONPATH': str(plugin_dir)
        }
        
        # Execute in sandbox
        sandbox = CommandSandbox()
        timeout = request.timeout_override or executor.resource_limits.get('timeout', 300)
        
        try:
            result = await sandbox.run_command(
                command,
                cwd=str(plugin_dir),
                env=env_vars,
                timeout=timeout,
                capture_output=True
            )
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr if result.returncode != 0 else None,
                'return_code': result.returncode
            }
            
        except asyncio.TimeoutError:
            return {
                'success': False,
                'error': f'Plugin execution timed out after {timeout} seconds'
            }
    
    async def _execute_ansible_plugin(
        self,
        plugin: InstalledPlugin,
        executor,
        request: PluginExecutionRequest,
        execution_env: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute Ansible-based plugin"""
        plugin_dir = execution_env['plugin_dir']
        playbook_path = plugin_dir / executor.entry_point
        
        if not playbook_path.exists():
            raise FileNotFoundError(f"Playbook not found: {executor.entry_point}")
        
        # Create inventory file
        inventory_file = execution_env['temp_dir'] / "inventory"
        with open(inventory_file, 'w') as f:
            f.write(f"target_host ansible_host={request.host_id}\n")
        
        # Prepare ansible-playbook command
        command = [
            'ansible-playbook',
            str(playbook_path),
            '-i', str(inventory_file),
            '--extra-vars', f'@{execution_env["context_file"]}'
        ]
        
        if request.dry_run:
            command.append('--check')
        
        # Execute in sandbox
        sandbox = CommandSandbox()
        timeout = request.timeout_override or executor.resource_limits.get('timeout', 600)
        
        try:
            result = await sandbox.run_command(
                command,
                cwd=str(plugin_dir),
                timeout=timeout,
                capture_output=True
            )
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr if result.returncode != 0 else None,
                'return_code': result.returncode
            }
            
        except asyncio.TimeoutError:
            return {
                'success': False,
                'error': f'Ansible execution timed out after {timeout} seconds'
            }
    
    async def _execute_api_plugin(
        self,
        plugin: InstalledPlugin,
        executor,
        request: PluginExecutionRequest,
        execution_env: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute API-based plugin"""
        # This would involve making HTTP requests based on plugin configuration
        # For now, return a placeholder implementation
        return {
            'success': False,
            'error': 'API plugin execution not yet implemented'
        }
    
    async def _update_usage_statistics(
        self,
        plugin: InstalledPlugin,
        result: PluginExecutionResult
    ):
        """Update plugin usage statistics"""
        plugin.usage_count += 1
        plugin.last_used = datetime.utcnow()
        
        # Add to execution history (keep last 100)
        history_entry = {
            'execution_id': result.execution_id,
            'executed_at': result.started_at.isoformat(),
            'duration_seconds': result.duration_seconds,
            'status': result.status,
            'user': 'system'  # Would get from request context
        }
        
        if not plugin.execution_history:
            plugin.execution_history = []
        
        plugin.execution_history.append(history_entry)
        if len(plugin.execution_history) > 100:
            plugin.execution_history = plugin.execution_history[-100:]
        
        await plugin.save()
    
    async def _cleanup_execution_environment(self, execution_env: Dict[str, Any]):
        """Clean up temporary execution environment"""
        try:
            import shutil
            shutil.rmtree(execution_env['temp_dir'])
        except Exception as e:
            logger.warning(f"Failed to cleanup execution environment: {e}")
    
    async def _record_execution_history(
        self,
        plugin: InstalledPlugin,
        request: PluginExecutionRequest,
        result: PluginExecutionResult
    ):
        """Record execution in system history"""
        # This could store in a separate audit log or database table
        self.execution_history[result.execution_id] = {
            'plugin_id': plugin.plugin_id,
            'request': request.dict(),
            'result': result.dict(),
            'recorded_at': datetime.utcnow().isoformat()
        }
    
    def _create_error_result(
        self,
        execution_id: str,
        started_at: datetime,
        error_message: str
    ) -> PluginExecutionResult:
        """Create error result"""
        completed_at = datetime.utcnow()
        duration = (completed_at - started_at).total_seconds()
        
        return PluginExecutionResult(
            execution_id=execution_id,
            plugin_id="unknown",
            status="error",
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=duration,
            error=error_message
        )