"""
Rule Parsing Service
Handles parsing and execution of unified compliance rules
"""
import asyncio
import subprocess
import re
import json
import configparser
import os
import tempfile
from typing import Dict, List, Any, Optional, Tuple, Union
from datetime import datetime
from pathlib import Path

from backend.app.models.unified_rule_models import (
    UnifiedComplianceRule, RuleExecution, RuleType, ComplianceStatus, 
    Platform, ExecutionContext
)


class RuleExecutionResult:
    """Result of rule execution"""
    
    def __init__(self):
        self.success: bool = False
        self.compliance_status: ComplianceStatus = ComplianceStatus.ERROR
        self.raw_output: Optional[str] = None
        self.processed_output: Optional[Dict[str, Any]] = None
        self.error_message: Optional[str] = None
        self.exit_code: Optional[int] = None
        self.execution_time: float = 0.0
        self.evidence_collected: List[str] = []
        self.artifacts_paths: List[str] = []


class RuleParsingService:
    """Service for parsing and executing unified compliance rules"""
    
    def __init__(self):
        """Initialize the rule parsing service"""
        self.temp_dir = Path(tempfile.gettempdir()) / "openwatch_rule_execution"
        self.temp_dir.mkdir(exist_ok=True)
    
    async def execute_rule(
        self,
        rule: UnifiedComplianceRule,
        host_id: str,
        execution_parameters: Optional[Dict[str, Any]] = None,
        scan_id: Optional[str] = None
    ) -> RuleExecution:
        """
        Execute a unified compliance rule
        
        Args:
            rule: Unified compliance rule to execute
            host_id: Target host identifier
            execution_parameters: Optional parameters for rule execution
            scan_id: Optional scan identifier
            
        Returns:
            RuleExecution record with results
        """
        execution_id = f"exec_{rule.rule_id}_{host_id}_{int(datetime.utcnow().timestamp())}"
        start_time = datetime.utcnow()
        
        # Initialize execution record
        execution = RuleExecution(
            execution_id=execution_id,
            rule_id=rule.rule_id,
            host_id=host_id,
            scan_id=scan_id,
            executed_by="RuleParsingService",
            executed_at=start_time,
            execution_parameters=execution_parameters or {},
            platform=await self._detect_platform(),
            platform_version=await self._detect_platform_version(),
            platform_architecture=await self._detect_architecture(),
            compliance_status=ComplianceStatus.ERROR,
            execution_success=False,
            execution_time=0.0
        )
        
        try:
            # Execute rule based on type
            result = await self._execute_by_type(rule, execution_parameters or {})
            
            # Calculate execution time
            end_time = datetime.utcnow()
            execution_time = (end_time - start_time).total_seconds()
            
            # Update execution record
            execution.compliance_status = result.compliance_status
            execution.execution_success = result.success
            execution.execution_time = execution_time
            execution.raw_output = result.raw_output
            execution.processed_output = result.processed_output
            execution.error_message = result.error_message
            execution.exit_code = result.exit_code
            execution.evidence_collected = result.evidence_collected
            execution.artifacts_paths = result.artifacts_paths
            
            # Generate framework-specific results
            execution.framework_results = await self._generate_framework_results(
                rule, result
            )
            
            # Generate justification
            execution.justification = await self._generate_justification(rule, result)
            
        except Exception as e:
            execution.error_message = str(e)
            execution.execution_success = False
            execution.compliance_status = ComplianceStatus.ERROR
            execution.execution_time = (datetime.utcnow() - start_time).total_seconds()
        
        # Save execution record
        await execution.save()
        return execution
    
    async def _execute_by_type(
        self,
        rule: UnifiedComplianceRule,
        parameters: Dict[str, Any]
    ) -> RuleExecutionResult:
        """
        Execute rule based on its type
        
        Args:
            rule: Rule to execute
            parameters: Execution parameters
            
        Returns:
            Rule execution result
        """
        if rule.rule_type == RuleType.COMMAND_EXECUTION:
            return await self._execute_command_rule(rule, parameters)
        elif rule.rule_type == RuleType.FILE_CHECK:
            return await self._execute_file_check_rule(rule, parameters)
        elif rule.rule_type == RuleType.CONFIGURATION_PARSE:
            return await self._execute_config_parse_rule(rule, parameters)
        elif rule.rule_type == RuleType.SERVICE_STATUS:
            return await self._execute_service_status_rule(rule, parameters)
        elif rule.rule_type == RuleType.PACKAGE_CHECK:
            return await self._execute_package_check_rule(rule, parameters)
        elif rule.rule_type == RuleType.PERMISSION_CHECK:
            return await self._execute_permission_check_rule(rule, parameters)
        elif rule.rule_type == RuleType.CONTENT_MATCH:
            return await self._execute_content_match_rule(rule, parameters)
        elif rule.rule_type == RuleType.COMPOSITE:
            return await self._execute_composite_rule(rule, parameters)
        else:
            raise Exception(f"Unsupported rule type: {rule.rule_type}")
    
    async def _execute_command_rule(
        self,
        rule: UnifiedComplianceRule,
        parameters: Dict[str, Any]
    ) -> RuleExecutionResult:
        """Execute command-based rule"""
        result = RuleExecutionResult()
        ctx = rule.execution_context
        
        # Prepare command with parameter substitution
        command = self._substitute_parameters(ctx.command, rule.parameters, parameters)
        
        try:
            # Execute command
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=ctx.working_directory,
                env={**os.environ, **ctx.environment_vars}
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=ctx.timeout
            )
            
            result.raw_output = stdout.decode('utf-8', errors='ignore')
            result.exit_code = process.returncode
            result.success = True
            
            # Process output and determine compliance
            result.processed_output = {
                "stdout": result.raw_output,
                "stderr": stderr.decode('utf-8', errors='ignore'),
                "exit_code": result.exit_code
            }
            
            # Check compliance based on expected value and operator
            result.compliance_status = self._check_compliance(
                result.raw_output,
                ctx.expected_value,
                ctx.comparison_operator
            )
            
            # Collect evidence
            result.evidence_collected.append(f"command_output_{rule.rule_id}")
            
        except asyncio.TimeoutError:
            result.error_message = f"Command execution timed out after {ctx.timeout} seconds"
            result.compliance_status = ComplianceStatus.ERROR
        except Exception as e:
            result.error_message = str(e)
            result.compliance_status = ComplianceStatus.ERROR
        
        return result
    
    async def _execute_file_check_rule(
        self,
        rule: UnifiedComplianceRule,
        parameters: Dict[str, Any]
    ) -> RuleExecutionResult:
        """Execute file check rule"""
        result = RuleExecutionResult()
        ctx = rule.execution_context
        
        file_path = self._substitute_parameters(ctx.file_path, rule.parameters, parameters)
        
        try:
            # Check if file exists
            path = Path(file_path)
            if not path.exists():
                result.compliance_status = ComplianceStatus.NON_COMPLIANT
                result.error_message = f"File not found: {file_path}"
                result.success = True  # Successful execution, but non-compliant
                return result
            
            # Get file information
            stat = path.stat()
            result.processed_output = {
                "file_exists": True,
                "file_size": stat.st_size,
                "file_mode": oct(stat.st_mode),
                "last_modified": stat.st_mtime
            }
            
            # Check compliance based on expected criteria
            if ctx.expected_value is not None:
                if ctx.comparison_operator == "exists":
                    result.compliance_status = ComplianceStatus.COMPLIANT
                elif ctx.comparison_operator == "size_gt":
                    result.compliance_status = (
                        ComplianceStatus.COMPLIANT if stat.st_size > ctx.expected_value
                        else ComplianceStatus.NON_COMPLIANT
                    )
                elif ctx.comparison_operator == "mode_eq":
                    expected_mode = oct(ctx.expected_value)
                    actual_mode = oct(stat.st_mode)
                    result.compliance_status = (
                        ComplianceStatus.COMPLIANT if actual_mode == expected_mode
                        else ComplianceStatus.NON_COMPLIANT
                    )
            else:
                result.compliance_status = ComplianceStatus.COMPLIANT
            
            result.success = True
            result.evidence_collected.append(f"file_check_{rule.rule_id}")
            
        except Exception as e:
            result.error_message = str(e)
            result.compliance_status = ComplianceStatus.ERROR
        
        return result
    
    async def _execute_config_parse_rule(
        self,
        rule: UnifiedComplianceRule,
        parameters: Dict[str, Any]
    ) -> RuleExecutionResult:
        """Execute configuration file parsing rule"""
        result = RuleExecutionResult()
        ctx = rule.execution_context
        
        file_path = self._substitute_parameters(ctx.file_path, rule.parameters, parameters)
        
        try:
            # Read configuration file
            config_path = Path(file_path)
            if not config_path.exists():
                result.compliance_status = ComplianceStatus.NON_COMPLIANT
                result.error_message = f"Configuration file not found: {file_path}"
                result.success = True
                return result
            
            # Parse configuration based on file type
            config_data = {}
            if file_path.endswith('.conf') or file_path.endswith('.ini'):
                config_data = self._parse_ini_config(file_path, ctx.config_section)
            elif file_path.endswith('.json'):
                with open(file_path, 'r') as f:
                    config_data = json.load(f)
            elif 'dconf' in file_path:
                config_data = self._parse_dconf_config(file_path, ctx.config_section)
            else:
                # Generic key-value parsing
                config_data = self._parse_generic_config(file_path)
            
            result.processed_output = {
                "config_data": config_data,
                "file_path": file_path
            }
            
            # Check compliance based on expected value
            compliance_value = self._extract_config_value(config_data, ctx)
            result.compliance_status = self._check_compliance(
                compliance_value,
                ctx.expected_value,
                ctx.comparison_operator
            )
            
            result.success = True
            result.evidence_collected.append(f"config_parse_{rule.rule_id}")
            
        except Exception as e:
            result.error_message = str(e)
            result.compliance_status = ComplianceStatus.ERROR
        
        return result
    
    async def _execute_service_status_rule(
        self,
        rule: UnifiedComplianceRule,
        parameters: Dict[str, Any]
    ) -> RuleExecutionResult:
        """Execute service status check rule"""
        result = RuleExecutionResult()
        ctx = rule.execution_context
        
        service_name = self._substitute_parameters(ctx.service_name, rule.parameters, parameters)
        
        try:
            # Check service status using systemctl
            command = f"systemctl is-active {service_name}"
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            service_status = stdout.decode('utf-8').strip()
            
            result.processed_output = {
                "service_name": service_name,
                "status": service_status,
                "exit_code": process.returncode
            }
            
            # Check compliance
            result.compliance_status = self._check_compliance(
                service_status,
                ctx.expected_value,
                ctx.comparison_operator
            )
            
            result.success = True
            result.evidence_collected.append(f"service_status_{rule.rule_id}")
            
        except Exception as e:
            result.error_message = str(e)
            result.compliance_status = ComplianceStatus.ERROR
        
        return result
    
    async def _execute_package_check_rule(
        self,
        rule: UnifiedComplianceRule,
        parameters: Dict[str, Any]
    ) -> RuleExecutionResult:
        """Execute package installation check rule"""
        result = RuleExecutionResult()
        ctx = rule.execution_context
        
        package_name = self._substitute_parameters(ctx.package_name, rule.parameters, parameters)
        
        try:
            # Detect package manager and check package
            platform = await self._detect_platform()
            
            if platform in [Platform.RHEL_8, Platform.RHEL_9, Platform.CENTOS_7, Platform.CENTOS_8]:
                command = f"rpm -q {package_name}"
            elif platform in [Platform.UBUNTU_20_04, Platform.UBUNTU_22_04, Platform.UBUNTU_24_04, Platform.DEBIAN_11, Platform.DEBIAN_12]:
                command = f"dpkg -l {package_name}"
            else:
                raise Exception(f"Unsupported platform for package check: {platform}")
            
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            result.processed_output = {
                "package_name": package_name,
                "output": stdout.decode('utf-8'),
                "exit_code": process.returncode,
                "platform": platform.value
            }
            
            # Package is installed if exit code is 0
            is_installed = process.returncode == 0
            
            if ctx.expected_value == "installed":
                result.compliance_status = (
                    ComplianceStatus.COMPLIANT if is_installed
                    else ComplianceStatus.NON_COMPLIANT
                )
            elif ctx.expected_value == "not_installed":
                result.compliance_status = (
                    ComplianceStatus.COMPLIANT if not is_installed
                    else ComplianceStatus.NON_COMPLIANT
                )
            
            result.success = True
            result.evidence_collected.append(f"package_check_{rule.rule_id}")
            
        except Exception as e:
            result.error_message = str(e)
            result.compliance_status = ComplianceStatus.ERROR
        
        return result
    
    async def _execute_permission_check_rule(
        self,
        rule: UnifiedComplianceRule,
        parameters: Dict[str, Any]
    ) -> RuleExecutionResult:
        """Execute file permission check rule"""
        result = RuleExecutionResult()
        ctx = rule.execution_context
        
        file_path = self._substitute_parameters(ctx.file_path, rule.parameters, parameters)
        
        try:
            # Get file permissions
            path = Path(file_path)
            if not path.exists():
                result.compliance_status = ComplianceStatus.NON_COMPLIANT
                result.error_message = f"File not found: {file_path}"
                result.success = True
                return result
            
            stat = path.stat()
            permissions = oct(stat.st_mode)[-3:]  # Last 3 digits
            
            result.processed_output = {
                "file_path": file_path,
                "permissions": permissions,
                "full_mode": oct(stat.st_mode)
            }
            
            # Check compliance
            result.compliance_status = self._check_compliance(
                permissions,
                ctx.expected_value,
                ctx.comparison_operator
            )
            
            result.success = True
            result.evidence_collected.append(f"permission_check_{rule.rule_id}")
            
        except Exception as e:
            result.error_message = str(e)
            result.compliance_status = ComplianceStatus.ERROR
        
        return result
    
    async def _execute_content_match_rule(
        self,
        rule: UnifiedComplianceRule,
        parameters: Dict[str, Any]
    ) -> RuleExecutionResult:
        """Execute content matching rule"""
        result = RuleExecutionResult()
        ctx = rule.execution_context
        
        file_path = self._substitute_parameters(ctx.file_path, rule.parameters, parameters)
        
        try:
            # Read file content
            with open(file_path, 'r') as f:
                content = f.read()
            
            result.processed_output = {
                "file_path": file_path,
                "content_length": len(content)
            }
            
            # Check content match
            if ctx.comparison_operator == "contains":
                matches = ctx.expected_value in content
            elif ctx.comparison_operator == "regex":
                matches = bool(re.search(ctx.expected_value, content))
            elif ctx.comparison_operator == "not_contains":
                matches = ctx.expected_value not in content
            else:
                matches = False
            
            result.compliance_status = (
                ComplianceStatus.COMPLIANT if matches
                else ComplianceStatus.NON_COMPLIANT
            )
            
            result.success = True
            result.evidence_collected.append(f"content_match_{rule.rule_id}")
            
        except Exception as e:
            result.error_message = str(e)
            result.compliance_status = ComplianceStatus.ERROR
        
        return result
    
    async def _execute_composite_rule(
        self,
        rule: UnifiedComplianceRule,
        parameters: Dict[str, Any]
    ) -> RuleExecutionResult:
        """Execute composite rule (multiple checks)"""
        # For composite rules, we would need to define sub-rules
        # This is a placeholder for future implementation
        result = RuleExecutionResult()
        result.error_message = "Composite rules not yet implemented"
        result.compliance_status = ComplianceStatus.ERROR
        return result
    
    def _substitute_parameters(
        self,
        template: Optional[str],
        rule_parameters: List,
        execution_parameters: Dict[str, Any]
    ) -> Optional[str]:
        """Substitute parameters in template strings"""
        if not template:
            return template
        
        # Create parameter mapping
        param_values = {}
        for param in rule_parameters:
            if param.name in execution_parameters:
                param_values[param.name] = execution_parameters[param.name]
            else:
                param_values[param.name] = param.default_value
        
        # Substitute parameters
        result = template
        for name, value in param_values.items():
            result = result.replace(f"{{{name}}}", str(value))
        
        return result
    
    def _check_compliance(
        self,
        actual_value: Any,
        expected_value: Any,
        operator: str
    ) -> ComplianceStatus:
        """Check compliance based on comparison operator"""
        try:
            if operator == "eq":
                return ComplianceStatus.COMPLIANT if actual_value == expected_value else ComplianceStatus.NON_COMPLIANT
            elif operator == "ne":
                return ComplianceStatus.COMPLIANT if actual_value != expected_value else ComplianceStatus.NON_COMPLIANT
            elif operator == "gt":
                return ComplianceStatus.COMPLIANT if float(actual_value) > float(expected_value) else ComplianceStatus.NON_COMPLIANT
            elif operator == "lt":
                return ComplianceStatus.COMPLIANT if float(actual_value) < float(expected_value) else ComplianceStatus.NON_COMPLIANT
            elif operator == "gte":
                return ComplianceStatus.COMPLIANT if float(actual_value) >= float(expected_value) else ComplianceStatus.NON_COMPLIANT
            elif operator == "lte":
                return ComplianceStatus.COMPLIANT if float(actual_value) <= float(expected_value) else ComplianceStatus.NON_COMPLIANT
            elif operator == "contains":
                return ComplianceStatus.COMPLIANT if str(expected_value) in str(actual_value) else ComplianceStatus.NON_COMPLIANT
            elif operator == "regex":
                return ComplianceStatus.COMPLIANT if re.search(str(expected_value), str(actual_value)) else ComplianceStatus.NON_COMPLIANT
            else:
                return ComplianceStatus.ERROR
        except Exception:
            return ComplianceStatus.ERROR
    
    def _parse_ini_config(self, file_path: str, section: Optional[str] = None) -> Dict[str, Any]:
        """Parse INI/CONF configuration file"""
        config = configparser.ConfigParser()
        config.read(file_path)
        
        result = {}
        if section:
            section_name = section.strip('[]')
            if section_name in config:
                result = dict(config[section_name])
        else:
            for section_name in config.sections():
                result[section_name] = dict(config[section_name])
        
        return result
    
    def _parse_dconf_config(self, file_path: str, section: Optional[str] = None) -> Dict[str, Any]:
        """Parse dconf configuration file"""
        result = {}
        current_section = None
        
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('[') and line.endswith(']'):
                    current_section = line
                    if current_section not in result:
                        result[current_section] = {}
                elif '=' in line and current_section:
                    key, value = line.split('=', 1)
                    result[current_section][key.strip()] = value.strip()
        
        if section and section in result:
            return result[section]
        return result
    
    def _parse_generic_config(self, file_path: str) -> Dict[str, Any]:
        """Parse generic key-value configuration file"""
        result = {}
        
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    result[key.strip()] = value.strip()
        
        return result
    
    def _extract_config_value(self, config_data: Dict[str, Any], ctx: ExecutionContext) -> Any:
        """Extract specific value from configuration data"""
        if ctx.config_section:
            section_data = config_data.get(ctx.config_section, {})
            # For dconf, extract specific key if needed
            if isinstance(section_data, dict) and len(section_data) == 1:
                return list(section_data.values())[0]
            return section_data
        return config_data
    
    async def _detect_platform(self) -> Platform:
        """Detect the current platform"""
        try:
            # Read /etc/os-release
            with open('/etc/os-release', 'r') as f:
                os_release = f.read()
            
            if 'Red Hat Enterprise Linux' in os_release or 'RHEL' in os_release:
                if 'VERSION_ID="8' in os_release:
                    return Platform.RHEL_8
                elif 'VERSION_ID="9' in os_release:
                    return Platform.RHEL_9
            elif 'Ubuntu' in os_release:
                if 'VERSION_ID="20.04"' in os_release:
                    return Platform.UBUNTU_20_04
                elif 'VERSION_ID="22.04"' in os_release:
                    return Platform.UBUNTU_22_04
                elif 'VERSION_ID="24.04"' in os_release:
                    return Platform.UBUNTU_24_04
            elif 'CentOS' in os_release:
                if 'VERSION_ID="7"' in os_release:
                    return Platform.CENTOS_7
                elif 'VERSION_ID="8"' in os_release:
                    return Platform.CENTOS_8
            elif 'Debian' in os_release:
                if 'VERSION_ID="11"' in os_release:
                    return Platform.DEBIAN_11
                elif 'VERSION_ID="12"' in os_release:
                    return Platform.DEBIAN_12
            
            # Default fallback
            return Platform.RHEL_9
            
        except Exception:
            return Platform.RHEL_9
    
    async def _detect_platform_version(self) -> str:
        """Detect platform version"""
        try:
            with open('/etc/os-release', 'r') as f:
                for line in f:
                    if line.startswith('VERSION_ID='):
                        return line.split('=')[1].strip().strip('"')
            return "unknown"
        except Exception:
            return "unknown"
    
    async def _detect_architecture(self) -> str:
        """Detect platform architecture"""
        try:
            process = await asyncio.create_subprocess_shell(
                "uname -m",
                stdout=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            return stdout.decode('utf-8').strip()
        except Exception:
            return "x86_64"
    
    async def _generate_framework_results(
        self,
        rule: UnifiedComplianceRule,
        execution_result: RuleExecutionResult
    ) -> List[Dict[str, Any]]:
        """Generate framework-specific results"""
        framework_results = []
        
        for mapping in rule.framework_mappings:
            for control_id in mapping.control_ids:
                framework_result = {
                    "framework_id": mapping.framework_id,
                    "control_id": control_id,
                    "status": execution_result.compliance_status.value,
                    "mapping_status": mapping.compliance_status.value,
                    "justification": mapping.justification,
                    "evidence": execution_result.evidence_collected
                }
                
                if mapping.enhancement_description:
                    framework_result["enhancement"] = mapping.enhancement_description
                
                framework_results.append(framework_result)
        
        return framework_results
    
    async def _generate_justification(
        self,
        rule: UnifiedComplianceRule,
        execution_result: RuleExecutionResult
    ) -> str:
        """Generate compliance justification"""
        base_justification = f"Rule {rule.rule_id} executed successfully. "
        
        if execution_result.compliance_status == ComplianceStatus.COMPLIANT:
            base_justification += "All compliance requirements satisfied."
        elif execution_result.compliance_status == ComplianceStatus.EXCEEDS:
            base_justification += "Implementation exceeds baseline compliance requirements."
        elif execution_result.compliance_status == ComplianceStatus.NON_COMPLIANT:
            base_justification += "Non-compliance detected. Remediation required."
        elif execution_result.compliance_status == ComplianceStatus.PARTIAL:
            base_justification += "Partial compliance achieved. Additional configuration needed."
        else:
            base_justification += "Compliance status could not be determined due to execution error."
        
        # Add framework-specific details
        framework_count = len(rule.framework_mappings)
        if framework_count > 1:
            base_justification += f" This rule addresses requirements across {framework_count} compliance frameworks."
        
        return base_justification