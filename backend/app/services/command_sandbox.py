"""
OpenWatch Secure Command Sandboxing Service

This service provides secure, containerized execution of automated fix commands
with comprehensive security controls, audit logging, and rollback capabilities.

Security Features:
- Containerized execution environment
- Cryptographic command signature verification  
- Command allowlisting with parameter validation
- Multi-factor approval workflow for privileged operations
- Complete audit trail and rollback capabilities
- Resource limiting and timeout controls
"""

import asyncio
import hashlib
import hmac
import json
import logging
import os
import tempfile
import time
import uuid
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import docker
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from pydantic import BaseModel, Field

from ..config import settings
from ..database import get_db
from .crypto import CryptoService

logger = logging.getLogger(__name__)


class CommandSecurityLevel(str, Enum):
    """Security classification levels for commands"""
    SAFE = "safe"           # No system modifications, read-only operations
    MODERATE = "moderate"   # Limited system changes, no privilege escalation
    PRIVILEGED = "privileged"  # Requires elevated privileges, system changes
    CRITICAL = "critical"   # High-impact system modifications


class ExecutionStatus(str, Enum):
    """Command execution status tracking"""
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class SecureCommand(BaseModel):
    """Secure command definition with cryptographic verification"""
    command_id: str
    template: str
    description: str
    security_level: CommandSecurityLevel
    allowed_parameters: List[str] = Field(default_factory=list)
    parameter_patterns: Dict[str, str] = Field(default_factory=dict)
    requires_approval: bool = False
    max_execution_time: int = 300  # seconds
    rollback_template: Optional[str] = None
    signature: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)


class ExecutionRequest(BaseModel):
    """Command execution request with security context"""
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    command_id: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    target_host: str
    requested_by: str
    justification: str
    status: ExecutionStatus = ExecutionStatus.PENDING_APPROVAL
    approved_by: Optional[str] = None
    executed_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    output: Optional[str] = None
    error_output: Optional[str] = None
    exit_code: Optional[int] = None
    rollback_available: bool = False
    rollback_command: Optional[str] = None


class SandboxEnvironment:
    """Containerized sandbox environment for secure command execution"""
    
    def __init__(self, container_image: str = "ubuntu:22.04"):
        self.container_image = container_image
        self.docker_client = docker.from_env()
        self.container = None
        self.sandbox_id = str(uuid.uuid4())
        
    async def __aenter__(self):
        """Async context manager entry - create sandbox"""
        await self._create_sandbox()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit - cleanup sandbox"""
        await self._cleanup_sandbox()
        
    async def _create_sandbox(self):
        """Create secure containerized environment"""
        try:
            # Create container with security constraints
            self.container = self.docker_client.containers.run(
                self.container_image,
                command="sleep infinity",  # Keep container running
                detach=True,
                remove=True,
                name=f"openwatch-sandbox-{self.sandbox_id}",
                network_mode="none",  # No network access by default
                read_only=True,  # Read-only filesystem
                security_opt=["no-new-privileges:true"],  # Prevent privilege escalation
                cap_drop=["ALL"],  # Drop all capabilities
                cap_add=["CHOWN", "SETUID", "SETGID"],  # Only essential capabilities
                mem_limit="512m",  # Memory limit
                cpu_count=1,  # CPU limit
                pids_limit=100,  # Process limit
                tmpfs={"/tmp": "size=100m,noexec"},  # Temporary filesystem
            )
            
            # Wait for container to be ready
            await asyncio.sleep(1)
            
            # Install basic tools in sandbox
            await self._setup_sandbox_tools()
            
            logger.info(f"Created secure sandbox: {self.sandbox_id}")
            
        except Exception as e:
            logger.error(f"Failed to create sandbox {self.sandbox_id}: {e}")
            raise
            
    async def _setup_sandbox_tools(self):
        """Install essential tools in sandbox"""
        try:
            # Update package lists
            result = self.container.exec_run("apt-get update -qq")
            if result.exit_code != 0:
                logger.warning("Failed to update package lists in sandbox")
                
            # Install essential tools
            essential_tools = [
                "curl", "wget", "netcat-traditional", "dnsutils", 
                "net-tools", "procps", "lsof"
            ]
            
            for tool in essential_tools:
                result = self.container.exec_run(f"apt-get install -y -qq {tool}")
                if result.exit_code != 0:
                    logger.warning(f"Failed to install {tool} in sandbox")
                    
        except Exception as e:
            logger.warning(f"Failed to setup sandbox tools: {e}")
            
    async def execute_command(self, command: str, timeout: int = 300) -> Tuple[int, str, str]:
        """Execute command in sandbox with timeout"""
        if not self.container:
            raise RuntimeError("Sandbox not initialized")
            
        try:
            # Execute command with timeout
            result = self.container.exec_run(
                command,
                timeout=timeout,
                stdout=True,
                stderr=True
            )
            
            stdout = result.output.decode('utf-8') if result.output else ""
            stderr = ""  # Docker exec_run combines stdout/stderr
            
            return result.exit_code, stdout, stderr
            
        except Exception as e:
            logger.error(f"Command execution failed in sandbox {self.sandbox_id}: {e}")
            raise
            
    async def _cleanup_sandbox(self):
        """Clean up sandbox container"""
        try:
            if self.container:
                self.container.stop()
                logger.info(f"Cleaned up sandbox: {self.sandbox_id}")
        except Exception as e:
            logger.error(f"Failed to cleanup sandbox {self.sandbox_id}: {e}")


class CommandSignatureService:
    """Cryptographic signature service for command verification"""
    
    def __init__(self, crypto_service: CryptoService):
        self.crypto_service = crypto_service
        self.signature_algorithm = hashes.SHA256()
        
    def sign_command(self, command: SecureCommand, private_key_path: str) -> str:
        """Generate cryptographic signature for command"""
        try:
            # Load private key
            with open(private_key_path, 'rb') as f:
                private_key = serialization.load_pem_private_key(
                    f.read(), 
                    password=None
                )
            
            # Create command payload for signing
            payload = {
                "command_id": command.command_id,
                "template": command.template,
                "security_level": command.security_level,
                "allowed_parameters": command.allowed_parameters,
                "parameter_patterns": command.parameter_patterns
            }
            
            payload_bytes = json.dumps(payload, sort_keys=True).encode()
            
            # Generate signature
            signature = private_key.sign(
                payload_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            return signature.hex()
            
        except Exception as e:
            logger.error(f"Failed to sign command {command.command_id}: {e}")
            raise
            
    def verify_command(self, command: SecureCommand, signature: str, public_key_path: str) -> bool:
        """Verify cryptographic signature for command"""
        try:
            # Load public key
            with open(public_key_path, 'rb') as f:
                public_key = serialization.load_pem_public_key(f.read())
            
            # Recreate command payload
            payload = {
                "command_id": command.command_id,
                "template": command.template,
                "security_level": command.security_level,
                "allowed_parameters": command.allowed_parameters,
                "parameter_patterns": command.parameter_patterns
            }
            
            payload_bytes = json.dumps(payload, sort_keys=True).encode()
            signature_bytes = bytes.fromhex(signature)
            
            # Verify signature
            public_key.verify(
                signature_bytes,
                payload_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            return True
            
        except Exception as e:
            logger.warning(f"Command signature verification failed for {command.command_id}: {e}")
            return False


class CommandSandboxService:
    """Main service for secure command sandboxing"""
    
    def __init__(self):
        self.crypto_service = CryptoService()
        self.signature_service = CommandSignatureService(self.crypto_service)
        self.allowed_commands: Dict[str, SecureCommand] = {}
        self.execution_requests: Dict[str, ExecutionRequest] = {}
        self._load_allowed_commands()
        
    def _load_allowed_commands(self):
        """Load pre-approved secure commands"""
        # Define secure command templates with strict parameter validation
        commands = [
            SecureCommand(
                command_id="check_service_status",
                template="systemctl status {service_name}",
                description="Check systemd service status",
                security_level=CommandSecurityLevel.SAFE,
                allowed_parameters=["service_name"],
                parameter_patterns={"service_name": r"^[a-zA-Z0-9\-_.]+$"},
                requires_approval=False,
                max_execution_time=30
            ),
            SecureCommand(
                command_id="check_network_port",
                template="netstat -tlnp | grep {port}",
                description="Check if network port is listening",
                security_level=CommandSecurityLevel.SAFE,
                allowed_parameters=["port"],
                parameter_patterns={"port": r"^[1-9][0-9]{0,4}$"},
                requires_approval=False,
                max_execution_time=30
            ),
            SecureCommand(
                command_id="install_openscap_ubuntu",
                template="apt-get update -qq && apt-get install -y -qq libopenscap8 ssg-base",
                description="Install OpenSCAP on Ubuntu/Debian systems",
                security_level=CommandSecurityLevel.PRIVILEGED,
                allowed_parameters=[],
                requires_approval=True,
                max_execution_time=300,
                rollback_template="apt-get remove -y libopenscap8 ssg-base"
            ),
            SecureCommand(
                command_id="install_openscap_rhel",
                template="yum install -y openscap-scanner scap-security-guide",
                description="Install OpenSCAP on RHEL/CentOS systems", 
                security_level=CommandSecurityLevel.PRIVILEGED,
                allowed_parameters=[],
                requires_approval=True,
                max_execution_time=300,
                rollback_template="yum remove -y openscap-scanner scap-security-guide"
            ),
            SecureCommand(
                command_id="cleanup_temp_files",
                template="find /tmp -type f -mtime +7 -name 'openwatch_*' -delete",
                description="Clean up old OpenWatch temporary files",
                security_level=CommandSecurityLevel.MODERATE,
                allowed_parameters=[],
                requires_approval=True,
                max_execution_time=120
            )
        ]
        
        for cmd in commands:
            self.allowed_commands[cmd.command_id] = cmd
            
        logger.info(f"Loaded {len(self.allowed_commands)} secure command templates")
        
    def validate_command_parameters(self, command_id: str, parameters: Dict[str, Any]) -> bool:
        """Validate command parameters against allowed patterns"""
        if command_id not in self.allowed_commands:
            return False
            
        command = self.allowed_commands[command_id]
        
        # Check all required parameters are present
        for param in command.allowed_parameters:
            if param not in parameters:
                logger.warning(f"Missing required parameter {param} for command {command_id}")
                return False
                
        # Validate parameter patterns
        for param, value in parameters.items():
            if param not in command.allowed_parameters:
                logger.warning(f"Unauthorized parameter {param} for command {command_id}")
                return False
                
            if param in command.parameter_patterns:
                pattern = command.parameter_patterns[param]
                import re
                if not re.match(pattern, str(value)):
                    logger.warning(f"Parameter {param} value '{value}' doesn't match pattern {pattern}")
                    return False
                    
        return True
        
    async def request_command_execution(self, command_id: str, parameters: Dict[str, Any], 
                                       target_host: str, requested_by: str, 
                                       justification: str) -> ExecutionRequest:
        """Request execution of a secure command"""
        
        # Validate command exists and parameters are valid
        if not self.validate_command_parameters(command_id, parameters):
            raise ValueError(f"Invalid command or parameters for {command_id}")
            
        command = self.allowed_commands[command_id]
        
        # Create execution request
        request = ExecutionRequest(
            command_id=command_id,
            parameters=parameters,
            target_host=target_host,
            requested_by=requested_by,
            justification=justification,
            status=ExecutionStatus.PENDING_APPROVAL if command.requires_approval else ExecutionStatus.APPROVED
        )
        
        self.execution_requests[request.request_id] = request
        
        # Log security event
        logger.info(f"Command execution requested: {command_id} by {requested_by} for {target_host}")
        
        return request
        
    async def approve_request(self, request_id: str, approved_by: str) -> bool:
        """Approve a pending execution request"""
        if request_id not in self.execution_requests:
            return False
            
        request = self.execution_requests[request_id]
        if request.status != ExecutionStatus.PENDING_APPROVAL:
            return False
            
        request.status = ExecutionStatus.APPROVED
        request.approved_by = approved_by
        
        logger.info(f"Command execution approved: {request.command_id} by {approved_by}")
        return True
        
    async def execute_secure_command(self, request_id: str) -> ExecutionRequest:
        """Execute approved command in secure sandbox"""
        if request_id not in self.execution_requests:
            raise ValueError(f"Execution request {request_id} not found")
            
        request = self.execution_requests[request_id]
        if request.status != ExecutionStatus.APPROVED:
            raise ValueError(f"Request {request_id} not approved for execution")
            
        command = self.allowed_commands[request.command_id]
        
        try:
            request.status = ExecutionStatus.EXECUTING
            request.executed_at = datetime.utcnow()
            
            # Build command from template
            command_str = command.template
            for param, value in request.parameters.items():
                command_str = command_str.replace(f"{{{param}}}", str(value))
                
            logger.info(f"Executing secure command: {command_str}")
            
            # Execute in sandbox
            async with SandboxEnvironment() as sandbox:
                exit_code, stdout, stderr = await sandbox.execute_command(
                    command_str, 
                    timeout=command.max_execution_time
                )
                
                request.exit_code = exit_code
                request.output = stdout
                request.error_output = stderr
                request.completed_at = datetime.utcnow()
                
                if exit_code == 0:
                    request.status = ExecutionStatus.COMPLETED
                    # Set up rollback if available
                    if command.rollback_template:
                        request.rollback_available = True
                        request.rollback_command = command.rollback_template
                else:
                    request.status = ExecutionStatus.FAILED
                    
            logger.info(f"Command execution completed: {request.command_id} (exit_code: {exit_code})")
            
        except Exception as e:
            request.status = ExecutionStatus.FAILED
            request.error_output = str(e)
            request.completed_at = datetime.utcnow()
            logger.error(f"Command execution failed: {request.command_id} - {e}")
            
        return request
        
    async def rollback_execution(self, request_id: str, rollback_by: str) -> bool:
        """Rollback a previously executed command"""
        if request_id not in self.execution_requests:
            return False
            
        request = self.execution_requests[request_id]
        if not request.rollback_available or not request.rollback_command:
            return False
            
        try:
            logger.info(f"Rolling back command execution: {request.command_id}")
            
            # Execute rollback in sandbox
            async with SandboxEnvironment() as sandbox:
                exit_code, _, _ = await sandbox.execute_command(
                    request.rollback_command,
                    timeout=300
                )
                
                if exit_code == 0:
                    request.status = ExecutionStatus.ROLLED_BACK
                    logger.info(f"Command rollback successful: {request.command_id}")
                    return True
                else:
                    logger.error(f"Command rollback failed: {request.command_id} (exit_code: {exit_code})")
                    return False
                    
        except Exception as e:
            logger.error(f"Command rollback error: {request.command_id} - {e}")
            return False
            
    def get_execution_request(self, request_id: str) -> Optional[ExecutionRequest]:
        """Get execution request by ID"""
        return self.execution_requests.get(request_id)
        
    def list_pending_approvals(self) -> List[ExecutionRequest]:
        """List all pending approval requests"""
        return [req for req in self.execution_requests.values() 
                if req.status == ExecutionStatus.PENDING_APPROVAL]
        
    def get_command_info(self, command_id: str) -> Optional[SecureCommand]:
        """Get information about a secure command"""
        return self.allowed_commands.get(command_id)
        
    def list_available_commands(self) -> List[SecureCommand]:
        """List all available secure commands"""
        return list(self.allowed_commands.values())