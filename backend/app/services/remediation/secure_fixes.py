"""
OpenWatch Secure Automated Fix Executor

This service provides secure execution of automated fixes with comprehensive
security controls, replacing the vulnerable direct command execution system.

Key Security Features:
- All commands executed in isolated containers
- Cryptographic signature verification for command authenticity
- Multi-factor approval workflow for privileged operations
- Complete audit trail with compliance logging
- Atomic rollback capabilities
- Resource limiting and timeout controls
"""

import json
import logging
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy import text

from ...database import get_async_db
from ..infrastructure import CommandSandboxService, CommandSecurityLevel, ExecutionRequest, ExecutionStatus
from ..validation import AutomatedFix

logger = logging.getLogger(__name__)


class SecureAutomatedFix:
    """Enhanced AutomatedFix with security controls"""

    def __init__(self, legacy_fix: AutomatedFix):
        self.fix_id = legacy_fix.fix_id
        self.description = legacy_fix.description
        self.requires_sudo = legacy_fix.requires_sudo
        self.estimated_time = legacy_fix.estimated_time
        self.command = legacy_fix.command
        self.is_safe = legacy_fix.is_safe
        self.rollback_command = legacy_fix.rollback_command

        # New security properties
        self.security_level = self._determine_security_level()
        self.requires_approval = self._requires_approval()
        self.secure_command_id = self._map_to_secure_command()
        self.parameters = self._extract_parameters()

    def _determine_security_level(self) -> CommandSecurityLevel:
        """Determine security level based on command characteristics"""
        if self.requires_sudo:
            return CommandSecurityLevel.PRIVILEGED
        elif any(
            dangerous in (self.command or "").lower() for dangerous in ["rm ", "delete", "modify", "install", "update"]
        ):
            return CommandSecurityLevel.MODERATE
        else:
            return CommandSecurityLevel.SAFE

    def _requires_approval(self) -> bool:
        """Determine if fix requires manual approval"""
        return (
            self.requires_sudo
            or self.security_level in [CommandSecurityLevel.PRIVILEGED, CommandSecurityLevel.CRITICAL]
            or not self.is_safe
        )

    def _map_to_secure_command(self) -> Optional[str]:
        """Map legacy fix to secure command template"""
        if not self.command:
            return None

        command_lower = self.command.lower()

        # Map common patterns to secure commands
        if "systemctl status" in command_lower:
            return "check_service_status"
        elif "netstat" in command_lower and "grep" in command_lower:
            return "check_network_port"
        elif "apt-get install" in command_lower and "openscap" in command_lower:
            return "install_openscap_ubuntu"
        elif "yum install" in command_lower and "openscap" in command_lower:
            return "install_openscap_rhel"
        elif "find /tmp" in command_lower and "delete" in command_lower:
            return "cleanup_temp_files"
        else:
            logger.warning(f"No secure mapping found for command: {self.command}")
            return None

    def _extract_parameters(self) -> Dict[str, Any]:
        """Extract parameters from legacy command"""
        parameters = {}

        if not self.command:
            return parameters

        # Extract common parameter patterns
        import re

        # Service name extraction
        service_match = re.search(r"systemctl\s+status\s+([a-zA-Z0-9\-_.]+)", self.command)
        if service_match:
            parameters["service_name"] = service_match.group(1)

        # Port extraction
        port_match = re.search(r"grep\s+(\d+)", self.command)
        if port_match:
            parameters["port"] = port_match.group(1)

        return parameters


class FixExecutionAudit:
    """Audit trail for fix executions"""

    def __init__(self):
        self.audit_entries = []

    async def log_fix_request(self, fix_id: str, requested_by: str, target_host: str, justification: str):
        """Log fix execution request"""
        entry = {
            "event_type": "fix_requested",
            "fix_id": fix_id,
            "requested_by": requested_by,
            "target_host": target_host,
            "justification": justification,
            "timestamp": datetime.utcnow(),
            "event_id": str(uuid.uuid4()),
        }

        await self._persist_audit_entry(entry)

    async def log_fix_approval(self, request_id: str, approved_by: str, approval_reason: str):
        """Log fix approval decision"""
        entry = {
            "event_type": "fix_approved",
            "request_id": request_id,
            "approved_by": approved_by,
            "approval_reason": approval_reason,
            "timestamp": datetime.utcnow(),
            "event_id": str(uuid.uuid4()),
        }

        await self._persist_audit_entry(entry)

    async def log_fix_execution(self, request_id: str, execution_result: ExecutionRequest):
        """Log fix execution results"""
        entry = {
            "event_type": "fix_executed",
            "request_id": request_id,
            "command_id": execution_result.command_id,
            "exit_code": execution_result.exit_code,
            "execution_duration": (
                (execution_result.completed_at - execution_result.executed_at).total_seconds()
                if execution_result.completed_at and execution_result.executed_at
                else None
            ),
            "success": execution_result.status == ExecutionStatus.COMPLETED,
            "output_length": len(execution_result.output or ""),
            "error_output_length": len(execution_result.error_output or ""),
            "timestamp": datetime.utcnow(),
            "event_id": str(uuid.uuid4()),
        }

        await self._persist_audit_entry(entry)

    async def log_fix_rollback(self, request_id: str, rollback_by: str, rollback_success: bool):
        """Log fix rollback operation"""
        entry = {
            "event_type": "fix_rolled_back",
            "request_id": request_id,
            "rollback_by": rollback_by,
            "success": rollback_success,
            "timestamp": datetime.utcnow(),
            "event_id": str(uuid.uuid4()),
        }

        await self._persist_audit_entry(entry)

    async def _persist_audit_entry(self, entry: Dict[str, Any]):
        """Persist audit entry to database"""
        try:
            async with get_async_db() as session:
                # Use the existing audit_logs table structure
                audit_sql = text(
                    """
                    INSERT INTO audit_logs (
                        event_type, user_id, resource_type, resource_id,
                        action, old_values, new_values, ip_address,
                        user_agent, timestamp
                    ) VALUES (
                        :event_type, :user_id, :resource_type, :resource_id,
                        :action, :old_values, :new_values, :ip_address,
                        :user_agent, :timestamp
                    )
                """
                )

                await session.execute(
                    audit_sql,
                    {
                        "event_type": entry["event_type"],
                        "user_id": entry.get("requested_by") or entry.get("approved_by") or entry.get("rollback_by"),
                        "resource_type": "automated_fix",
                        "resource_id": entry.get("request_id") or entry.get("fix_id"),
                        "action": entry["event_type"],
                        "old_values": None,
                        "new_values": json.dumps(
                            {k: v for k, v in entry.items() if k not in ["event_type", "timestamp"]}
                        ),
                        "ip_address": "system",
                        "user_agent": "openwatch-secure-fix-executor",
                        "timestamp": entry["timestamp"],
                    },
                )

                await session.commit()

        except Exception as e:
            logger.error(f"Failed to persist audit entry: {e}")


class SecureAutomatedFixExecutor:
    """Main service for secure automated fix execution"""

    def __init__(self):
        self.sandbox_service = CommandSandboxService()
        self.audit_service = FixExecutionAudit()
        self.pending_approvals = {}

    async def evaluate_fix_options(self, legacy_fixes: List[AutomatedFix], target_host: str) -> List[Dict[str, Any]]:
        """Evaluate legacy fixes and convert to secure options"""
        secure_options = []

        for legacy_fix in legacy_fixes:
            secure_fix = SecureAutomatedFix(legacy_fix)

            # Only include fixes that can be mapped to secure commands
            if secure_fix.secure_command_id:
                secure_command = self.sandbox_service.get_command_info(secure_fix.secure_command_id)

                if secure_command:
                    option = {
                        "fix_id": secure_fix.fix_id,
                        "description": secure_fix.description,
                        "security_level": secure_fix.security_level.value,
                        "requires_approval": secure_fix.requires_approval,
                        "estimated_time": secure_fix.estimated_time,
                        "secure_command_id": secure_fix.secure_command_id,
                        "parameters": secure_fix.parameters,
                        "rollback_available": bool(secure_command.rollback_template),
                        "is_safe": secure_fix.security_level == CommandSecurityLevel.SAFE,
                    }
                    secure_options.append(option)
                else:
                    logger.warning(f"Secure command not found: {secure_fix.secure_command_id}")
            else:
                # Create a warning for unmappable fixes
                logger.warning(f"Legacy fix cannot be securely executed: {legacy_fix.fix_id}")
                secure_options.append(
                    {
                        "fix_id": legacy_fix.fix_id,
                        "description": f"[SECURITY BLOCKED] {legacy_fix.description}",
                        "security_level": "blocked",
                        "requires_approval": True,
                        "estimated_time": 0,
                        "secure_command_id": None,
                        "parameters": {},
                        "rollback_available": False,
                        "is_safe": False,
                        "blocked_reason": "Command cannot be safely executed in current security model",
                    }
                )

        return secure_options

    async def request_fix_execution(
        self,
        fix_id: str,
        secure_command_id: str,
        parameters: Dict[str, Any],
        target_host: str,
        requested_by: str,
        justification: str,
    ) -> Dict[str, Any]:
        """Request execution of a secure automated fix"""

        try:
            # Validate the secure command exists
            if not self.sandbox_service.get_command_info(secure_command_id):
                raise ValueError(f"Secure command not found: {secure_command_id}")

            # Request execution through sandbox service
            request = await self.sandbox_service.request_command_execution(
                command_id=secure_command_id,
                parameters=parameters,
                target_host=target_host,
                requested_by=requested_by,
                justification=justification,
            )

            # Log audit trail
            await self.audit_service.log_fix_request(
                fix_id=fix_id,
                requested_by=requested_by,
                target_host=target_host,
                justification=justification,
            )

            # Store pending approval if needed
            if request.status == ExecutionStatus.PENDING_APPROVAL:
                self.pending_approvals[request.request_id] = {
                    "fix_id": fix_id,
                    "request": request,
                    "requested_at": datetime.utcnow(),
                }

            return {
                "request_id": request.request_id,
                "status": request.status.value,
                "requires_approval": request.status == ExecutionStatus.PENDING_APPROVAL,
                "message": "Fix execution requested successfully",
            }

        except Exception as e:
            logger.error(f"Failed to request fix execution for {fix_id}: {e}")
            return {
                "request_id": None,
                "status": "failed",
                "requires_approval": False,
                "message": f"Failed to request fix execution: {str(e)}",
            }

    async def approve_fix_request(self, request_id: str, approved_by: str, approval_reason: str) -> Dict[str, Any]:
        """Approve a pending fix execution request"""

        try:
            # Approve through sandbox service
            success = await self.sandbox_service.approve_request(request_id, approved_by)

            if success:
                # Log approval
                await self.audit_service.log_fix_approval(
                    request_id=request_id,
                    approved_by=approved_by,
                    approval_reason=approval_reason,
                )

                # Remove from pending approvals
                if request_id in self.pending_approvals:
                    del self.pending_approvals[request_id]

                return {
                    "success": True,
                    "message": "Fix execution approved successfully",
                }
            else:
                return {
                    "success": False,
                    "message": "Failed to approve fix execution - request not found or already processed",
                }

        except Exception as e:
            logger.error(f"Failed to approve fix request {request_id}: {e}")
            return {
                "success": False,
                "message": f"Failed to approve fix execution: {str(e)}",
            }

    async def execute_approved_fix(self, request_id: str) -> Dict[str, Any]:
        """Execute an approved fix in secure sandbox"""

        try:
            # Execute through sandbox service
            result = await self.sandbox_service.execute_secure_command(request_id)

            # Log execution results
            await self.audit_service.log_fix_execution(request_id, result)

            # Prepare response
            response = {
                "request_id": request_id,
                "status": result.status.value,
                "success": result.status == ExecutionStatus.COMPLETED,
                "exit_code": result.exit_code,
                "output": result.output,
                "error_output": result.error_output,
                "execution_time": (
                    (result.completed_at - result.executed_at).total_seconds()
                    if result.completed_at and result.executed_at
                    else None
                ),
                "rollback_available": result.rollback_available,
            }

            if result.status == ExecutionStatus.COMPLETED:
                response["message"] = "Fix executed successfully"
            else:
                response["message"] = f"Fix execution failed: {result.error_output}"

            return response

        except Exception as e:
            logger.error(f"Failed to execute fix {request_id}: {e}")
            return {
                "request_id": request_id,
                "status": "failed",
                "success": False,
                "message": f"Failed to execute fix: {str(e)}",
            }

    async def rollback_fix(self, request_id: str, rollback_by: str) -> Dict[str, Any]:
        """Rollback a previously executed fix"""

        try:
            success = await self.sandbox_service.rollback_execution(request_id, rollback_by)

            # Log rollback attempt
            await self.audit_service.log_fix_rollback(request_id, rollback_by, success)

            return {
                "success": success,
                "message": ("Fix rolled back successfully" if success else "Fix rollback failed"),
            }

        except Exception as e:
            logger.error(f"Failed to rollback fix {request_id}: {e}")
            return {"success": False, "message": f"Failed to rollback fix: {str(e)}"}

    async def get_fix_status(self, request_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a fix execution request"""

        request = self.sandbox_service.get_execution_request(request_id)
        if not request:
            return None

        return {
            "request_id": request.request_id,
            "command_id": request.command_id,
            "status": request.status.value,
            "target_host": request.target_host,
            "requested_by": request.requested_by,
            "approved_by": request.approved_by,
            "executed_at": (request.executed_at.isoformat() if request.executed_at else None),
            "completed_at": (request.completed_at.isoformat() if request.completed_at else None),
            "exit_code": request.exit_code,
            "rollback_available": request.rollback_available,
        }

    async def list_pending_approvals(self) -> List[Dict[str, Any]]:
        """List all fixes pending approval"""

        pending = self.sandbox_service.list_pending_approvals()

        return [
            {
                "request_id": req.request_id,
                "command_id": req.command_id,
                "target_host": req.target_host,
                "requested_by": req.requested_by,
                "justification": req.justification,
                "requested_at": self.pending_approvals.get(req.request_id, {}).get("requested_at"),
            }
            for req in pending
        ]

    async def get_secure_command_catalog(self) -> List[Dict[str, Any]]:
        """Get catalog of available secure commands"""

        commands = self.sandbox_service.list_available_commands()

        return [
            {
                "command_id": cmd.command_id,
                "description": cmd.description,
                "security_level": cmd.security_level.value,
                "requires_approval": cmd.requires_approval,
                "allowed_parameters": cmd.allowed_parameters,
                "max_execution_time": cmd.max_execution_time,
                "rollback_available": bool(cmd.rollback_template),
            }
            for cmd in commands
        ]

    async def cleanup_old_requests(self, max_age_days: int = 30):
        """Clean up old execution requests"""
        cutoff_date = datetime.utcnow() - timedelta(days=max_age_days)

        # Clean up pending approvals that are too old
        expired_requests = [
            req_id for req_id, data in self.pending_approvals.items() if data["requested_at"] < cutoff_date
        ]

        for req_id in expired_requests:
            del self.pending_approvals[req_id]
            logger.info(f"Cleaned up expired approval request: {req_id}")

        logger.info(f"Cleaned up {len(expired_requests)} expired approval requests")
