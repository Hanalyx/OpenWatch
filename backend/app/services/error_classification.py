"""
OpenWatch Error Classification and Handling Service
Provides comprehensive error taxonomy and user-friendly guidance
Enhanced with security sanitization to prevent information disclosure
"""

import logging
import os
import socket
from datetime import datetime
from typing import Any, Dict, List, Optional

import paramiko
from pydantic import BaseModel, Field

from ..models.error_models import (
    ErrorCategory,
    ErrorSeverity,
    ScanErrorInternal,
    ScanErrorResponse,
    ValidationResultInternal,
    ValidationResultResponse,
)
from .error_sanitization import get_error_sanitization_service
from .security_audit_logger import get_security_audit_logger

logger = logging.getLogger(__name__)
sanitization_service = get_error_sanitization_service()
audit_logger = get_security_audit_logger()


# ErrorCategory and ErrorSeverity are now imported from models.error_models


class AutomatedFix(BaseModel):
    """Represents an automated fix option"""

    fix_id: str
    description: str
    requires_sudo: bool = False
    estimated_time: int = Field(default=30, description="Estimated time in seconds")
    command: Optional[str] = None
    is_safe: bool = True
    rollback_command: Optional[str] = None


# ScanError is now replaced by ScanErrorInternal (imported from models.error_models)
# This internal version contains technical details for server-side processing


# ValidationResult is now replaced by ValidationResultInternal (imported from models.error_models)
# This internal version contains sensitive system information for server-side processing


class NetworkValidator:
    """Network connectivity validation"""

    @staticmethod
    async def validate_connectivity(hostname: str, port: int = 22) -> List[ScanErrorInternal]:
        """Comprehensive network connectivity validation"""
        errors = []

        try:
            # Stage 1: DNS Resolution
            try:
                ip_address = socket.gethostbyname(hostname)
                logger.debug(f"DNS resolution successful: {hostname} -> {ip_address}")
            except socket.gaierror as e:
                errors.append(
                    ScanErrorInternal(
                        error_code="NET_001",
                        category=ErrorCategory.NETWORK,
                        severity=ErrorSeverity.ERROR,
                        message=f"DNS resolution failed for {hostname}",
                        technical_details={"hostname": hostname, "error": str(e)},
                        user_guidance="Verify the hostname is correct or use an IP address directly. Check your DNS server configuration.",
                        automated_fixes=[
                            AutomatedFix(
                                fix_id="use_ip_address",
                                description="Use IP address instead of hostname",
                                requires_sudo=False,
                                estimated_time=5,
                            )
                        ],
                        can_retry=True,
                        retry_after=30,
                        documentation_url="https://docs.openwatch.dev/troubleshooting/network#dns-resolution",
                    )
                )
                return errors

            # Stage 2: TCP Connection Test
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            try:
                result = sock.connect_ex((ip_address, port))
                if result != 0:
                    errors.append(
                        ScanErrorInternal(
                            error_code="NET_002",
                            category=ErrorCategory.NETWORK,
                            severity=ErrorSeverity.ERROR,
                            message=f"Cannot connect to {hostname}:{port}",
                            technical_details={
                                "hostname": hostname,
                                "port": port,
                                "ip_address": ip_address,
                                "connection_result": result,
                            },
                            user_guidance=f"Check if SSH service is running on port {port} and firewall rules allow connections.",
                            automated_fixes=[
                                AutomatedFix(
                                    fix_id="check_firewall",
                                    description="Check firewall rules for SSH port",
                                    command=f"netstat -tlnp | grep {port}",
                                    requires_sudo=False,
                                    estimated_time=10,
                                    is_safe=True,  # Read-only command is safe
                                )
                            ],
                            can_retry=True,
                            retry_after=60,
                            documentation_url="https://docs.openwatch.dev/troubleshooting/network#connection-refused",
                        )
                    )
                    return errors
            except socket.timeout:
                errors.append(
                    ScanErrorInternal(
                        error_code="NET_003",
                        category=ErrorCategory.NETWORK,
                        severity=ErrorSeverity.ERROR,
                        message=f"Connection timeout to {hostname}:{port}",
                        technical_details={
                            "hostname": hostname,
                            "port": port,
                            "timeout": 10,
                        },
                        user_guidance="Host may be unreachable or behind a firewall. Check network connectivity and firewall rules.",
                        can_retry=True,
                        retry_after=120,
                        documentation_url="https://docs.openwatch.dev/troubleshooting/network#timeout",
                    )
                )
                return errors
            finally:
                sock.close()

            # Stage 3: SSH Banner Check
            try:
                transport = paramiko.Transport((hostname, port))
                transport.start_client(timeout=5)
                banner = transport.get_banner()
                transport.close()

                if banner and b"ssh" not in banner.lower():
                    errors.append(
                        ScanErrorInternal(
                            error_code="NET_004",
                            category=ErrorCategory.NETWORK,
                            severity=ErrorSeverity.WARNING,
                            message=f"Unexpected service on port {port}",
                            technical_details={"banner": banner.decode("utf-8", errors="ignore")},
                            user_guidance=f"Port {port} is not running SSH service. Verify SSH daemon is running on the correct port.",
                            documentation_url="https://docs.openwatch.dev/troubleshooting/network#wrong-service",
                        )
                    )

            except Exception as e:
                errors.append(
                    ScanErrorInternal(
                        error_code="NET_005",
                        category=ErrorCategory.NETWORK,
                        severity=ErrorSeverity.WARNING,
                        message="SSH service not responding properly",
                        technical_details={"error": str(e)},
                        user_guidance="SSH daemon may not be running or configured properly. Check SSH service status.",
                        automated_fixes=[
                            AutomatedFix(
                                fix_id="check_ssh_service",
                                description="Check SSH service status",
                                command="systemctl status sshd",
                                requires_sudo=False,
                                estimated_time=5,
                                is_safe=True,  # Read-only command is safe
                            )
                        ],
                        documentation_url="https://docs.openwatch.dev/troubleshooting/network#ssh-daemon",
                    )
                )

        except Exception as e:
            errors.append(
                ScanErrorInternal(
                    error_code="NET_999",
                    category=ErrorCategory.NETWORK,
                    severity=ErrorSeverity.ERROR,
                    message="Unexpected network validation error",
                    technical_details={"error": str(e)},
                    user_guidance="An unexpected error occurred during network validation. Please check logs and try again.",
                    can_retry=True,
                )
            )

        return errors


class AuthenticationValidator:
    """SSH authentication validation"""

    @staticmethod
    async def validate_credentials(
        hostname: str, port: int, username: str, auth_method: str, credential: str
    ) -> List[ScanErrorInternal]:
        """Validate SSH authentication credentials"""
        errors = []

        try:
            ssh = paramiko.SSHClient()
            # Security Fix: Use strict host key checking instead of AutoAddPolicy
            ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
            # Load system and user host keys for validation
            try:
                ssh.load_system_host_keys()
                ssh.load_host_keys(os.path.expanduser("~/.ssh/known_hosts"))
            except FileNotFoundError:
                logger.warning(
                    "No known_hosts files found - SSH connections may fail without proper host key management"
                )

            if auth_method == "password":
                try:
                    ssh.connect(
                        hostname,
                        port=port,
                        username=username,
                        password=credential,
                        timeout=10,
                    )
                    ssh.close()
                    return errors  # Success
                except paramiko.AuthenticationException as e:
                    error_msg = str(e).lower()
                    if "too many authentication failures" in error_msg:
                        errors.append(
                            ScanErrorInternal(
                                error_code="AUTH_001",
                                category=ErrorCategory.AUTHENTICATION,
                                severity=ErrorSeverity.ERROR,
                                message="Account temporarily locked due to failed login attempts",
                                technical_details={
                                    "username": username,
                                    "hostname": hostname,
                                },
                                user_guidance="Wait for account lockout to expire or contact system administrator to unlock the account.",
                                can_retry=True,
                                retry_after=900,  # 15 minutes
                                documentation_url="https://docs.openwatch.dev/troubleshooting/auth#account-locked",
                            )
                        )
                    else:
                        errors.append(
                            ScanErrorInternal(
                                error_code="AUTH_002",
                                category=ErrorCategory.AUTHENTICATION,
                                severity=ErrorSeverity.ERROR,
                                message="Invalid username or password",
                                technical_details={
                                    "username": username,
                                    "auth_method": auth_method,
                                },
                                user_guidance="Verify the username and password are correct. Check if account is disabled or expired.",
                                automated_fixes=[
                                    AutomatedFix(
                                        fix_id="test_password_reset",
                                        description="Test password reset if available",
                                        requires_sudo=False,
                                        estimated_time=60,
                                    )
                                ],
                                documentation_url="https://docs.openwatch.dev/troubleshooting/auth#invalid-credentials",
                            )
                        )

            elif auth_method in ["ssh_key", "ssh-key"]:
                try:
                    # parse_ssh_key converts PEM content to Paramiko key object
                    from .ssh import parse_ssh_key, validate_ssh_key

                    # First validate the key format
                    validation_result = validate_ssh_key(credential)
                    if not validation_result.is_valid:
                        errors.append(
                            ScanErrorInternal(
                                error_code="AUTH_003",
                                category=ErrorCategory.AUTHENTICATION,
                                severity=ErrorSeverity.ERROR,
                                message=f"Invalid SSH key format: {validation_result.error_message}",
                                technical_details={"validation_error": validation_result.error_message},
                                user_guidance="Ensure SSH private key is in correct format (RSA, DSA, ECDSA, or Ed25519). Check key file integrity.",
                                automated_fixes=[
                                    AutomatedFix(
                                        fix_id="regenerate_key",
                                        description="[SECURITY] Use secure automated fix system to generate SSH key",
                                        command=None,  # No direct command - use secure system
                                        requires_sudo=False,
                                        estimated_time=30,
                                        is_safe=False,  # Mark as unsafe for direct execution
                                    )
                                ],
                                documentation_url="https://docs.openwatch.dev/troubleshooting/auth#invalid-key-format",
                            )
                        )
                        return errors

                    # Parse and test the key
                    key = parse_ssh_key(credential)
                    ssh.connect(hostname, port=port, username=username, pkey=key, timeout=10)
                    ssh.close()
                    return errors  # Success

                except paramiko.AuthenticationException:
                    errors.append(
                        ScanErrorInternal(
                            error_code="AUTH_004",
                            category=ErrorCategory.AUTHENTICATION,
                            severity=ErrorSeverity.ERROR,
                            message="SSH key authentication failed",
                            technical_details={
                                "username": username,
                                "auth_method": auth_method,
                            },
                            user_guidance="SSH public key not authorized for this user. Add public key to ~/.ssh/authorized_keys on target host.",
                            automated_fixes=[
                                AutomatedFix(
                                    fix_id="copy_public_key",
                                    description="[SECURITY] Use secure automated fix system to copy SSH key",
                                    command=None,  # No direct command - use secure system
                                    requires_sudo=False,
                                    estimated_time=15,
                                    is_safe=False,  # Mark as unsafe for direct execution
                                )
                            ],
                            documentation_url="https://docs.openwatch.dev/troubleshooting/auth#key-not-authorized",
                        )
                    )

        except Exception as e:
            errors.append(
                ScanErrorInternal(
                    error_code="AUTH_999",
                    category=ErrorCategory.AUTHENTICATION,
                    severity=ErrorSeverity.ERROR,
                    message="Unexpected authentication error",
                    technical_details={"error": str(e)},
                    user_guidance="An unexpected error occurred during authentication validation. Check network connectivity and try again.",
                    can_retry=True,
                )
            )

        return errors


class PrivilegeValidator:
    """System privilege validation"""

    @staticmethod
    async def validate_privileges(
        ssh_client: paramiko.SSHClient,
    ) -> List[ScanErrorInternal]:
        """Check if user has required privileges for scanning"""
        errors = []

        try:
            # Check sudo access for oscap
            _, stdout, stderr = ssh_client.exec_command("sudo -n oscap --version", timeout=10)
            exit_status = stdout.channel.recv_exit_status()
            stderr_output = stderr.read().decode()

            if exit_status != 0:
                if "password is required" in stderr_output.lower():
                    errors.append(
                        ScanErrorInternal(
                            error_code="PRIV_001",
                            category=ErrorCategory.PRIVILEGE,
                            severity=ErrorSeverity.ERROR,
                            message="User lacks passwordless sudo access for OpenSCAP",
                            technical_details={
                                "command": "sudo -n oscap --version",
                                "stderr": stderr_output,
                            },
                            user_guidance="Configure passwordless sudo for oscap command",
                            automated_fixes=[
                                AutomatedFix(
                                    fix_id="add_sudoers_oscap",
                                    description="[SECURITY] Use secure automated fix system to configure sudo access",
                                    command=None,  # No direct command - use secure system
                                    requires_sudo=True,
                                    estimated_time=30,
                                    is_safe=False,  # Mark as unsafe for direct execution
                                )
                            ],
                            documentation_url="https://docs.openwatch.dev/troubleshooting/privileges#sudo-access",
                        )
                    )

            # Check SELinux enforcement (if applicable)
            stdin, stdout, stderr = ssh_client.exec_command("getenforce 2>/dev/null", timeout=5)
            selinux_status = stdout.read().decode().strip().lower()

            if selinux_status == "enforcing":
                # Check OpenSCAP SELinux policies
                stdin, stdout, stderr = ssh_client.exec_command("getsebool openscap_can_network 2>/dev/null", timeout=5)
                bool_output = stdout.read().decode().strip()

                if "off" in bool_output:
                    errors.append(
                        ScanErrorInternal(
                            error_code="PRIV_002",
                            category=ErrorCategory.PRIVILEGE,
                            severity=ErrorSeverity.WARNING,
                            message="SELinux blocking OpenSCAP network operations",
                            technical_details={
                                "selinux_status": "enforcing",
                                "openscap_can_network": "off",
                            },
                            user_guidance="Enable SELinux boolean to allow OpenSCAP network operations",
                            automated_fixes=[
                                AutomatedFix(
                                    fix_id="enable_selinux_openscap",
                                    description="[SECURITY] Use secure automated fix system to configure SELinux",
                                    command=None,  # No direct command - use secure system
                                    requires_sudo=True,
                                    estimated_time=15,
                                    is_safe=False,  # Mark as unsafe for direct execution
                                )
                            ],
                            documentation_url="https://docs.openwatch.dev/troubleshooting/privileges#selinux",
                        )
                    )

        except Exception as e:
            logger.warning(f"Privilege validation error (non-critical): {e}")
            # Don't add critical errors for privilege checks - they're warnings

        return errors


class ResourceValidator:
    """System resource validation"""

    MIN_DISK_SPACE_MB = 500
    MIN_MEMORY_MB = 512

    @classmethod
    async def validate_resources(cls, ssh_client: paramiko.SSHClient) -> List[ScanErrorInternal]:
        """Check system resource availability"""
        errors = []

        try:
            # Check disk space in /tmp
            _, stdout, _ = ssh_client.exec_command("df -BM /tmp | tail -1 | awk '{print $4}'", timeout=10)
            available_output = stdout.read().decode().strip()

            if available_output:
                try:
                    available_mb = int(available_output.rstrip("M"))
                    if available_mb < cls.MIN_DISK_SPACE_MB:
                        errors.append(
                            ScanErrorInternal(
                                error_code="RES_001",
                                category=ErrorCategory.RESOURCE,
                                severity=ErrorSeverity.ERROR,
                                message=f"Insufficient disk space: {available_mb}MB available in /tmp",
                                technical_details={
                                    "available_space_mb": available_mb,
                                    "required_space_mb": cls.MIN_DISK_SPACE_MB,
                                },
                                user_guidance=f"Free up disk space in /tmp directory. Need at least {cls.MIN_DISK_SPACE_MB}MB for scan results.",
                                automated_fixes=[
                                    AutomatedFix(
                                        fix_id="cleanup_tmp",
                                        description="[SECURITY] Use secure automated fix system to clean up files",
                                        command=None,  # No direct command - use secure system
                                        requires_sudo=True,
                                        estimated_time=60,
                                        is_safe=False,  # Mark as unsafe for direct execution
                                    )
                                ],
                                can_retry=True,
                                retry_after=300,
                                documentation_url="https://docs.openwatch.dev/troubleshooting/resources#disk-space",
                            )
                        )
                except ValueError:
                    logger.warning(f"Could not parse disk space output: {available_output}")

            # Check memory availability
            stdin, stdout, stderr = ssh_client.exec_command("free -m | grep '^Mem:' | awk '{print $7}'", timeout=10)
            available_memory = stdout.read().decode().strip()

            if available_memory:
                try:
                    available_mem_mb = int(available_memory)
                    if available_mem_mb < cls.MIN_MEMORY_MB:
                        errors.append(
                            ScanErrorInternal(
                                error_code="RES_002",
                                category=ErrorCategory.RESOURCE,
                                severity=ErrorSeverity.WARNING,
                                message=f"Low available memory: {available_mem_mb}MB",
                                technical_details={
                                    "available_memory_mb": available_mem_mb,
                                    "recommended_memory_mb": cls.MIN_MEMORY_MB,
                                },
                                user_guidance="Available memory is low. Scan may run slower or fail. Consider stopping other processes.",
                                documentation_url="https://docs.openwatch.dev/troubleshooting/resources#memory",
                            )
                        )
                except ValueError:
                    logger.warning(f"Could not parse memory output: {available_memory}")

        except Exception as e:
            logger.warning(f"Resource validation error (non-critical): {e}")

        return errors


class DependencyValidator:
    """System dependency validation"""

    MIN_OPENSCAP_VERSION = "1.3.0"

    @classmethod
    async def validate_dependencies(cls, ssh_client: paramiko.SSHClient) -> List[ScanErrorInternal]:
        """Validate OpenSCAP installation and dependencies"""
        errors = []

        try:
            # Check if OpenSCAP is installed
            _, stdout, _ = ssh_client.exec_command("which oscap", timeout=10)
            oscap_path = stdout.read().decode().strip()

            if not oscap_path:
                errors.append(
                    ScanErrorInternal(
                        error_code="DEP_001",
                        category=ErrorCategory.DEPENDENCY,
                        severity=ErrorSeverity.ERROR,
                        message="OpenSCAP not installed on target system",
                        technical_details={"missing_command": "oscap"},
                        user_guidance="Install OpenSCAP scanner package on the target system",
                        automated_fixes=[
                            AutomatedFix(
                                fix_id="install_openscap_rhel",
                                description="[SECURITY] Use secure automated fix system to install OpenSCAP on RHEL/CentOS",
                                command=None,  # No direct command - use secure system
                                requires_sudo=True,
                                estimated_time=120,
                                is_safe=False,  # Mark as unsafe for direct execution
                            ),
                            AutomatedFix(
                                fix_id="install_openscap_ubuntu",
                                description="[SECURITY] Use secure automated fix system to install OpenSCAP on Ubuntu/Debian",
                                command=None,  # No direct command - use secure system
                                requires_sudo=True,
                                estimated_time=120,
                                is_safe=False,  # Mark as unsafe for direct execution
                            ),
                        ],
                        documentation_url="https://docs.openwatch.dev/troubleshooting/dependencies#openscap-installation",
                    )
                )
                return errors

            # Check OpenSCAP version
            stdin, stdout, stderr = ssh_client.exec_command("oscap --version", timeout=10)
            version_output = stdout.read().decode()

            version = cls._parse_openscap_version(version_output)
            if version and cls._version_compare(version, cls.MIN_OPENSCAP_VERSION) < 0:
                errors.append(
                    ScanErrorInternal(
                        error_code="DEP_002",
                        category=ErrorCategory.DEPENDENCY,
                        severity=ErrorSeverity.WARNING,
                        message=f"OpenSCAP version {version} installed, recommended >= {cls.MIN_OPENSCAP_VERSION}",
                        technical_details={
                            "current_version": version,
                            "minimum_version": cls.MIN_OPENSCAP_VERSION,
                        },
                        user_guidance="Update OpenSCAP to latest version for best compatibility",
                        automated_fixes=[
                            AutomatedFix(
                                fix_id="update_openscap",
                                description="[SECURITY] Use secure automated fix system to update OpenSCAP",
                                command=None,  # No direct command - use secure system
                                requires_sudo=True,
                                estimated_time=60,
                                is_safe=False,  # Mark as unsafe for direct execution
                            )
                        ],
                        documentation_url="https://docs.openwatch.dev/troubleshooting/dependencies#version-upgrade",
                    )
                )

        except Exception as e:
            errors.append(
                ScanErrorInternal(
                    error_code="DEP_999",
                    category=ErrorCategory.DEPENDENCY,
                    severity=ErrorSeverity.ERROR,
                    message="Failed to validate system dependencies",
                    technical_details={"error": str(e)},
                    user_guidance="Could not check system dependencies. Ensure SSH access is working properly.",
                    can_retry=True,
                )
            )

        return errors

    @staticmethod
    def _parse_openscap_version(version_output: str) -> Optional[str]:
        """Extract version number from oscap --version output"""
        import re

        match = re.search(r"(\d+\.\d+\.\d+)", version_output)
        return match.group(1) if match else None

    @staticmethod
    def _version_compare(version1: str, version2: str) -> int:
        """Compare two version strings. Returns -1, 0, or 1"""

        def version_tuple(v):
            return tuple(map(int, v.split(".")))

        v1_tuple = version_tuple(version1)
        v2_tuple = version_tuple(version2)

        return (v1_tuple > v2_tuple) - (v1_tuple < v2_tuple)


# Stub classes needed for credential validation
class SecurityContext(BaseModel):
    """Security context for error classification"""

    hostname: str = ""
    username: str = ""
    auth_method: str = ""
    source_ip: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


def classify_authentication_error(context: SecurityContext) -> ScanErrorInternal:
    """Classify authentication errors based on context"""
    return ScanErrorInternal(
        error_code="AUTH_GENERIC",
        category=ErrorCategory.AUTHENTICATION,
        severity=ErrorSeverity.ERROR,
        message="Authentication error occurred",
        technical_details={"context": context.dict()},
        user_guidance="Please check your authentication credentials and try again.",
    )


class ErrorClassificationService:
    """Main error classification service."""

    def __init__(self) -> None:
        """Initialize the error classification service with validators."""
        self.network_validator = NetworkValidator()
        self.auth_validator = AuthenticationValidator()
        self.privilege_validator = PrivilegeValidator()
        self.resource_validator = ResourceValidator()
        self.dependency_validator = DependencyValidator()

    async def classify_error(self, error: Exception, context: Dict[str, Any] = None) -> ScanErrorInternal:
        """Classify and enhance a generic error with actionable guidance"""
        context = context or {}
        error_str = str(error).lower()

        # Network errors
        if any(keyword in error_str for keyword in ["connection refused", "timeout", "unreachable"]):
            return ScanErrorInternal(
                error_code="NET_006",
                category=ErrorCategory.NETWORK,
                severity=ErrorSeverity.ERROR,
                message=f"Network connectivity issue: {str(error)}",
                technical_details={"original_error": str(error), "context": context},
                user_guidance="Check network connectivity and ensure target host is reachable",
                can_retry=True,
                retry_after=60,
            )

        # Authentication errors
        if any(
            keyword in error_str
            for keyword in [
                "permission denied",
                "authentication failed",
                "invalid credentials",
            ]
        ):
            return ScanErrorInternal(
                error_code="AUTH_005",
                category=ErrorCategory.AUTHENTICATION,
                severity=ErrorSeverity.ERROR,
                message=f"Authentication failed: {str(error)}",
                technical_details={"original_error": str(error), "context": context},
                user_guidance="Verify username and credentials are correct and have proper access",
            )

        # Resource errors
        if any(keyword in error_str for keyword in ["no space", "disk full", "out of memory"]):
            return ScanErrorInternal(
                error_code="RES_003",
                category=ErrorCategory.RESOURCE,
                severity=ErrorSeverity.ERROR,
                message=f"Resource constraint: {str(error)}",
                technical_details={"original_error": str(error), "context": context},
                user_guidance="Free up system resources (disk space, memory) and try again",
                can_retry=True,
                retry_after=300,
            )

        # Default to execution error
        return ScanErrorInternal(
            error_code="EXEC_001",
            category=ErrorCategory.EXECUTION,
            severity=ErrorSeverity.ERROR,
            message=f"Scan execution failed: {str(error)}",
            technical_details={"original_error": str(error), "context": context},
            user_guidance="An unexpected error occurred during scan execution. Check logs for more details.",
            can_retry=True,
        )

    async def validate_scan_prerequisites(
        self,
        hostname: str,
        port: int,
        username: str,
        auth_method: str,
        credential: str,
        user_id: Optional[str] = None,
        source_ip: Optional[str] = None,
    ) -> ValidationResultInternal:
        """Comprehensive pre-flight validation"""
        start_time = datetime.utcnow()
        errors = []
        warnings = []
        system_info = {}
        validation_checks = {}

        logger.info(f"Starting pre-flight validation for ***REDACTED***@{hostname}:{port}")

        # Stage 1: Network Connectivity
        try:
            network_errors = await self.network_validator.validate_connectivity(hostname, port)
            validation_checks["network_connectivity"] = len(network_errors) == 0
            errors.extend([e for e in network_errors if e.severity in [ErrorSeverity.ERROR, ErrorSeverity.CRITICAL]])
            warnings.extend([e for e in network_errors if e.severity == ErrorSeverity.WARNING])

            if errors:  # Can't proceed if network fails
                duration = (datetime.utcnow() - start_time).total_seconds()
                return ValidationResultInternal(
                    can_proceed=False,
                    errors=errors,
                    warnings=warnings,
                    pre_flight_duration=duration,
                    validation_checks=validation_checks,
                )
        except Exception as e:
            logger.error(f"Network validation failed: {e}")
            validation_checks["network_connectivity"] = False
            errors.append(await self.classify_error(e, {"stage": "network_validation"}))

        # Stage 2: Authentication
        try:
            auth_errors = await self.auth_validator.validate_credentials(
                hostname, port, username, auth_method, credential
            )
            validation_checks["authentication"] = len(auth_errors) == 0
            errors.extend([e for e in auth_errors if e.severity in [ErrorSeverity.ERROR, ErrorSeverity.CRITICAL]])
            warnings.extend([e for e in auth_errors if e.severity == ErrorSeverity.WARNING])

            if errors:  # Can't proceed if auth fails
                duration = (datetime.utcnow() - start_time).total_seconds()
                return ValidationResultInternal(
                    can_proceed=False,
                    errors=errors,
                    warnings=warnings,
                    pre_flight_duration=duration,
                    validation_checks=validation_checks,
                )

        except Exception as e:
            logger.error(f"Authentication validation failed: {e}")
            validation_checks["authentication"] = False
            errors.append(await self.classify_error(e, {"stage": "authentication_validation"}))

        # Stage 3: Advanced validations (if we can connect)
        ssh_client = None
        try:
            ssh_client = paramiko.SSHClient()
            # Security Fix: Use strict host key checking instead of AutoAddPolicy
            ssh_client.set_missing_host_key_policy(paramiko.RejectPolicy())
            # Load system and user host keys for validation
            try:
                ssh_client.load_system_host_keys()
                ssh_client.load_host_keys(os.path.expanduser("~/.ssh/known_hosts"))
            except FileNotFoundError:
                logger.warning(
                    "No known_hosts files found - SSH connections may fail without proper host key management"
                )

            if auth_method == "password":
                ssh_client.connect(
                    hostname,
                    port=port,
                    username=username,
                    password=credential,
                    timeout=10,
                )
            else:
                # parse_ssh_key converts PEM content to Paramiko key object
                from .ssh import parse_ssh_key

                key = parse_ssh_key(credential)
                ssh_client.connect(hostname, port=port, username=username, pkey=key, timeout=10)

            # Get system information (will be sanitized later)
            stdin, stdout, stderr = ssh_client.exec_command(
                'uname -a && cat /etc/os-release 2>/dev/null || echo "OS info not available"',
                timeout=10,
            )
            system_info_output = stdout.read().decode()

            # Store raw system info for sanitization
            system_info["system_details"] = system_info_output.strip()
            system_info["collection_timestamp"] = datetime.utcnow().isoformat()

            # Add additional system information safely
            # Check OpenSCAP availability for compliance
            stdin, stdout, stderr = ssh_client.exec_command("which oscap", timeout=5)
            oscap_path = stdout.read().decode().strip()
            system_info["openscap_available"] = bool(oscap_path)

            # Check SSH availability (we're already connected, so it's available)
            system_info["ssh_available"] = True

            # Check basic resource info (will be sanitized)
            stdin, stdout, stderr = ssh_client.exec_command("df /tmp | tail -1 | awk '{print $4}'", timeout=5)
            disk_output = stdout.read().decode().strip()
            if disk_output and disk_output.rstrip("M").isdigit():
                system_info["disk_space"] = int(disk_output.rstrip("M"))

            stdin, stdout, stderr = ssh_client.exec_command("free -m | grep \"^Mem:\" | awk '{print $7}'", timeout=5)
            memory_output = stdout.read().decode().strip()
            if memory_output and memory_output.isdigit():
                system_info["memory"] = int(memory_output)

            # Privilege validation
            privilege_errors = await self.privilege_validator.validate_privileges(ssh_client)
            validation_checks["privileges"] = (
                len([e for e in privilege_errors if e.severity == ErrorSeverity.ERROR]) == 0
            )
            errors.extend([e for e in privilege_errors if e.severity in [ErrorSeverity.ERROR, ErrorSeverity.CRITICAL]])
            warnings.extend([e for e in privilege_errors if e.severity == ErrorSeverity.WARNING])

            # Resource validation
            resource_errors = await self.resource_validator.validate_resources(ssh_client)
            validation_checks["resources"] = len([e for e in resource_errors if e.severity == ErrorSeverity.ERROR]) == 0
            errors.extend([e for e in resource_errors if e.severity in [ErrorSeverity.ERROR, ErrorSeverity.CRITICAL]])
            warnings.extend([e for e in resource_errors if e.severity == ErrorSeverity.WARNING])

            # Dependency validation
            dependency_errors = await self.dependency_validator.validate_dependencies(ssh_client)
            validation_checks["dependencies"] = (
                len([e for e in dependency_errors if e.severity == ErrorSeverity.ERROR]) == 0
            )
            errors.extend([e for e in dependency_errors if e.severity in [ErrorSeverity.ERROR, ErrorSeverity.CRITICAL]])
            warnings.extend([e for e in dependency_errors if e.severity == ErrorSeverity.WARNING])

        except Exception as e:
            logger.error(f"Advanced validation failed: {e}")
            # Don't fail completely - basic connectivity/auth worked
            warnings.append(await self.classify_error(e, {"stage": "advanced_validation"}))
        finally:
            if ssh_client:
                ssh_client.close()

        duration = (datetime.utcnow() - start_time).total_seconds()
        can_proceed = len(errors) == 0

        logger.info(
            f"Pre-flight validation completed in {duration:.2f}s: can_proceed={can_proceed}, errors={len(errors)}, warnings={len(warnings)}"
        )

        # Log the internal validation result for audit (contains sensitive data)
        if errors or warnings:
            for error in errors + warnings:
                audit_logger.log_error_classification_event(
                    error_code=error.error_code,
                    technical_details=error.technical_details,
                    sanitized_response={
                        "error_code": error.error_code,
                        "category": error.category.value,
                        "severity": error.severity.value,
                        "can_retry": error.can_retry,
                    },
                    user_id=user_id,
                    source_ip=source_ip,
                    severity=error.severity,
                )

        return ValidationResultInternal(
            can_proceed=can_proceed,
            errors=errors,
            warnings=warnings,
            pre_flight_duration=duration,
            system_info=system_info,
            validation_checks=validation_checks,
        )

    def get_sanitized_validation_result(
        self,
        internal_result: ValidationResultInternal,
        user_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        user_role: Optional[str] = None,
        is_admin: bool = False,
    ) -> ValidationResultResponse:
        """
        Convert internal validation result to sanitized user response.
        This integrates with Security Fix 5 system information sanitization.
        """

        # Sanitize errors using existing error sanitization
        sanitized_errors = []
        for error in internal_result.errors:
            sanitized_error = sanitization_service.sanitize_error(error.dict(), user_id=user_id, source_ip=source_ip)
            # Convert SanitizedError to ScanErrorResponse
            scan_error_response = ScanErrorResponse(
                error_code=sanitized_error.error_code,
                category=sanitized_error.category,
                severity=sanitized_error.severity,
                message=sanitized_error.message,
                user_guidance=sanitized_error.user_guidance,
                can_retry=sanitized_error.can_retry,
                retry_after=sanitized_error.retry_after,
                documentation_url=sanitized_error.documentation_url,
                timestamp=sanitized_error.timestamp,
            )
            sanitized_errors.append(scan_error_response)

        # Sanitize warnings using existing error sanitization
        sanitized_warnings = []
        for warning in internal_result.warnings:
            sanitized_warning = sanitization_service.sanitize_error(
                warning.dict(), user_id=user_id, source_ip=source_ip
            )
            # Convert SanitizedError to ScanErrorResponse
            scan_warning_response = ScanErrorResponse(
                error_code=sanitized_warning.error_code,
                category=sanitized_warning.category,
                severity=sanitized_warning.severity,
                message=sanitized_warning.message,
                user_guidance=sanitized_warning.user_guidance,
                can_retry=sanitized_warning.can_retry,
                retry_after=sanitized_warning.retry_after,
                documentation_url=sanitized_warning.documentation_url,
                timestamp=sanitized_warning.timestamp,
            )
            sanitized_warnings.append(scan_warning_response)

        # Sanitize system information using Security Fix 5 integration
        sanitized_system_info = {}
        if internal_result.system_info:
            sanitized_system_info = sanitization_service.sanitize_system_info_context(
                internal_result.system_info,
                user_role=user_role,
                is_admin=is_admin,
                user_id=user_id,
                source_ip=source_ip,
            )

        return ValidationResultResponse(
            can_proceed=internal_result.can_proceed,
            errors=sanitized_errors,
            warnings=sanitized_warnings,
            pre_flight_duration=internal_result.pre_flight_duration,
            validation_checks=internal_result.validation_checks,
            system_info=sanitized_system_info,  # Now includes sanitized system info
        )
