"""
Unified Rule Models for OpenWatch Phase 2
Defines data models for unified compliance rules, executions, and related structures
"""

from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, field
from pydantic import BaseModel, Field


class ComplianceStatus(str, Enum):
    """Compliance status for rule executions"""

    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIAL = "partial"
    ERROR = "error"
    EXCEEDS = "exceeds"


class Platform(str, Enum):
    """Supported platforms"""

    RHEL_7 = "rhel_7"
    RHEL_8 = "rhel_8"
    RHEL_9 = "rhel_9"
    UBUNTU_18 = "ubuntu_18"
    UBUNTU_20 = "ubuntu_20"
    UBUNTU_22 = "ubuntu_22"
    DEBIAN_9 = "debian_9"
    DEBIAN_10 = "debian_10"
    DEBIAN_11 = "debian_11"
    CENTOS_7 = "centos_7"
    CENTOS_8 = "centos_8"
    WINDOWS_SERVER_2019 = "windows_server_2019"
    WINDOWS_SERVER_2022 = "windows_server_2022"


@dataclass
class RuleExecution:
    """Represents a single rule execution result"""

    execution_id: str
    rule_id: str
    execution_success: bool
    compliance_status: ComplianceStatus
    execution_time: float
    output_data: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    executed_at: Optional[datetime] = None


@dataclass
class FrameworkMapping:
    """Framework-specific mapping for a rule"""

    framework_id: str
    control_ids: List[str]
    implementation_status: str
    justification: Optional[str] = None
    enhancement_details: Optional[str] = None


@dataclass
class PlatformImplementation:
    """Platform-specific implementation details"""

    platform: Platform
    implementation_type: str
    commands: List[str] = field(default_factory=list)
    files_modified: List[str] = field(default_factory=list)
    services_affected: List[str] = field(default_factory=list)
    validation_commands: List[str] = field(default_factory=list)


@dataclass
class UnifiedComplianceRule:
    """Unified compliance rule definition"""

    rule_id: str
    title: str
    description: str
    category: str
    security_function: str
    risk_level: str
    framework_mappings: List[FrameworkMapping] = field(default_factory=list)
    platform_implementations: List[PlatformImplementation] = field(default_factory=list)
