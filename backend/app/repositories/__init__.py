"""
Repository Pattern for MongoDB Operations
OW-REFACTOR-002: Centralized MongoDB query logic

This module provides the repository pattern implementation for all MongoDB
Document models in OpenWatch. Using repositories:
- Centralizes query logic
- Provides consistent error handling
- Enables easier testing via dependency injection
- Supports audit logging and performance monitoring

Usage:
    from app.repositories import ComplianceRuleRepository

    repo = ComplianceRuleRepository()
    rules = await repo.find_by_framework("CIS")
"""

from .base_repository import BaseRepository
from .compliance_repository import ComplianceRuleRepository

# Enhanced Models
from .enhanced_repository import FrameworkControlRepository, UnifiedComplianceRuleRepository  # noqa: F401

# Health Monitoring
from .health_repository import ContentHealthRepository, HealthSummaryRepository, ServiceHealthRepository  # noqa: F401

# Intelligence and Upload History
from .intelligence_repository import RuleIntelligenceRepository, UploadHistoryRepository  # noqa: F401

# Plugin Management
from .plugin_repository import InstalledPluginRepository  # noqa: F401

# Remediation Jobs
from .remediation_job_repository import BulkRemediationJobRepository, RemediationResultRepository  # noqa: F401

# Remediation Scripts
from .remediation_repository import RemediationScriptRepository  # noqa: F401

# Scan Management
from .scan_repository import ScanResultRepository, ScanScheduleRepository, ScanTemplateRepository  # noqa: F401

__all__ = [
    # Base
    "BaseRepository",
    # Compliance
    "ComplianceRuleRepository",
    # Intelligence
    "RuleIntelligenceRepository",
    "UploadHistoryRepository",
    # Remediation Scripts
    "RemediationScriptRepository",
    # Plugins
    "InstalledPluginRepository",
    # Health
    "ServiceHealthRepository",
    "ContentHealthRepository",
    "HealthSummaryRepository",
    # Scans
    "ScanTemplateRepository",
    "ScanResultRepository",
    "ScanScheduleRepository",
    # Remediation Jobs
    "RemediationResultRepository",
    "BulkRemediationJobRepository",
    # Enhanced
    "UnifiedComplianceRuleRepository",
    "FrameworkControlRepository",
]
