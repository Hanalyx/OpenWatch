"""
OpenWatch Models Package
Enhanced MongoDB models for unified compliance architecture
"""

# Import Host from database module to make it available at package level
import sys

sys.path.insert(0, "/app")
from backend.app.database import Host

from .authorization_models import *
from .enhanced_mongo_models import (
    CheckContent,
    FixContent,
    FrameworkControlDefinition,
    FrameworkMapping,
    FrameworkVersions,
    PlatformImplementation,
)
from .enhanced_mongo_models import RuleIntelligence as EnhancedRuleIntelligence
from .enhanced_mongo_models import UnifiedComplianceRule
from .error_models import *
from .health_models import ContentHealthDocument, HealthSummaryDocument, ServiceHealthDocument
from .mongo_models import (
    ComplianceRule,
    MongoManager,
    RemediationScript,
    RuleIntelligence,
    get_mongo_manager,
    mongo_manager,
)
from .plugin_models import *
from .readiness_models import (
    BulkReadinessReport,
    BulkReadinessRequest,
    HostReadiness,
    HostReadinessCheck,
    HostReadinessValidation,
    QuickCheckRequest,
    ReadinessCheckResult,
    ReadinessCheckSeverity,
    ReadinessCheckType,
    ReadinessHistory,
    ReadinessHistoryRequest,
    ReadinessStatus,
    ReadinessTrendPoint,
)
from .system_models import *

__all__ = [
    # Database models
    "Host",
    # Original models
    "ComplianceRule",
    "RuleIntelligence",
    "RemediationScript",
    "MongoManager",
    "mongo_manager",
    "get_mongo_manager",
    # Enhanced unified models
    "UnifiedComplianceRule",
    "FrameworkMapping",
    "FrameworkVersions",
    "PlatformImplementation",
    "EnhancedRuleIntelligence",
    "FrameworkControlDefinition",
    "CheckContent",
    "FixContent",
    # Health models
    "ServiceHealthDocument",
    "ContentHealthDocument",
    "HealthSummaryDocument",
    # Readiness models
    "HostReadiness",
    "HostReadinessCheck",
    "HostReadinessValidation",
    "ReadinessCheckResult",
    "ReadinessCheckSeverity",
    "ReadinessCheckType",
    "ReadinessStatus",
    "BulkReadinessRequest",
    "BulkReadinessReport",
    "ReadinessHistoryRequest",
    "ReadinessHistory",
    "ReadinessTrendPoint",
    "QuickCheckRequest",
]
