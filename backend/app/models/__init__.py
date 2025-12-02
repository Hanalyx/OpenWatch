"""
OpenWatch Models Package
Enhanced MongoDB models for unified compliance architecture
"""

# Import Host from database module to make it available at package level
import sys

sys.path.insert(0, "/app")
from backend.app.database import Host  # noqa: E402

from .enhanced_mongo_models import UnifiedComplianceRule  # noqa: E402
from .enhanced_mongo_models import (  # noqa: E402
    CheckContent,
    FixContent,
    FrameworkControlDefinition,
    FrameworkMapping,
    FrameworkVersions,
    PlatformImplementation,
)
from .enhanced_mongo_models import RuleIntelligence as EnhancedRuleIntelligence  # noqa: E402
from .health_models import (
    ContentHealthDocument,
    HealthSummaryDocument,
    ServiceHealthDocument,
)  # noqa: E402
from .mongo_models import (  # noqa: E402
    ComplianceRule,
    MongoManager,
    RemediationScript,
    RuleIntelligence,
    get_mongo_manager,
    mongo_manager,
)
from .readiness_models import (  # noqa: E402
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
