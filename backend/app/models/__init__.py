"""
OpenWatch Models Package
Enhanced MongoDB models for unified compliance architecture
"""

from .mongo_models import (
    ComplianceRule,
    RuleIntelligence,
    RemediationScript,
    MongoManager,
    mongo_manager,
    get_mongo_manager,
)

from .enhanced_mongo_models import (
    UnifiedComplianceRule,
    FrameworkMapping,
    FrameworkVersions,
    PlatformImplementation,
    RuleIntelligence as EnhancedRuleIntelligence,
    FrameworkControlDefinition,
    CheckContent,
    FixContent,
)

from .health_models import (
    ServiceHealthDocument,
    ContentHealthDocument,
    HealthSummaryDocument,
)

from .authorization_models import *
from .error_models import *
from .system_models import *
from .plugin_models import *

__all__ = [
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
]
