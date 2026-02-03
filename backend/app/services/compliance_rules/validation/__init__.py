"""
Compliance Rules Validation Submodule

Handles security validation and smart deduplication for compliance rule uploads.
"""

import logging

from .deduplication import DeduplicationStrategy, SmartDeduplicationService
from .security import ComplianceRulesSecurityService, SecurityCheckResult

logger = logging.getLogger(__name__)

__all__ = [
    # Security validation
    "ComplianceRulesSecurityService",
    "SecurityCheckResult",
    # Deduplication
    "SmartDeduplicationService",
    "DeduplicationStrategy",
]

logger.debug("Compliance rules validation submodule initialized")
