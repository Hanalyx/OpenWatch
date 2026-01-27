"""
OWCA Framework Layer

Provides framework-specific compliance intelligence for:
- NIST 800-53 (control families, baselines, enhancements)
- CIS Benchmarks (levels, implementation groups)
- STIG (CAT I/II/III, finding statuses)

Usage:
    >>> from app.services.owca.framework import get_framework_intelligence
    >>> intelligence = get_framework_intelligence("NIST_800_53", db, score_calculator)
    >>> result = await intelligence.analyze_host_compliance(host_id)
"""

import logging
from typing import Optional

from sqlalchemy.orm import Session

from ..core.score_calculator import ComplianceScoreCalculator
from .base import BaseFrameworkIntelligence
from .cis import CISBenchmarkIntelligence
from .models import (
    CISFrameworkIntelligence,
    CISImplementationGroup,
    CISLevel,
    NISTBaseline,
    NISTControlFamily,
    NISTFrameworkIntelligence,
    STIGFrameworkIntelligence,
    STIGSeverity,
)
from .nist_800_53 import NIST80053FrameworkIntelligence
from .stig import STIGFrameworkIntelligence as STIGIntelligence

logger = logging.getLogger(__name__)

# Framework intelligence factory registry
_FRAMEWORK_REGISTRY = {
    "NIST_800_53": NIST80053FrameworkIntelligence,
    "nist_800_53": NIST80053FrameworkIntelligence,
    "nist": NIST80053FrameworkIntelligence,
    "CIS": CISBenchmarkIntelligence,
    "cis": CISBenchmarkIntelligence,
    "STIG": STIGIntelligence,
    "stig": STIGIntelligence,
}


def get_framework_intelligence(
    framework: str, db: Session, score_calculator: ComplianceScoreCalculator
) -> Optional[BaseFrameworkIntelligence]:
    """
    Factory function to get framework-specific intelligence provider.

    Args:
        framework: Framework identifier ("NIST_800_53", "CIS", "STIG")
        db: SQLAlchemy database session
        score_calculator: OWCA score calculator

    Returns:
        Framework intelligence provider or None if framework not supported

    Example:
        >>> nist_intel = get_framework_intelligence("NIST_800_53", db, calculator)
        >>> result = await nist_intel.analyze_host_compliance(host_id)
    """
    intelligence_class = _FRAMEWORK_REGISTRY.get(framework)

    if not intelligence_class:
        logger.warning(f"Unknown framework: {framework}")
        return None

    return intelligence_class(db, score_calculator)


__all__ = [
    # Base
    "BaseFrameworkIntelligence",
    "get_framework_intelligence",
    # NIST
    "NIST80053FrameworkIntelligence",
    "NISTFrameworkIntelligence",
    "NISTBaseline",
    "NISTControlFamily",
    # CIS
    "CISBenchmarkIntelligence",
    "CISFrameworkIntelligence",
    "CISLevel",
    "CISImplementationGroup",
    # STIG
    "STIGIntelligence",
    "STIGFrameworkIntelligence",
    "STIGSeverity",
]
