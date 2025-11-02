"""
Repository Pattern for MongoDB Operations
OW-REFACTOR-002: Centralized MongoDB query logic
"""

from .base_repository import BaseRepository
from .compliance_repository import ComplianceRuleRepository

# from .framework_repository import FrameworkRepository  # TODO: Enable when Framework model exists

__all__ = [
    "BaseRepository",
    "ComplianceRuleRepository",
    # "FrameworkRepository",  # TODO: Enable when Framework model exists
]
