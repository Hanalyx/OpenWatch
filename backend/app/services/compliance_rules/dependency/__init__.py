"""
Compliance Rules Dependency Submodule

Handles rule dependencies, inheritance, and impact analysis for compliance rules.
"""

import logging

from .graph import INHERITABLE_FIELDS, NON_INHERITABLE_FIELDS, InheritanceResolver, RuleDependencyGraph

logger = logging.getLogger(__name__)

__all__ = [
    "RuleDependencyGraph",
    "InheritanceResolver",
    "INHERITABLE_FIELDS",
    "NON_INHERITABLE_FIELDS",
]

logger.debug("Compliance rules dependency submodule initialized")
