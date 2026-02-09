"""Remediation handlers and dispatch.

This module re-exports remediation handlers from runner.handlers.remediation for
backward compatibility. All implementations are in the handlers subpackage.
"""

from runner.handlers.remediation import REMEDIATION_HANDLERS, run_remediation

__all__ = ["REMEDIATION_HANDLERS", "run_remediation"]
