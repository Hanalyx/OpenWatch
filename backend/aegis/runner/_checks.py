"""Check handlers and dispatch.

This module re-exports check handlers from runner.handlers.checks for
backward compatibility. New code should import directly from
runner.handlers.checks.

Example:
-------
    # Preferred (new code)
    from runner.handlers.checks import run_check, CHECK_HANDLERS

    # Backward compatible (existing code)
    from runner._checks import run_check, CHECK_HANDLERS

"""

from runner.handlers.checks import CHECK_HANDLERS, run_check

__all__ = ["CHECK_HANDLERS", "run_check"]
