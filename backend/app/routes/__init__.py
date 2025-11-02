"""
OpenWatch API Routes Package
"""

# Import compliance modules to make them available
# Note: These imports are optional for testing compatibility
try:
    from . import compliance
    from . import group_compliance
except ImportError as e:
    # Allow tests to run without MongoDB/motor or other optional dependencies
    import logging

    logging.warning(f"Optional compliance routes not available: {e}")
