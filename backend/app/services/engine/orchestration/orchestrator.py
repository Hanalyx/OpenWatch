"""
Scan Orchestrator - DEPRECATED

This orchestrator coordinated multi-scanner compliance scanning via MongoDB.
It has been superseded by:
- Aegis compliance engine (app/plugins/aegis/) for compliance scanning
- BulkScanOrchestrator (app/services/bulk_scan_orchestrator.py) for multi-host scans

This stub is kept for import compatibility only.
"""

import logging

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    """Deprecated MongoDB-based scan orchestrator.

    Use Aegis plugin or BulkScanOrchestrator instead.
    """

    def __init__(self, *args, **kwargs):
        logger.warning("ScanOrchestrator is deprecated. " "Use Aegis plugin or BulkScanOrchestrator instead.")
