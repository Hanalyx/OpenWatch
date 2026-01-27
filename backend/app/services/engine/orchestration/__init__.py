"""
Orchestration Module - Scan Coordination and Multi-Scanner Management

This module provides high-level orchestration for compliance scanning operations,
coordinating multiple scanners and aggregating results.

Components:
    - ScanOrchestrator: Central coordinator for multi-scanner compliance scanning

The orchestration layer sits above the scanner layer and coordinates:
1. Rule selection from MongoDB based on scan configuration
2. Routing rules to appropriate scanners based on scanner_type
3. Parallel execution of multiple scanners
4. Result aggregation and summary calculation
5. Persistence of scan results

Architecture:
    ┌─────────────────────────────────────────────────────────┐
    │                   Orchestration Layer                    │
    │  ┌─────────────────────────────────────────────────────┐│
    │  │                  ScanOrchestrator                   ││
    │  │  - Query rules from MongoDB                         ││
    │  │  - Group rules by scanner_type                      ││
    │  │  - Execute scanners in parallel                     ││
    │  │  - Aggregate and store results                      ││
    │  └─────────────────────────────────────────────────────┘│
    └─────────────────────────────────────────────────────────┘
                              │
                              ▼
    ┌─────────────────────────────────────────────────────────┐
    │                    Scanner Layer                         │
    │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
    │  │ OSCAPScanner │  │  K8sScanner  │  │ CustomScanner│  │
    │  └──────────────┘  └──────────────┘  └──────────────┘  │
    └─────────────────────────────────────────────────────────┘

Usage:
    from app.services.engine import ScanOrchestrator

    # Create orchestrator with MongoDB connection
    orchestrator = ScanOrchestrator(db=mongodb)

    # Execute scan
    result = await orchestrator.execute_scan(
        config=scan_config,
        started_by="admin",
        scan_name="Weekly STIG Compliance"
    )

    # Check results
    print(f"Compliance: {result.summary.compliance_percentage}%")

Why Orchestration is Part of Engine:
    - Core scanning concern, not application-specific feature
    - Tightly coupled with ScannerFactory and scanner implementations
    - No external dependencies on HTTP layer or user-specific logic
    - Reusable by CLI tools, background tasks, and API endpoints

Security Notes:
    - Orchestrator does not handle credentials directly
    - Credentials passed through to scanners via configuration
    - MongoDB queries use proper query construction (no injection)
    - Results stored with proper access controls
"""

import logging

from .orchestrator import ScanOrchestrator  # noqa: F401

logger = logging.getLogger(__name__)

__all__ = [
    "ScanOrchestrator",
]

logger.debug("Orchestration module loaded")
