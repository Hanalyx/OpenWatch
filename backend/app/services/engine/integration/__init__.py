#!/usr/bin/env python3
"""
Engine Integration Module

Provides external system integrations for the SCAP processing engine, including:
- AEGIS remediation system mapping and job generation
- Semantic analysis engine for intelligent compliance insights
- Cross-framework compliance intelligence

This module enables:
1. Automated remediation workflows via AEGIS integration
2. Rich semantic understanding of SCAP compliance rules
3. Intelligent trend prediction and analysis
4. Universal framework mapping (NIST, CIS, STIG, etc.)

Security Considerations:
- All external API calls use validated inputs
- No shell command execution in integration layer
- Audit logging for all integration operations

Usage:
    from backend.app.services.engine.integration import (
        AegisMapper,
        SemanticEngine,
        get_aegis_mapper,
        get_semantic_engine,
    )

    # AEGIS remediation mapping
    mapper = get_aegis_mapper()
    plan = mapper.create_remediation_plan(failed_rules, host_id)

    # Semantic analysis
    engine = get_semantic_engine()
    result = await engine.process_scan_with_intelligence(scan_id)
"""

from backend.app.services.engine.integration.aegis_mapper import (
    AegisMapper,
    AEGISMapping,
    RemediationPlan,
    get_aegis_mapper,
)
from backend.app.services.engine.integration.semantic_engine import (
    IntelligentScanResult,
    SemanticEngine,
    SemanticRule,
    get_semantic_engine,
)

__all__ = [
    # AEGIS Integration
    "AegisMapper",
    "AEGISMapping",
    "RemediationPlan",
    "get_aegis_mapper",
    # Semantic Engine
    "SemanticEngine",
    "SemanticRule",
    "IntelligentScanResult",
    "get_semantic_engine",
]
