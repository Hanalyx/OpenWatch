#!/usr/bin/env python3
"""
Engine Providers Module (Future)

Placeholder module for cloud provider integrations. This module will contain
implementations for external cloud and infrastructure providers such as:
- AWS Security Hub integration
- Azure Security Center integration
- Google Cloud Security Command Center integration
- Kubernetes cluster providers
- Custom infrastructure providers

Current Status: Placeholder for future Phase 6+ implementation.

Architecture Vision:
    The providers module will follow a consistent interface pattern defined
    in base.py, allowing OpenWatch to push compliance data to various
    external systems and pull security configurations.

Planned Features:
    1. AWS Integration:
       - Push compliance findings to Security Hub
       - Pull EC2/ECS security configurations
       - Integrate with AWS Config rules

    2. Azure Integration:
       - Push findings to Azure Security Center
       - Pull Azure VM compliance status
       - Integrate with Azure Policy

    3. GCP Integration:
       - Push findings to Security Command Center
       - Pull GCE security configurations
       - Integrate with Security Health Analytics

    4. Kubernetes Integration:
       - Multi-cluster compliance aggregation
       - Pod Security Policy validation
       - Network Policy compliance

Usage (Future):
    from backend.app.services.engine.providers import (
        get_provider,
        AWSProvider,
        AzureProvider,
        GCPProvider,
    )

    # Get configured provider
    provider = get_provider("aws")
    await provider.push_findings(scan_results)
"""

from backend.app.services.engine.providers.base import (
    BaseProvider,
    ProviderCapability,
    ProviderConfig,
    ProviderError,
)

__all__ = [
    "BaseProvider",
    "ProviderCapability",
    "ProviderConfig",
    "ProviderError",
]
