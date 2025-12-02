#!/usr/bin/env python3
"""
Base Provider Interface

Defines the abstract interface for external cloud and infrastructure
provider integrations. All provider implementations must inherit from
BaseProvider and implement the required methods.

This module provides:
1. Abstract base class defining provider contract
2. Common capability definitions
3. Configuration dataclass for provider settings
4. Error hierarchy for provider operations

Security Considerations:
- All provider implementations must validate credentials
- API calls must use proper authentication
- Sensitive data must not be logged
- Rate limiting must be implemented per provider

Architecture:
    BaseProvider defines the contract that all providers must follow:
    - connect(): Establish connection with credentials validation
    - disconnect(): Clean up resources
    - push_findings(): Send compliance data to provider
    - pull_configuration(): Retrieve security configurations
    - health_check(): Validate provider connectivity

Usage:
    from backend.app.services.engine.providers.base import (
        BaseProvider,
        ProviderConfig,
    )

    class AWSProvider(BaseProvider):
        async def connect(self) -> bool:
            # AWS-specific connection logic
            pass

        async def push_findings(self, findings: List[Dict]) -> Dict[str, Any]:
            # Push to AWS Security Hub
            pass
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class ProviderCapability(Enum):
    """
    Enumeration of capabilities that providers may support.

    Not all providers support all capabilities. Use these values
    to check provider support before calling specific methods.

    Attributes:
        PUSH_FINDINGS: Can send compliance findings to the provider
        PULL_CONFIGURATION: Can retrieve security configurations
        REAL_TIME_ALERTS: Can receive/send real-time security alerts
        COMPLIANCE_REPORTS: Can generate compliance reports
        REMEDIATION: Can trigger automated remediation actions
        INVENTORY_SYNC: Can synchronize asset inventory
    """

    PUSH_FINDINGS = "push_findings"
    PULL_CONFIGURATION = "pull_configuration"
    REAL_TIME_ALERTS = "real_time_alerts"
    COMPLIANCE_REPORTS = "compliance_reports"
    REMEDIATION = "remediation"
    INVENTORY_SYNC = "inventory_sync"


class ProviderError(Exception):
    """
    Base exception for provider operations.

    All provider-specific exceptions should inherit from this class
    to enable consistent error handling across providers.

    Attributes:
        message: Human-readable error description
        provider_name: Name of the provider that raised the error
        operation: Operation that failed (e.g., "connect", "push_findings")
        details: Additional error context (optional)
    """

    def __init__(
        self,
        message: str,
        provider_name: str,
        operation: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Initialize ProviderError with context.

        Args:
            message: Human-readable error description.
            provider_name: Name of the provider that raised the error.
            operation: Operation that failed.
            details: Additional error context.
        """
        self.provider_name = provider_name
        self.operation = operation
        self.details = details or {}
        super().__init__(f"[{provider_name}] {operation} failed: {message}")


class ProviderConnectionError(ProviderError):
    """Raised when provider connection fails."""

    pass


class ProviderAuthenticationError(ProviderError):
    """Raised when provider authentication fails."""

    pass


class ProviderRateLimitError(ProviderError):
    """Raised when provider rate limit is exceeded."""

    pass


@dataclass
class ProviderConfig:
    """
    Configuration for external provider integration.

    This dataclass contains all settings needed to configure
    a provider integration, including credentials and options.

    Attributes:
        provider_name: Unique identifier for the provider (e.g., "aws", "azure")
        enabled: Whether this provider integration is active
        credentials: Provider-specific credentials (API keys, tokens, etc.)
        endpoint_url: Custom endpoint URL (for private/gov clouds)
        region: Cloud region for regional services
        timeout_seconds: Request timeout in seconds
        retry_count: Number of retries for failed requests
        rate_limit_per_minute: Maximum requests per minute
        custom_options: Provider-specific additional options

    Example:
        config = ProviderConfig(
            provider_name="aws",
            enabled=True,
            credentials={
                "access_key_id": "AKIAIOSFODNN7EXAMPLE",  # pragma: allowlist secret
                "secret_access_key": "...",
            },
            region="us-east-1",
            timeout_seconds=30,
        )

    Security Note:
        Credentials should be loaded from secure storage (environment
        variables, secrets manager) not hardcoded.
    """

    provider_name: str
    enabled: bool = True
    credentials: Dict[str, str] = field(default_factory=dict)
    endpoint_url: Optional[str] = None
    region: Optional[str] = None
    timeout_seconds: int = 30
    retry_count: int = 3
    rate_limit_per_minute: int = 60
    custom_options: Dict[str, Any] = field(default_factory=dict)


class BaseProvider(ABC):
    """
    Abstract base class for external provider integrations.

    All provider implementations must inherit from this class and
    implement the abstract methods. This ensures consistent behavior
    across different cloud and infrastructure providers.

    Providers enable OpenWatch to:
    - Push compliance findings to external security platforms
    - Pull security configurations for compliance checking
    - Synchronize asset inventory
    - Trigger automated remediation

    Attributes:
        config: ProviderConfig with settings and credentials
        _connected: Connection state flag
        _capabilities: Set of supported capabilities

    Example:
        class AWSProvider(BaseProvider):
            def __init__(self, config: ProviderConfig):
                super().__init__(config)
                self._capabilities = {
                    ProviderCapability.PUSH_FINDINGS,
                    ProviderCapability.PULL_CONFIGURATION,
                }

            async def connect(self) -> bool:
                # Validate AWS credentials
                # Initialize boto3 clients
                return True
    """

    def __init__(self, config: ProviderConfig) -> None:
        """
        Initialize provider with configuration.

        Args:
            config: ProviderConfig containing credentials and settings.

        Raises:
            ValueError: If required configuration is missing.
        """
        if not config.provider_name:
            raise ValueError("provider_name is required")

        self.config = config
        self._connected = False
        self._capabilities: set[ProviderCapability] = set()

        logger.info(f"Initialized provider: {config.provider_name}")

    @property
    def name(self) -> str:
        """Get provider name."""
        return self.config.provider_name

    @property
    def is_connected(self) -> bool:
        """Check if provider is connected."""
        return self._connected

    @property
    def capabilities(self) -> set[ProviderCapability]:
        """Get set of supported capabilities."""
        return self._capabilities

    def supports(self, capability: ProviderCapability) -> bool:
        """
        Check if provider supports a specific capability.

        Args:
            capability: Capability to check for.

        Returns:
            True if capability is supported, False otherwise.
        """
        return capability in self._capabilities

    @abstractmethod
    async def connect(self) -> bool:
        """
        Establish connection to the provider.

        This method should validate credentials, establish any
        persistent connections, and prepare the provider for use.

        Returns:
            True if connection successful, False otherwise.

        Raises:
            ProviderConnectionError: If connection fails.
            ProviderAuthenticationError: If credentials invalid.
        """
        pass

    @abstractmethod
    async def disconnect(self) -> None:
        """
        Disconnect from the provider and clean up resources.

        This method should close any open connections, release
        resources, and prepare for shutdown.
        """
        pass

    @abstractmethod
    async def health_check(self) -> Dict[str, Any]:
        """
        Check provider health and connectivity.

        Returns:
            Dictionary containing health status:
            {
                "healthy": bool,
                "latency_ms": float,
                "last_check": str (ISO timestamp),
                "details": dict (provider-specific info)
            }
        """
        pass

    @abstractmethod
    async def push_findings(
        self,
        findings: List[Dict[str, Any]],
        scan_id: str,
        host_id: str,
    ) -> Dict[str, Any]:
        """
        Push compliance findings to the provider.

        Args:
            findings: List of compliance finding dictionaries.
            scan_id: Source scan identifier.
            host_id: Source host identifier.

        Returns:
            Dictionary containing push result:
            {
                "success": bool,
                "findings_pushed": int,
                "provider_ids": list (external IDs assigned),
                "errors": list (any partial failures)
            }

        Raises:
            ProviderError: If push operation fails.
        """
        pass

    @abstractmethod
    async def pull_configuration(
        self,
        resource_type: str,
        resource_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Pull security configuration from the provider.

        Args:
            resource_type: Type of resource to pull (e.g., "ec2", "vm").
            resource_id: Specific resource ID (optional, pulls all if None).

        Returns:
            Dictionary containing configuration data:
            {
                "resource_type": str,
                "configurations": list,
                "timestamp": str (ISO timestamp)
            }

        Raises:
            ProviderError: If pull operation fails.
        """
        pass

    async def __aenter__(self) -> "BaseProvider":
        """Async context manager entry."""
        await self.connect()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        await self.disconnect()
