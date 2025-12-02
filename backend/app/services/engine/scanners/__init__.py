"""
Engine Scanners Module

This module provides scanner implementations for different compliance
scanning technologies and content formats.

Scanners are responsible for:
- Validating SCAP content before execution
- Building scanner-specific command lines
- Parsing scan results into normalized format
- Providing scanner capabilities and metadata

Available Scanners:
- BaseScanner: Abstract base class defining the scanner interface
- UnifiedSCAPScanner: Primary SCAP scanner with MongoDB rule integration
- OSCAPScanner: OpenSCAP-based content validation and profile extraction
- KubernetesScanner: Kubernetes/OpenShift compliance scanner

Scanner Registry (ScannerFactory):
- "scap" -> UnifiedSCAPScanner (primary, MongoDB-integrated)
- "oscap" -> OSCAPScanner (content operations, validation)
- "kubernetes" -> KubernetesScanner (K8s/OpenShift)

Usage:
    from backend.app.services.engine.scanners import (
        UnifiedSCAPScanner,
        OSCAPScanner,
        KubernetesScanner,
        ScannerFactory,
        get_unified_scanner,
    )

    # Get unified scanner for MongoDB-integrated scanning (recommended)
    scanner = get_unified_scanner()
    await scanner.initialize()
    result = await scanner.scan_with_rules(
        host_id=host_id,
        hostname="192.168.1.100",
        platform="rhel9",
        rules=rules,
        connection_params=conn_params,
    )

    # Get scanner by type via factory
    scap_scanner = ScannerFactory.get_scanner("scap")

    # Get content-only scanner for validation
    oscap_scanner = ScannerFactory.get_scanner("oscap")
    profiles = oscap_scanner.extract_profiles(content_path)

Architecture Notes:
- Scanners are stateless (content paths passed to methods)
- Scanners do NOT handle execution (that's the executor's job)
- Scanners focus on content validation and result parsing
- Scanner capabilities advertise what each scanner supports
- UnifiedSCAPScanner is the primary scanner for compliance operations
"""

import logging
from pathlib import Path
from typing import Optional

from ..models import ScanProvider

logger = logging.getLogger(__name__)

# Import scanner implementations (re-exported for public API)
from .base import BaseScanner  # noqa: F401, E402
from .kubernetes import KubernetesScanner  # noqa: F401, E402
from .oscap import OSCAPScanner  # noqa: F401, E402
from .scap import UnifiedSCAPScanner  # noqa: F401, E402


def get_scanner(provider: ScanProvider) -> BaseScanner:
    """
    Factory function to get the appropriate scanner for a provider.

    This is the recommended way to obtain scanner instances, as it handles
    instantiation and configuration automatically.

    Args:
        provider: The scan provider determining which scanner to use.

    Returns:
        Configured scanner instance ready for use.

    Raises:
        ValueError: If provider is not supported.

    Usage:
        >>> scanner = get_scanner(ScanProvider.OSCAP)
        >>> profiles = scanner.extract_profiles(content_path)
    """
    if provider == ScanProvider.OSCAP:
        return OSCAPScanner()

    elif provider == ScanProvider.KUBERNETES:
        return KubernetesScanner()

    elif provider == ScanProvider.CUSTOM:
        # Custom scanner support is planned for plugin architecture
        raise NotImplementedError("Custom scanners are not yet implemented. " "See plugin architecture documentation.")

    else:
        raise ValueError(f"Unsupported scan provider: {provider}")


def get_scanner_for_content(content_path: str) -> Optional[BaseScanner]:
    """
    Auto-detect and return appropriate scanner based on content format.

    Examines the content file to determine which scanner can handle it.

    Args:
        content_path: Path to SCAP content file.

    Returns:
        Scanner instance that can handle the content, or None if
        no suitable scanner is found.

    Usage:
        >>> scanner = get_scanner_for_content("/path/to/ssg-rhel8-ds.xml")
        >>> if scanner:
        ...     info = scanner.get_content_info(content_path)
    """
    path = Path(content_path)

    # Try OSCAP scanner first (handles most common formats)
    oscap_scanner = OSCAPScanner()
    try:
        if oscap_scanner.can_handle_content(content_path):
            logger.debug("Using OSCAP scanner for: %s", path.name)
            return oscap_scanner
    except Exception as e:
        logger.debug("OSCAP scanner cannot handle content: %s", e)

    # Try Kubernetes scanner for YAML/JSON rule files
    k8s_scanner = KubernetesScanner()
    try:
        if k8s_scanner.validate_content(path):
            logger.debug("Using Kubernetes scanner for: %s", path.name)
            return k8s_scanner
    except Exception as e:
        logger.debug("Kubernetes scanner cannot handle content: %s", e)

    # No suitable scanner found
    logger.warning("No scanner found for content: %s", content_path)
    return None


def get_unified_scanner(
    content_dir: Optional[str] = None,
    results_dir: Optional[str] = None,
    encryption_service: Optional[object] = None,
) -> "UnifiedSCAPScanner":
    """
    Get the unified SCAP scanner with MongoDB integration.

    The unified scanner combines all SCAP scanning capabilities including:
    - MongoDB rule selection and generation
    - Dynamic XCCDF/OVAL content creation
    - Local and remote scan execution
    - Result enrichment with rule intelligence

    Note: After obtaining the scanner, call `await scanner.initialize()`
    before using MongoDB-dependent methods.

    Args:
        content_dir: Directory for SCAP content (default: /app/data/scap).
        results_dir: Directory for scan results (default: /app/data/results).
        encryption_service: Encryption service for credential decryption.

    Returns:
        Configured UnifiedSCAPScanner instance (requires async initialization).

    Usage:
        >>> scanner = get_unified_scanner()
        >>> await scanner.initialize()  # Required before MongoDB operations
        >>> result = await scanner.scan_with_rules(
        ...     host_id="uuid",
        ...     hostname="192.168.1.100",
        ...     platform="rhel9",
        ...     rules=rules,
        ...     connection_params=params,
        ... )
    """
    return UnifiedSCAPScanner(
        content_dir=content_dir,
        results_dir=results_dir,
        encryption_service=encryption_service,
    )


# =============================================================================
# Scanner Factory
# =============================================================================


class ScannerFactory:
    """
    Factory for creating scanner instances by type identifier.

    Provides a registry-based pattern for scanner instantiation, allowing
    dynamic scanner selection at runtime based on scanner type strings.
    This is useful for orchestration services that need to route rules
    to appropriate scanners based on rule metadata.

    The factory maintains a registry of scanner types to scanner classes,
    and creates new instances on demand. Custom scanners can be registered
    at runtime for plugin support.

    Attributes:
        _scanners: Class-level registry mapping scanner type strings to classes.

    Usage:
        # Get scanner by type
        scanner = ScannerFactory.get_scanner("oscap")
        result = scanner.validate_content(content_path)

        # List available scanners
        available = ScannerFactory.get_available_scanners()

        # Register custom scanner (for plugins)
        ScannerFactory.register_scanner("custom", CustomScanner)

    Security Notes:
        - Only pre-registered scanner types are instantiated
        - Custom scanners must inherit from BaseScanner
        - No dynamic code execution based on user input
    """

    # Registry of scanner types to scanner classes
    # Keys are lowercase identifiers used in rule metadata
    _scanners: dict[str, type[BaseScanner]] = {
        # Primary scanner for SCAP compliance (MongoDB-integrated)
        "scap": UnifiedSCAPScanner,
        # Legacy/content-only scanner (profile extraction, validation)
        "oscap": OSCAPScanner,
        # Kubernetes/OpenShift compliance
        "kubernetes": KubernetesScanner,
        # Future scanner types:
        # "python": PythonScanner,  # For Python-based checks
        # "bash": BashScanner,      # For shell script checks
        # "aws_api": AWSScanner,    # For AWS API compliance
        # "azure_api": AzureScanner,  # For Azure compliance
    }

    @classmethod
    def get_scanner(cls, scanner_type: str) -> BaseScanner:
        """
        Get scanner instance by type identifier.

        Creates a new scanner instance for the specified type. Each call
        returns a fresh instance - scanners are stateless and lightweight.

        Args:
            scanner_type: Scanner type identifier (e.g., "oscap", "kubernetes").
                         Case-insensitive matching is performed.

        Returns:
            New scanner instance of the requested type.

        Raises:
            ValueError: If scanner_type is not registered in the factory.

        Usage:
            >>> scanner = ScannerFactory.get_scanner("oscap")
            >>> if scanner.validate_content(path):
            ...     profiles = scanner.extract_profiles(path)
        """
        # Normalize to lowercase for case-insensitive matching
        normalized_type = scanner_type.lower().strip()

        scanner_class = cls._scanners.get(normalized_type)

        if scanner_class is None:
            available = ", ".join(sorted(cls._scanners.keys()))
            raise ValueError(f"Unknown scanner type: '{scanner_type}'. " f"Available scanners: {available}")

        return scanner_class()

    @classmethod
    def get_available_scanners(cls) -> dict[str, str]:
        """
        Get list of available scanner types with descriptions.

        Returns a mapping of scanner type identifiers to human-readable
        descriptions. Useful for UI display and documentation.

        Returns:
            Dict mapping scanner type to description string.

        Usage:
            >>> scanners = ScannerFactory.get_available_scanners()
            >>> for name, desc in scanners.items():
            ...     print(f"{name}: {desc}")
        """
        return {
            "scap": "Unified SCAP Scanner - MongoDB-integrated compliance scanning with rule intelligence",
            "oscap": "OpenSCAP - OVAL-based content validation and profile extraction",
            "kubernetes": "Kubernetes - YAML-based checks for K8s/OpenShift clusters",
            # Future scanners will be documented here
        }

    @classmethod
    def register_scanner(
        cls,
        scanner_type: str,
        scanner_class: type[BaseScanner],
    ) -> None:
        """
        Register a new scanner type in the factory.

        Allows plugins and extensions to register custom scanner implementations
        at runtime. The scanner class must inherit from BaseScanner to ensure
        interface compatibility.

        Args:
            scanner_type: Unique identifier for the scanner type.
                         Will be normalized to lowercase.
            scanner_class: Scanner class (must inherit from BaseScanner).

        Raises:
            TypeError: If scanner_class does not inherit from BaseScanner.
            ValueError: If scanner_type is empty or invalid.

        Usage:
            >>> class CustomScanner(BaseScanner):
            ...     # Custom implementation
            ...     pass
            >>> ScannerFactory.register_scanner("custom", CustomScanner)
            >>> scanner = ScannerFactory.get_scanner("custom")

        Security Notes:
            - Only classes inheriting from BaseScanner can be registered
            - This prevents arbitrary code execution through the factory
        """
        # Validate scanner type
        if not scanner_type or not scanner_type.strip():
            raise ValueError("Scanner type cannot be empty")

        # Validate scanner class inheritance
        if not issubclass(scanner_class, BaseScanner):
            raise TypeError(f"Scanner class must inherit from BaseScanner, " f"got {scanner_class.__name__}")

        # Register with normalized key
        normalized_type = scanner_type.lower().strip()
        cls._scanners[normalized_type] = scanner_class

        logger.info(
            "Registered scanner type '%s' with class %s",
            normalized_type,
            scanner_class.__name__,
        )

    @classmethod
    def is_registered(cls, scanner_type: str) -> bool:
        """
        Check if a scanner type is registered.

        Args:
            scanner_type: Scanner type identifier to check.

        Returns:
            True if the scanner type is registered, False otherwise.
        """
        return scanner_type.lower().strip() in cls._scanners


# Public API exports
__all__ = [
    # Base class
    "BaseScanner",
    # Scanner implementations
    "OSCAPScanner",
    "UnifiedSCAPScanner",
    "KubernetesScanner",
    # Factory class
    "ScannerFactory",
    # Factory functions
    "get_scanner",
    "get_scanner_for_content",
    "get_unified_scanner",
]
