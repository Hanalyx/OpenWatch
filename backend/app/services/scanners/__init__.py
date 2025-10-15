#!/usr/bin/env python3
"""
Scanner Factory and Registry

Provides centralized scanner management and instantiation.
"""

from typing import Dict, Type
from .base_scanner import BaseScanner
from .oscap_scanner import OSCAPScanner
from .kubernetes_scanner import KubernetesScanner


class ScannerFactory:
    """
    Factory for creating scanner instances
    
    Maintains registry of available scanners and creates instances on demand.
    """
    
    # Registry of scanner types to scanner classes
    _scanners: Dict[str, Type[BaseScanner]] = {
        'oscap': OSCAPScanner,
        'kubernetes': KubernetesScanner,
        # Future scanners:
        # 'aws_api': AWSScanner,
        # 'azure_api': AzureScanner,
        # 'gcp_api': GCPScanner,
        # 'python': PythonScanner,
        # 'bash': BashScanner,
    }
    
    @classmethod
    def get_scanner(cls, scanner_type: str) -> BaseScanner:
        """
        Get scanner instance by type
        
        Args:
            scanner_type: Scanner type (oscap, kubernetes, aws_api, etc.)
        
        Returns:
            Scanner instance
        
        Raises:
            ValueError: If scanner type is not registered
        """
        scanner_class = cls._scanners.get(scanner_type)
        
        if not scanner_class:
            raise ValueError(
                f"Unknown scanner type: {scanner_type}. "
                f"Available scanners: {list(cls._scanners.keys())}"
            )
        
        return scanner_class()
    
    @classmethod
    def get_available_scanners(cls) -> Dict[str, str]:
        """
        Get list of available scanner types with descriptions
        
        Returns:
            Dict mapping scanner type to description
        """
        return {
            'oscap': 'OpenSCAP - Traditional OVAL-based compliance scanning',
            'kubernetes': 'Kubernetes - YAML-based checks for K8s/OpenShift clusters',
            # Future scanners will be added here
        }
    
    @classmethod
    def register_scanner(cls, scanner_type: str, scanner_class: Type[BaseScanner]):
        """
        Register a new scanner type
        
        Allows plugins to register custom scanners at runtime.
        
        Args:
            scanner_type: Unique scanner type identifier
            scanner_class: Scanner class (must inherit from BaseScanner)
        """
        if not issubclass(scanner_class, BaseScanner):
            raise TypeError(f"Scanner class must inherit from BaseScanner")
        
        cls._scanners[scanner_type] = scanner_class


# Export public API
__all__ = [
    'ScannerFactory',
    'BaseScanner',
    'OSCAPScanner',
    'KubernetesScanner',
]
