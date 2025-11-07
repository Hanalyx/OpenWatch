"""
Compliance Framework Constants

Centralized definitions for supported compliance frameworks and platforms.
Following CLAUDE.md best practices - NO hardcoded values in business logic.

Last Updated: 2025-11-07
"""

from typing import Dict, List

# Supported compliance frameworks
#  These frameworks are validated against MongoDB compliance_rules collection
SUPPORTED_FRAMEWORKS = [
    "nist",
    "cis",
    "stig",
    "pci",
    "disa_stig",
    "nist_800_53",
    "pci_dss",
    "cis-csc",
    "hipaa",
    "iso_27001",
    "cmmc",
    "fedramp",
]

# Framework display names for UI
FRAMEWORK_DISPLAY_NAMES: Dict[str, str] = {
    "nist": "NIST Security Controls",
    "nist_800_53": "NIST SP 800-53",
    "cis": "CIS Benchmarks",
    "cis-csc": "CIS Critical Security Controls",
    "stig": "DISA STIG",
    "disa_stig": "DISA Security Technical Implementation Guide",
    "pci": "PCI Security Standards",
    "pci_dss": "PCI Data Security Standard",
    "hipaa": "HIPAA Security Rule",
    "iso_27001": "ISO/IEC 27001",
    "cmmc": "Cybersecurity Maturity Model Certification",
    "fedramp": "FedRAMP Security Controls",
}

# Supported platforms
SUPPORTED_PLATFORMS = [
    "rhel",
    "ubuntu",
    "debian",
    "centos",
    "fedora",
    "suse",
]

# Platform display names
PLATFORM_DISPLAY_NAMES: Dict[str, str] = {
    "rhel": "Red Hat Enterprise Linux",
    "ubuntu": "Ubuntu",
    "debian": "Debian",
    "centos": "CentOS",
    "fedora": "Fedora",
    "suse": "SUSE Linux Enterprise",
}

# Platform version mappings
PLATFORM_VERSIONS: Dict[str, List[str]] = {
    "rhel": ["7", "8", "9"],
    "ubuntu": ["18.04", "20.04", "22.04", "24.04"],
    "debian": ["10", "11", "12"],
    "centos": ["7", "8", "9"],
    "fedora": ["37", "38", "39"],
    "suse": ["12", "15"],
}


def is_framework_supported(framework: str) -> bool:
    """
    Check if a framework is supported by OpenWatch.

    Args:
        framework: Framework identifier (e.g., 'disa_stig', 'cis')

    Returns:
        True if framework is supported, False otherwise
    """
    return framework.lower() in SUPPORTED_FRAMEWORKS


def is_platform_supported(platform: str) -> bool:
    """
    Check if a platform is supported by OpenWatch.

    Args:
        platform: Platform identifier (e.g., 'rhel', 'ubuntu')

    Returns:
        True if platform is supported, False otherwise
    """
    return platform.lower() in SUPPORTED_PLATFORMS


def get_framework_display_name(framework: str) -> str:
    """
    Get human-readable display name for a framework.

    Args:
        framework: Framework identifier

    Returns:
        Display name or the framework identifier if not found
    """
    return FRAMEWORK_DISPLAY_NAMES.get(framework.lower(), framework)


def get_platform_display_name(platform: str) -> str:
    """
    Get human-readable display name for a platform.

    Args:
        platform: Platform identifier

    Returns:
        Display name or the platform identifier if not found
    """
    return PLATFORM_DISPLAY_NAMES.get(platform.lower(), platform)


def get_supported_versions(platform: str) -> List[str]:
    """
    Get list of supported versions for a platform.

    Args:
        platform: Platform identifier

    Returns:
        List of supported version strings, or empty list if platform not found
    """
    return PLATFORM_VERSIONS.get(platform.lower(), [])
