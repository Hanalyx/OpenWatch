"""
Rule Reference Service

Service for reading and parsing Aegis YAML compliance rules.
Provides rule browsing, search, and metadata extraction for the
Rule Reference UI.

This service reads directly from the Aegis YAML files to provide
a live view of the current rule definitions.
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

logger = logging.getLogger(__name__)

# Path to Aegis rules directory
AEGIS_RULES_PATH = Path(__file__).parent.parent.parent / "aegis" / "rules"


# =============================================================================
# Capability Probe Definitions
# =============================================================================

CAPABILITY_PROBES = {
    "sshd_config_d": {
        "name": "SSH Drop-in Config",
        "description": "SSH daemon uses /etc/ssh/sshd_config.d/ drop-in directory for configuration",
        "detection_method": "Check if /etc/ssh/sshd_config.d/ exists and is enabled",
    },
    "authselect": {
        "name": "Authselect PAM Management",
        "description": "Modern PAM management using authselect (RHEL 8+)",
        "detection_method": "Run 'authselect current' and check for success",
    },
    "crypto_policies": {
        "name": "System Crypto Policies",
        "description": "System-wide cryptographic policies via update-crypto-policies",
        "detection_method": "Check if /etc/crypto-policies/state/current exists",
    },
    "fips_mode": {
        "name": "FIPS 140-2 Mode",
        "description": "System running in FIPS 140-2 validated cryptographic mode",
        "detection_method": "Run 'fips-mode-setup --check' or check /proc/sys/crypto/fips_enabled",
    },
    "firewalld": {
        "name": "Firewalld",
        "description": "Firewalld service is the active firewall",
        "detection_method": "Check if firewalld service is active",
    },
    "nftables": {
        "name": "nftables",
        "description": "nftables is the active firewall backend",
        "detection_method": "Check if nftables service is active",
    },
    "iptables": {
        "name": "iptables",
        "description": "Legacy iptables is the active firewall",
        "detection_method": "Check if iptables rules are loaded",
    },
    "systemd": {
        "name": "systemd Init",
        "description": "System uses systemd as init system",
        "detection_method": "Check if PID 1 is systemd",
    },
    "grub2": {
        "name": "GRUB2 Bootloader",
        "description": "System uses GRUB2 bootloader",
        "detection_method": "Check for /etc/default/grub or grub2-mkconfig",
    },
    "selinux": {
        "name": "SELinux",
        "description": "SELinux is available and enabled",
        "detection_method": "Run 'getenforce' and check for Enforcing/Permissive",
    },
    "audit": {
        "name": "Linux Audit System",
        "description": "auditd service for security auditing",
        "detection_method": "Check if auditd service is active",
    },
    "rsyslog": {
        "name": "rsyslog",
        "description": "rsyslog service for system logging",
        "detection_method": "Check if rsyslog service is active",
    },
    "journald": {
        "name": "systemd-journald",
        "description": "systemd journal for logging",
        "detection_method": "Check if systemd-journald service is active",
    },
    "chrony": {
        "name": "Chrony NTP",
        "description": "Chrony service for time synchronization",
        "detection_method": "Check if chronyd service is active",
    },
    "timesyncd": {
        "name": "systemd-timesyncd",
        "description": "systemd time synchronization service",
        "detection_method": "Check if systemd-timesyncd service is active",
    },
    "aide": {
        "name": "AIDE",
        "description": "AIDE file integrity monitoring",
        "detection_method": "Check if aide package is installed",
    },
    "fapolicyd": {
        "name": "fapolicyd",
        "description": "File Access Policy Daemon for application whitelisting",
        "detection_method": "Check if fapolicyd service is active",
    },
    "dnf_automatic": {
        "name": "DNF Automatic",
        "description": "Automatic package updates via dnf-automatic",
        "detection_method": "Check if dnf-automatic package is installed",
    },
    "subscription_manager": {
        "name": "Subscription Manager",
        "description": "Red Hat Subscription Manager for updates",
        "detection_method": "Check if subscription-manager package is installed",
    },
    "sudo": {
        "name": "sudo",
        "description": "sudo privilege escalation",
        "detection_method": "Check if sudo package is installed",
    },
    "polkit": {
        "name": "PolicyKit",
        "description": "PolicyKit for fine-grained privilege control",
        "detection_method": "Check if polkit service is active",
    },
    "usbguard": {
        "name": "USBGuard",
        "description": "USBGuard for USB device authorization",
        "detection_method": "Check if usbguard service is active",
    },
}

# =============================================================================
# Category Definitions
# =============================================================================

CATEGORY_INFO = {
    "access-control": {
        "name": "Access Control",
        "description": "Rules for authentication, authorization, SSH, PAM, and privilege management",
    },
    "audit": {
        "name": "Audit & Logging",
        "description": "Rules for auditd, audit rules, and security event logging",
    },
    "filesystem": {
        "name": "Filesystem",
        "description": "Rules for file permissions, ownership, and filesystem configuration",
    },
    "network": {
        "name": "Network",
        "description": "Rules for network configuration, firewall, and network services",
    },
    "system": {
        "name": "System Configuration",
        "description": "Rules for kernel parameters, boot configuration, and system hardening",
    },
    "services": {
        "name": "Services",
        "description": "Rules for service management and unnecessary service removal",
    },
    "maintenance": {
        "name": "Maintenance",
        "description": "Rules for patching, updates, and system maintenance",
    },
    "encryption": {
        "name": "Encryption",
        "description": "Rules for cryptographic configuration and data protection",
    },
}

# =============================================================================
# Framework Definitions
# =============================================================================

FRAMEWORK_INFO = {
    "cis": {
        "name": "CIS Benchmarks",
        "description": "Center for Internet Security configuration guidelines",
        "versions": ["rhel8_v4", "rhel9_v2", "rhel10_v1"],
    },
    "stig": {
        "name": "DISA STIGs",
        "description": "Defense Information Systems Agency Security Technical Implementation Guides",
        "versions": ["rhel8_v2r6", "rhel9_v2r7"],
    },
    "nist_800_53": {
        "name": "NIST SP 800-53",
        "description": "NIST Security and Privacy Controls for Information Systems",
        "versions": ["r4", "r5"],
    },
    "pci_dss_4": {
        "name": "PCI DSS 4.0",
        "description": "Payment Card Industry Data Security Standard version 4.0",
        "versions": ["v4.0"],
    },
    "srg": {
        "name": "DISA SRGs",
        "description": "Security Requirements Guides for operating systems",
        "versions": [],
    },
}


class RuleReferenceService:
    """
    Service for reading and parsing Aegis compliance rules.

    Provides methods for:
    - Listing and searching rules
    - Getting rule details
    - Extracting framework mappings
    - Listing categories and capabilities
    - Reading variable definitions
    """

    def __init__(self, rules_path: Optional[Path] = None):
        """
        Initialize the Rule Reference Service.

        Args:
            rules_path: Path to Aegis rules directory. Defaults to AEGIS_RULES_PATH.
        """
        self.rules_path = rules_path or AEGIS_RULES_PATH
        self._rules_cache: Optional[List[Dict[str, Any]]] = None
        self._variables_cache: Optional[Dict[str, Any]] = None

    def _load_rules(self) -> List[Dict[str, Any]]:
        """Load all rules from YAML files."""
        if self._rules_cache is not None:
            return self._rules_cache

        rules = []

        if not self.rules_path.exists():
            logger.warning("Aegis rules path does not exist: %s", self.rules_path)
            return rules

        # Find all YAML files in rules directory (excluding defaults.yml)
        for yaml_file in self.rules_path.rglob("*.yml"):
            if yaml_file.name == "defaults.yml":
                continue

            try:
                with open(yaml_file, encoding="utf-8") as f:
                    rule = yaml.safe_load(f)
                    if rule and isinstance(rule, dict) and "id" in rule:
                        # Add source file for debugging
                        rule["_source_file"] = str(yaml_file.relative_to(self.rules_path))
                        rules.append(rule)
            except Exception as e:
                logger.warning("Failed to load rule from %s: %s", yaml_file, e)

        self._rules_cache = rules
        logger.info("Loaded %d Aegis rules from %s", len(rules), self.rules_path)
        return rules

    def _load_variables(self) -> Dict[str, Any]:
        """Load variables from defaults.yml."""
        if self._variables_cache is not None:
            return self._variables_cache

        defaults_file = self.rules_path / "defaults.yml"
        if not defaults_file.exists():
            logger.warning("defaults.yml not found at %s", defaults_file)
            return {"variables": {}, "frameworks": {}}

        try:
            with open(defaults_file, encoding="utf-8") as f:
                data = yaml.safe_load(f)
                self._variables_cache = data or {"variables": {}, "frameworks": {}}
                return self._variables_cache
        except Exception as e:
            logger.warning("Failed to load defaults.yml: %s", e)
            return {"variables": {}, "frameworks": {}}

    def clear_cache(self) -> None:
        """Clear cached rules and variables."""
        self._rules_cache = None
        self._variables_cache = None

    # =========================================================================
    # Rule Listing and Search
    # =========================================================================

    def list_rules(
        self,
        search: Optional[str] = None,
        framework: Optional[str] = None,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        capability: Optional[str] = None,
        tags: Optional[List[str]] = None,
        platform: Optional[str] = None,
        has_remediation: Optional[bool] = None,
        page: int = 1,
        per_page: int = 50,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """
        List rules with optional filters.

        Args:
            search: Search in title, description, tags
            framework: Filter by framework (cis, stig, nist_800_53)
            category: Filter by category
            severity: Filter by severity
            capability: Filter by required capability
            tags: Filter by tags (any match)
            platform: Filter by platform (rhel8, rhel9)
            has_remediation: Filter by remediation availability
            page: Page number (1-indexed)
            per_page: Items per page

        Returns:
            Tuple of (paginated rules, total count)
        """
        rules = self._load_rules()

        # Apply filters
        filtered = []
        for rule in rules:
            # Search filter
            if search:
                search_lower = search.lower()
                title = rule.get("title", "").lower()
                desc = rule.get("description", "").lower()
                rule_tags = [t.lower() for t in rule.get("tags", [])]
                rule_id = rule.get("id", "").lower()

                if not (
                    search_lower in title
                    or search_lower in desc
                    or search_lower in rule_id
                    or any(search_lower in t for t in rule_tags)
                ):
                    continue

            # Framework filter
            if framework:
                refs = rule.get("references", {})
                if framework.lower() not in [k.lower() for k in refs.keys()]:
                    continue

            # Category filter
            if category and rule.get("category", "").lower() != category.lower():
                continue

            # Severity filter
            if severity and rule.get("severity", "").lower() != severity.lower():
                continue

            # Capability filter
            if capability:
                implementations = rule.get("implementations", [])
                cap_found = False
                for impl in implementations:
                    when_cap = impl.get("when")
                    # Only match string capabilities
                    if when_cap and isinstance(when_cap, str) and when_cap.lower() == capability.lower():
                        cap_found = True
                        break
                if not cap_found:
                    continue

            # Tags filter (any match)
            if tags:
                rule_tags = [t.lower() for t in rule.get("tags", [])]
                if not any(t.lower() in rule_tags for t in tags):
                    continue

            # Platform filter
            if platform:
                platforms = rule.get("platforms", [])
                platform_match = any(platform.lower() in p.get("family", "").lower() for p in platforms)
                if not platform_match:
                    continue

            # Has remediation filter
            if has_remediation is not None:
                implementations = rule.get("implementations", [])
                has_remed = any(impl.get("remediation") for impl in implementations)
                if has_remediation and not has_remed:
                    continue
                if not has_remediation and has_remed:
                    continue

            filtered.append(rule)

        # Calculate pagination
        total = len(filtered)
        start = (page - 1) * per_page
        end = start + per_page
        paginated = filtered[start:end]

        return paginated, total

    def get_rule(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a single rule by ID.

        Args:
            rule_id: The rule ID

        Returns:
            Rule dict or None if not found
        """
        rules = self._load_rules()
        for rule in rules:
            if rule.get("id") == rule_id:
                return rule
        return None

    # =========================================================================
    # Framework and Category Methods
    # =========================================================================

    def list_frameworks(self) -> List[Dict[str, Any]]:
        """
        List available frameworks with rule counts.

        Returns:
            List of framework info dicts
        """
        rules = self._load_rules()

        frameworks = []
        for fw_id, fw_info in FRAMEWORK_INFO.items():
            # Count rules with this framework
            count = 0
            for rule in rules:
                refs = rule.get("references", {})
                if fw_id in refs:
                    count += 1

            frameworks.append(
                {
                    "id": fw_id,
                    "name": fw_info["name"],
                    "description": fw_info["description"],
                    "versions": fw_info["versions"],
                    "rule_count": count,
                }
            )

        return frameworks

    def list_categories(self) -> List[Dict[str, Any]]:
        """
        List rule categories with rule counts.

        Returns:
            List of category info dicts
        """
        rules = self._load_rules()

        # Count rules per category
        category_counts: Dict[str, int] = {}
        for rule in rules:
            cat = rule.get("category", "unknown")
            category_counts[cat] = category_counts.get(cat, 0) + 1

        categories = []
        for cat_id, cat_info in CATEGORY_INFO.items():
            categories.append(
                {
                    "id": cat_id,
                    "name": cat_info["name"],
                    "description": cat_info["description"],
                    "rule_count": category_counts.get(cat_id, 0),
                }
            )

        # Add any categories found in rules but not in CATEGORY_INFO
        for cat_id, count in category_counts.items():
            if cat_id not in CATEGORY_INFO:
                categories.append(
                    {
                        "id": cat_id,
                        "name": cat_id.replace("-", " ").title(),
                        "description": f"Rules in the {cat_id} category",
                        "rule_count": count,
                    }
                )

        return sorted(categories, key=lambda x: x["rule_count"], reverse=True)

    # =========================================================================
    # Variable Methods
    # =========================================================================

    def list_variables(self) -> List[Dict[str, Any]]:
        """
        List configurable variables with framework overrides.

        Returns:
            List of variable definitions
        """
        data = self._load_variables()
        variables = data.get("variables", {})
        frameworks = data.get("frameworks", {})
        rules = self._load_rules()

        # Find which rules use each variable
        variable_usage: Dict[str, List[str]] = {}
        for rule in rules:
            implementations = rule.get("implementations", [])
            for impl in implementations:
                check = impl.get("check", {})
                expected = check.get("expected", "")
                if isinstance(expected, str) and "{{" in expected:
                    # Extract variable names
                    import re

                    var_matches = re.findall(r"\{\{\s*(\w+)\s*\}\}", expected)
                    for var_name in var_matches:
                        if var_name not in variable_usage:
                            variable_usage[var_name] = []
                        if rule["id"] not in variable_usage[var_name]:
                            variable_usage[var_name].append(rule["id"])

        # Build variable list
        result = []
        for var_name, default_value in variables.items():
            # Get framework overrides
            overrides = {}
            for fw_id, fw_vars in frameworks.items():
                if var_name in fw_vars:
                    overrides[fw_id] = fw_vars[var_name]

            result.append(
                {
                    "name": var_name,
                    "default_value": default_value,
                    "description": self._get_variable_description(var_name),
                    "framework_overrides": overrides,
                    "used_by_rules": variable_usage.get(var_name, []),
                }
            )

        return result

    def _get_variable_description(self, var_name: str) -> str:
        """Get description for a variable based on its name."""
        descriptions = {
            "pam_pwquality_minlen": "Minimum password length",
            "pam_pwquality_minclass": "Minimum character classes in password",
            "pam_pwquality_difok": "Minimum characters different from old password",
            "pam_pwquality_maxrepeat": "Maximum consecutive repeating characters",
            "pam_pwquality_maxclassrepeat": "Maximum consecutive same-class characters",
            "pam_pwquality_dcredit": "Credit for digits (-N requires N digits)",
            "pam_pwquality_ucredit": "Credit for uppercase (-N requires N uppercase)",
            "pam_pwquality_lcredit": "Credit for lowercase (-N requires N lowercase)",
            "pam_pwquality_ocredit": "Credit for special chars (-N requires N special)",
            "pam_faillock_deny": "Failed login attempts before lockout",
            "pam_faillock_fail_interval": "Time window for counting failures (seconds)",
            "pam_faillock_unlock_time": "Lockout duration (0 = permanent until admin)",
            "login_defs_pass_max_days": "Maximum password age (days)",
            "login_defs_pass_min_days": "Minimum password age (days)",
            "login_defs_pass_warn_age": "Password expiry warning (days before)",
            "login_defs_umask": "Default umask for new users",
            "password_remember": "Number of previous passwords to remember",  # pragma: allowlist secret
            "ssh_client_alive_interval": "SSH idle timeout interval (seconds)",
            "ssh_client_alive_count_max": "SSH keepalive count before disconnect",
            "ssh_max_auth_tries": "Maximum SSH authentication attempts",
            "ssh_max_sessions": "Maximum SSH sessions per connection",
            "ssh_login_grace_time": "SSH login grace period (seconds)",
        }
        return descriptions.get(var_name, f"Configuration variable: {var_name}")

    # =========================================================================
    # Capability Methods
    # =========================================================================

    def list_capabilities(self) -> List[Dict[str, Any]]:
        """
        List capability probes with rule counts.

        Returns:
            List of capability probe info
        """
        rules = self._load_rules()

        # Count rules requiring each capability
        cap_counts: Dict[str, int] = {}
        for rule in rules:
            implementations = rule.get("implementations", [])
            for impl in implementations:
                when_cap = impl.get("when")
                # Only count string capabilities (ignore dict/list structures)
                if when_cap and isinstance(when_cap, str):
                    cap_counts[when_cap] = cap_counts.get(when_cap, 0) + 1

        capabilities = []
        for cap_id, cap_info in CAPABILITY_PROBES.items():
            capabilities.append(
                {
                    "id": cap_id,
                    "name": cap_info["name"],
                    "description": cap_info["description"],
                    "detection_method": cap_info["detection_method"],
                    "rules_requiring": cap_counts.get(cap_id, 0),
                }
            )

        # Add any capabilities found in rules but not in CAPABILITY_PROBES
        for cap_id, count in cap_counts.items():
            if cap_id not in CAPABILITY_PROBES:
                capabilities.append(
                    {
                        "id": cap_id,
                        "name": cap_id.replace("_", " ").title(),
                        "description": f"Capability: {cap_id}",
                        "detection_method": "Detection method not documented",
                        "rules_requiring": count,
                    }
                )

        return sorted(capabilities, key=lambda x: x["rules_requiring"], reverse=True)

    # =========================================================================
    # Statistics
    # =========================================================================

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get rule statistics.

        Returns:
            Statistics dict with counts by severity, category, framework
        """
        rules = self._load_rules()

        stats = {
            "total_rules": len(rules),
            "by_severity": {},
            "by_category": {},
            "by_framework": {},
            "with_remediation": 0,
            "without_remediation": 0,
        }

        for rule in rules:
            # Severity
            sev = rule.get("severity", "unknown")
            stats["by_severity"][sev] = stats["by_severity"].get(sev, 0) + 1

            # Category
            cat = rule.get("category", "unknown")
            stats["by_category"][cat] = stats["by_category"].get(cat, 0) + 1

            # Frameworks
            refs = rule.get("references", {})
            for fw in refs.keys():
                stats["by_framework"][fw] = stats["by_framework"].get(fw, 0) + 1

            # Remediation
            implementations = rule.get("implementations", [])
            has_remed = any(impl.get("remediation") for impl in implementations)
            if has_remed:
                stats["with_remediation"] += 1
            else:
                stats["without_remediation"] += 1

        return stats


# Singleton instance
_service_instance: Optional[RuleReferenceService] = None


def get_rule_reference_service() -> RuleReferenceService:
    """Get the singleton RuleReferenceService instance."""
    global _service_instance
    if _service_instance is None:
        _service_instance = RuleReferenceService()
    return _service_instance


__all__ = [
    "RuleReferenceService",
    "get_rule_reference_service",
    "CAPABILITY_PROBES",
    "CATEGORY_INFO",
    "FRAMEWORK_INFO",
]
