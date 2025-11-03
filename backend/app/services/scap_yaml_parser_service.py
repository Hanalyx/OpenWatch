#!/usr/bin/env python3
"""
SCAP YAML Parser Service - Extract XCCDF Variables and Remediation Content

This service parses SCAP YAML rules (ComplianceAsCode format) to extract:
- XCCDF variable definitions (for Solution A scan-time customization)
- Remediation content (Ansible, Bash scripts)
- Scanner type detection (oscap vs custom scanners)

Part of Phase 1, Issue #2: Enhanced SCAP Converter with Variable Extraction
"""

import re
from typing import Dict, List, Any, Optional, Set
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class XCCDFVariableExtractor:
    """
    Extracts XCCDF variable definitions from SCAP YAML rules

    XCCDF variables enable scan-time customization of compliance checks.
    These are referenced in rule templates and can be overridden by users.

    Examples:
        - var_accounts_tmout: Session timeout (300-3600 seconds)
        - login_banner_text: Custom login banner
        - var_password_pam_minlen: Minimum password length
    """

    # Common XCCDF variable patterns in YAML
    VARIABLE_PATTERNS = [
        r"{{% set\s+(\w+)\s*=\s*(.+?)\s*%}}",  # Jinja2 set
        r"\$(\w+)",  # Shell variable
        r"{{{?\s*(\w+)\s*}}}?",  # Jinja2 variable reference
    ]

    # Variable type inference from naming conventions
    TYPE_INFERENCE = {
        "timeout": "number",
        "minlen": "number",
        "maxlen": "number",
        "min_": "number",
        "max_": "number",
        "count": "number",
        "banner": "string",
        "text": "string",
        "password": "string",
        "enabled": "boolean",
        "disabled": "boolean",
        "enforce": "boolean",
    }

    def extract_variables(self, rule_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Extract XCCDF variables from SCAP rule

        Args:
            rule_data: Parsed YAML rule data

        Returns:
            Dict mapping variable IDs to XCCDFVariable definitions or None
        """
        variables = {}

        # Extract from template vars (most reliable source)
        template = rule_data.get("template", {})
        if template and isinstance(template, dict):
            template_vars = template.get("vars", {})
            for var_id, var_value in template_vars.items():
                # Skip internal template variables (starts with underscore or is internal)
                if var_id.startswith("_") or var_id in [
                    "name",
                    "ocp_data",
                    "filepath",
                    "yamlpath",
                ]:
                    continue

                var_def = self._create_variable_definition(var_id, var_value, rule_data)
                if var_def:
                    variables[var_id] = var_def

        # Extract from description text (look for variable references)
        description = rule_data.get("description", "")
        var_refs = self._find_variable_references(description)

        for var_ref in var_refs:
            if var_ref not in variables:
                # Create placeholder variable definition
                var_def = self._create_placeholder_variable(var_ref, rule_data)
                if var_def:
                    variables[var_ref] = var_def

        return variables if variables else None

    def _create_variable_definition(
        self, var_id: str, var_value: Any, rule_data: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Create XCCDFVariable definition from template variable

        Args:
            var_id: Variable identifier
            var_value: Variable default value
            rule_data: Full rule data for context

        Returns:
            XCCDFVariable dict or None
        """
        # Determine variable type
        var_type = self._infer_type(var_id, var_value)

        # Create variable definition
        var_def = {
            "id": var_id,
            "title": self._generate_title(var_id),
            "description": self._extract_variable_description(var_id, rule_data),
            "type": var_type,
            "default_value": str(var_value),
            "interactive": True,  # Most template vars are user-customizable
            "sensitive": self._is_sensitive(var_id),
        }

        # Add constraints if we can infer them
        constraints = self._infer_constraints(var_id, var_value, var_type)
        if constraints:
            var_def["constraints"] = constraints

        return var_def

    def _create_placeholder_variable(
        self, var_id: str, rule_data: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Create placeholder for variable referenced but not defined
        """
        return {
            "id": var_id,
            "title": self._generate_title(var_id),
            "description": f"Referenced in rule but not explicitly defined. May be inherited from profile.",
            "type": "string",  # Conservative default
            "default_value": "",
            "interactive": True,
            "sensitive": self._is_sensitive(var_id),
        }

    def _infer_type(self, var_id: str, var_value: Any) -> str:
        """Infer XCCDF variable type"""
        if isinstance(var_value, bool):
            return "boolean"
        if isinstance(var_value, (int, float)):
            return "number"

        if isinstance(var_value, str):
            if var_value.lower() in ("true", "false", "yes", "no", "0", "1"):
                return "boolean"
            try:
                float(var_value)
                return "number"
            except ValueError:
                pass

        var_id_lower = var_id.lower()
        for pattern, var_type in self.TYPE_INFERENCE.items():
            if pattern in var_id_lower:
                return var_type

        return "string"

    def _generate_title(self, var_id: str) -> str:
        """Generate human-readable title from variable ID"""
        title = var_id.replace("_", " ").replace("var ", "").title()
        return title

    def _extract_variable_description(
        self, var_id: str, rule_data: Dict[str, Any]
    ) -> Optional[str]:
        """Extract variable description from rule metadata"""
        description = rule_data.get("description", "")
        if var_id in description:
            sentences = description.split(".")
            for sentence in sentences:
                if var_id in sentence:
                    return sentence.strip()

        rationale = rule_data.get("rationale", "")
        if var_id in rationale:
            sentences = rationale.split(".")
            for sentence in sentences:
                if var_id in sentence:
                    return sentence.strip()

        return None

    def _is_sensitive(self, var_id: str) -> bool:
        """Determine if variable contains sensitive data"""
        sensitive_patterns = [
            "password",
            "passwd",
            "secret",
            "key",
            "private",
            "credential",
            "token",
            "api_key",
            "auth",
        ]
        var_id_lower = var_id.lower()
        return any(pattern in var_id_lower for pattern in sensitive_patterns)

    def _infer_constraints(
        self, var_id: str, var_value: Any, var_type: str
    ) -> Optional[Dict[str, Any]]:
        """Infer validation constraints"""
        constraints = {}

        if var_type == "number":
            if "timeout" in var_id.lower() or "tmout" in var_id.lower():
                constraints["min_value"] = 60
                constraints["max_value"] = 3600
            elif "minlen" in var_id.lower():
                constraints["min_value"] = 6
                constraints["max_value"] = 128
            elif "maxlen" in var_id.lower():
                constraints["min_value"] = 8
                constraints["max_value"] = 256

        elif var_type == "string":
            if "banner" in var_id.lower() or "text" in var_id.lower():
                constraints["min_length"] = 1
                constraints["max_length"] = 1024

            if "password" in var_id.lower() and "grub" in var_id.lower():
                constraints["pattern"] = r"^grub\.pbkdf2\.sha512\."

        return constraints if constraints else None

    def _find_variable_references(self, text: str) -> Set[str]:
        """Find all variable references in text"""
        var_refs = set()

        for pattern in self.VARIABLE_PATTERNS:
            matches = re.findall(pattern, text)
            if matches:
                if isinstance(matches[0], tuple):
                    matches = [m[0] for m in matches]
                var_refs.update(matches)

        filtered = {v for v in var_refs if v.startswith("var_") or len(v) > 3}

        return filtered


class RemediationExtractor:
    """Extract remediation content from SCAP rules"""

    # Template to Ansible module mappings
    TEMPLATE_MAPPINGS = {
        "sysctl": "ansible.posix.sysctl",
        "file_permissions": "ansible.builtin.file",
        "file_owner": "ansible.builtin.file",
        "file_groupowner": "ansible.builtin.file",
        "service_enabled": "ansible.builtin.systemd",
        "service_disabled": "ansible.builtin.systemd",
        "package_installed": "ansible.builtin.package",
        "package_removed": "ansible.builtin.package",
        "mount_option": "ansible.posix.mount",
        "kernel_module_disabled": "community.general.kernel_blacklist",
        "audit_rules": "ansible.builtin.lineinfile",
        "grub2_argument": "ansible.builtin.lineinfile",
        "yamlfile_value": None,  # K8s/OpenShift - no Ansible needed
    }

    def extract_remediations(
        self, rule_data: Dict[str, Any], rule_file: Path
    ) -> Optional[Dict[str, Any]]:
        """Extract all remediation content from SCAP rule"""
        remediations = {}

        # Extract from template
        template = rule_data.get("template", {})
        if template and isinstance(template, dict):
            template_name = template.get("name", "")
            template_vars = template.get("vars", {})

            remediation_content = self._extract_from_template(template_name, template_vars)
            if remediation_content:
                remediations.update(remediation_content)

        # Check for separate remediation files
        rule_dir = rule_file.parent
        remediation_files = self._find_remediation_files(rule_dir)

        for rem_type, rem_file in remediation_files.items():
            try:
                with open(rem_file, "r", encoding="utf-8") as f:
                    remediations[rem_type] = f.read()
            except Exception as e:
                logger.warning(f"Could not read remediation file {rem_file}: {e}")

        return remediations if remediations else None

    def _extract_from_template(
        self, template_name: str, template_vars: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Extract remediation from template definition"""
        remediations = {}

        if template_name in self.TEMPLATE_MAPPINGS:
            ansible_module = self.TEMPLATE_MAPPINGS[template_name]

            if ansible_module:
                ansible_task = self._generate_ansible_task(ansible_module, template_vars)
                remediations["ansible"] = ansible_task

            bash_script = self._generate_bash_script(template_name, template_vars)
            if bash_script:
                remediations["bash"] = bash_script

        return remediations

    def _generate_ansible_task(self, module_name: str, vars_dict: Dict[str, Any]) -> str:
        """Generate Ansible task YAML"""
        import yaml

        task = {
            "name": f"Apply {module_name} configuration",
            module_name: self._map_vars_to_module_params(module_name, vars_dict),
        }
        return yaml.dump([task], default_flow_style=False, sort_keys=False)

    def _map_vars_to_module_params(
        self, module_name: str, vars_dict: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Map template variables to Ansible module parameters"""
        params = {}

        if "sysctl" in module_name:
            params["name"] = vars_dict.get("sysctlvar", vars_dict.get("name"))
            params["value"] = vars_dict.get("sysctlval", vars_dict.get("value"))
            params["state"] = "present"
            params["reload"] = True

        elif "file" in module_name:
            params["path"] = vars_dict.get("filepath", vars_dict.get("path"))
            if "filemode" in vars_dict:
                params["mode"] = vars_dict["filemode"]
            if "fileuid" in vars_dict:
                params["owner"] = vars_dict["fileuid"]
            if "filegid" in vars_dict:
                params["group"] = vars_dict["filegid"]

        elif "systemd" in module_name or "service" in module_name:
            params["name"] = vars_dict.get("servicename", vars_dict.get("name"))
            params["enabled"] = vars_dict.get("servicestate") != "disabled"
            params["state"] = "started" if params["enabled"] else "stopped"

        elif "package" in module_name:
            params["name"] = vars_dict.get("packagename", vars_dict.get("name"))
            params["state"] = "present" if "installed" in module_name else "absent"

        else:
            params = vars_dict.copy()

        return params

    def _generate_bash_script(self, template_name: str, vars_dict: Dict[str, Any]) -> Optional[str]:
        """Generate Bash script for simple remediation"""
        script_lines = ["#!/bin/bash", f"# Apply {template_name} configuration", ""]

        if template_name == "sysctl":
            sysctl_var = vars_dict.get("sysctlvar")
            sysctl_val = vars_dict.get("sysctlval")
            if sysctl_var and sysctl_val is not None:
                script_lines.append(f"sysctl -w {sysctl_var}={sysctl_val}")
                script_lines.append(f'echo "{sysctl_var} = {sysctl_val}" >> /etc/sysctl.conf')
                return "\n".join(script_lines)

        elif template_name in ["file_permissions", "file_owner", "file_groupowner"]:
            filepath = vars_dict.get("filepath")
            if filepath:
                if "filemode" in vars_dict:
                    script_lines.append(f'chmod {vars_dict["filemode"]} {filepath}')
                if "fileuid" in vars_dict:
                    script_lines.append(f'chown {vars_dict["fileuid"]} {filepath}')
                if "filegid" in vars_dict:
                    script_lines.append(f'chgrp {vars_dict["filegid"]} {filepath}')
                return "\n".join(script_lines)

        elif template_name in ["service_enabled", "service_disabled"]:
            service = vars_dict.get("servicename")
            if service:
                action = "enable" if "enabled" in template_name else "disable"
                script_lines.append(f"systemctl {action} {service}")
                script_lines.append(
                    f'systemctl {"start" if action == "enable" else "stop"} {service}'
                )
                return "\n".join(script_lines)

        return None

    def _find_remediation_files(self, rule_dir: Path) -> Dict[str, Path]:
        """Find separate remediation files in rule directory"""
        remediation_files = {}

        ansible_file = rule_dir / "ansible" / "shared.yml"
        if ansible_file.exists():
            remediation_files["ansible"] = ansible_file

        bash_file = rule_dir / "bash" / "shared.sh"
        if bash_file.exists():
            remediation_files["bash"] = bash_file

        puppet_file = rule_dir / "puppet" / "shared.pp"
        if puppet_file.exists():
            remediation_files["puppet"] = puppet_file

        return remediation_files


class ScannerTypeDetector:
    """Detects scanner type from SCAP rule metadata"""

    PLATFORM_SCANNER_MAPPINGS = {
        "kubernetes": "kubernetes",
        "openshift": "kubernetes",
        "docker": "docker",
        "podman": "docker",
        "aws": "aws_api",
        "azure": "azure_api",
        "gcp": "gcp_api",
    }

    def detect_scanner(self, rule_data: Dict[str, Any], rule_file: Path) -> str:
        """Detect scanner type from rule metadata"""
        # Method 1: Detect from template name
        template = rule_data.get("template", {})
        if template and isinstance(template, dict):
            template_name = template.get("name", "")

            if template_name == "yamlfile_value":
                template_vars = template.get("vars", {})
                if template_vars.get("ocp_data") == "true":
                    return "kubernetes"

            if "aws" in template_name.lower():
                return "aws_api"
            if "azure" in template_name.lower():
                return "azure_api"
            if "gcp" in template_name.lower():
                return "gcp_api"

        # Method 2: Detect from file path
        path_str = str(rule_file).lower()
        for platform, scanner in self.PLATFORM_SCANNER_MAPPINGS.items():
            if platform in path_str:
                return scanner

        # Default: OSCAP for traditional Linux/Unix compliance
        return "oscap"


def extract_scap_metadata(rule_data: Dict[str, Any], rule_file: Path) -> Dict[str, Any]:
    """
    Extract all SCAP metadata (variables, remediation, scanner type)

    Args:
        rule_data: Parsed YAML rule data
        rule_file: Path to rule.yml file

    Returns:
        Dict with keys: xccdf_variables, remediation, scanner_type
    """
    var_extractor = XCCDFVariableExtractor()
    rem_extractor = RemediationExtractor()
    scanner_detector = ScannerTypeDetector()

    return {
        "xccdf_variables": var_extractor.extract_variables(rule_data),
        "remediation": rem_extractor.extract_remediations(rule_data, rule_file),
        "scanner_type": scanner_detector.detect_scanner(rule_data, rule_file),
    }
