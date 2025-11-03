"""
SCAP XML Parser Service for OpenWatch
Parses XCCDF rules from SCAP datastream files and prepares them for MongoDB import
"""

import xml.etree.ElementTree as ET
import hashlib
import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class SCAPParserService:
    """Service for parsing SCAP XML datastream files"""

    # XML namespaces used in SCAP files
    NAMESPACES = {
        "ds": "http://scap.nist.gov/schema/scap/source/1.2",
        "xccdf": "http://checklists.nist.gov/xccdf/1.2",
        "xccdf-1.2": "http://checklists.nist.gov/xccdf/1.2",
        "oval": "http://oval.mitre.org/XMLSchema/oval-common-5",
        "oval-def": "http://oval.mitre.org/XMLSchema/oval-definitions-5",
        "cpe-dict": "http://cpe.mitre.org/dictionary/2.0",
        "dc": "http://purl.org/dc/elements/1.1/",
        "xlink": "http://www.w3.org/1999/xlink",
        "html": "http://www.w3.org/1999/xhtml",
    }

    # Framework reference mapping
    FRAMEWORK_MAPPINGS = {
        "nist": {
            "pattern": r"NIST-800-53",
            "version_patterns": {
                "800-53r4": r"NIST.*800-53.*r4|NIST.*800-53.*Revision 4",
                "800-53r5": r"NIST.*800-53.*r5|NIST.*800-53.*Revision 5",
            },
        },
        "cis": {
            "pattern": r"CIS",
            "version_extraction": r"CIS.*v?(\d+\.\d+(?:\.\d+)?)",
        },
        "stig": {"pattern": r"DISA.*STIG|stigid", "id_extraction": r"([A-Z]+-\d+-\d+)"},
        "pci_dss": {
            "pattern": r"PCI.*DSS",
            "version_extraction": r"PCI.*DSS.*v?(\d+\.\d+(?:\.\d+)?)",
        },
        "hipaa": {"pattern": r"HIPAA", "section_extraction": r"§?\s*(\d+\.\d+)"},
        "iso27001": {
            "pattern": r"ISO.*27001",
            "control_extraction": r"(\d+\.\d+\.\d+)",
        },
    }

    def __init__(self):
        self.rules_parsed = 0
        self.errors = []
        self.warnings = []

    def parse_scap_file(self, file_path: str) -> Dict[str, Any]:
        """Parse a SCAP datastream file and extract all rules"""
        logger.info(f"Starting SCAP file parsing: {file_path}")

        result = {
            "file_path": file_path,
            "file_hash": self._calculate_file_hash(file_path),
            "parsed_at": datetime.utcnow().isoformat(),
            "rules": [],
            "metadata": {},
            "statistics": {
                "total_rules": 0,
                "rules_by_severity": {},
                "rules_by_category": {},
                "framework_coverage": {},
            },
            "errors": [],
            "warnings": [],
        }

        try:
            # Parse XML file
            tree = ET.parse(file_path)
            root = tree.getroot()

            # Extract datastream metadata
            result["metadata"] = self._extract_datastream_metadata(root)

            # Find the Benchmark element
            benchmark = self._find_benchmark(root)
            if benchmark is None:
                raise ValueError("No Benchmark element found in SCAP file")

            # Extract benchmark metadata
            result["metadata"]["benchmark"] = self._extract_benchmark_metadata(benchmark)

            # Parse all rules
            rules = self._parse_all_rules(benchmark)
            result["rules"] = rules

            # Calculate statistics
            result["statistics"] = self._calculate_statistics(rules)
            result["statistics"]["total_rules"] = len(rules)

            # Add any errors/warnings
            result["errors"] = self.errors
            result["warnings"] = self.warnings

            logger.info(f"Successfully parsed {len(rules)} rules from {file_path}")

        except Exception as e:
            logger.error(f"Failed to parse SCAP file: {str(e)}")
            result["errors"].append({"type": "parse_error", "message": str(e), "file": file_path})

        return result

    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of the file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def _find_benchmark(self, root: ET.Element) -> Optional[ET.Element]:
        """Find the Benchmark element in the datastream"""
        # Try direct path first
        benchmark = root.find(".//xccdf-1.2:Benchmark", self.NAMESPACES)
        if benchmark is not None:
            return benchmark

        # Try alternative namespace
        benchmark = root.find(".//xccdf:Benchmark", self.NAMESPACES)
        if benchmark is not None:
            return benchmark

        # Try without namespace
        for elem in root.iter():
            if elem.tag.endswith("Benchmark"):
                return elem

        return None

    def _extract_datastream_metadata(self, root: ET.Element) -> Dict[str, Any]:
        """Extract metadata from the datastream"""
        metadata = {
            "datastream_id": root.get("id", "unknown"),
            "schematron_version": root.get("schematron-version"),
            "components": [],
        }

        # Find datastream components
        for ds in root.findall(".//ds:data-stream", self.NAMESPACES):
            metadata["components"].append(
                {
                    "id": ds.get("id"),
                    "scap_version": ds.get("scap-version"),
                    "use_case": ds.get("use-case"),
                }
            )

        return metadata

    def _extract_benchmark_metadata(self, benchmark: ET.Element) -> Dict[str, Any]:
        """Extract metadata from the Benchmark element"""
        metadata = {
            "id": benchmark.get("id", "unknown"),
            "resolved": benchmark.get("resolved", "false"),
            "style": benchmark.get("style"),
            "lang": benchmark.get("{http://www.w3.org/XML/1998/namespace}lang", "en-US"),
        }

        # Extract title
        title = benchmark.find(".//xccdf-1.2:title", self.NAMESPACES)
        if title is None:
            title = benchmark.find(".//xccdf:title", self.NAMESPACES)
        if title is not None:
            metadata["title"] = title.text

        # Extract description
        desc = benchmark.find(".//xccdf-1.2:description", self.NAMESPACES)
        if desc is None:
            desc = benchmark.find(".//xccdf:description", self.NAMESPACES)
        if desc is not None:
            metadata["description"] = self._extract_text_content(desc)

        # Extract version
        version = benchmark.find(".//xccdf-1.2:version", self.NAMESPACES)
        if version is None:
            version = benchmark.find(".//xccdf:version", self.NAMESPACES)
        if version is not None:
            metadata["version"] = version.text

        # Extract status
        status = benchmark.find(".//xccdf-1.2:status", self.NAMESPACES)
        if status is None:
            status = benchmark.find(".//xccdf:status", self.NAMESPACES)
        if status is not None:
            metadata["status"] = status.text
            metadata["status_date"] = status.get("date")

        return metadata

    def _parse_all_rules(self, benchmark: ET.Element) -> List[Dict[str, Any]]:
        """Parse all Rule elements from the benchmark"""
        rules = []

        # Find all Rule elements
        rule_elements = benchmark.findall(".//xccdf-1.2:Rule", self.NAMESPACES)
        if not rule_elements:
            rule_elements = benchmark.findall(".//xccdf:Rule", self.NAMESPACES)

        logger.info(f"Found {len(rule_elements)} rule elements to parse")

        for rule_elem in rule_elements:
            try:
                rule = self._parse_rule(rule_elem)
                if rule:
                    rules.append(rule)
                    self.rules_parsed += 1
            except Exception as e:
                rule_id = rule_elem.get("id", "unknown")
                logger.error(f"Failed to parse rule {rule_id}: {str(e)}")
                self.errors.append({"rule_id": rule_id, "error": str(e)})

        return rules

    def _parse_rule(self, rule_elem: ET.Element) -> Dict[str, Any]:
        """Parse a single Rule element"""
        rule_id = rule_elem.get("id", "")
        if not rule_id:
            return None

        rule = {
            "scap_rule_id": rule_id,
            "selected": rule_elem.get("selected", "true") == "true",
            "severity": rule_elem.get("severity", "unknown").lower(),
            "weight": rule_elem.get("weight", "1.0"),
            "metadata": {
                "title": self._get_element_text(rule_elem, ["title"]),
                "description": self._get_element_text(rule_elem, ["description"]),
                "rationale": self._get_element_text(rule_elem, ["rationale"]),
                "warning": self._get_element_text(rule_elem, ["warning"]),
                "requires": self._get_element_text(rule_elem, ["requires"]),
                "conflicts": self._get_element_text(rule_elem, ["conflicts"]),
            },
            "references": self._extract_references(rule_elem),
            "identifiers": self._extract_identifiers(rule_elem),
            "check": self._extract_check_content(rule_elem),
            "fix": self._extract_fix_content(rule_elem),
            "complex_check": self._extract_complex_check(rule_elem),
            "platform": self._extract_platform_info(rule_elem),
            "profiles": self._extract_profile_membership(rule_elem),
            "tags": self._extract_tags(rule_elem),
            "frameworks": self._map_to_frameworks(rule_elem),
        }

        # Determine category from rule ID and content
        rule["category"] = self._determine_category(rule)

        # Extract security function
        rule["security_function"] = self._determine_security_function(rule)

        return rule

    def _get_element_text(self, parent: ET.Element, tags: List[str]) -> Optional[str]:
        """Get text content from child elements"""
        for tag in tags:
            # Try with namespaces
            elem = parent.find(f".//xccdf-1.2:{tag}", self.NAMESPACES)
            if elem is None:
                elem = parent.find(f".//xccdf:{tag}", self.NAMESPACES)
            if elem is None:
                elem = parent.find(f".//{tag}")

            if elem is not None:
                return self._extract_text_content(elem)

        return None

    def _extract_text_content(self, elem: ET.Element) -> str:
        """Extract text content including HTML tags"""
        if elem.text:
            text = elem.text
        else:
            text = ""

        # Handle HTML content
        for child in elem:
            if child.tag.endswith("br"):
                text += "\n"
            elif child.tag.endswith("code"):
                text += f"`{child.text or ''}`"
            elif child.tag.endswith("em"):
                text += f"_{child.text or ''}_"
            elif child.tag.endswith("strong"):
                text += f"**{child.text or ''}**"
            else:
                text += child.text or ""
            text += child.tail or ""

        return text.strip()

    def _extract_references(self, rule_elem: ET.Element) -> Dict[str, List[str]]:
        """Extract all references from the rule"""
        references = {}

        for ref in rule_elem.findall(".//xccdf-1.2:reference", self.NAMESPACES):
            ref_text = ref.text
            href = ref.get("href", "")

            # Try to categorize the reference
            if "nist" in ref_text.lower() or "nist" in href.lower():
                framework = "nist"
            elif "cis" in ref_text.lower() or "cis" in href.lower():
                framework = "cis"
            elif "stig" in ref_text.lower() or "disa" in ref_text.lower():
                framework = "stig"
            elif "pci" in ref_text.lower():
                framework = "pci_dss"
            elif "hipaa" in ref_text.lower():
                framework = "hipaa"
            elif "iso" in ref_text.lower() and "27001" in ref_text:
                framework = "iso27001"
            else:
                framework = "other"

            if framework not in references:
                references[framework] = []
            references[framework].append({"text": ref_text, "href": href})

        return references

    def _extract_identifiers(self, rule_elem: ET.Element) -> Dict[str, str]:
        """Extract rule identifiers"""
        identifiers = {}

        for ident in rule_elem.findall(".//xccdf-1.2:ident", self.NAMESPACES):
            system = ident.get("system", "unknown")
            value = ident.text

            # Map system to a simple key
            if "cce" in system.lower():
                identifiers["cce"] = value
            elif "cve" in system.lower():
                identifiers["cve"] = value
            elif "rhsa" in system.lower():
                identifiers["rhsa"] = value
            else:
                identifiers[system.split("/")[-1]] = value

        return identifiers

    def _extract_check_content(self, rule_elem: ET.Element) -> Dict[str, Any]:
        """Extract check content from the rule"""
        check_content = {"system": None, "content": {}, "multi_check": False}

        # Find check element
        check = rule_elem.find(".//xccdf-1.2:check", self.NAMESPACES)
        if check is None:
            check = rule_elem.find(".//xccdf:check", self.NAMESPACES)

        if check is not None:
            check_content["system"] = check.get("system", "")

            # Extract check-content-ref
            ref = check.find(".//xccdf-1.2:check-content-ref", self.NAMESPACES)
            if ref is None:
                ref = check.find(".//xccdf:check-content-ref", self.NAMESPACES)

            if ref is not None:
                check_content["content"] = {
                    "href": ref.get("href", ""),
                    "name": ref.get("name", ""),
                    "multi_check": ref.get("multi-check", "false") == "true",
                }
                check_content["multi_check"] = check_content["content"]["multi_check"]

            # Extract check-export
            exports = {}
            for export in check.findall(".//xccdf-1.2:check-export", self.NAMESPACES):
                var_name = export.get("export-name", "")
                value_id = export.get("value-id", "")
                if var_name and value_id:
                    exports[var_name] = value_id
            if exports:
                check_content["exports"] = exports

        return check_content

    def _extract_fix_content(self, rule_elem: ET.Element) -> Dict[str, Any]:
        """Extract fix content from the rule"""
        fix_content = {"available": False, "fixes": []}

        fixes = rule_elem.findall(".//xccdf-1.2:fix", self.NAMESPACES)
        if not fixes:
            fixes = rule_elem.findall(".//xccdf:fix", self.NAMESPACES)

        for fix in fixes:
            fix_data = {
                "system": fix.get("system", ""),
                "platform": fix.get("platform", ""),
                "complexity": fix.get("complexity", "low"),
                "disruption": fix.get("disruption", "low"),
                "reboot": fix.get("reboot", "false") == "true",
                "strategy": fix.get("strategy", ""),
                "content": self._extract_text_content(fix),
            }
            fix_content["fixes"].append(fix_data)

        if fix_content["fixes"]:
            fix_content["available"] = True

        return fix_content

    def _extract_complex_check(self, rule_elem: ET.Element) -> Dict[str, Any]:
        """Extract complex check with boolean logic"""
        complex_check = {"operator": "AND", "checks": []}

        # Look for complex-check element
        complex = rule_elem.find(".//xccdf-1.2:complex-check", self.NAMESPACES)
        if complex is None:
            complex = rule_elem.find(".//xccdf:complex-check", self.NAMESPACES)

        if complex is not None:
            complex_check["operator"] = complex.get("operator", "AND")

            # Extract all checks within complex check
            for check in complex.findall(".//xccdf-1.2:check", self.NAMESPACES):
                check_data = {
                    "system": check.get("system", ""),
                    "negate": check.get("negate", "false") == "true",
                }

                ref = check.find(".//xccdf-1.2:check-content-ref", self.NAMESPACES)
                if ref is not None:
                    check_data["ref"] = {
                        "href": ref.get("href", ""),
                        "name": ref.get("name", ""),
                    }

                complex_check["checks"].append(check_data)

        return complex_check if complex_check["checks"] else None

    def _extract_platform_info(self, rule_elem: ET.Element) -> List[str]:
        """Extract platform information"""
        platforms = []

        for platform in rule_elem.findall(".//xccdf-1.2:platform", self.NAMESPACES):
            platform_id = platform.get("idref", "")
            if platform_id:
                platforms.append(platform_id)

        return platforms

    def _extract_profile_membership(self, rule_elem: ET.Element) -> List[str]:
        """Extract which profiles this rule belongs to"""
        # This would need to be populated by analyzing Profile elements
        # For now, return empty list
        return []

    def _extract_tags(self, rule_elem: ET.Element) -> List[str]:
        """Extract tags from rule metadata"""
        tags = []

        # Extract from title and description
        title = self._get_element_text(rule_elem, ["title"]) or ""
        desc = self._get_element_text(rule_elem, ["description"]) or ""

        # Common tag patterns
        tag_patterns = {
            "ssh": r"\bssh\b|openssh",
            "audit": r"\baudit\b|auditd",
            "firewall": r"\bfirewall\b|iptables|firewalld",
            "selinux": r"\bselinux\b",
            "kernel": r"\bkernel\b|sysctl",
            "authentication": r"\bauth\b|authentication|login|password",
            "crypto": r"\bcrypto\b|encryption|certificate|tls|ssl",
            "network": r"\bnetwork\b|tcp|udp|port",
            "filesystem": r"\bfile\b|filesystem|permission|ownership",
            "service": r"\bservice\b|daemon|systemd",
        }

        combined_text = f"{title} {desc}".lower()
        for tag, pattern in tag_patterns.items():
            if re.search(pattern, combined_text, re.IGNORECASE):
                tags.append(tag)

        return list(set(tags))

    def _map_to_frameworks(self, rule_elem: ET.Element) -> Dict[str, Dict[str, List[str]]]:
        """Map references to framework versions"""
        frameworks = {
            "nist": {},
            "cis": {},
            "stig": {},
            "pci_dss": {},
            "iso27001": {},
            "hipaa": {},
        }

        references = self._extract_references(rule_elem)

        # Process NIST references
        if "nist" in references:
            for ref in references["nist"]:
                ref_text = ref["text"]

                # Extract control IDs (e.g., AC-2, IA-5)
                control_ids = re.findall(r"([A-Z]{2}-\d+(?:\(\d+\))?)", ref_text)

                # Determine version
                if "r5" in ref_text.lower() or "revision 5" in ref_text.lower():
                    version = "800-53r5"
                elif "r4" in ref_text.lower() or "revision 4" in ref_text.lower():
                    version = "800-53r4"
                else:
                    version = "800-53r5"  # Default to r5

                if control_ids:
                    if version not in frameworks["nist"]:
                        frameworks["nist"][version] = []
                    frameworks["nist"][version].extend(control_ids)

        # Process CIS references
        if "cis" in references:
            for ref in references["cis"]:
                ref_text = ref["text"]

                # Extract CIS control numbers
                control_nums = re.findall(r"(\d+(?:\.\d+)+)", ref_text)

                # Try to extract version
                version_match = re.search(r"v?(\d+\.\d+(?:\.\d+)?)", ref_text)
                if version_match:
                    version = f"v{version_match.group(1)}"
                else:
                    version = "v2.0.0"  # Default version

                if control_nums:
                    if version not in frameworks["cis"]:
                        frameworks["cis"][version] = []
                    frameworks["cis"][version].extend(control_nums)

        # Process STIG references
        if "stig" in references:
            for ref in references["stig"]:
                ref_text = ref["text"]

                # Extract STIG IDs
                stig_ids = re.findall(r"([A-Z]+-\d+-\d+)", ref_text)

                if stig_ids:
                    # Determine version from STIG ID pattern
                    for stig_id in stig_ids:
                        if stig_id.startswith("RHEL-08"):
                            version = "rhel8_v1r11"
                        elif stig_id.startswith("RHEL-09"):
                            version = "rhel9_v1r1"
                        else:
                            version = "generic"

                        frameworks["stig"][version] = stig_id

        # Process identifiers for additional mappings
        identifiers = self._extract_identifiers(rule_elem)

        # Clean up empty frameworks
        frameworks = {k: v for k, v in frameworks.items() if v}

        return frameworks

    def _determine_category(self, rule: Dict[str, Any]) -> str:
        """Determine rule category based on content"""
        rule_id = rule["scap_rule_id"].lower()
        title = (rule["metadata"].get("title") or "").lower()
        desc = (rule["metadata"].get("description") or "").lower()

        # Category patterns
        categories = {
            "authentication": ["auth", "login", "password", "pam", "sudo", "su"],
            "access_control": ["permission", "ownership", "acl", "rbac", "selinux"],
            "audit": ["audit", "log", "rsyslog", "journald"],
            "network": ["firewall", "iptables", "tcp", "udp", "port", "network"],
            "crypto": ["crypto", "encrypt", "certificate", "tls", "ssl", "key"],
            "kernel": ["kernel", "sysctl", "module", "grub"],
            "service": ["service", "daemon", "systemd", "xinetd"],
            "filesystem": ["mount", "partition", "filesystem", "disk"],
            "package": ["package", "rpm", "yum", "dnf", "update"],
            "system": ["system", "boot", "init", "cron"],
        }

        combined_text = f"{rule_id} {title} {desc}"

        for category, keywords in categories.items():
            for keyword in keywords:
                if keyword in combined_text:
                    return category

        return "system"  # Default category

    def _determine_security_function(self, rule: Dict[str, Any]) -> str:
        """Determine high-level security function"""
        category = rule["category"]
        frameworks = rule.get("frameworks", {})

        # Map categories to security functions
        function_map = {
            "authentication": "identity_management",
            "access_control": "access_management",
            "audit": "security_monitoring",
            "network": "network_protection",
            "crypto": "data_encryption",
            "kernel": "system_hardening",
            "service": "service_management",
            "filesystem": "data_protection",
            "package": "vulnerability_management",
            "system": "system_configuration",
        }

        return function_map.get(category, "system_configuration")

    def _calculate_statistics(self, rules: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate statistics from parsed rules"""
        stats = {
            "rules_by_severity": {},
            "rules_by_category": {},
            "framework_coverage": {},
            "platforms": set(),
            "fix_availability": {"with_fix": 0, "without_fix": 0},
        }

        for rule in rules:
            # Severity stats
            severity = rule.get("severity", "unknown")
            stats["rules_by_severity"][severity] = stats["rules_by_severity"].get(severity, 0) + 1

            # Category stats
            category = rule.get("category", "unknown")
            stats["rules_by_category"][category] = stats["rules_by_category"].get(category, 0) + 1

            # Framework coverage
            for framework, versions in rule.get("frameworks", {}).items():
                if framework not in stats["framework_coverage"]:
                    stats["framework_coverage"][framework] = {
                        "total_rules": 0,
                        "versions": {},
                    }
                stats["framework_coverage"][framework]["total_rules"] += 1

                for version in versions:
                    if version not in stats["framework_coverage"][framework]["versions"]:
                        stats["framework_coverage"][framework]["versions"][version] = 0
                    stats["framework_coverage"][framework]["versions"][version] += 1

            # Platform stats
            for platform in rule.get("platform", []):
                stats["platforms"].add(platform)

            # Fix availability
            if rule.get("fix", {}).get("available"):
                stats["fix_availability"]["with_fix"] += 1
            else:
                stats["fix_availability"]["without_fix"] += 1

        # Convert set to list for JSON serialization
        stats["platforms"] = list(stats["platforms"])

        return stats
