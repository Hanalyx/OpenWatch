"""
CSV Analysis Service
Provides intelligent analysis of CSV files for frictionless import
"""

import csv
import io
import ipaddress
import re
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Tuple


class FieldType(Enum):
    """Detected field types with confidence scoring"""

    HOSTNAME = "hostname"
    IP_ADDRESS = "ip_address"
    DISPLAY_NAME = "display_name"
    OPERATING_SYSTEM = "operating_system"
    PORT = "port"
    USERNAME = "username"
    AUTH_METHOD = "auth_method"
    ENVIRONMENT = "environment"
    TAGS = "tags"
    OWNER = "owner"
    UNKNOWN = "unknown"


@dataclass
class FieldAnalysis:
    """Analysis result for a CSV column"""

    column_name: str
    detected_type: FieldType
    confidence: float  # 0.0 to 1.0
    sample_values: List[str]
    unique_count: int
    null_count: int
    suggestions: List[str]


@dataclass
class CSVAnalysis:
    """Complete analysis result for a CSV file"""

    total_rows: int
    total_columns: int
    headers: List[str]
    field_analyses: List[FieldAnalysis]
    auto_mappings: Dict[str, str]  # detected_column -> target_field
    template_matches: List[str]  # Known template names that might match


class CSVAnalyzer:
    """Intelligent CSV analysis for field mapping"""

    def __init__(self):
        self.ip_patterns = [
            re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$"),  # IPv4
            re.compile(r"^[0-9a-fA-F:]+$"),  # IPv6 (simplified)
        ]

        self.hostname_patterns = [
            re.compile(
                r"^[a-zA-Z\d]([a-zA-Z\d\-]{0,61}[a-zA-Z\d])?(\.[a-zA-Z\d]([a-zA-Z\d\-]{0,61}[a-zA-Z\d])?)*$"
            ),
            re.compile(r"^[a-zA-Z0-9\-_]+$"),  # Simple hostname
        ]

        self.os_keywords = {
            "rhel": ["rhel", "red hat", "redhat"],
            "centos": ["centos", "cent os"],
            "ubuntu": ["ubuntu"],
            "windows": ["windows", "win"],
            "suse": ["suse", "sles"],
            "debian": ["debian"],
            "linux": ["linux"],
        }

        self.environment_keywords = {
            "production": ["prod", "production", "prd"],
            "staging": ["staging", "stage", "stg"],
            "development": ["dev", "development", "test"],
            "qa": ["qa", "testing", "qual"],
        }

        self.auth_methods = ["password", "ssh_key", "system_default"]

        # Common column name mappings
        self.column_mappings = {
            # Hostname variations
            "hostname": FieldType.HOSTNAME,
            "host_name": FieldType.HOSTNAME,
            "name": FieldType.HOSTNAME,
            "vm_name": FieldType.HOSTNAME,
            "machine_name": FieldType.HOSTNAME,
            "server_name": FieldType.HOSTNAME,
            "computer_name": FieldType.HOSTNAME,
            # IP Address variations
            "ip": FieldType.IP_ADDRESS,
            "ip_address": FieldType.IP_ADDRESS,
            "ipv4": FieldType.IP_ADDRESS,
            "ipv6": FieldType.IP_ADDRESS,
            "address": FieldType.IP_ADDRESS,
            "host_ip": FieldType.IP_ADDRESS,
            # Display name variations
            "display_name": FieldType.DISPLAY_NAME,
            "description": FieldType.DISPLAY_NAME,
            "friendly_name": FieldType.DISPLAY_NAME,
            "label": FieldType.DISPLAY_NAME,
            # Operating System variations
            "os": FieldType.OPERATING_SYSTEM,
            "operating_system": FieldType.OPERATING_SYSTEM,
            "os_type": FieldType.OPERATING_SYSTEM,
            "guest_os": FieldType.OPERATING_SYSTEM,
            "platform": FieldType.OPERATING_SYSTEM,
            # Port variations
            "port": FieldType.PORT,
            "ssh_port": FieldType.PORT,
            "port_ssh": FieldType.PORT,
            # Username variations
            "user": FieldType.USERNAME,
            "username": FieldType.USERNAME,
            "ssh_user": FieldType.USERNAME,
            "admin_user": FieldType.USERNAME,
            # Environment variations
            "env": FieldType.ENVIRONMENT,
            "environment": FieldType.ENVIRONMENT,
            "stage": FieldType.ENVIRONMENT,
            # Tags variations
            "tags": FieldType.TAGS,
            "labels": FieldType.TAGS,
            "categories": FieldType.TAGS,
            # Owner variations
            "owner": FieldType.OWNER,
            "responsible": FieldType.OWNER,
            "contact": FieldType.OWNER,
            "admin": FieldType.OWNER,
        }

    def analyze_csv(self, csv_content: str, max_preview_rows: int = 10) -> CSVAnalysis:
        """Analyze CSV content and provide intelligent field mapping suggestions"""

        if not csv_content or not csv_content.strip():
            raise ValueError("CSV content is empty")

        try:
            # Parse CSV
            csv_reader = csv.DictReader(io.StringIO(csv_content))
            headers = csv_reader.fieldnames or []

            if not headers:
                raise ValueError("CSV file has no headers or is malformed")

            # Read all rows for analysis
            rows = list(csv_reader)
            total_rows = len(rows)

            if total_rows == 0:
                raise ValueError("CSV file is empty or has no data rows")

        except csv.Error as e:
            raise ValueError(f"Invalid CSV format: {e}")
        except Exception as e:
            raise ValueError(f"Error parsing CSV: {e}")

        # Analyze each column
        field_analyses = []
        for header in headers:
            analysis = self._analyze_column(header, rows, max_preview_rows)
            field_analyses.append(analysis)

        # Generate auto-mappings
        auto_mappings = self._generate_auto_mappings(field_analyses)

        # Check for template matches
        template_matches = self._check_template_matches(headers)

        return CSVAnalysis(
            total_rows=total_rows,
            total_columns=len(headers),
            headers=headers,
            field_analyses=field_analyses,
            auto_mappings=auto_mappings,
            template_matches=template_matches,
        )

    def _analyze_column(
        self, column_name: str, rows: List[Dict], max_preview: int
    ) -> FieldAnalysis:
        """Analyze a single column and detect its likely type"""

        # Extract values for this column, handling None values
        values = [(row.get(column_name) or "").strip() for row in rows]
        non_empty_values = [v for v in values if v]

        # Basic stats
        unique_count = len(set(non_empty_values))
        null_count = len(values) - len(non_empty_values)
        sample_values = non_empty_values[:max_preview]

        # Detect field type
        detected_type, confidence = self._detect_field_type(column_name, non_empty_values)

        # Generate suggestions
        suggestions = self._generate_suggestions(detected_type, non_empty_values)

        return FieldAnalysis(
            column_name=column_name,
            detected_type=detected_type,
            confidence=confidence,
            sample_values=sample_values,
            unique_count=unique_count,
            null_count=null_count,
            suggestions=suggestions,
        )

    def _detect_field_type(self, column_name: str, values: List[str]) -> Tuple[FieldType, float]:
        """Detect the most likely field type for a column"""

        if not values:
            return FieldType.UNKNOWN, 0.0

        # Check column name first (high confidence)
        normalized_name = column_name.lower().replace(" ", "_").replace("-", "_")
        if normalized_name in self.column_mappings:
            return self.column_mappings[normalized_name], 0.95

        # Content-based detection
        detectors = [
            (self._is_ip_address_column, FieldType.IP_ADDRESS),
            (self._is_hostname_column, FieldType.HOSTNAME),
            (self._is_port_column, FieldType.PORT),
            (self._is_os_column, FieldType.OPERATING_SYSTEM),
            (self._is_environment_column, FieldType.ENVIRONMENT),
            (self._is_auth_method_column, FieldType.AUTH_METHOD),
        ]

        best_type = FieldType.UNKNOWN
        best_confidence = 0.0

        for detector, field_type in detectors:
            confidence = detector(values)
            if confidence > best_confidence:
                best_type = field_type
                best_confidence = confidence

        # Fallback heuristics
        if best_confidence < 0.3:
            if "name" in normalized_name:
                if len(set(values)) / len(values) > 0.8:  # High uniqueness
                    return FieldType.HOSTNAME, 0.6
                else:
                    return FieldType.DISPLAY_NAME, 0.6
            elif "user" in normalized_name:
                return FieldType.USERNAME, 0.6
            elif "tag" in normalized_name or "label" in normalized_name:
                return FieldType.TAGS, 0.6
            elif "owner" in normalized_name or "contact" in normalized_name:
                return FieldType.OWNER, 0.6

        return best_type, best_confidence

    def _is_ip_address_column(self, values: List[str]) -> float:
        """Check if column contains IP addresses"""
        if not values:
            return 0.0

        valid_ips = 0
        for value in values[:20]:  # Sample first 20 values
            try:
                ipaddress.ip_address(value)
                valid_ips += 1
            except ValueError:
                pass

        return valid_ips / min(len(values), 20)

    def _is_hostname_column(self, values: List[str]) -> float:
        """Check if column contains hostnames"""
        if not values:
            return 0.0

        valid_hostnames = 0
        for value in values[:20]:
            if any(pattern.match(value) for pattern in self.hostname_patterns):
                valid_hostnames += 1

        return valid_hostnames / min(len(values), 20)

    def _is_port_column(self, values: List[str]) -> float:
        """Check if column contains port numbers"""
        if not values:
            return 0.0

        valid_ports = 0
        for value in values[:20]:
            try:
                port = int(value)
                if 1 <= port <= 65535:
                    valid_ports += 1
            except ValueError:
                pass

        return valid_ports / min(len(values), 20)

    def _is_os_column(self, values: List[str]) -> float:
        """Check if column contains operating system names"""
        if not values:
            return 0.0

        os_matches = 0
        for value in values[:20]:
            value_lower = value.lower()
            for os_type, keywords in self.os_keywords.items():
                if any(keyword in value_lower for keyword in keywords):
                    os_matches += 1
                    break

        return os_matches / min(len(values), 20)

    def _is_environment_column(self, values: List[str]) -> float:
        """Check if column contains environment names"""
        if not values:
            return 0.0

        env_matches = 0
        for value in values[:20]:
            value_lower = value.lower()
            for env_type, keywords in self.environment_keywords.items():
                if any(keyword in value_lower for keyword in keywords):
                    env_matches += 1
                    break

        return env_matches / min(len(values), 20)

    def _is_auth_method_column(self, values: List[str]) -> float:
        """Check if column contains authentication methods"""
        if not values:
            return 0.0

        auth_matches = 0
        for value in values[:20]:
            if value.lower() in self.auth_methods:
                auth_matches += 1

        return auth_matches / min(len(values), 20)

    def _generate_suggestions(self, field_type: FieldType, values: List[str]) -> List[str]:
        """Generate helpful suggestions for field mapping"""
        suggestions = []

        if field_type == FieldType.IP_ADDRESS:
            # Check for IPv6 addresses
            has_ipv6 = any(":" in v for v in values[:10])
            if has_ipv6:
                suggestions.append("Contains IPv6 addresses - ensure proper formatting")

        elif field_type == FieldType.PORT:
            unique_ports = set(values[:20])
            if len(unique_ports) == 1:
                suggestions.append(f"All hosts use port {list(unique_ports)[0]}")

        elif field_type == FieldType.OPERATING_SYSTEM:
            unique_os = set(v.lower() for v in values[:20])
            if len(unique_os) <= 3:
                suggestions.append(f"Limited OS variety: {', '.join(unique_os)}")

        elif field_type == FieldType.ENVIRONMENT:
            unique_envs = set(v.lower() for v in values[:20])
            suggestions.append(f"Environments detected: {', '.join(unique_envs)}")

        return suggestions

    def _generate_auto_mappings(self, field_analyses: List[FieldAnalysis]) -> Dict[str, str]:
        """Generate automatic field mappings based on confidence scores"""
        mappings = {}

        # Required fields that should be mapped

        # Track which target fields have been assigned
        assigned_targets = set()

        # Sort by confidence (highest first)
        sorted_analyses = sorted(field_analyses, key=lambda x: x.confidence, reverse=True)

        for analysis in sorted_analyses:
            if analysis.confidence >= 0.7 and analysis.detected_type != FieldType.UNKNOWN:
                target_field = analysis.detected_type.value

                # Avoid duplicate mappings
                if target_field not in assigned_targets:
                    mappings[analysis.column_name] = target_field
                    assigned_targets.add(target_field)

        return mappings

    def _check_template_matches(self, headers: List[str]) -> List[str]:
        """Check if headers match known source templates"""
        templates = []

        headers_lower = [h.lower() for h in headers]

        # VMware vCenter patterns
        vmware_indicators = ["vm_name", "guest_os", "ip_address", "power_state"]
        if any(indicator in " ".join(headers_lower) for indicator in vmware_indicators):
            templates.append("VMware vCenter Export")

        # Red Hat Satellite patterns
        satellite_indicators = ["name", "operating_system", "ip", "environment"]
        if all(
            any(indicator in h for h in headers_lower) for indicator in satellite_indicators[:2]
        ):
            templates.append("Red Hat Satellite Export")

        # AWS EC2 patterns
        aws_indicators = ["instance_id", "instance_type", "public_ip", "private_ip"]
        if any(indicator in " ".join(headers_lower) for indicator in aws_indicators):
            templates.append("AWS EC2 Instance List")

        # Azure VM patterns
        azure_indicators = ["vm_name", "resource_group", "location", "vm_size"]
        if any(indicator in " ".join(headers_lower) for indicator in azure_indicators):
            templates.append("Azure VM Export")

        return templates
