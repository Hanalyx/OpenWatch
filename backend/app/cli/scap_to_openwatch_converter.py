#!/usr/bin/env python3
"""
SCAP to OpenWatch Compliance Rules Converter
Transforms ComplianceAsCode YAML rules into OpenWatch MongoDB-optimized JSON format

Usage:
    python -m backend.app.cli.scap_to_openwatch_converter convert
    python -m backend.app.cli.scap_to_openwatch_converter validate
    python -m backend.app.cli.scap_to_openwatch_converter stats
"""

import os
import re
import json
import yaml
import hashlib
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from datetime import datetime, timezone
import logging
from dataclasses import dataclass
import argparse

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class ConversionStats:
    """Track conversion statistics"""
    total_rules_found: int = 0
    successfully_converted: int = 0
    conversion_errors: int = 0
    template_expansions: int = 0
    framework_mappings: int = 0
    platform_implementations: int = 0
    
class FrameworkMapper:
    """Maps SCAP framework references to OpenWatch framework structure"""
    
    def __init__(self):
        self.framework_mappings = {
            # NIST mappings
            'nist': {
                'pattern': r'nist',
                'versions': {
                    'default': '800-53r5',
                    'r4': '800-53r4',
                    'r5': '800-53r5'
                }
            },
            # CIS mappings  
            'cis': {
                'pattern': r'cis',
                'versions': {
                    'default': 'controls_v8',
                    'v7': 'controls_v7',
                    'v8': 'controls_v8'
                }
            },
            # STIG mappings
            'stig': {
                'pattern': r'stig|srg',
                'versions': {
                    'default': 'current',
                    'rhel8': 'rhel8_v1r11',
                    'rhel9': 'rhel9_v1r3'
                }
            },
            # PCI DSS mappings
            'pci': {
                'pattern': r'pci|pcidss',
                'versions': {
                    'default': 'v4.0',
                    'v3': 'v3.2.1',
                    'v4': 'v4.0'
                }
            },
            # ISO 27001 mappings
            'iso27001': {
                'pattern': r'iso27001',
                'versions': {
                    'default': '2013',
                    '2013': '2013',
                    '2022': '2022'
                }
            },
            # HIPAA mappings
            'hipaa': {
                'pattern': r'hipaa',
                'versions': {
                    'default': 'current'
                }
            }
        }
    
    def map_references_to_frameworks(self, references: Dict[str, Any]) -> Dict[str, Dict[str, List[str]]]:
        """Convert SCAP references to OpenWatch framework structure"""
        frameworks = {}
        
        for ref_key, ref_value in references.items():
            if not ref_value:
                continue
                
            # Parse reference values (can be comma-separated)
            if isinstance(ref_value, str):
                ref_list = [item.strip() for item in ref_value.split(',') if item.strip()]
            elif isinstance(ref_value, list):
                ref_list = ref_value
            else:
                continue
            
            # Map to OpenWatch framework structure
            framework_name = self._identify_framework(ref_key)
            if framework_name:
                version = self._determine_version(ref_key, framework_name)
                
                if framework_name not in frameworks:
                    frameworks[framework_name] = {}
                
                if version not in frameworks[framework_name]:
                    frameworks[framework_name][version] = []
                
                frameworks[framework_name][version].extend(ref_list)
        
        return frameworks
    
    def _identify_framework(self, ref_key: str) -> Optional[str]:
        """Identify framework from reference key"""
        ref_key_lower = ref_key.lower()
        
        for framework, config in self.framework_mappings.items():
            if re.search(config['pattern'], ref_key_lower):
                return framework
        
        return None
    
    def _determine_version(self, ref_key: str, framework: str) -> str:
        """Determine framework version from reference key"""
        config = self.framework_mappings[framework]
        ref_key_lower = ref_key.lower()
        
        # Check for specific version indicators
        for version_key, version_value in config['versions'].items():
            if version_key != 'default' and version_key in ref_key_lower:
                return version_value
        
        return config['versions']['default']

class TemplateProcessor:
    """Processes ComplianceAsCode templates into platform-specific implementations"""
    
    def __init__(self):
        self.template_handlers = {
            'sshd_lineinfile': self._handle_sshd_lineinfile,
            'package_installed': self._handle_package_installed,
            'service_enabled': self._handle_service_enabled,
            'sysctl': self._handle_sysctl,
        }
    
    def process_template(self, template_name: str, template_vars: Dict[str, Any]) -> Dict[str, Any]:
        """Process template into platform implementations"""
        handler = self.template_handlers.get(template_name)
        if handler:
            return handler(template_vars)
        else:
            logger.warning(f"No handler for template: {template_name}")
            return self._handle_generic_template(template_name, template_vars)
    
    def _handle_sshd_lineinfile(self, vars: Dict[str, Any]) -> Dict[str, Any]:
        """Handle SSH configuration line template"""
        parameter = vars.get('parameter', '')
        value = vars.get('value', '')
        
        return {
            'rhel': {
                'versions': ['7', '8', '9'],
                'service_name': 'sshd',
                'config_files': ['/etc/ssh/sshd_config'],
                'check_method': 'file',
                'check_command': f"grep '^{parameter}\\s\\+{value}' /etc/ssh/sshd_config",
                'enable_command': f"sed -i 's/^#\\?{parameter}.*/{{ parameter }} {value}/' /etc/ssh/sshd_config",
                'validation_command': 'sshd -t',
                'service_dependencies': ['openssh-server']
            },
            'ubuntu': {
                'versions': ['18.04', '20.04', '22.04', '24.04'],
                'service_name': 'ssh',
                'config_files': ['/etc/ssh/sshd_config'],
                'check_method': 'file',
                'check_command': f"grep '^{parameter}\\s\\+{value}' /etc/ssh/sshd_config",
                'enable_command': f"sed -i 's/^#\\?{parameter}.*/{{ parameter }} {value}/' /etc/ssh/sshd_config",
                'validation_command': 'sshd -t',
                'service_dependencies': ['openssh-server']
            }
        }
    
    def _handle_package_installed(self, vars: Dict[str, Any]) -> Dict[str, Any]:
        """Handle package installation template"""
        package_name = vars.get('pkgname', vars.get('name', ''))
        
        return {
            'rhel': {
                'versions': ['7', '8', '9'],
                'check_method': 'package',
                'check_command': f"rpm -q {package_name}",
                'enable_command': f"yum install -y {package_name}",
                'disable_command': f"yum remove -y {package_name}",
                'service_dependencies': []
            },
            'ubuntu': {
                'versions': ['18.04', '20.04', '22.04', '24.04'],
                'check_method': 'package',
                'check_command': f"dpkg -l | grep {package_name}",
                'enable_command': f"apt-get install -y {package_name}",
                'disable_command': f"apt-get remove -y {package_name}",
                'service_dependencies': []
            }
        }
    
    def _handle_service_enabled(self, vars: Dict[str, Any]) -> Dict[str, Any]:
        """Handle service enablement template"""
        service_name = vars.get('servicename', vars.get('name', ''))
        
        return {
            'rhel': {
                'versions': ['7', '8', '9'],
                'service_name': service_name,
                'check_method': 'systemd',
                'check_command': f"systemctl is-enabled {service_name}",
                'enable_command': f"systemctl enable {service_name}",
                'disable_command': f"systemctl disable {service_name}",
                'validation_command': f"systemctl status {service_name}",
                'service_dependencies': []
            },
            'ubuntu': {
                'versions': ['18.04', '20.04', '22.04', '24.04'],
                'service_name': service_name,
                'check_method': 'systemd',
                'check_command': f"systemctl is-enabled {service_name}",
                'enable_command': f"systemctl enable {service_name}",
                'disable_command': f"systemctl disable {service_name}",
                'validation_command': f"systemctl status {service_name}",
                'service_dependencies': []
            }
        }
    
    def _handle_sysctl(self, vars: Dict[str, Any]) -> Dict[str, Any]:
        """Handle sysctl parameter template"""
        parameter = vars.get('sysctlvar', '')
        value = vars.get('sysctlval', '')
        
        return {
            'rhel': {
                'versions': ['7', '8', '9'],
                'check_method': 'sysctl',
                'check_command': f"sysctl {parameter} | grep '{parameter} = {value}'",
                'enable_command': f"echo '{parameter} = {value}' >> /etc/sysctl.conf && sysctl -p",
                'config_files': ['/etc/sysctl.conf', '/etc/sysctl.d/*.conf'],
                'service_dependencies': []
            },
            'ubuntu': {
                'versions': ['18.04', '20.04', '22.04', '24.04'],
                'check_method': 'sysctl',
                'check_command': f"sysctl {parameter} | grep '{parameter} = {value}'",
                'enable_command': f"echo '{parameter} = {value}' >> /etc/sysctl.conf && sysctl -p",
                'config_files': ['/etc/sysctl.conf', '/etc/sysctl.d/*.conf'],
                'service_dependencies': []
            }
        }
    
    def _handle_generic_template(self, template_name: str, vars: Dict[str, Any]) -> Dict[str, Any]:
        """Handle unknown templates with basic structure"""
        return {
            'rhel': {
                'versions': ['8', '9'],
                'check_method': 'custom',
                'check_command': f"# TODO: Implement {template_name} check",
                'enable_command': f"# TODO: Implement {template_name} remediation",
                'service_dependencies': []
            }
        }

class SCAPToOpenWatchConverter:
    """Main converter class"""
    
    def __init__(self, scap_content_path: str, output_path: str):
        self.scap_content_path = Path(scap_content_path)
        self.output_path = Path(output_path)
        self.framework_mapper = FrameworkMapper()
        self.template_processor = TemplateProcessor()
        self.stats = ConversionStats()
        
        # Ensure output directory exists
        self.output_path.mkdir(parents=True, exist_ok=True)
    
    def convert_all_rules(self) -> ConversionStats:
        """Convert all SCAP rules to OpenWatch format"""
        logger.info(f"Starting conversion from {self.scap_content_path} to {self.output_path}")
        
        # Find all rule.yml files, excluding test directories
        rule_files = []
        for rule_file in self.scap_content_path.rglob("rule.yml"):
            # Skip test files and unit test directories
            if 'test' not in str(rule_file).lower() and 'unit' not in str(rule_file).lower():
                rule_files.append(rule_file)
        
        self.stats.total_rules_found = len(rule_files)
        
        logger.info(f"Found {self.stats.total_rules_found} rule files (excluding tests)")
        
        for rule_file in rule_files:
            try:
                self._convert_single_rule(rule_file)
                self.stats.successfully_converted += 1
                
                if self.stats.successfully_converted % 50 == 0:
                    logger.info(f"Converted {self.stats.successfully_converted}/{self.stats.total_rules_found} rules")
                    
            except Exception as e:
                logger.error(f"Error converting {rule_file}: {e}")
                self.stats.conversion_errors += 1
        
        logger.info(f"Conversion complete: {self.stats.successfully_converted} successful, {self.stats.conversion_errors} errors")
        return self.stats
    
    def _convert_single_rule(self, rule_file: Path) -> None:
        """Convert a single SCAP rule to OpenWatch format"""
        
        # Load YAML rule
        try:
            with open(rule_file, 'r', encoding='utf-8') as f:
                content = f.read()
                
                # Skip files with Jinja2 templating that can't be parsed as pure YAML
                if '{{{' in content or '{{%' in content or '{%-' in content:
                    logger.debug(f"Skipping {rule_file} - contains Jinja2 templating")
                    return
                
                rule_data = yaml.safe_load(content)
        except yaml.YAMLError as e:
            logger.warning(f"YAML parsing error in {rule_file}: {e}")
            return
        
        if not rule_data or not isinstance(rule_data, dict):
            return
        
        # Extract rule ID from path
        rule_id = self._extract_rule_id(rule_file)
        
        # Create OpenWatch rule structure
        openwatch_rule = {
            "_id": f"ow-{rule_id}",
            "rule_id": f"ow-{rule_id}",
            "scap_rule_id": f"xccdf_org.ssgproject.content_rule_{rule_id}",
            "parent_rule_id": None,
            
            # Metadata
            "metadata": self._convert_metadata(rule_data, rule_file),
            
            # Rule classification
            "abstract": False,
            "severity": rule_data.get('severity', 'medium'),
            "category": self._determine_category(rule_data, rule_file),
            "security_function": self._determine_security_function(rule_data),
            "tags": self._generate_tags(rule_data, rule_file),
            
            # Framework mappings
            "frameworks": self._convert_frameworks(rule_data),
            
            # Platform implementations
            "platform_implementations": self._convert_platform_implementations(rule_data),
            
            # Platform requirements
            "platform_requirements": self._generate_platform_requirements(rule_data),
            
            # Check configuration
            "check_type": self._determine_check_type(rule_data),
            "check_content": self._convert_check_content(rule_data, rule_id),
            
            # Remediation
            "fix_available": self._has_remediation(rule_data),
            "fix_content": self._convert_fix_content(rule_data),
            "manual_remediation": self._generate_manual_remediation(rule_data),
            "remediation_complexity": self._determine_remediation_complexity(rule_data),
            "remediation_risk": self._determine_remediation_risk(rule_data),
            
            # Dependencies
            "dependencies": {
                "requires": [],
                "conflicts": [],
                "related": []
            },
            
            # Provenance
            "source_file": str(rule_file.relative_to(self.scap_content_path)),
            "source_hash": self._calculate_file_hash(rule_file),
            "version": "2024.2",
            "imported_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            
            # Identifiers
            "identifiers": self._extract_identifiers(rule_data)
        }
        
        # Write OpenWatch rule
        output_file = self.output_path / f"ow-{rule_id}.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(openwatch_rule, f, indent=2, ensure_ascii=False)
    
    def _extract_rule_id(self, rule_file: Path) -> str:
        """Extract rule ID from file path"""
        # Rule ID is typically the parent directory name
        return rule_file.parent.name.replace('-', '_')
    
    def _convert_metadata(self, rule_data: Dict[str, Any], rule_file: Path) -> Dict[str, Any]:
        """Convert SCAP metadata to OpenWatch format"""
        return {
            "name": rule_data.get('title', ''),
            "description": rule_data.get('description', ''),
            "rationale": rule_data.get('rationale', ''),
            "source": {
                "upstream_id": self._extract_rule_id(rule_file),
                "complianceascode_version": "0.1.73",
                "source_file": "converted_from_yaml",
                "cce_id": self._extract_cce_id(rule_data),
                "imported_at": datetime.now(timezone.utc).isoformat()
            }
        }
    
    def _convert_frameworks(self, rule_data: Dict[str, Any]) -> Dict[str, Dict[str, List[str]]]:
        """Convert SCAP references to OpenWatch framework structure"""
        references = rule_data.get('references', {})
        frameworks = self.framework_mapper.map_references_to_frameworks(references)
        
        if frameworks:
            self.stats.framework_mappings += 1
        
        return frameworks
    
    def _convert_platform_implementations(self, rule_data: Dict[str, Any]) -> Dict[str, Any]:
        """Convert template to platform-specific implementations"""
        template = rule_data.get('template')
        if not template:
            return {}
        
        template_name = template.get('name', '')
        template_vars = template.get('vars', {})
        
        platform_impls = self.template_processor.process_template(template_name, template_vars)
        
        if platform_impls:
            self.stats.template_expansions += 1
            self.stats.platform_implementations += len(platform_impls)
        
        return platform_impls
    
    def _determine_category(self, rule_data: Dict[str, Any], rule_file: Path) -> str:
        """Determine rule category from path and content"""
        path_str = str(rule_file).lower()
        
        category_mappings = {
            'ssh': 'authentication',
            'login': 'authentication', 
            'password': 'authentication',
            'audit': 'audit_logging',
            'logging': 'audit_logging',
            'firewall': 'network_security',
            'network': 'network_security',
            'crypto': 'cryptography',
            'encryption': 'cryptography',
            'access': 'access_control',
            'permission': 'access_control',
            'service': 'system_hardening',
            'kernel': 'system_hardening',
            'mount': 'system_hardening'
        }
        
        for keyword, category in category_mappings.items():
            if keyword in path_str:
                return category
        
        return 'system_hardening'  # Default category
    
    def _generate_tags(self, rule_data: Dict[str, Any], rule_file: Path) -> List[str]:
        """Generate searchable tags for the rule"""
        tags = ['scap', 'ssg', 'converted']
        
        # Add category-based tags
        path_parts = rule_file.parts
        for part in path_parts:
            if part in ['ssh', 'audit', 'firewall', 'crypto', 'password', 'service']:
                tags.append(part)
        
        # Add severity tag
        severity = rule_data.get('severity')
        if severity:
            tags.append(f"severity_{severity}")
        
        return list(set(tags))  # Remove duplicates
    
    def _extract_cce_id(self, rule_data: Dict[str, Any]) -> str:
        """Extract CCE ID from identifiers"""
        identifiers = rule_data.get('identifiers', {})
        
        # Look for CCE IDs (prefer RHEL 8/9)
        for key, value in identifiers.items():
            if key.startswith('cce@'):
                return value
        
        return ""
    
    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA256 hash of file content"""
        with open(file_path, 'rb') as f:
            return f"sha256:{hashlib.sha256(f.read()).hexdigest()[:16]}"
    
    def _extract_identifiers(self, rule_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract identifiers from rule data"""
        identifiers = rule_data.get('identifiers', {})
        result = {}
        
        # Extract CCE ID
        cce_id = self._extract_cce_id(rule_data)
        if cce_id:
            result['cce'] = cce_id
        
        return result
    
    # Additional helper methods for other conversions...
    def _determine_security_function(self, rule_data: Dict[str, Any]) -> str:
        """Determine high-level security function"""
        return "access_control"  # Simplified for now
    
    def _generate_platform_requirements(self, rule_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate platform requirements"""
        return {
            "required_capabilities": [],
            "excluded_environments": []
        }
    
    def _determine_check_type(self, rule_data: Dict[str, Any]) -> str:
        """Determine the type of check to perform"""
        template = rule_data.get('template', {})
        if template:
            return "template"
        return "scap"
    
    def _convert_check_content(self, rule_data: Dict[str, Any], rule_id: str) -> Dict[str, Any]:
        """Convert check content"""
        return {
            "scap_rule_id": f"xccdf_org.ssgproject.content_rule_{rule_id}",
            "method": "xccdf_evaluation",
            "expected_result": "pass"
        }
    
    def _has_remediation(self, rule_data: Dict[str, Any]) -> bool:
        """Check if rule has automated remediation"""
        return rule_data.get('template') is not None
    
    def _convert_fix_content(self, rule_data: Dict[str, Any]) -> Dict[str, Any]:
        """Convert remediation content"""
        return {}  # Simplified for now
    
    def _generate_manual_remediation(self, rule_data: Dict[str, Any]) -> str:
        """Generate manual remediation instructions"""
        return rule_data.get('description', 'See SCAP guidance for remediation')
    
    def _determine_remediation_complexity(self, rule_data: Dict[str, Any]) -> str:
        """Determine remediation complexity"""
        return "medium"
    
    def _determine_remediation_risk(self, rule_data: Dict[str, Any]) -> str:
        """Determine remediation risk level"""
        return "low"

def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(description='SCAP to OpenWatch Compliance Rules Converter')
    parser.add_argument('command', choices=['convert', 'validate', 'stats'], 
                       help='Command to execute')
    parser.add_argument('--scap-path', default='/home/rracine/hanalyx/scap_content/content',
                       help='Path to SCAP content directory')
    parser.add_argument('--output-path', default='/home/rracine/hanalyx/openwatch/data/compliance_rules_converted',
                       help='Output directory for converted rules')
    parser.add_argument('--limit', type=int, help='Limit number of rules to convert (for testing)')
    
    args = parser.parse_args()
    
    if args.command == 'convert':
        converter = SCAPToOpenWatchConverter(args.scap_path, args.output_path)
        stats = converter.convert_all_rules()
        
        print("\n=== Conversion Summary ===")
        print(f"Total rules found: {stats.total_rules_found}")
        print(f"Successfully converted: {stats.successfully_converted}")
        print(f"Conversion errors: {stats.conversion_errors}")
        print(f"Template expansions: {stats.template_expansions}")
        print(f"Framework mappings: {stats.framework_mappings}")
        print(f"Platform implementations: {stats.platform_implementations}")
        
    elif args.command == 'validate':
        # TODO: Implement validation
        print("Validation not yet implemented")
        
    elif args.command == 'stats':
        # TODO: Implement statistics
        print("Statistics not yet implemented")

if __name__ == '__main__':
    main()