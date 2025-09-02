"""
OpenSCAP Scanner Service
Handles SCAP content processing and scanning operations
"""
import os
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple
import logging
import json
import uuid
from pathlib import Path
import shutil
from datetime import datetime

import lxml.etree as etree
import paramiko
import io
from paramiko.ssh_exception import SSHException
from .ssh_utils import parse_ssh_key, validate_ssh_key, SSHKeyError, format_validation_message
from ..config import get_settings

logger = logging.getLogger(__name__)


class SCAPContentError(Exception):
    """Exception raised for SCAP content processing errors"""
    pass


class ScanExecutionError(Exception):
    """Exception raised for scan execution errors"""
    pass


class SCAPScanner:
    """Main SCAP scanning service"""
    
    def __init__(self, content_dir: Optional[str] = None, 
                 results_dir: Optional[str] = None):
        settings = get_settings()
        
        # Use provided paths or fall back to configuration
        content_path = content_dir or settings.scap_content_dir
        results_path = results_dir or settings.scan_results_dir
        
        self.content_dir = Path(content_path)
        self.results_dir = Path(results_path)
        
        # Create directories if they don't exist
        try:
            self.content_dir.mkdir(parents=True, exist_ok=True)
            self.results_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"SCAP Scanner initialized - Content: {self.content_dir}, Results: {self.results_dir}")
        except Exception as e:
            logger.error(f"Failed to create SCAP directories: {e}")
            raise SCAPContentError(f"Directory creation failed: {str(e)}")
        
    def validate_scap_content(self, file_path: str) -> Dict:
        """Validate SCAP content file and extract metadata"""
        try:
            logger.info(f"Validating SCAP content: {file_path}")
            
            # First check if file exists and is readable
            if not os.path.exists(file_path):
                raise SCAPContentError(f"File not found: {file_path}")
                
            # Use oscap to validate the file
            result = subprocess.run([
                'oscap', 'info', file_path
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                raise SCAPContentError(f"Invalid SCAP content: {result.stderr}")
                
            # Parse the output to extract information
            info = self._parse_oscap_info(result.stdout)
            logger.info(f"SCAP content validated successfully: {info.get('title', 'Unknown')}")
            
            return info
            
        except subprocess.TimeoutExpired:
            raise SCAPContentError("Timeout validating SCAP content")
        except Exception as e:
            logger.error(f"Error validating SCAP content: {e}")
            raise SCAPContentError(f"Validation failed: {str(e)}")
            
    def extract_profiles(self, file_path: str) -> List[Dict]:
        """Extract available profiles from SCAP content"""
        try:
            logger.info(f"Extracting profiles from: {file_path}")
            
            result = subprocess.run([
                'oscap', 'info', '--profiles', file_path
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                raise SCAPContentError(f"Failed to extract profiles: {result.stderr}")
                
            profiles = self._parse_profiles(result.stdout)
            logger.info(f"Extracted {len(profiles)} profiles")
            
            return profiles
            
        except subprocess.TimeoutExpired:
            raise SCAPContentError("Timeout extracting profiles")
        except Exception as e:
            logger.error(f"Error extracting profiles: {e}")
            raise SCAPContentError(f"Profile extraction failed: {str(e)}")
            
    def test_ssh_connection(self, hostname: str, port: int, username: str, 
                          auth_method: str, credential: str) -> Dict:
        """Test SSH connection to remote host"""
        try:
            logger.info(f"Testing SSH connection to {username}@{hostname}:{port}")
            
            ssh = paramiko.SSHClient()
            # Security Fix: Use strict host key checking instead of AutoAddPolicy
            # AutoAddPolicy automatically accepts unknown host keys, vulnerable to MITM attacks
            ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
            # Load system and user host keys for validation
            try:
                ssh.load_system_host_keys()  # Load from /etc/ssh/ssh_known_hosts
                ssh.load_host_keys(os.path.expanduser('~/.ssh/known_hosts'))  # Load user known_hosts
            except FileNotFoundError:
                logger.warning("No known_hosts files found - SSH connections may fail without proper host key management")
            
            # Connect based on auth method
            if auth_method == "password":
                ssh.connect(hostname, port=port, username=username, 
                           password=credential, timeout=10)
            elif auth_method in ["ssh-key", "ssh_key"]:
                # Handle SSH key authentication using new utility
                try:
                    # Validate SSH key first
                    validation_result = validate_ssh_key(credential)
                    if not validation_result.is_valid:
                        logger.error(f"Invalid SSH key for {hostname}: {validation_result.error_message}")
                        raise SSHException(f"Invalid SSH key: {validation_result.error_message}")
                    
                    # Log any warnings
                    if validation_result.warnings:
                        logger.warning(f"SSH key warnings for {hostname}: {'; '.join(validation_result.warnings)}")
                    
                    # Parse key using unified parser
                    key = parse_ssh_key(credential)
                    ssh.connect(hostname, port=port, username=username, 
                               pkey=key, timeout=10)
                except SSHKeyError as e:
                    logger.error(f"SSH key parsing failed for {hostname}: {e}")
                    raise SSHException(f"SSH key error: {str(e)}")
                except Exception as e:
                    logger.error(f"SSH key connection failed for {hostname}: {e}")
                    raise
            else:
                raise SCAPContentError(f"Unsupported auth method: {auth_method}")
                
            # Test basic command execution
            stdin, stdout, stderr = ssh.exec_command('echo "OpenWatch SSH Test"')
            output = stdout.read().decode()
            error = stderr.read().decode()
            
            # Check if oscap is available on remote host
            stdin, stdout, stderr = ssh.exec_command('oscap --version')
            oscap_output = stdout.read().decode()
            oscap_error = stderr.read().decode()
            
            oscap_available = stdout.channel.recv_exit_status() == 0
            
            ssh.close()
            
            result = {
                "success": True,
                "message": "SSH connection successful",
                "oscap_available": oscap_available,
                "oscap_version": oscap_output.strip() if oscap_available else None,
                "test_output": output.strip()
            }
            
            if not oscap_available:
                result["warning"] = "OpenSCAP not found on remote host"
                
            logger.info(f"SSH test successful: {hostname}")
            return result
            
        except SSHException as e:
            logger.error(f"SSH connection failed: {e}")
            return {
                "success": False,
                "message": f"SSH connection failed: {str(e)}",
                "oscap_available": False
            }
        except Exception as e:
            logger.error(f"SSH test error: {e}")
            return {
                "success": False,
                "message": f"Connection test failed: {str(e)}",
                "oscap_available": False
            }
            
    def execute_local_scan(self, content_path: str, profile_id: str, 
                          scan_id: str, rule_id: str = None) -> Dict:
        """Execute SCAP scan on local system"""
        try:
            logger.info(f"Starting local scan: {scan_id}")
            
            # Create result directory for this scan
            scan_dir = self.results_dir / scan_id
            scan_dir.mkdir(exist_ok=True)
            
            # Define output files
            xml_result = scan_dir / "results.xml"
            html_report = scan_dir / "report.html"
            arf_result = scan_dir / "results.arf.xml"
            
            # Execute oscap scan
            cmd = [
                'oscap', 'xccdf', 'eval',
                '--profile', profile_id,
                '--results', str(xml_result),
                '--report', str(html_report),
                '--results-arf', str(arf_result)
            ]
            
            # Add rule-specific scanning if rule_id is provided
            if rule_id:
                cmd.extend(['--rule', rule_id])
                logger.info(f"Scanning specific rule: {rule_id}")
            
            cmd.append(content_path)
            
            logger.info(f"Executing: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd, capture_output=True, text=True, 
                timeout=1800  # 30 minutes timeout
            )
            
            # Parse results with content file for remediation extraction
            scan_results = self._parse_scan_results(str(xml_result), content_path)
            scan_results.update({
                "scan_id": scan_id,
                "scan_type": "local",
                "exit_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "xml_result": str(xml_result),
                "html_report": str(html_report),
                "arf_result": str(arf_result)
            })
            
            logger.info(f"Local scan completed: {scan_id}")
            return scan_results
            
        except subprocess.TimeoutExpired:
            logger.error(f"Scan timeout: {scan_id}")
            raise ScanExecutionError("Scan execution timeout")
        except Exception as e:
            logger.error(f"Local scan failed: {e}")
            raise ScanExecutionError(f"Scan execution failed: {str(e)}")
            
    def execute_remote_scan(self, hostname: str, port: int, username: str,
                           auth_method: str, credential: str, content_path: str,
                           profile_id: str, scan_id: str, rule_id: str = None) -> Dict:
        """Execute SCAP scan on remote system via SSH"""
        try:
            logger.info(f"Starting remote scan: {scan_id} on {hostname}")
            
            # Create result directory for this scan
            scan_dir = self.results_dir / scan_id
            scan_dir.mkdir(exist_ok=True)
            
            # Define output files
            xml_result = scan_dir / "results.xml"
            html_report = scan_dir / "report.html"
            arf_result = scan_dir / "results.arf.xml"
            
            # Prepare SSH connection parameters
            ssh_options = [
                '-o', 'StrictHostKeyChecking=no',
                '-o', 'UserKnownHostsFile=/dev/null',
                '-p', str(port)
            ]
            
            # For all authentication methods, use paramiko for SSH execution
            # oscap-ssh is not available in the standard OpenSCAP package
            return self._execute_remote_scan_with_paramiko(
                hostname, port, username, auth_method, credential, content_path,
                profile_id, scan_id, xml_result, html_report, arf_result, rule_id
            )
            
        except subprocess.TimeoutExpired:
            logger.error(f"Remote scan timeout: {scan_id}")
            raise ScanExecutionError("Remote scan execution timeout")
        except Exception as e:
            logger.error(f"Remote scan failed: {e}")
            raise ScanExecutionError(f"Remote scan execution failed: {str(e)}")
            
    def get_system_info(self, hostname: str = None, port: int = 22, 
                       username: str = None, auth_method: str = None,
                       credential: str = None) -> Dict:
        """Get system information from local or remote host"""
        try:
            if hostname:
                # Remote system info
                return self._get_remote_system_info(hostname, port, username, 
                                                   auth_method, credential)
            else:
                # Local system info
                return self._get_local_system_info()
                
        except Exception as e:
            logger.error(f"Error getting system info: {e}")
            return {"error": str(e)}
            
    def _parse_oscap_info(self, info_output: str) -> Dict:
        """Parse oscap info command output"""
        info = {}
        lines = info_output.split('\n')
        
        for line in lines:
            line = line.strip()
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower().replace(' ', '_')
                value = value.strip()
                info[key] = value
                
        return info
        
    def _parse_profiles(self, profiles_output: str) -> List[Dict]:
        """Parse profiles from oscap info --profiles output"""
        profiles = []
        lines = profiles_output.split('\n')
        
        current_profile = None
        for line in lines:
            line = line.strip()
            if line.startswith('Profile ID:'):
                if current_profile:
                    profiles.append(current_profile)
                current_profile = {
                    'id': line.split(':', 1)[1].strip(),
                    'title': '',
                    'description': ''
                }
            elif line.startswith('Title:') and current_profile:
                current_profile['title'] = line.split(':', 1)[1].strip()
            elif line.startswith('Description:') and current_profile:
                current_profile['description'] = line.split(':', 1)[1].strip()
                
        if current_profile:
            profiles.append(current_profile)
            
        return profiles
        
    def _parse_scan_results(self, xml_file: str, content_file: str = None) -> Dict:
        """Parse SCAP scan results from XML file with enhanced remediation extraction"""
        try:
            if not os.path.exists(xml_file):
                return {"error": "Results file not found"}
                
            tree = etree.parse(xml_file)
            root = tree.getroot()
            
            # Extract basic statistics
            namespaces = {
                'xccdf': 'http://checklists.nist.gov/xccdf/1.2'
            }
            
            results = {
                "timestamp": datetime.now().isoformat(),
                "rules_total": 0,
                "rules_passed": 0,
                "rules_failed": 0,
                "rules_error": 0,
                "rules_unknown": 0,
                "rules_notapplicable": 0,
                "rules_notchecked": 0,
                "score": 0.0,
                "failed_rules": [],
                "rule_details": []  # Enhanced rule details with remediation
            }
            
            # Load SCAP content for remediation extraction if available
            content_tree = None
            if content_file and os.path.exists(content_file):
                try:
                    content_tree = etree.parse(content_file)
                    logger.info(f"Loaded SCAP content for remediation extraction: {content_file}")
                except Exception as e:
                    logger.warning(f"Could not load SCAP content file: {e}")
            
            # Count rule results and extract detailed information
            rule_results = root.xpath('//xccdf:rule-result', namespaces=namespaces)
            results["rules_total"] = len(rule_results)
            
            for rule_result in rule_results:
                result_elem = rule_result.find('xccdf:result', namespaces)
                if result_elem is not None:
                    result_value = result_elem.text
                    rule_id = rule_result.get('idref', '')
                    severity = rule_result.get('severity', 'unknown')
                    
                    # Extract remediation information from SCAP content
                    remediation_info = self._extract_rule_remediation(rule_id, content_tree, namespaces)
                    
                    # Create detailed rule entry
                    rule_detail = {
                        "rule_id": rule_id,
                        "result": result_value,
                        "severity": severity,
                        "title": remediation_info.get("title", ""),
                        "description": remediation_info.get("description", ""),
                        "rationale": remediation_info.get("rationale", ""),
                        "remediation": remediation_info.get("remediation", {}),
                        "references": remediation_info.get("references", [])
                    }
                    
                    results["rule_details"].append(rule_detail)
                    
                    # Count by result type
                    if result_value == 'pass':
                        results["rules_passed"] += 1
                    elif result_value == 'fail':
                        results["rules_failed"] += 1
                        # Extract failed rule info (backward compatibility)
                        results["failed_rules"].append({
                            "rule_id": rule_id,
                            "severity": severity
                        })
                    elif result_value == 'error':
                        results["rules_error"] += 1
                    elif result_value == 'unknown':
                        results["rules_unknown"] += 1
                    elif result_value == 'notapplicable':
                        results["rules_notapplicable"] += 1
                    elif result_value == 'notchecked':
                        results["rules_notchecked"] += 1
                        
            # Calculate score
            if results["rules_total"] > 0:
                results["score"] = (results["rules_passed"] / 
                                 (results["rules_passed"] + results["rules_failed"])) * 100
                                 
            return results
            
        except Exception as e:
            logger.error(f"Error parsing scan results: {e}")
            return {"error": f"Failed to parse results: {str(e)}"}
    
    def _extract_rule_remediation(self, rule_id: str, content_tree, namespaces: Dict) -> Dict:
        """Extract detailed rule information and remediation from SCAP content"""
        remediation_info = {
            "title": "",
            "description": "",
            "rationale": "", 
            "remediation": {},
            "references": []
        }
        
        if not content_tree:
            return remediation_info
            
        try:
            # Find the rule definition in the SCAP content
            rule_xpath = f'.//xccdf:Rule[@id="{rule_id}"]'
            rules = content_tree.xpath(rule_xpath, namespaces=namespaces)
            
            if not rules:
                logger.debug(f"Rule not found in SCAP content: {rule_id}")
                return remediation_info
                
            rule = rules[0]
            
            # Extract title
            title_elem = rule.find('xccdf:title', namespaces)
            if title_elem is not None:
                remediation_info["title"] = self._extract_text_content(title_elem)
            
            # Extract description
            desc_elem = rule.find('xccdf:description', namespaces)
            if desc_elem is not None:
                remediation_info["description"] = self._extract_text_content(desc_elem)
            
            # Extract rationale
            rationale_elem = rule.find('xccdf:rationale', namespaces)
            if rationale_elem is not None:
                remediation_info["rationale"] = self._extract_text_content(rationale_elem)
            
            # Extract remediation information
            remediation_info["remediation"] = self._extract_remediation_details(rule, namespaces)
            
            # Extract references
            remediation_info["references"] = self._extract_references(rule, namespaces)
            
            logger.debug(f"Extracted remediation info for rule: {rule_id}")
            return remediation_info
            
        except Exception as e:
            logger.error(f"Error extracting remediation for rule {rule_id}: {e}")
            return remediation_info
    
    def _extract_text_content(self, element) -> str:
        """Extract clean text content from XML element, handling HTML tags"""
        if element is None:
            return ""
            
        # Get text content and clean up HTML tags
        text = etree.tostring(element, method='text', encoding='unicode').strip()
        
        # Clean up extra whitespace
        import re
        text = re.sub(r'\s+', ' ', text).strip()
        
        return text
    
    def _extract_remediation_details(self, rule_element, namespaces: Dict) -> Dict:
        """Extract remediation details from rule element with enhanced Fix Text and OpenSCAP remediation parsing"""
        remediation = {
            "type": "manual",
            "complexity": "unknown", 
            "disruption": "unknown",
            "description": "",
            "fix_text": "",
            "detailed_description": "",
            "steps": [],
            "commands": [],
            "configuration": []
        }
        
        try:
            # First Priority: Look for SCAP compliance checker "Fix Text" elements
            fixtext_elements = rule_element.findall('.//xccdf:fixtext', namespaces)
            if fixtext_elements:
                logger.debug("Found SCAP compliance checker Fix Text elements")
                for fixtext in fixtext_elements:
                    fix_content = self._extract_text_content(fixtext)
                    if fix_content:
                        remediation["fix_text"] = fix_content
                        remediation["description"] = fix_content
                        remediation["type"] = "manual"
                        
                        # Extract detailed steps from Fix Text
                        parsed_steps = self._parse_remediation_text(fix_content)
                        remediation.update(parsed_steps)
                        
                        logger.debug(f"Extracted Fix Text: {fix_content[:100]}...")
                        break  # Use first available fix text
            
            # Second Priority: Look for OpenSCAP Evaluation Report "remediation" elements
            remediation_elements = rule_element.findall('.//xccdf:remediation', namespaces)
            if remediation_elements and not remediation["description"]:
                logger.debug("Found OpenSCAP Evaluation Report remediation elements")
                for remediation_elem in remediation_elements:
                    remediation_content = self._extract_text_content(remediation_elem)
                    if remediation_content:
                        remediation["description"] = remediation_content
                        remediation["type"] = "manual"
                        
                        # Extract steps from remediation content
                        parsed_steps = self._parse_remediation_text(remediation_content)
                        remediation.update(parsed_steps)
                        
                        logger.debug(f"Extracted OpenSCAP remediation: {remediation_content[:100]}...")
                        break
            
            # Third Priority: Look for fix elements with different strategies
            fix_elements = rule_element.findall('.//xccdf:fix', namespaces)
            for fix_elem in fix_elements:
                strategy = fix_elem.get('strategy', 'unknown')
                complexity = fix_elem.get('complexity', 'unknown')
                disruption = fix_elem.get('disruption', 'unknown')
                
                remediation["complexity"] = complexity
                remediation["disruption"] = disruption
                
                fix_content = self._extract_text_content(fix_elem)
                if fix_content and not remediation["description"]:
                    logger.debug("Found xccdf:fix element")
                    if strategy in ['configure', 'patch']:
                        remediation["type"] = "automatic"
                        # Extract configuration commands
                        parsed_config = self._parse_configuration_commands(fix_content)
                        remediation["commands"].extend(parsed_config)
                    else:
                        remediation["type"] = "manual"
                        parsed_steps = self._parse_remediation_text(fix_content)
                        remediation.update(parsed_steps)
                    
                    remediation["description"] = fix_content
            
            # Fourth Priority: Look for detailed description elements
            description_selectors = [
                './/xccdf:description',
                './/description',
                './/long_name', 
                './/detail'
            ]
            
            for selector in description_selectors:
                desc_elements = rule_element.findall(selector, namespaces)
                for desc_elem in desc_elements:
                    detailed_desc = self._extract_text_content(desc_elem)
                    if detailed_desc and len(detailed_desc) > len(remediation.get("detailed_description", "")):
                        remediation["detailed_description"] = detailed_desc
                        logger.debug(f"Found detailed description: {detailed_desc[:100]}...")
            
            # Fifth Priority: Look for check-content for additional context
            check_elements = rule_element.findall('.//xccdf:check-content', namespaces)
            for check_elem in check_elements:
                check_content = self._extract_text_content(check_elem)
                if check_content and not remediation["description"]:
                    # Use check content as description if no other description available
                    remediation["description"] = f"Ensure: {check_content}"
                    logger.debug("Using check-content as fallback description")
            
            # Enhanced parsing for specific compliance frameworks
            self._extract_framework_specific_remediation(rule_element, namespaces, remediation)
            
            return remediation
            
        except Exception as e:
            logger.error(f"Error extracting remediation details: {e}")
            return remediation
    
    def _parse_remediation_text(self, text: str) -> Dict:
        """Parse remediation text to extract structured steps and commands"""
        steps = []
        commands = []
        configuration = []
        
        if not text:
            return {"steps": steps, "commands": commands, "configuration": configuration}
        
        try:
            # Split text into lines for processing
            lines = [line.strip() for line in text.split('\n') if line.strip()]
            
            current_step = ""
            for line in lines:
                # Detect commands (lines that look like shell commands)
                if self._is_command_line(line):
                    commands.append({
                        "command": line,
                        "type": "shell",
                        "description": current_step or "Execute command"
                    })
                    current_step = ""
                # Detect configuration entries
                elif self._is_configuration_line(line):
                    configuration.append({
                        "setting": line,
                        "type": "config",
                        "description": current_step or "Configuration setting"
                    })
                    current_step = ""
                # Detect step descriptions
                elif line.endswith(':') or any(keyword in line.lower() for keyword in 
                    ['step', 'install', 'configure', 'edit', 'modify', 'ensure', 'set', 'enable', 'disable']):
                    if current_step:
                        steps.append(current_step)
                    current_step = line
                else:
                    # Continue building current step
                    if current_step:
                        current_step += " " + line
                    else:
                        current_step = line
            
            # Add any remaining step
            if current_step:
                steps.append(current_step)
            
            return {"steps": steps, "commands": commands, "configuration": configuration}
            
        except Exception as e:
            logger.error(f"Error parsing remediation text: {e}")
            return {"steps": steps, "commands": commands, "configuration": configuration}
    
    def _is_command_line(self, line: str) -> bool:
        """Check if a line looks like a shell command"""
        command_indicators = [
            'sudo ', '# ', '$ ', 'yum ', 'apt-get ', 'systemctl ', 'chmod ', 'chown ',
            'grep ', 'sed ', 'awk ', 'echo ', 'cat ', 'vi ', 'nano ', 'service ',
            'mount ', 'umount ', 'iptables ', 'firewall-cmd ', 'sysctl '
        ]
        
        line_lower = line.lower()
        return any(line_lower.startswith(indicator) for indicator in command_indicators)
    
    def _is_configuration_line(self, line: str) -> bool:
        """Check if a line looks like a configuration setting"""
        config_patterns = [
            '=', ':', 'yes', 'no', 'true', 'false', 'enabled', 'disabled'
        ]
        
        # Lines that contain assignment or common config values
        return any(pattern in line.lower() for pattern in config_patterns) and \
               not self._is_command_line(line) and \
               len(line.split()) <= 5  # Config lines are usually short
    
    def _parse_configuration_commands(self, text: str) -> List[Dict]:
        """Parse configuration-style commands from fix text"""
        commands = []
        
        try:
            lines = [line.strip() for line in text.split('\n') if line.strip()]
            
            for line in lines:
                if self._is_command_line(line):
                    commands.append({
                        "command": line,
                        "type": "shell",
                        "description": "Automated remediation command"
                    })
                elif '=' in line or ':' in line:
                    commands.append({
                        "command": line,
                        "type": "config",
                        "description": "Configuration setting"
                    })
            
            return commands
            
        except Exception as e:
            logger.error(f"Error parsing configuration commands: {e}")
            return commands
    
    def _extract_references(self, rule_element, namespaces: Dict) -> List[Dict]:
        """Extract reference information from rule element"""
        references = []
        
        try:
            # Look for reference elements
            ref_elements = rule_element.findall('.//xccdf:reference', namespaces)
            for ref_elem in ref_elements:
                href = ref_elem.get('href', '')
                text = self._extract_text_content(ref_elem)
                
                if href or text:
                    references.append({
                        "href": href,
                        "text": text,
                        "type": "external"
                    })
            
            # Look for ident elements (like CCE, CVE references)
            ident_elements = rule_element.findall('.//xccdf:ident', namespaces)
            for ident_elem in ident_elements:
                system = ident_elem.get('system', '')
                ident_text = ident_elem.text or ''
                
                if ident_text:
                    ref_type = "CCE" if "cce" in system.lower() else "identifier"
                    references.append({
                        "href": system,
                        "text": ident_text,
                        "type": ref_type
                    })
            
            return references
            
        except Exception as e:
            logger.error(f"Error extracting references: {e}")
            return references
    
    def _extract_framework_specific_remediation(self, rule_element, namespaces: Dict, remediation: Dict):
        """Extract remediation from framework-specific elements (DISA STIG, CIS, etc.)"""
        try:
            # Look for DISA STIG specific elements
            stig_elements = [
                './/stig:fix_text',
                './/stig:fixtext', 
                './/fixtext',
                './/fix_text'
            ]
            
            for selector in stig_elements:
                try:
                    elements = rule_element.findall(selector, namespaces)
                    for elem in elements:
                        stig_content = self._extract_text_content(elem)
                        if stig_content and not remediation["fix_text"]:
                            remediation["fix_text"] = stig_content
                            remediation["description"] = stig_content
                            logger.debug(f"Found DISA STIG fix text: {stig_content[:100]}...")
                            return
                except:
                    continue
            
            # Look for CIS Benchmark specific elements
            cis_elements = [
                './/cis:remediation',
                './/benchmark:remediation',
                './/remediation_procedure',
                './/audit_procedure'
            ]
            
            for selector in cis_elements:
                try:
                    elements = rule_element.findall(selector, namespaces)
                    for elem in elements:
                        cis_content = self._extract_text_content(elem)
                        if cis_content and not remediation["description"]:
                            remediation["description"] = cis_content
                            logger.debug(f"Found CIS Benchmark remediation: {cis_content[:100]}...")
                            return
                except:
                    continue
            
            # Look for NIST specific elements
            nist_elements = [
                './/nist:implementation_guidance',
                './/implementation_guidance',
                './/guidance',
                './/supplemental_guidance'
            ]
            
            for selector in nist_elements:
                try:
                    elements = rule_element.findall(selector, namespaces)
                    for elem in elements:
                        nist_content = self._extract_text_content(elem)
                        if nist_content and not remediation["detailed_description"]:
                            remediation["detailed_description"] = nist_content
                            logger.debug(f"Found NIST guidance: {nist_content[:100]}...")
                except:
                    continue
                    
            # Look for generic remediation patterns in text content
            self._extract_generic_remediation_patterns(rule_element, remediation)
            
        except Exception as e:
            logger.error(f"Error extracting framework-specific remediation: {e}")
    
    def _extract_generic_remediation_patterns(self, rule_element, remediation: Dict):
        """Extract remediation from common text patterns"""
        try:
            # Get all text content from the rule element
            all_text = self._extract_text_content(rule_element)
            
            if not all_text:
                return
            
            # Look for common remediation keywords and sections
            remediation_keywords = [
                "fix text:", "remediation:", "to remediate:", "fix procedure:",
                "corrective action:", "resolution:", "mitigation:", "solution:",
                "to resolve:", "recommended action:", "implementation:"
            ]
            
            lines = all_text.split('\n')
            current_section = ""
            remediation_found = False
            
            for i, line in enumerate(lines):
                line_lower = line.lower().strip()
                
                # Check if this line contains a remediation keyword
                for keyword in remediation_keywords:
                    if keyword in line_lower:
                        # Extract the remediation content that follows
                        remediation_content = ""
                        
                        # Get content from the same line (after the keyword)
                        if ':' in line:
                            remediation_content = line.split(':', 1)[1].strip()
                        
                        # Get content from following lines until we hit another section
                        for j in range(i + 1, min(i + 10, len(lines))):  # Look ahead up to 10 lines
                            next_line = lines[j].strip()
                            if not next_line:
                                continue
                            
                            # Stop if we hit another section header
                            if any(stop_word in next_line.lower() for stop_word in 
                                  ['vulnerability discussion:', 'check text:', 'references:', 'severity:']):
                                break
                                
                            remediation_content += " " + next_line
                        
                        if remediation_content and len(remediation_content.strip()) > 20:
                            if not remediation["description"]:
                                remediation["description"] = remediation_content.strip()
                            elif not remediation["fix_text"]:
                                remediation["fix_text"] = remediation_content.strip()
                            
                            logger.debug(f"Found generic remediation pattern: {remediation_content[:100]}...")
                            remediation_found = True
                            break
                
                if remediation_found:
                    break
                    
        except Exception as e:
            logger.error(f"Error extracting generic remediation patterns: {e}")
            
    def _get_local_system_info(self) -> Dict:
        """Get local system information"""
        try:
            # Get OS info
            with open('/etc/os-release', 'r') as f:
                os_info = {}
                for line in f:
                    if '=' in line:
                        key, value = line.strip().split('=', 1)
                        os_info[key] = value.strip('"')
                        
            # Get system stats
            import psutil
            
            return {
                "hostname": os.uname().nodename,
                "os_name": os_info.get('NAME', 'Unknown'),
                "os_version": os_info.get('VERSION', 'Unknown'),
                "kernel": os.uname().release,
                "architecture": os.uname().machine,
                "cpu_count": psutil.cpu_count(),
                "memory_total": psutil.virtual_memory().total,
                "disk_usage": dict(psutil.disk_usage('/')),
                "uptime": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting local system info: {e}")
            return {"error": str(e)}
            
    def _get_remote_system_info(self, hostname: str, port: int, username: str,
                               auth_method: str, credential: str) -> Dict:
        """Get remote system information via SSH"""
        try:
            ssh = paramiko.SSHClient()
            # Security Fix: Use strict host key checking instead of AutoAddPolicy
            ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
            # Load system and user host keys for validation
            try:
                ssh.load_system_host_keys()
                ssh.load_host_keys(os.path.expanduser('~/.ssh/known_hosts'))
            except FileNotFoundError:
                logger.warning("No known_hosts files found - SSH connections may fail without proper host key management")
            
            # Connect
            if auth_method == "password":
                ssh.connect(hostname, port=port, username=username, 
                           password=credential, timeout=10)
            else:
                # Handle SSH key using new utility
                try:
                    key = parse_ssh_key(credential)
                    ssh.connect(hostname, port=port, username=username, 
                               pkey=key, timeout=10)
                except SSHKeyError as e:
                    logger.error(f"SSH key parsing failed for remote system info: {e}")
                    raise Exception(f"SSH key error: {str(e)}")
                except Exception as e:
                    logger.error(f"SSH connection failed for remote system info: {e}")
                    raise
                           
            # Execute commands to get system info
            commands = {
                "hostname": "hostname",
                "os_release": "cat /etc/os-release 2>/dev/null || echo 'ID=unknown'",
                "kernel": "uname -r",
                "architecture": "uname -m",
                "uptime": "uptime",
                "memory": "free -m | grep '^Mem:' | awk '{print $2}'",
                "cpu_info": "nproc"
            }
            
            results = {}
            for key, cmd in commands.items():
                stdin, stdout, stderr = ssh.exec_command(cmd)
                output = stdout.read().decode().strip()
                results[key] = output
                
            ssh.close()
            
            # Parse OS release info
            os_info = {}
            for line in results.get("os_release", "").split('\n'):
                if '=' in line:
                    key, value = line.split('=', 1)
                    os_info[key] = value.strip('"')
                    
            return {
                "hostname": results.get("hostname", hostname),
                "os_name": os_info.get('NAME', 'Unknown'),
                "os_version": os_info.get('VERSION', 'Unknown'),
                "kernel": results.get("kernel", "Unknown"),
                "architecture": results.get("architecture", "Unknown"),
                "cpu_count": int(results.get("cpu_info", "0")),
                "memory_mb": int(results.get("memory", "0")),
                "uptime": results.get("uptime", "Unknown")
            }
            
        except Exception as e:
            logger.error(f"Error getting remote system info: {e}")
            return {"error": str(e)}
            
    def _execute_remote_scan_with_paramiko(self, hostname: str, port: int, username: str,
                                          auth_method: str, credential: str, content_path: str, 
                                          profile_id: str, scan_id: str, xml_result: Path, 
                                          html_report: Path, arf_result: Path, rule_id: str = None) -> Dict:
        """Execute remote SCAP scan using paramiko for all authentication methods"""
        try:
            logger.info(f"Executing remote scan via paramiko: {scan_id} on {hostname}")
            
            ssh = paramiko.SSHClient()
            # Security Fix: Use strict host key checking instead of AutoAddPolicy
            ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
            # Load system and user host keys for validation
            try:
                ssh.load_system_host_keys()
                ssh.load_host_keys(os.path.expanduser('~/.ssh/known_hosts'))
            except FileNotFoundError:
                logger.warning("No known_hosts files found - SSH connections may fail without proper host key management")
            
            # Connect based on authentication method
            if auth_method == "password":
                ssh.connect(hostname, port=port, username=username, 
                           password=credential, timeout=30)
            elif auth_method in ["ssh-key", "ssh_key"]:
                # Handle SSH key authentication using new utility
                try:
                    # Validate SSH key first
                    validation_result = validate_ssh_key(credential)
                    if not validation_result.is_valid:
                        logger.error(f"Invalid SSH key for {hostname}: {validation_result.error_message}")
                        raise SSHException(f"Invalid SSH key: {validation_result.error_message}")
                    
                    # Parse key using unified parser
                    key = parse_ssh_key(credential)
                    ssh.connect(hostname, port=port, username=username, 
                               pkey=key, timeout=30)
                except SSHKeyError as e:
                    logger.error(f"SSH key parsing failed for {hostname}: {e}")
                    raise SSHException(f"SSH key error: {str(e)}")
                except Exception as e:
                    logger.error(f"SSH key connection failed for {hostname}: {e}")
                    raise
            else:
                raise ScanExecutionError(f"Unsupported auth method: {auth_method}")
            
            # Create remote directory for results
            remote_results_dir = f"/tmp/openwatch_scan_{scan_id}"
            ssh.exec_command(f"mkdir -p {remote_results_dir}")
            
            # Define remote file paths
            remote_xml = f"{remote_results_dir}/results.xml"
            remote_html = f"{remote_results_dir}/report.html"
            remote_arf = f"{remote_results_dir}/results.arf.xml"
            
            # Transfer SCAP content file to remote host
            sftp = ssh.open_sftp()
            remote_content_path = f"{remote_results_dir}/content.xml"
            
            try:
                sftp.put(content_path, remote_content_path)
                logger.info(f"Transferred SCAP content to remote host: {remote_content_path}")
            except Exception as e:
                sftp.close()
                raise ScanExecutionError(f"Failed to transfer SCAP content to remote host: {str(e)}")
            
            sftp.close()
            
            # Build and execute oscap command on remote host with transferred file
            oscap_cmd = (f"oscap xccdf eval "
                        f"--profile {profile_id} "
                        f"--results {remote_xml} "
                        f"--report {remote_html} "
                        f"--results-arf {remote_arf} ")
            
            # Add rule-specific scanning if rule_id is provided
            if rule_id:
                oscap_cmd += f"--rule {rule_id} "
                logger.info(f"Remote scanning specific rule via paramiko: {rule_id}")
            
            oscap_cmd += f"{remote_content_path}"
            
            logger.info(f"Executing remote command: {oscap_cmd}")
            
            stdin, stdout, stderr = ssh.exec_command(oscap_cmd, timeout=1800)  # 30 minutes
            
            # Wait for command completion and get exit code
            exit_code = stdout.channel.recv_exit_status()
            stdout_data = stdout.read().decode()
            stderr_data = stderr.read().decode()
            
            logger.info(f"Remote oscap command completed with exit code: {exit_code}")
            
            # Copy result files back to local system
            sftp = ssh.open_sftp()
            
            try:
                sftp.get(remote_xml, str(xml_result))
                logger.info(f"Downloaded results file: {xml_result}")
            except FileNotFoundError:
                logger.warning("Results XML file not found on remote host")
                
            try:
                sftp.get(remote_html, str(html_report))
                logger.info(f"Downloaded report file: {html_report}")
            except FileNotFoundError:
                logger.warning("HTML report file not found on remote host")
                
            try:
                sftp.get(remote_arf, str(arf_result))
                logger.info(f"Downloaded ARF file: {arf_result}")
            except FileNotFoundError:
                logger.warning("ARF results file not found on remote host")
            
            sftp.close()
            
            # Clean up remote files
            ssh.exec_command(f"rm -rf {remote_results_dir}")
            ssh.close()
            
            # Parse results if XML file exists
            if xml_result.exists():
                scan_results = self._parse_scan_results(str(xml_result), content_path)
            else:
                # If no results file, create basic results from command output
                scan_results = {
                    "timestamp": datetime.now().isoformat(),
                    "rules_total": 0,
                    "rules_passed": 0,
                    "rules_failed": 0,
                    "rules_error": 0,
                    "score": 0.0,
                    "failed_rules": []
                }
                
            scan_results.update({
                "scan_id": scan_id,
                "scan_type": "remote_paramiko",
                "target_host": hostname,
                "exit_code": exit_code,
                "stdout": stdout_data,
                "stderr": stderr_data,
                "xml_result": str(xml_result) if xml_result.exists() else None,
                "html_report": str(html_report) if html_report.exists() else None,
                "arf_result": str(arf_result) if arf_result.exists() else None
            })
            
            logger.info(f"Remote paramiko scan completed: {scan_id}")
            return scan_results
            
        except Exception as e:
            logger.error(f"Remote paramiko scan failed: {e}")
            raise ScanExecutionError(f"Remote scan execution failed: {str(e)}")
        finally:
            try:
                ssh.close()
            except:
                pass