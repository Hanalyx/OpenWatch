"""
OpenSCAP Scanner Service - Refactored
Handles SCAP content processing and scanning operations using the base scanner architecture
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

from .base_scap_scanner import BaseSCAPScanner, SCAPBaseError, SCAPConnectionManager
from ..config import get_settings

logger = logging.getLogger(__name__)


class SCAPContentError(SCAPBaseError):
    """Exception raised for SCAP content processing errors"""

    pass


class ScanExecutionError(SCAPBaseError):
    """Exception raised for scan execution errors"""

    pass


class SCAPScanner(BaseSCAPScanner):
    """
    Main SCAP scanning service - refactored to use base class

    This refactored version eliminates code duplication by inheriting from
    BaseSCAPScanner and focusing on implementation-specific logic.
    """

    def __init__(self, content_dir: Optional[str] = None, results_dir: Optional[str] = None):
        # Initialize base class with directory setup and shared components
        super().__init__(content_dir, results_dir)

        logger.info("SCAPScanner initialized with base scanner architecture")

    def execute_local_scan(
        self, content_path: str, profile_id: str, scan_id: str, rule_id: str = None
    ) -> Dict:
        """Execute SCAP scan on local system"""
        try:
            logger.info(f"Starting local scan: {scan_id}")

            # Create scan directory and get file paths
            scan_dir = self.create_scan_directory(scan_id)
            xml_result, html_report, arf_result = self.get_scan_file_paths(scan_dir)

            # Build oscap command using base class method
            cmd = self.build_oscap_command(
                profile_id, xml_result, html_report, arf_result, content_path, rule_id
            )

            logger.info(f"Executing: {' '.join(cmd)}")

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=1800  # 30 minutes timeout
            )

            # Parse results with content file for remediation extraction
            scan_results = self._parse_scan_results(str(xml_result), content_path)
            scan_results.update(
                {
                    "scan_id": scan_id,
                    "scan_type": "local",
                    "exit_code": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "xml_result": str(xml_result),
                    "html_report": str(html_report),
                    "arf_result": str(arf_result),
                }
            )

            logger.info(f"Local scan completed: {scan_id}")
            return scan_results

        except subprocess.TimeoutExpired:
            logger.error(f"Scan timeout: {scan_id}")
            raise ScanExecutionError("Scan execution timeout")
        except Exception as e:
            logger.error(f"Local scan failed: {e}")
            raise ScanExecutionError(f"Scan execution failed: {str(e)}")

    def execute_remote_scan(
        self,
        hostname: str,
        port: int,
        username: str,
        auth_method: str,
        credential: str,
        content_path: str,
        profile_id: str,
        scan_id: str,
        rule_id: str = None,
    ) -> Dict:
        """Execute SCAP scan on remote system via SSH"""
        try:
            logger.info(f"Starting remote scan: {scan_id} on {hostname}")

            # Create scan directory and get file paths
            scan_dir = self.create_scan_directory(scan_id)
            xml_result, html_report, arf_result = self.get_scan_file_paths(scan_dir)

            # Use paramiko for remote scan execution
            return self._execute_remote_scan_with_paramiko(
                hostname,
                port,
                username,
                auth_method,
                credential,
                content_path,
                profile_id,
                scan_id,
                xml_result,
                html_report,
                arf_result,
                rule_id,
            )

        except subprocess.TimeoutExpired:
            logger.error(f"Remote scan timeout: {scan_id}")
            raise ScanExecutionError("Remote scan execution timeout")
        except Exception as e:
            logger.error(f"Remote scan failed: {e}")
            raise ScanExecutionError(f"Remote scan execution failed: {str(e)}")

    def _execute_remote_scan_with_paramiko(
        self,
        hostname: str,
        port: int,
        username: str,
        auth_method: str,
        credential: str,
        content_path: str,
        profile_id: str,
        scan_id: str,
        xml_result: Path,
        html_report: Path,
        arf_result: Path,
        rule_id: str = None,
    ) -> Dict:
        """Execute remote SCAP scan using paramiko with base class connection manager"""
        try:
            logger.info(f"Executing remote scan via paramiko: {scan_id} on {hostname}")

            # Use base class connection manager for SSH setup
            ssh = self.connection_manager.create_ssh_client()

            # Connect based on authentication method using connection manager
            if auth_method == "password":
                ssh.connect(
                    hostname,
                    port=port,
                    username=username,
                    password=credential,
                    timeout=30,
                )
            elif auth_method in ["ssh-key", "ssh_key"]:
                # Use base class connection manager for key validation and parsing
                key = self.connection_manager.validate_and_parse_key(credential)
                ssh.connect(hostname, port=port, username=username, pkey=key, timeout=30)
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
                raise ScanExecutionError(
                    f"Failed to transfer SCAP content to remote host: {str(e)}"
                )

            sftp.close()

            # Build and execute oscap command on remote host
            oscap_cmd = (
                f"oscap xccdf eval "
                f"--profile {profile_id} "
                f"--results {remote_xml} "
                f"--report {remote_html} "
                f"--results-arf {remote_arf} "
            )

            # Add rule-specific scanning if rule_id is provided
            if rule_id:
                oscap_cmd += f"--rule {rule_id} "
                logger.info(f"Remote scanning specific rule: {rule_id}")

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
                    "failed_rules": [],
                }

            scan_results.update(
                {
                    "scan_id": scan_id,
                    "scan_type": "remote_paramiko",
                    "target_host": hostname,
                    "exit_code": exit_code,
                    "stdout": stdout_data,
                    "stderr": stderr_data,
                    "xml_result": str(xml_result) if xml_result.exists() else None,
                    "html_report": str(html_report) if html_report.exists() else None,
                    "arf_result": str(arf_result) if arf_result.exists() else None,
                }
            )

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

    def _parse_scan_results(self, xml_file: str, content_file: str = None) -> Dict:
        """Parse SCAP scan results from XML file with enhanced remediation extraction"""
        try:
            if not os.path.exists(xml_file):
                return {"error": "Results file not found"}

            tree = etree.parse(xml_file)
            root = tree.getroot()

            # Extract basic statistics
            namespaces = {"xccdf": "http://checklists.nist.gov/xccdf/1.2"}

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
                "rule_details": [],  # Enhanced rule details with remediation
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
            rule_results = root.xpath("//xccdf:rule-result", namespaces=namespaces)
            results["rules_total"] = len(rule_results)

            for rule_result in rule_results:
                result_elem = rule_result.find("xccdf:result", namespaces)
                if result_elem is not None:
                    result_value = result_elem.text
                    rule_id = rule_result.get("idref", "")
                    severity = rule_result.get("severity", "unknown")

                    # Extract remediation information from SCAP content
                    remediation_info = self._extract_rule_remediation(
                        rule_id, content_tree, namespaces
                    )

                    # Create detailed rule entry
                    rule_detail = {
                        "rule_id": rule_id,
                        "result": result_value,
                        "severity": severity,
                        "title": remediation_info.get("title", ""),
                        "description": remediation_info.get("description", ""),
                        "rationale": remediation_info.get("rationale", ""),
                        "remediation": remediation_info.get("remediation", {}),
                        "references": remediation_info.get("references", []),
                    }

                    results["rule_details"].append(rule_detail)

                    # Count by result type
                    if result_value == "pass":
                        results["rules_passed"] += 1
                    elif result_value == "fail":
                        results["rules_failed"] += 1
                        # Extract failed rule info (backward compatibility)
                        results["failed_rules"].append({"rule_id": rule_id, "severity": severity})
                    elif result_value == "error":
                        results["rules_error"] += 1
                    elif result_value == "unknown":
                        results["rules_unknown"] += 1
                    elif result_value == "notapplicable":
                        results["rules_notapplicable"] += 1
                    elif result_value == "notchecked":
                        results["rules_notchecked"] += 1

            # Calculate score
            if results["rules_total"] > 0:
                results["score"] = (
                    results["rules_passed"] / (results["rules_passed"] + results["rules_failed"])
                ) * 100

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
            "references": [],
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
            title_elem = rule.find("xccdf:title", namespaces)
            if title_elem is not None:
                remediation_info["title"] = self._extract_text_content(title_elem)

            # Extract description
            desc_elem = rule.find("xccdf:description", namespaces)
            if desc_elem is not None:
                remediation_info["description"] = self._extract_text_content(desc_elem)

            # Extract rationale
            rationale_elem = rule.find("xccdf:rationale", namespaces)
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
        text = etree.tostring(element, method="text", encoding="unicode").strip()

        # Clean up extra whitespace
        import re

        text = re.sub(r"\s+", " ", text).strip()

        return text

    def _extract_remediation_details(self, rule_element, namespaces: Dict) -> Dict:
        """Extract remediation details from rule element"""
        remediation = {
            "type": "manual",
            "complexity": "unknown",
            "disruption": "unknown",
            "description": "",
            "fix_text": "",
            "steps": [],
            "commands": [],
        }

        try:
            # Look for fixtext elements (SCAP compliance checker)
            fixtext_elements = rule_element.findall(".//xccdf:fixtext", namespaces)
            if fixtext_elements:
                for fixtext in fixtext_elements:
                    fix_content = self._extract_text_content(fixtext)
                    if fix_content:
                        remediation["fix_text"] = fix_content
                        remediation["description"] = fix_content
                        break

            # Look for fix elements with different strategies
            fix_elements = rule_element.findall(".//xccdf:fix", namespaces)
            for fix_elem in fix_elements:
                strategy = fix_elem.get("strategy", "unknown")
                complexity = fix_elem.get("complexity", "unknown")
                disruption = fix_elem.get("disruption", "unknown")

                remediation["complexity"] = complexity
                remediation["disruption"] = disruption

                fix_content = self._extract_text_content(fix_elem)
                if fix_content and not remediation["description"]:
                    if strategy in ["configure", "patch"]:
                        remediation["type"] = "automatic"
                    else:
                        remediation["type"] = "manual"

                    remediation["description"] = fix_content

            return remediation

        except Exception as e:
            logger.error(f"Error extracting remediation details: {e}")
            return remediation

    def _extract_references(self, rule_element, namespaces: Dict) -> List[Dict]:
        """Extract reference information from rule element"""
        references = []

        try:
            # Look for reference elements
            ref_elements = rule_element.findall(".//xccdf:reference", namespaces)
            for ref_elem in ref_elements:
                href = ref_elem.get("href", "")
                text = self._extract_text_content(ref_elem)

                if href or text:
                    references.append({"href": href, "text": text, "type": "external"})

            return references

        except Exception as e:
            logger.error(f"Error extracting references: {e}")
            return references
