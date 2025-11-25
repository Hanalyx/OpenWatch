"""
SCAP Data-Stream Processor Service
Handles modern SCAP data-stream format processing with profile extraction
"""

import hashlib
import logging
import os
import subprocess
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import lxml.etree as etree

from ..utils.scap_xml_utils import extract_text_content

logger = logging.getLogger(__name__)


class DataStreamError(Exception):
    """Exception for data-stream processing errors"""


class SCAPDataStreamProcessor:
    """Process SCAP data-stream format content"""

    def __init__(self, content_dir: str = "/app/data/scap"):
        self.content_dir = Path(content_dir)
        self.content_dir.mkdir(parents=True, exist_ok=True)

        # Namespaces for SCAP data-stream
        self.namespaces = {
            "ds": "http://scap.nist.gov/schema/scap/source/1.2",
            "xccdf": "http://checklists.nist.gov/xccdf/1.2",
            "cpe": "http://cpe.mitre.org/language/2.0",
            "oval": "http://oval.mitre.org/XMLSchema/oval-definitions-5",
            "xlink": "http://www.w3.org/1999/xlink",
        }

    def validate_datastream(self, file_path: str) -> Dict:
        """Validate SCAP data-stream file and extract metadata"""
        try:
            # Validate file path to prevent path traversal attacks
            if not isinstance(file_path, str) or ".." in file_path or not os.path.isfile(file_path):
                raise DataStreamError(f"Invalid or unsafe file path: {file_path}")

            logger.info(f"Validating SCAP data-stream: {file_path}")

            # First check if it's a ZIP file (common for DISA distributions)
            if zipfile.is_zipfile(file_path):
                return self._process_zip_content(file_path)

            # Use oscap to validate data-stream
            result = subprocess.run(
                ["oscap", "ds", "sds-validate", file_path],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                # Try as XCCDF file if data-stream validation fails
                return self._validate_xccdf_file(file_path)

            # Extract data-stream info
            info_result = subprocess.run(
                ["oscap", "info", file_path], capture_output=True, text=True, timeout=30
            )

            if info_result.returncode != 0:
                raise DataStreamError(f"Failed to extract info: {info_result.stderr}")

            metadata = self._parse_oscap_info(info_result.stdout)
            metadata["format"] = "data-stream"
            metadata["validation_status"] = "valid"

            # Extract additional metadata from XML
            xml_metadata = self._extract_xml_metadata(file_path)
            metadata.update(xml_metadata)

            logger.info(f"Data-stream validated successfully: {metadata.get('title', 'Unknown')}")
            return metadata

        except subprocess.TimeoutExpired:
            raise DataStreamError("Timeout validating data-stream")
        except Exception as e:
            logger.error(f"Error validating data-stream: {e}")
            raise DataStreamError(f"Validation failed: {str(e)}")

    def extract_profiles_with_metadata(self, file_path: str) -> List[Dict]:
        """Extract profiles with full metadata using oscap info --profiles"""
        try:
            # Validate file path to prevent path traversal attacks
            if not isinstance(file_path, str) or ".." in file_path or not os.path.isfile(file_path):
                raise DataStreamError(f"Invalid or unsafe file path: {file_path}")

            logger.info(f"Extracting profiles from: {file_path}")

            # Handle ZIP files
            if zipfile.is_zipfile(file_path):
                with tempfile.TemporaryDirectory() as temp_dir:
                    extracted_file = self._extract_scap_from_zip(file_path, temp_dir)
                    if extracted_file:
                        return self.extract_profiles_with_metadata(extracted_file)
                    else:
                        return []

            # Use oscap info --profiles for detailed profile information
            result = subprocess.run(
                ["oscap", "info", "--profiles", file_path],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                logger.warning(f"Failed to extract profiles: {result.stderr}")
                return []

            profiles = self._parse_detailed_profiles(result.stdout)

            # Enhance with XML parsing for additional metadata
            enhanced_profiles = self._enhance_profiles_from_xml(file_path, profiles)

            logger.info(f"Extracted {len(enhanced_profiles)} profiles with metadata")
            return enhanced_profiles

        except Exception as e:
            logger.error(f"Error extracting profiles: {e}")
            return []

    def extract_content_components(self, file_path: str) -> Dict:
        """Extract all components from SCAP content (data-streams, benchmarks, checks)"""
        try:
            # Validate file path to prevent path traversal attacks
            if not isinstance(file_path, str) or ".." in file_path or not os.path.isfile(file_path):
                raise DataStreamError(f"Invalid or unsafe file path: {file_path}")

            components = {
                "data_streams": [],
                "benchmarks": [],
                "profiles": [],
                "cpe_lists": [],
                "oval_definitions": [],
                "rules": [],
            }

            # Parse XML to extract components
            tree = etree.parse(file_path)
            root = tree.getroot()

            # Check if it's a data-stream collection
            if root.tag.endswith("data-stream-collection"):
                components["format"] = "data-stream-collection"
                components["data_streams"] = self._extract_datastreams(root)
            elif root.tag.endswith("Benchmark"):
                components["format"] = "xccdf-benchmark"
                components["benchmarks"] = [self._extract_benchmark_info(root)]
            else:
                components["format"] = "unknown"

            # Extract profiles
            components["profiles"] = self._extract_profiles_from_tree(root)

            # Extract rules with metadata
            components["rules"] = self._extract_rules_with_metadata(root)

            # Extract CPE and OVAL references
            components["cpe_lists"] = self._extract_cpe_references(root)
            components["oval_definitions"] = self._extract_oval_references(root)

            return components

        except Exception as e:
            logger.error(f"Error extracting content components: {e}")
            raise DataStreamError(f"Failed to extract components: {str(e)}")

    def create_content_validation_report(self, file_path: str) -> Dict:
        """Create comprehensive validation report for SCAP content"""
        # Validate file path to prevent path traversal attacks
        if not isinstance(file_path, str) or ".." in file_path or not os.path.isfile(file_path):
            return {
                "file_path": "INVALID_PATH",
                "timestamp": datetime.now().isoformat(),
                "validation_status": "error",
                "errors": [f"Invalid or unsafe file path: {file_path}"],
                "warnings": [],
                "info": {},
                "recommendations": [],
            }

        report = {
            "file_path": file_path,
            "timestamp": datetime.now().isoformat(),
            "validation_status": "unknown",
            "errors": [],
            "warnings": [],
            "info": {},
            "recommendations": [],
        }

        try:
            # Basic file checks
            file_stats = os.stat(file_path)
            report["info"]["file_size"] = file_stats.st_size
            report["info"]["file_hash"] = self._calculate_file_hash(file_path)

            # Validate with oscap
            validation_result = subprocess.run(
                ["oscap", "ds", "sds-validate", file_path],
                capture_output=True,
                text=True,
                timeout=60,
            )

            if validation_result.returncode == 0:
                report["validation_status"] = "valid_datastream"
            else:
                # Try XCCDF validation
                xccdf_result = subprocess.run(
                    ["oscap", "xccdf", "validate", file_path],
                    capture_output=True,
                    text=True,
                    timeout=60,
                )

                if xccdf_result.returncode == 0:
                    report["validation_status"] = "valid_xccdf"
                else:
                    report["validation_status"] = "invalid"
                    report["errors"].append(validation_result.stderr)

            # Extract content info
            info_result = subprocess.run(
                ["oscap", "info", file_path], capture_output=True, text=True, timeout=30
            )

            if info_result.returncode == 0:
                report["info"]["content_metadata"] = self._parse_oscap_info(info_result.stdout)

            # Check for common issues
            self._check_common_issues(file_path, report)

            # Generate recommendations
            self._generate_recommendations(report)

            return report

        except Exception as e:
            report["validation_status"] = "error"
            report["errors"].append(f"Validation error: {str(e)}")
            return report

    def _process_zip_content(self, zip_path: str) -> Dict:
        """Process SCAP content from ZIP file"""
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                with zipfile.ZipFile(zip_path, "r") as zip_file:
                    # Extract all files
                    zip_file.extractall(temp_dir)

                    # Find SCAP content files with path validation
                    scap_files = []
                    for root, dirs, files in os.walk(temp_dir):
                        # Prevent path traversal by checking that root is within temp_dir
                        if not os.path.commonpath([root, temp_dir]) == temp_dir:
                            continue
                        for file in files:
                            # Validate filename to prevent path traversal
                            if ".." in file or "/" in file:
                                continue
                            if file.endswith((".xml", ".scap")):
                                full_path = os.path.join(root, file)
                                # Additional security check
                                if not os.path.commonpath([full_path, temp_dir]) == temp_dir:
                                    continue
                                # Skip small files (likely metadata)
                                if os.path.getsize(full_path) > 1000:
                                    scap_files.append(full_path)

                    if not scap_files:
                        raise DataStreamError("No SCAP content found in ZIP file")

                    # Process the main SCAP file (usually the largest)
                    main_file = max(scap_files, key=os.path.getsize)

                    # Validate the extracted file
                    metadata = self.validate_datastream(main_file)
                    metadata["source_format"] = "zip"
                    metadata["extracted_from"] = os.path.basename(zip_path)

                    return metadata

        except Exception as e:
            logger.error(f"Error processing ZIP content: {e}")
            raise DataStreamError(f"Failed to process ZIP: {str(e)}")

    def _validate_xccdf_file(self, file_path: str) -> Dict:
        """Validate as XCCDF file if not a data-stream"""
        try:
            result = subprocess.run(
                ["oscap", "xccdf", "validate", file_path],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                raise DataStreamError(f"Invalid XCCDF content: {result.stderr}")

            # Extract XCCDF info
            info_result = subprocess.run(
                ["oscap", "info", file_path], capture_output=True, text=True, timeout=30
            )

            metadata = self._parse_oscap_info(info_result.stdout)
            metadata["format"] = "xccdf"
            metadata["validation_status"] = "valid"

            return metadata

        except Exception as e:
            raise DataStreamError(f"XCCDF validation failed: {str(e)}")

    def _extract_scap_from_zip(self, zip_path: str, extract_dir: str) -> Optional[str]:
        """Extract SCAP content file from ZIP"""
        try:
            with zipfile.ZipFile(zip_path, "r") as zip_file:
                # Look for SCAP data-stream or XCCDF files
                scap_patterns = ["-scap_", "_datastream", "-xccdf", ".xml", ".scap"]

                for file_info in zip_file.filelist:
                    filename = file_info.filename.lower()
                    if any(pattern in filename for pattern in scap_patterns):
                        # Skip directories and small files
                        if not file_info.is_dir() and file_info.file_size > 1000:
                            extracted_path = zip_file.extract(file_info, extract_dir)
                            return extracted_path

            return None

        except Exception as e:
            logger.error(f"Error extracting from ZIP: {e}")
            return None

    def _parse_oscap_info(self, info_output: str) -> Dict:
        """Parse oscap info command output"""
        info = {}
        lines = info_output.split("\n")

        for line in lines:
            line = line.strip()
            if ":" in line:
                key, value = line.split(":", 1)
                key = key.strip().lower().replace(" ", "_").replace("-", "_")
                value = value.strip()

                # Handle special cases
                if key == "profiles":
                    continue  # Profiles are parsed separately
                elif key == "referenced_check_files":
                    info[key] = [v.strip() for v in value.split(",") if v.strip()]
                else:
                    info[key] = value

        return info

    def _parse_detailed_profiles(self, profiles_output: str) -> List[Dict]:
        """Parse detailed profiles from oscap info --profiles output"""
        profiles = []
        current_profile = None

        lines = profiles_output.split("\n")

        for line in lines:
            line = line.strip()

            if line.startswith("Profile:"):
                # Save previous profile if exists
                if current_profile:
                    profiles.append(current_profile)

                # Extract profile ID (format: "Profile: profile_id")
                profile_id = line.split(":", 1)[1].strip()
                current_profile = {
                    "id": profile_id,
                    "title": "",
                    "description": "",
                    "extends": None,
                    "selected_rules": [],
                    "metadata": {},
                }

            elif line.startswith("Title:") and current_profile:
                current_profile["title"] = line.split(":", 1)[1].strip()

            elif line.startswith("Description:") and current_profile:
                # Description might span multiple lines
                desc_start = line.split(":", 1)[1].strip()
                current_profile["description"] = desc_start

            elif line.startswith("Extends:") and current_profile:
                current_profile["extends"] = line.split(":", 1)[1].strip()

            elif (
                line
                and current_profile
                and not any(
                    line.startswith(prefix)
                    for prefix in ["Profile:", "Title:", "Description:", "Extends:"]
                )
            ):
                # Continue description if no new field
                if current_profile["description"]:
                    current_profile["description"] += " " + line

        # Don't forget the last profile
        if current_profile:
            profiles.append(current_profile)

        return profiles

    def _enhance_profiles_from_xml(self, file_path: str, profiles: List[Dict]) -> List[Dict]:
        """Enhance profile information by parsing XML directly"""
        try:
            tree = etree.parse(file_path)
            root = tree.getroot()

            # Create profile lookup
            profile_lookup = {p["id"]: p for p in profiles}

            # Find all Profile elements
            profile_elements = root.xpath(".//xccdf:Profile", namespaces=self.namespaces)

            for profile_elem in profile_elements:
                profile_id = profile_elem.get("id", "")

                if profile_id in profile_lookup:
                    profile = profile_lookup[profile_id]

                    # Extract additional metadata
                    profile["metadata"]["severity"] = profile_elem.get("severity", "unknown")

                    # Extract platform information
                    platforms = profile_elem.xpath(".//xccdf:platform", namespaces=self.namespaces)
                    profile["metadata"]["platforms"] = [p.get("idref", "") for p in platforms]

                    # Count selected rules
                    selections = profile_elem.xpath(".//xccdf:select", namespaces=self.namespaces)
                    profile["metadata"]["rule_count"] = len(
                        [s for s in selections if s.get("selected") == "true"]
                    )

                    # Extract profile notes or remarks
                    remarks = profile_elem.xpath(".//xccdf:remark", namespaces=self.namespaces)
                    if remarks:
                        profile["metadata"]["remarks"] = [r.text for r in remarks if r.text]
                else:
                    # Profile found in XML but not in oscap output
                    new_profile = self._extract_profile_from_element(profile_elem)
                    profiles.append(new_profile)

            return profiles

        except Exception as e:
            logger.warning(f"Could not enhance profiles from XML: {e}")
            return profiles

    def _extract_profile_from_element(self, profile_elem) -> Dict:
        """Extract profile information from XML element"""
        profile = {
            "id": profile_elem.get("id", ""),
            "title": "",
            "description": "",
            "extends": profile_elem.get("extends", None),
            "selected_rules": [],
            "metadata": {},
        }

        # Extract title
        title_elem = profile_elem.find("xccdf:title", self.namespaces)
        if title_elem is not None and title_elem.text:
            profile["title"] = title_elem.text

        # Extract description
        desc_elem = profile_elem.find("xccdf:description", self.namespaces)
        if desc_elem is not None:
            profile["description"] = self._extract_text_content(desc_elem)

        # Extract selected rules
        selections = profile_elem.xpath(
            './/xccdf:select[@selected="true"]', namespaces=self.namespaces
        )
        profile["selected_rules"] = [s.get("idref", "") for s in selections]

        return profile

    def _extract_text_content(self, element) -> str:
        """Extract clean text content from XML element"""
        return extract_text_content(element)

    def _extract_xml_metadata(self, file_path: str) -> Dict:
        """Extract additional metadata from XML structure"""
        metadata = {}

        try:
            tree = etree.parse(file_path)
            root = tree.getroot()

            # Determine content type
            if root.tag.endswith("data-stream-collection"):
                metadata["content_type"] = "SCAP Data Stream Collection"
                metadata["scap_version"] = root.get("schematron-version", "1.2")

                # Count data streams
                streams = root.xpath(".//ds:data-stream", namespaces=self.namespaces)
                metadata["data_stream_count"] = len(streams)

            elif root.tag.endswith("Benchmark"):
                metadata["content_type"] = "XCCDF Benchmark"
                metadata["benchmark_id"] = root.get("id", "")
                metadata["benchmark_version"] = root.get("version", "")

                # Extract status
                status_elem = root.find(".//xccdf:status", self.namespaces)
                if status_elem is not None:
                    metadata["status"] = status_elem.text
                    metadata["status_date"] = status_elem.get("date", "")

            # Extract metadata elements
            metadata_elem = root.find(".//xccdf:metadata", self.namespaces)
            if metadata_elem is not None:
                # Extract DC metadata if present
                dc_elements = metadata_elem.xpath(
                    './/*[namespace-uri()="http://purl.org/dc/elements/1.1/"]'
                )
                for dc_elem in dc_elements:
                    tag_name = dc_elem.tag.split("}")[-1]
                    metadata[f"dc_{tag_name}"] = dc_elem.text

            return metadata

        except Exception as e:
            logger.warning(f"Could not extract XML metadata: {e}")
            return metadata

    def _extract_datastreams(self, root) -> List[Dict]:
        """Extract data-stream information"""
        datastreams = []

        ds_elements = root.xpath(".//ds:data-stream", namespaces=self.namespaces)
        for ds_elem in ds_elements:
            ds_info = {
                "id": ds_elem.get("id", ""),
                "timestamp": ds_elem.get("timestamp", ""),
                "version": ds_elem.get("scap-version", "1.2"),
                "components": [],
            }

            # Extract component references
            components = ds_elem.xpath(".//ds:component-ref", namespaces=self.namespaces)
            for comp in components:
                ds_info["components"].append(
                    {
                        "id": comp.get("id", ""),
                        "href": comp.get("{http://www.w3.org/1999/xlink}href", ""),
                    }
                )

            datastreams.append(ds_info)

        return datastreams

    def _extract_benchmark_info(self, benchmark_elem) -> Dict:
        """Extract benchmark information"""
        benchmark = {
            "id": benchmark_elem.get("id", ""),
            "version": benchmark_elem.get("version", ""),
            "status": "",
            "title": "",
            "description": "",
        }

        # Extract title
        title_elem = benchmark_elem.find(".//xccdf:title", self.namespaces)
        if title_elem is not None:
            benchmark["title"] = title_elem.text or ""

        # Extract description
        desc_elem = benchmark_elem.find(".//xccdf:description", self.namespaces)
        if desc_elem is not None:
            benchmark["description"] = self._extract_text_content(desc_elem)

        # Extract status
        status_elem = benchmark_elem.find(".//xccdf:status", self.namespaces)
        if status_elem is not None:
            benchmark["status"] = status_elem.text or ""

        return benchmark

    def _extract_profiles_from_tree(self, root) -> List[Dict]:
        """Extract all profiles from XML tree"""
        profiles = []

        profile_elements = root.xpath(".//xccdf:Profile", namespaces=self.namespaces)
        for profile_elem in profile_elements:
            profiles.append(self._extract_profile_from_element(profile_elem))

        return profiles

    def _extract_rules_with_metadata(self, root) -> List[Dict]:
        """Extract rules with compliance metadata"""
        rules = []

        rule_elements = root.xpath(".//xccdf:Rule", namespaces=self.namespaces)
        for rule_elem in rule_elements[:10]:  # Limit to first 10 for performance
            rule = {
                "id": rule_elem.get("id", ""),
                "severity": rule_elem.get("severity", "unknown"),
                "title": "",
                "description": "",
                "rationale": "",
                "references": [],
            }

            # Extract title
            title_elem = rule_elem.find(".//xccdf:title", self.namespaces)
            if title_elem is not None:
                rule["title"] = title_elem.text or ""

            # Extract description
            desc_elem = rule_elem.find(".//xccdf:description", self.namespaces)
            if desc_elem is not None:
                rule["description"] = self._extract_text_content(desc_elem)[:200] + "..."

            # Extract rationale
            rat_elem = rule_elem.find(".//xccdf:rationale", self.namespaces)
            if rat_elem is not None:
                rule["rationale"] = self._extract_text_content(rat_elem)[:200] + "..."

            # Extract references (CCE, CCI, etc.)
            ref_elements = rule_elem.xpath(".//xccdf:reference", namespaces=self.namespaces)
            for ref_elem in ref_elements:
                rule["references"].append(
                    {"href": ref_elem.get("href", ""), "text": ref_elem.text or ""}
                )

            rules.append(rule)

        return rules

    def _extract_cpe_references(self, root) -> List[str]:
        """Extract CPE (platform) references"""
        cpe_refs = set()

        # Look for platform elements
        platform_elements = root.xpath(".//xccdf:platform", namespaces=self.namespaces)
        for platform in platform_elements:
            cpe_ref = platform.get("idref", "")
            if cpe_ref:
                cpe_refs.add(cpe_ref)

        return list(cpe_refs)

    def _extract_oval_references(self, root) -> List[str]:
        """Extract OVAL definition references"""
        oval_refs = set()

        # Look for check-content-ref elements
        check_refs = root.xpath(".//xccdf:check-content-ref", namespaces=self.namespaces)
        for check_ref in check_refs:
            href = check_ref.get("href", "")
            if "oval" in href.lower():
                oval_refs.add(href)

        return list(oval_refs)

    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def _check_common_issues(self, file_path: str, report: Dict):
        """Check for common SCAP content issues"""
        try:
            tree = etree.parse(file_path)
            root = tree.getroot()

            # Check for missing profiles
            profiles = root.xpath(".//xccdf:Profile", namespaces=self.namespaces)
            if not profiles:
                report["warnings"].append("No profiles found in content")

            # Check for platform specifications
            platforms = root.xpath(".//xccdf:platform", namespaces=self.namespaces)
            if not platforms:
                report["warnings"].append("No platform specifications found")

            # Check for large rule sets
            rules = root.xpath(".//xccdf:Rule", namespaces=self.namespaces)
            if len(rules) > 1000:
                report["info"]["rule_count"] = len(rules)
                report["warnings"].append(
                    f"Large rule set ({len(rules)} rules) may impact performance"
                )

            # Check for OVAL content references
            oval_refs = root.xpath(".//xccdf:check-content-ref[@href]", namespaces=self.namespaces)
            if oval_refs:
                report["info"]["has_oval_content"] = True
                report["info"]["oval_ref_count"] = len(oval_refs)

        except Exception as e:
            report["warnings"].append(f"Could not perform content checks: {str(e)}")

    def _generate_recommendations(self, report: Dict):
        """Generate recommendations based on validation report"""
        if report["validation_status"] == "valid_datastream":
            report["recommendations"].append("Content is valid SCAP data-stream format")
        elif report["validation_status"] == "valid_xccdf":
            report["recommendations"].append(
                "Consider converting to SCAP data-stream format for better tool support"
            )

        if report.get("warnings"):
            if "No profiles found" in str(report["warnings"]):
                report["recommendations"].append(
                    "Define profiles to group rules for different use cases"
                )

            if "Large rule set" in str(report["warnings"]):
                report["recommendations"].append(
                    "Consider creating focused profiles for different compliance requirements"
                )

        if report["info"].get("has_oval_content"):
            report["recommendations"].append(
                "Ensure OVAL definitions are accessible for automated checking"
            )
