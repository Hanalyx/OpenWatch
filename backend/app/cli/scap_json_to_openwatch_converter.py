#!/usr/bin/env python3
"""
ComplianceAsCode JSON to OpenWatch Converter
Converts pre-rendered JSON rules from ComplianceAsCode build to OpenWatch format

This converter handles the output from ComplianceAsCode cmake builds:
  Input:  /path/to/build/rhel8/rules/*.json (pre-rendered, Jinja2 already processed)
  Output: OpenWatch-compatible BSON/JSON bundles

Usage:
    # Convert RHEL 8 built rules to OpenWatch format
    python -m app.cli.scap_json_to_openwatch_converter convert \
        --build-path /home/rracine/hanalyx/scap_content/build/rhel8 \
        --output-path /tmp/openwatch_rules_rhel8 \
        --format bson \
        --create-bundle \
        --bundle-version 1.0.0-rhel8

    # Dry-run to see what would be converted
    python -m app.cli.scap_json_to_openwatch_converter convert \
        --build-path /home/rracine/hanalyx/scap_content/build/rhel8 \
        --dry-run

    # Create bundle from existing converted rules
    python -m app.cli.scap_json_to_openwatch_converter bundle \
        --source /tmp/openwatch_rules_rhel8 \
        --output /tmp/openwatch-rhel8-bundle.tar.gz \
        --version 1.0.0-rhel8
"""

import os
import json
import bson
import hashlib
import tarfile
import shutil
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
from dataclasses import dataclass
import argparse
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class ConversionStats:
    """Track conversion statistics"""
    total_rules_found: int = 0
    successfully_converted: int = 0
    conversion_errors: int = 0
    skipped_rules: int = 0
    errors: List[str] = None

    def __post_init__(self):
        if self.errors is None:
            self.errors = []


class ComplianceAsCodeJSONConverter:
    """
    Converts pre-rendered ComplianceAsCode JSON rules to OpenWatch format.

    ComplianceAsCode builds output JSON files in build/<product>/rules/*.json
    These files contain fully rendered rules with all Jinja2 templates processed.
    """

    def __init__(
        self,
        build_path: str,
        output_path: str,
        dry_run: bool = False,
        product_name: str = "rhel8"
    ):
        """
        Initialize converter

        Args:
            build_path: Path to ComplianceAsCode build directory (e.g., build/rhel8)
            output_path: Path where converted rules will be written
            dry_run: If True, only show what would be converted
            product_name: Product identifier (rhel8, rhel9, ubuntu2204, etc.)
        """
        self.build_path = Path(build_path)
        self.rules_path = self.build_path / "rules"
        self.output_path = Path(output_path)
        self.dry_run = dry_run
        self.product_name = product_name
        self.stats = ConversionStats()

        if not dry_run:
            self.output_path.mkdir(parents=True, exist_ok=True)

    def convert_all_rules(self, output_format: str = 'json') -> ConversionStats:
        """
        Convert all JSON rules from ComplianceAsCode build

        Args:
            output_format: Output format ('json' or 'bson')

        Returns:
            ConversionStats with conversion results
        """
        logger.info(f"{'[DRY-RUN] ' if self.dry_run else ''}Converting rules from {self.rules_path}")

        if not self.rules_path.exists():
            logger.error(f"Rules directory not found: {self.rules_path}")
            logger.error(f"Expected structure: {self.build_path}/rules/*.json")
            return self.stats

        # Find all JSON rule files
        rule_files = list(self.rules_path.glob("*.json"))

        # Filter out group.json files (these are metadata, not rules)
        rule_files = [f for f in rule_files if not f.name.endswith('_group.json')]

        self.stats.total_rules_found = len(rule_files)
        logger.info(f"Found {len(rule_files)} rule files")

        if self.dry_run:
            logger.info(f"[DRY-RUN] Would convert {len(rule_files)} rules")
            for rule_file in rule_files[:5]:
                logger.info(f"  - {rule_file.name}")
            if len(rule_files) > 5:
                logger.info(f"  ... and {len(rule_files) - 5} more")
            return self.stats

        # Convert each rule
        for rule_file in rule_files:
            try:
                self._convert_single_rule(rule_file, output_format)
                self.stats.successfully_converted += 1

                if self.stats.successfully_converted % 100 == 0:
                    logger.info(f"Converted {self.stats.successfully_converted}/{len(rule_files)} rules...")
            except Exception as e:
                self.stats.conversion_errors += 1
                error_msg = f"Error converting {rule_file.name}: {str(e)}"
                logger.error(error_msg)
                self.stats.errors.append(error_msg)

        self._print_summary()
        return self.stats

    def _convert_single_rule(self, rule_file: Path, output_format: str) -> None:
        """Convert a single ComplianceAsCode JSON rule to OpenWatch format"""

        # Load ComplianceAsCode JSON
        with open(rule_file, 'r', encoding='utf-8') as f:
            cac_rule = json.load(f)

        # Extract rule ID from filename (e.g., "account_disable_post_pw_expiration.json")
        rule_id = rule_file.stem

        # Convert to OpenWatch format
        ow_rule = self._transform_to_openwatch_format(cac_rule, rule_id)

        # Write output
        if output_format == 'bson':
            self._write_bson_rule(ow_rule, rule_id)
        else:
            self._write_json_rule(ow_rule, rule_id)

    def _transform_to_openwatch_format(self, cac_rule: Dict[str, Any], rule_id: str) -> Dict[str, Any]:
        """
        Transform ComplianceAsCode JSON to OpenWatch format

        ComplianceAsCode JSON structure:
        {
            "title": "...",
            "description": "...",
            "rationale": "...",
            "severity": "medium",
            "references": {"nist": [...], "cis": [...], ...},
            "identifiers": {"cce": "CCE-..."},
            "platform": "...",
            "ocil": "...",
            "ocil_clause": "...",
            ...
        }

        OpenWatch format:
        {
            "rule_id": "...",
            "name": "...",
            "description": "...",
            "rationale": "...",
            "severity": "medium",
            "category": "...",
            "frameworks": {...},
            "tags": [...],
            "source": {...},
            "platform_implementations": {...},
            ...
        }
        """

        # Basic metadata
        ow_rule = {
            "rule_id": f"ow-{rule_id}",  # Add ow- prefix for MongoDB validation
            "name": cac_rule.get("title", rule_id),
            "severity": self._map_severity(cac_rule.get("severity", "unknown")),
            "category": self._determine_category(rule_id, cac_rule),
            "tags": self._generate_tags(cac_rule),
            "source": {
                "upstream_id": rule_id,  # Keep original ID for traceability
                "source_type": "complianceascode",
                "product": self.product_name,
                "complianceascode_version": "0.1.73",
                "source_file": f"build/{self.product_name}/rules/{rule_id}.json",
                "imported_at": datetime.now(timezone.utc).isoformat(),
                "build_type": "prerendered"
            },
            "frameworks": self._convert_frameworks(cac_rule.get("references", {})),
            "identifiers": self._extract_identifiers(cac_rule),
            "check_content": {
                "type": "manual" if not cac_rule.get("oval_external_content") else "automated",
                "ocil": cac_rule.get("ocil", ""),
                "ocil_clause": cac_rule.get("ocil_clause", "")
            },
            "metadata": {
                "name": cac_rule.get("title", rule_id),  # Required by MongoDB validator
                "description": self._clean_html_tags(cac_rule.get("description", "")),  # UI looks here
                "rationale": self._clean_html_tags(cac_rule.get("rationale", "")),  # UI looks here
                "components": cac_rule.get("components", []),
                "warnings": cac_rule.get("warnings", []),
                "conflicts": cac_rule.get("conflicts", []),
                "requires": cac_rule.get("requires", [])
            },
            "platform_implementations": self._build_platform_implementations(cac_rule)
        }

        # STIG-specific content
        if "policy_specific_content" in cac_rule:
            stig_content = cac_rule["policy_specific_content"].get("stig", {})
            if stig_content:
                ow_rule["stig"] = {
                    "srg_requirement": stig_content.get("srg_requirement", ""),
                    "vuldiscussion": stig_content.get("vuldiscussion", ""),
                    "checktext": stig_content.get("checktext", ""),
                    "fixtext": stig_content.get("fixtext", "")
                }

        # Remediation content (if available)
        if "fixes" in cac_rule and cac_rule["fixes"]:
            ow_rule["remediation"] = {
                "available": True,
                "types": list(cac_rule["fixes"].keys())
            }

        return ow_rule

    def _clean_html_tags(self, text: str) -> str:
        """Remove HTML tags from text (basic cleaning)"""
        import re
        if not text:
            return ""
        # Remove <tt>, <pre>, <sub>, and other basic HTML tags
        text = re.sub(r'<tt>|</tt>|<pre>|</pre>|<i>|</i>|<b>|</b>', '', text)
        # Clean up <sub idref="..."/> tags
        text = re.sub(r'<sub idref="[^"]+"\s*/>', '[VALUE]', text)
        return text.strip()

    def _map_severity(self, severity: str) -> str:
        """Map ComplianceAsCode severity to OpenWatch severity"""
        severity_map = {
            "low": "low",
            "medium": "medium",
            "high": "high",
            "unknown": "info"
        }
        return severity_map.get(severity.lower(), "info")

    def _determine_category(self, rule_id: str, cac_rule: Dict) -> str:
        """Determine rule category from rule ID and content"""
        rule_id_lower = rule_id.lower()

        # Category mapping based on rule ID patterns
        if any(x in rule_id_lower for x in ['ssh', 'login', 'password', 'auth', 'pam']):
            return 'authentication'
        elif any(x in rule_id_lower for x in ['audit', 'logging', 'rsyslog', 'journald']):
            return 'audit_logging'
        elif any(x in rule_id_lower for x in ['firewall', 'network', 'iptables', 'nftables']):
            return 'network_security'
        elif any(x in rule_id_lower for x in ['crypto', 'encryption', 'fips', 'tls', 'ssl']):
            return 'cryptography'
        elif any(x in rule_id_lower for x in ['access', 'permission', 'selinux', 'apparmor']):
            return 'access_control'
        elif any(x in rule_id_lower for x in ['kernel', 'boot', 'grub']):
            return 'system_configuration'
        elif any(x in rule_id_lower for x in ['update', 'package', 'yum', 'dnf', 'apt']):
            return 'patch_management'
        else:
            return 'system_hardening'

    def _generate_tags(self, cac_rule: Dict) -> List[str]:
        """Generate tags for the rule"""
        tags = ['complianceascode', 'prerendered', self.product_name]

        # Add severity tag
        severity = cac_rule.get("severity", "unknown")
        if severity:
            tags.append(f"severity_{severity}")

        # Add framework tags
        references = cac_rule.get("references", {})
        for framework in references.keys():
            tags.append(f"framework_{framework}")

        return list(set(tags))

    def _convert_frameworks(self, references: Dict[str, Any]) -> Dict[str, Any]:
        """Convert ComplianceAsCode references to OpenWatch frameworks format"""
        frameworks = {}

        # Framework mapping
        framework_map = {
            'nist': 'nist_800_53',
            'cis': 'cis',
            'pci-dss': 'pci_dss',
            'pcidss': 'pci_dss',
            'pcidss4': 'pci_dss_v4',
            'hipaa': 'hipaa',
            'iso27001-2013': 'iso_27001',
            'stig': 'disa_stig',
            'stigid': 'disa_stig',
            'stigref': 'disa_stig'
        }

        for ref_key, ref_value in references.items():
            framework_key = framework_map.get(ref_key.lower(), ref_key.lower())

            if isinstance(ref_value, list):
                frameworks[framework_key] = {
                    "controls": ref_value,
                    "applicable": True
                }
            elif isinstance(ref_value, str):
                frameworks[framework_key] = {
                    "controls": [ref_value],
                    "applicable": True
                }

        return frameworks

    def _extract_identifiers(self, cac_rule: Dict) -> Dict[str, str]:
        """Extract identifiers (CCE, etc.)"""
        identifiers = {}

        cce_data = cac_rule.get("identifiers", {})
        for key, value in cce_data.items():
            if key.lower() == 'cce' or key.startswith('cce@'):
                identifiers['cce'] = value
                break

        return identifiers

    def _build_platform_implementations(self, cac_rule: Dict) -> Dict[str, Any]:
        """
        Build platform_implementations dict for OpenWatch UI.
        UI displays platforms from Object.keys(platform_implementations).

        Returns:
            Dict with platform names as keys, implementation details as values
        """
        implementations = {}

        # Determine the primary platform - this is the product we're building for
        # (rhel8, rhel9, ubuntu2204, etc.)
        platform_name = self.product_name

        # Build implementation details for this platform
        impl = {}

        # REQUIRED FIELD: versions array
        # Map product names to version lists
        version_map = {
            "rhel8": ["8.0", "8.1", "8.2", "8.3", "8.4", "8.5", "8.6", "8.7", "8.8", "8.9", "8.10"],
            "rhel9": ["9.0", "9.1", "9.2", "9.3", "9.4"],
            "rhel7": ["7.0", "7.1", "7.2", "7.3", "7.4", "7.5", "7.6", "7.7", "7.8", "7.9"],
            "ubuntu2004": ["20.04"],
            "ubuntu2204": ["22.04"],
            "ubuntu2404": ["24.04"],
            "fedora": ["38", "39", "40"],
            "ol8": ["8.0", "8.1", "8.2", "8.3", "8.4", "8.5", "8.6", "8.7", "8.8", "8.9"],
            "ol9": ["9.0", "9.1", "9.2", "9.3"],
        }
        impl["versions"] = version_map.get(platform_name, [platform_name])

        # Check type and command from check_content
        if cac_rule.get("ocil"):
            impl["check_method"] = "oscap"  # ComplianceAsCode primarily uses OSCAP
            impl["check_command"] = self._clean_html_tags(cac_rule.get("ocil", ""))

        # Remediation/fix information
        fixes = cac_rule.get("fixes", {})
        if fixes:
            impl["remediation_available"] = True
            impl["remediation_types"] = list(fixes.keys())

            # If there's a bash fix, include it
            if "bash" in fixes:
                impl["remediation_script"] = fixes["bash"]
            # If there's an ansible fix, include it
            if "ansible" in fixes:
                impl["ansible_task"] = fixes["ansible"]

        # Add STIG-specific fixtext if available
        stig_content = cac_rule.get("policy_specific_content", {}).get("stig", {})
        if stig_content and stig_content.get("fixtext"):
            impl["fixtext"] = self._clean_html_tags(stig_content["fixtext"])
            impl["checktext"] = self._clean_html_tags(stig_content.get("checktext", ""))

        # Only add the platform if we have some implementation details
        if impl:
            implementations[platform_name] = impl

        return implementations

    def _write_json_rule(self, rule: Dict[str, Any], rule_id: str) -> None:
        """Write rule as JSON file"""
        output_file = self.output_path / f"ow-{rule_id}.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(rule, f, indent=2, ensure_ascii=False)

    def _write_bson_rule(self, rule: Dict[str, Any], rule_id: str) -> None:
        """Write rule as BSON file"""
        output_file = self.output_path / f"ow-{rule_id}.bson"
        with open(output_file, 'wb') as f:
            f.write(bson.encode(rule))

    def create_bundle(
        self,
        source_dir: Path,
        bundle_path: Path,
        version: str = "1.0.0",
        sign_bundle: bool = False,
        private_key_path: Optional[Path] = None,
        signer_name: str = "ComplianceAsCode Project"
    ) -> None:
        """
        Create a tar.gz bundle from converted rules

        Args:
            source_dir: Directory containing converted rules
            bundle_path: Output path for bundle
            version: Bundle version string
            sign_bundle: Whether to sign the bundle with RSA key
            private_key_path: Path to RSA private key (required if sign_bundle=True)
            signer_name: Name/identifier of the signer
        """
        logger.info(f"Creating bundle from {source_dir} to {bundle_path}")

        # Find rule files
        json_files = list(source_dir.glob("ow-*.json"))
        bson_files = list(source_dir.glob("ow-*.bson"))

        if not json_files and not bson_files:
            logger.error(f"No rule files found in {source_dir}")
            return

        # Determine format
        use_bson = len(bson_files) > 0
        rule_files = bson_files if use_bson else json_files

        logger.info(f"Found {len(rule_files)} rule files ({use_bson and 'BSON' or 'JSON'} format)")

        # Create manifest (format compatible with OpenWatch upload service)
        manifest = {
            "name": f"complianceascode-{self.product_name}",
            "version": version,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "rules_count": len(rule_files),
            "format": "bson" if use_bson else "json",
            "source": "complianceascode_prerendered",
            "product": self.product_name,
            "rules": []
        }

        # Add rule metadata to manifest
        for rule_file in rule_files:
            # Keep the full rule_id including ow- prefix (matches MongoDB rule_id field)
            rule_id = rule_file.stem
            file_hash = self._calculate_file_hash(rule_file)

            manifest["rules"].append({
                "rule_id": rule_id,
                "filename": rule_file.name,
                "hash": file_hash
            })

        # Create bundle
        import tempfile
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            rules_dir = temp_path / "rules"
            rules_dir.mkdir()

            # Copy rule files
            for rule_file in rule_files:
                shutil.copy(rule_file, rules_dir / rule_file.name)

            # Write manifest (without signature initially)
            manifest_path = temp_path / "manifest.json"
            with open(manifest_path, 'w') as f:
                json.dump(manifest, f, indent=2)

            # Create tar.gz (without signature first)
            with tarfile.open(bundle_path, 'w:gz') as tar:
                tar.add(manifest_path, arcname="manifest.json")
                for rule_file in rules_dir.glob("*"):
                    tar.add(rule_file, arcname=f"rules/{rule_file.name}")

        bundle_size_mb = bundle_path.stat().st_size / (1024 * 1024)
        logger.info(f"Bundle created: {bundle_path} ({bundle_size_mb:.2f} MB)")

        # Sign bundle if requested
        if sign_bundle:
            if not private_key_path or not private_key_path.exists():
                logger.error(f"Cannot sign bundle: private key not found at {private_key_path}")
                return

            logger.info(f"Signing bundle with key: {private_key_path}")

            # Import signature service
            import sys
            sys.path.insert(0, str(Path(__file__).parent.parent.parent))
            from backend.app.services.compliance_rules_signature_service import ComplianceRulesSignatureService

            # Read bundle data
            with open(bundle_path, 'rb') as f:
                bundle_data = f.read()

            # Sign the bundle
            signature_service = ComplianceRulesSignatureService()
            import asyncio
            result = asyncio.run(signature_service.sign_bundle(
                bundle_data=bundle_data,
                private_key_path=private_key_path,
                signer_name=signer_name,
                algorithm="SHA512"
            ))

            if not result['success']:
                logger.error(f"Failed to sign bundle: {result.get('error')}")
                return

            # Add signature to manifest and recreate bundle
            manifest['signature'] = result['signature']

            # Recreate bundle with signed manifest
            import tempfile
            with tempfile.TemporaryDirectory() as temp_dir2:
                temp_path2 = Path(temp_dir2)
                rules_dir2 = temp_path2 / "rules"
                rules_dir2.mkdir()

                # Copy rule files again
                for rule_file in rule_files:
                    shutil.copy(rule_file, rules_dir2 / rule_file.name)

                # Write signed manifest
                manifest_path2 = temp_path2 / "manifest.json"
                with open(manifest_path2, 'w') as f:
                    json.dump(manifest, f, indent=2)

                # Create signed tar.gz
                with tarfile.open(bundle_path, 'w:gz') as tar:
                    tar.add(manifest_path2, arcname="manifest.json")
                    for rule_file in rules_dir2.glob("*"):
                        tar.add(rule_file, arcname=f"rules/{rule_file.name}")

            signed_bundle_size_mb = bundle_path.stat().st_size / (1024 * 1024)
            logger.info(
                f"Bundle signed successfully: {bundle_path} ({signed_bundle_size_mb:.2f} MB) "
                f"by {signer_name}"
            )

    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA256 hash of file"""
        with open(file_path, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        return f"sha256:{file_hash[:16]}"

    def _print_summary(self):
        """Print conversion summary"""
        print("\n" + "="*70)
        print("CONVERSION SUMMARY")
        print("="*70)
        print(f"Product:                  {self.product_name}")
        print(f"Build path:               {self.build_path}")
        print(f"Output path:              {self.output_path}")
        print(f"Total rules found:        {self.stats.total_rules_found}")
        print(f"Successfully converted:   {self.stats.successfully_converted}")
        print(f"Conversion errors:        {self.stats.conversion_errors}")
        print(f"Skipped rules:            {self.stats.skipped_rules}")

        if self.stats.errors:
            print(f"\nErrors ({len(self.stats.errors)}):")
            for error in self.stats.errors[:10]:
                print(f"  - {error}")
            if len(self.stats.errors) > 10:
                print(f"  ... and {len(self.stats.errors) - 10} more errors")

        print("="*70 + "\n")


def main():
    """CLI interface"""
    parser = argparse.ArgumentParser(
        description='ComplianceAsCode JSON to OpenWatch Converter',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    subparsers = parser.add_subparsers(dest='command', required=True)

    # Convert command
    convert_parser = subparsers.add_parser('convert', help='Convert ComplianceAsCode JSON rules')
    convert_parser.add_argument(
        '--build-path',
        required=True,
        help='Path to ComplianceAsCode build directory (e.g., /path/to/build/rhel8)'
    )
    convert_parser.add_argument(
        '--output-path',
        default='/tmp/openwatch_rules',
        help='Output directory for converted rules'
    )
    convert_parser.add_argument(
        '--product',
        default='rhel8',
        help='Product name (rhel8, rhel9, ubuntu2204, etc.)'
    )
    convert_parser.add_argument(
        '--format',
        choices=['json', 'bson'],
        default='bson',
        help='Output format (default: bson)'
    )
    convert_parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be converted without converting'
    )
    convert_parser.add_argument(
        '--create-bundle',
        action='store_true',
        help='Create tar.gz bundle after conversion'
    )
    convert_parser.add_argument(
        '--bundle-version',
        default='1.0.0',
        help='Bundle version (default: 1.0.0)'
    )
    convert_parser.add_argument(
        '--sign-bundle',
        action='store_true',
        help='Sign bundle with RSA private key'
    )
    convert_parser.add_argument(
        '--private-key-path',
        help='Path to RSA private key for signing'
    )
    convert_parser.add_argument(
        '--signer',
        default='ComplianceAsCode Project',
        help='Signer name for signature metadata'
    )

    # Bundle command
    bundle_parser = subparsers.add_parser('bundle', help='Create bundle from existing rules')
    bundle_parser.add_argument(
        '--source',
        required=True,
        help='Source directory with converted JSON/BSON files'
    )
    bundle_parser.add_argument(
        '--output',
        required=True,
        help='Output bundle path (tar.gz)'
    )
    bundle_parser.add_argument(
        '--product',
        default='rhel8',
        help='Product name'
    )
    bundle_parser.add_argument(
        '--version',
        default='1.0.0',
        help='Bundle version'
    )

    args = parser.parse_args()

    if args.command == 'convert':
        converter = ComplianceAsCodeJSONConverter(
            build_path=args.build_path,
            output_path=args.output_path,
            dry_run=args.dry_run,
            product_name=args.product
        )

        stats = converter.convert_all_rules(output_format=args.format)

        # Create bundle if requested
        if args.create_bundle and not args.dry_run and stats.successfully_converted > 0:
            bundle_path = Path(args.output_path).parent / f"openwatch-{args.product}-bundle_v{args.bundle_version}.tar.gz"
            converter.create_bundle(
                Path(args.output_path),
                bundle_path,
                args.bundle_version,
                sign_bundle=args.sign_bundle,
                private_key_path=Path(args.private_key_path) if args.private_key_path else None,
                signer_name=args.signer
            )

    elif args.command == 'bundle':
        converter = ComplianceAsCodeJSONConverter(
            build_path='',
            output_path='',
            product_name=args.product
        )
        converter.create_bundle(
            Path(args.source),
            Path(args.output),
            args.version
        )


if __name__ == '__main__':
    main()
