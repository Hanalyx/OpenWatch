#!/usr/bin/env python3
"""
Enhanced SCAP to OpenWatch Compliance Rules Converter
Transforms ComplianceAsCode YAML rules into OpenWatch BSON bundles with dry-run support

Usage:
    # Dry-run (show what would be converted)
    python -m backend.app.cli.scap_to_openwatch_converter_enhanced convert --dry-run

    # Convert to JSON only
    python -m backend.app.cli.scap_to_openwatch_converter_enhanced convert --format json

    # Convert and create BSON bundle
    python -m backend.app.cli.scap_to_openwatch_converter_enhanced convert --format bson

    # Create bundle from existing JSON files
    python -m backend.app.cli.scap_to_openwatch_converter_enhanced bundle \
        --source /path/to/json/rules \
        --output /path/to/bundle.tar.gz

    # Compare with existing MongoDB rules
    python -m backend.app.cli.scap_to_openwatch_converter_enhanced compare \
        --local /path/to/json/rules
"""

import os
import re
import json
import yaml
import bson
import hashlib
import tarfile
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple
from datetime import datetime, timezone
import logging
from dataclasses import dataclass, field
import argparse
import asyncio
from motor.motor_asyncio import AsyncIOMotorClient

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
    skipped_jinja: int = 0
    new_rules: int = 0
    modified_rules: int = 0
    unchanged_rules: int = 0

@dataclass
class ComparisonResult:
    """Comparison result for a single rule"""
    rule_id: str
    status: str  # 'new', 'modified', 'unchanged'
    changes: List[str] = field(default_factory=list)
    old_hash: Optional[str] = None
    new_hash: Optional[str] = None

# Import the original converter classes
from .scap_to_openwatch_converter import (
    FrameworkMapper,
    TemplateProcessor
)

# Import SCAP YAML parser for variable/remediation extraction
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from services.scap_yaml_parser_service import extract_scap_metadata

class EnhancedSCAPConverter:
    """Enhanced converter with BSON and dry-run support"""

    def __init__(
        self,
        scap_content_path: str,
        output_path: str,
        dry_run: bool = False,
        extract_variables: bool = False,
        extract_remediation: bool = False
    ):
        self.scap_content_path = Path(scap_content_path)
        self.output_path = Path(output_path)
        self.dry_run = dry_run
        self.extract_variables = extract_variables
        self.extract_remediation = extract_remediation
        self.framework_mapper = FrameworkMapper()
        self.template_processor = TemplateProcessor()
        self.stats = ConversionStats()

        if not dry_run:
            self.output_path.mkdir(parents=True, exist_ok=True)

    def convert_all_rules(self, output_format: str = 'json') -> ConversionStats:
        """Convert all SCAP rules to OpenWatch format

        Args:
            output_format: 'json' or 'bson'
        """
        logger.info(f"Starting {'dry-run ' if self.dry_run else ''}conversion from {self.scap_content_path}")

        # Find all rule.yml files
        rule_files = self._find_rule_files()
        self.stats.total_rules_found = len(rule_files)

        logger.info(f"Found {self.stats.total_rules_found} rule files")

        if self.dry_run:
            logger.info("DRY RUN MODE - No files will be written")

        for rule_file in rule_files:
            try:
                self._convert_single_rule(rule_file, output_format)
                self.stats.successfully_converted += 1

                if self.stats.successfully_converted % 50 == 0:
                    logger.info(
                        f"{'[DRY RUN] ' if self.dry_run else ''}Processed "
                        f"{self.stats.successfully_converted}/{self.stats.total_rules_found} rules"
                    )

            except Exception as e:
                logger.error(f"Error converting {rule_file}: {e}")
                self.stats.conversion_errors += 1

        self._print_summary()
        return self.stats

    def _find_rule_files(self) -> List[Path]:
        """Find all SCAP rule.yml files"""
        rule_files = []
        for rule_file in self.scap_content_path.rglob("rule.yml"):
            # Skip test files
            if 'test' not in str(rule_file).lower() and 'unit' not in str(rule_file).lower():
                rule_files.append(rule_file)
        return rule_files

    def _convert_single_rule(self, rule_file: Path, output_format: str) -> None:
        """Convert a single SCAP rule"""

        # Load YAML rule
        try:
            with open(rule_file, 'r', encoding='utf-8') as f:
                content = f.read()

                # Skip Jinja2 templated files
                if '{{{' in content or '{{%' in content or '{%-' in content:
                    self.stats.skipped_jinja += 1
                    logger.debug(f"Skipped (Jinja2): {rule_file}")
                    return

                rule_data = yaml.safe_load(content)
        except yaml.YAMLError as e:
            logger.warning(f"YAML error in {rule_file}: {e}")
            return

        if not rule_data or not isinstance(rule_data, dict):
            return

        # Extract rule ID
        rule_id = self._extract_rule_id(rule_file)

        # Create OpenWatch rule structure (same as original converter)
        openwatch_rule = self._build_openwatch_rule(rule_data, rule_file, rule_id)

        # Dry-run: just log what would be created
        if self.dry_run:
            logger.info(f"[DRY RUN] Would convert: {rule_id}")
            return

        # Write output in requested format
        if output_format == 'json':
            self._write_json_rule(openwatch_rule, rule_id)
        elif output_format == 'bson':
            self._write_bson_rule(openwatch_rule, rule_id)

    def _build_openwatch_rule(self, rule_data: Dict[str, Any], rule_file: Path, rule_id: str) -> Dict[str, Any]:
        """Build OpenWatch rule structure (from original converter)"""
        # Base rule structure
        rule = {
            "_id": f"ow-{rule_id}",
            "rule_id": f"ow-{rule_id}",
            "scap_rule_id": f"xccdf_org.ssgproject.content_rule_{rule_id}",
            "parent_rule_id": None,
            "metadata": self._convert_metadata(rule_data, rule_file, rule_id),
            "abstract": False,
            "severity": rule_data.get('severity', 'medium'),
            "category": self._determine_category(rule_data, rule_file),
            "security_function": "access_control",
            "tags": self._generate_tags(rule_data, rule_file),
            "frameworks": self._convert_frameworks(rule_data),
            "platform_implementations": self._convert_platform_implementations(rule_data),
            "platform_requirements": {
                "required_capabilities": [],
                "excluded_environments": []
            },
            "check_type": "scap" if not rule_data.get('template') else "template",
            "check_content": {
                "scap_rule_id": f"xccdf_org.ssgproject.content_rule_{rule_id}",
                "method": "xccdf_evaluation",
                "expected_result": "pass"
            },
            "fix_available": rule_data.get('template') is not None,
            "fix_content": {},
            "manual_remediation": rule_data.get('description', 'See SCAP guidance'),
            "remediation_complexity": "medium",
            "remediation_risk": "low",
            "dependencies": {
                "requires": [],
                "conflicts": [],
                "related": []
            },
            "source_file": str(rule_file.relative_to(self.scap_content_path)),
            "source_hash": self._calculate_file_hash(rule_file),
            "version": "2024.2",
            "imported_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "identifiers": self._extract_identifiers(rule_data)
        }

        # Extract Phase 1 metadata (variables, remediation, scanner type)
        if self.extract_variables or self.extract_remediation:
            try:
                extracted_metadata = extract_scap_metadata(rule_data, rule_file)

                # Add XCCDF variables
                if self.extract_variables and extracted_metadata.get('xccdf_variables'):
                    rule['xccdf_variables'] = extracted_metadata['xccdf_variables']

                # Add remediation content
                if self.extract_remediation and extracted_metadata.get('remediation'):
                    rule['remediation'] = extracted_metadata['remediation']

                # Always add scanner type (defaults to 'oscap' if not detected)
                rule['scanner_type'] = extracted_metadata.get('scanner_type', 'oscap')

            except Exception as e:
                logger.warning(f"Failed to extract metadata for {rule_id}: {e}")
                # Set defaults on error
                rule['scanner_type'] = 'oscap'

        else:
            # If not extracting, set default scanner type
            rule['scanner_type'] = 'oscap'

        return rule

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

    def create_bundle(self, source_dir: Path, bundle_path: Path, version: str = "0.0.1") -> None:
        """Create tar.gz bundle from JSON or BSON files

        Args:
            source_dir: Directory containing rule files (JSON or BSON)
            bundle_path: Output path for bundle tar.gz
            version: Bundle version string
        """
        logger.info(f"Creating bundle from {source_dir} to {bundle_path}")

        # Find rule files (JSON or BSON)
        json_files = list(source_dir.glob("ow-*.json"))
        bson_files = list(source_dir.glob("ow-*.bson"))

        # Determine source format
        if json_files and not bson_files:
            rule_files = json_files
            source_format = 'json'
            logger.info(f"Found {len(json_files)} JSON rule files")
        elif bson_files:
            rule_files = bson_files
            source_format = 'bson'
            logger.info(f"Found {len(bson_files)} BSON rule files")
        else:
            raise ValueError(f"No rule files found in {source_dir}")

        # Create manifest
        manifest = {
            "name": f"openwatch-rules-bundle_{version}",
            "version": version,
            "rules_count": len(rule_files),
            "format": source_format,
            "created_at": datetime.now(timezone.utc).isoformat()
        }

        # Create temporary directory for bundle contents
        temp_dir = Path(f"/tmp/bundle_{version}")
        temp_dir.mkdir(exist_ok=True)
        rules_dir = temp_dir / "rules"
        rules_dir.mkdir(exist_ok=True)

        try:
            # Convert JSON to BSON if needed
            if source_format == 'json':
                logger.info("Converting JSON files to BSON...")
                for json_file in rule_files:
                    with open(json_file, 'r') as f:
                        rule_data = json.load(f)

                    bson_file = rules_dir / f"{json_file.stem}.bson"
                    with open(bson_file, 'wb') as f:
                        f.write(bson.encode(rule_data))
            else:
                # Copy BSON files
                import shutil
                for bson_file in rule_files:
                    shutil.copy(bson_file, rules_dir / bson_file.name)

            # Write manifest
            with open(temp_dir / "manifest.json", 'w') as f:
                json.dump(manifest, f, indent=2)

            # Create tar.gz bundle
            logger.info(f"Creating tar.gz bundle: {bundle_path}")
            with tarfile.open(bundle_path, 'w:gz') as tar:
                tar.add(temp_dir / "manifest.json", arcname="manifest.json")
                for bson_file in rules_dir.glob("*.bson"):
                    tar.add(bson_file, arcname=f"rules/{bson_file.name}")

            logger.info(f"Bundle created successfully: {bundle_path} ({len(rule_files)} rules)")

        finally:
            # Cleanup temp directory
            import shutil
            shutil.rmtree(temp_dir)

    async def compare_with_mongodb(self, local_dir: Path, mongodb_url: str, db_name: str) -> List[ComparisonResult]:
        """Compare local rules with MongoDB rules

        Args:
            local_dir: Directory containing local JSON/BSON rules
            mongodb_url: MongoDB connection URL
            db_name: Database name

        Returns:
            List of comparison results
        """
        logger.info(f"Comparing local rules in {local_dir} with MongoDB")

        # Connect to MongoDB
        client = AsyncIOMotorClient(mongodb_url)
        db = client[db_name]
        collection = db.compliance_rules

        # Load local rules
        local_rules = {}
        for json_file in local_dir.glob("ow-*.json"):
            with open(json_file, 'r') as f:
                rule = json.load(f)
                local_rules[rule['rule_id']] = rule

        logger.info(f"Found {len(local_rules)} local rules")

        # Compare with MongoDB
        results = []
        for rule_id, local_rule in local_rules.items():
            # Find in MongoDB
            mongo_rule = await collection.find_one({"rule_id": rule_id, "is_latest": True})

            if not mongo_rule:
                results.append(ComparisonResult(
                    rule_id=rule_id,
                    status='new',
                    new_hash=self._calculate_rule_hash(local_rule)
                ))
            else:
                # Compare hashes and content
                local_hash = self._calculate_rule_hash(local_rule)
                mongo_hash = mongo_rule.get('version_hash', '')

                if local_hash != mongo_hash:
                    changes = self._detect_changes(mongo_rule, local_rule)
                    results.append(ComparisonResult(
                        rule_id=rule_id,
                        status='modified',
                        changes=changes,
                        old_hash=mongo_hash,
                        new_hash=local_hash
                    ))
                else:
                    results.append(ComparisonResult(
                        rule_id=rule_id,
                        status='unchanged',
                        old_hash=mongo_hash,
                        new_hash=local_hash
                    ))

        # Summary
        new_count = sum(1 for r in results if r.status == 'new')
        modified_count = sum(1 for r in results if r.status == 'modified')
        unchanged_count = sum(1 for r in results if r.status == 'unchanged')

        logger.info(f"Comparison complete: {new_count} new, {modified_count} modified, {unchanged_count} unchanged")

        return results

    def _detect_changes(self, old_rule: Dict, new_rule: Dict) -> List[str]:
        """Detect which fields changed between rules"""
        changes = []
        excluded_fields = {'_id', 'imported_at', 'updated_at', 'version', 'effective_from', 'effective_until'}

        for key in new_rule.keys():
            if key in excluded_fields:
                continue

            old_val = old_rule.get(key)
            new_val = new_rule.get(key)

            if old_val != new_val:
                changes.append(key)

        return changes

    def _calculate_rule_hash(self, rule: Dict[str, Any]) -> str:
        """Calculate content hash for rule"""
        excluded = {'_id', 'imported_at', 'updated_at', 'version', 'version_hash'}
        content = {k: v for k, v in rule.items() if k not in excluded}
        content_json = json.dumps(content, sort_keys=True, default=str)
        return hashlib.sha256(content_json.encode()).hexdigest()

    # Helper methods from original converter
    def _extract_rule_id(self, rule_file: Path) -> str:
        return rule_file.parent.name.replace('-', '_')

    def _convert_metadata(self, rule_data: Dict, rule_file: Path, rule_id: str) -> Dict:
        return {
            "name": rule_data.get('title', ''),
            "description": rule_data.get('description', ''),
            "rationale": rule_data.get('rationale', ''),
            "source": {
                "upstream_id": rule_id,
                "complianceascode_version": "0.1.73",
                "source_file": "converted_from_yaml",
                "cce_id": self._extract_cce_id(rule_data),
                "imported_at": datetime.now(timezone.utc).isoformat()
            }
        }

    def _determine_category(self, rule_data: Dict, rule_file: Path) -> str:
        path_str = str(rule_file).lower()
        mappings = {
            'ssh': 'authentication', 'login': 'authentication', 'password': 'authentication',
            'audit': 'audit_logging', 'logging': 'audit_logging',
            'firewall': 'network_security', 'network': 'network_security',
            'crypto': 'cryptography', 'encryption': 'cryptography',
            'access': 'access_control', 'permission': 'access_control'
        }
        for keyword, category in mappings.items():
            if keyword in path_str:
                return category
        return 'system_hardening'

    def _generate_tags(self, rule_data: Dict, rule_file: Path) -> List[str]:
        tags = ['scap', 'ssg', 'converted']
        severity = rule_data.get('severity')
        if severity:
            tags.append(f"severity_{severity}")
        return list(set(tags))

    def _convert_frameworks(self, rule_data: Dict) -> Dict:
        references = rule_data.get('references', {})
        frameworks = self.framework_mapper.map_references_to_frameworks(references)
        if frameworks:
            self.stats.framework_mappings += 1
        return frameworks

    def _convert_platform_implementations(self, rule_data: Dict) -> Dict:
        template = rule_data.get('template')
        if not template:
            return {}
        return self.template_processor.process_template(
            template.get('name', ''),
            template.get('vars', {})
        )

    def _extract_cce_id(self, rule_data: Dict) -> str:
        identifiers = rule_data.get('identifiers', {})
        for key, value in identifiers.items():
            if key.startswith('cce@'):
                return value
        return ""

    def _extract_identifiers(self, rule_data: Dict) -> Dict:
        result = {}
        cce_id = self._extract_cce_id(rule_data)
        if cce_id:
            result['cce'] = cce_id
        return result

    def _calculate_file_hash(self, file_path: Path) -> str:
        with open(file_path, 'rb') as f:
            return f"sha256:{hashlib.sha256(f.read()).hexdigest()[:16]}"

    def _print_summary(self):
        """Print conversion summary"""
        print("\n" + "="*60)
        print("CONVERSION SUMMARY")
        print("="*60)
        print(f"Total rules found:        {self.stats.total_rules_found}")
        print(f"Successfully converted:   {self.stats.successfully_converted}")
        print(f"Conversion errors:        {self.stats.conversion_errors}")
        print(f"Skipped (Jinja2):         {self.stats.skipped_jinja}")
        print(f"Template expansions:      {self.stats.template_expansions}")
        print(f"Framework mappings:       {self.stats.framework_mappings}")
        print(f"Platform implementations: {self.stats.platform_implementations}")
        print("="*60 + "\n")


def main():
    """CLI interface"""
    parser = argparse.ArgumentParser(description='Enhanced SCAP to OpenWatch Converter')
    subparsers = parser.add_subparsers(dest='command', required=True)

    # Convert command
    convert_parser = subparsers.add_parser('convert', help='Convert SCAP rules')
    convert_parser.add_argument('--scap-path', default='/home/rracine/hanalyx/scap_content/content')
    convert_parser.add_argument('--output-path', default='/home/rracine/hanalyx/openwatch/data/compliance_rules_converted')
    convert_parser.add_argument('--format', choices=['json', 'bson'], default='json')
    convert_parser.add_argument('--dry-run', action='store_true', help='Show what would be converted')
    convert_parser.add_argument('--extract-variables', action='store_true', help='Extract XCCDF variables (Phase 1)')
    convert_parser.add_argument('--extract-remediation', action='store_true', help='Extract remediation content (Phase 1)')
    convert_parser.add_argument('--create-bundle', action='store_true', help='Create tar.gz bundle after conversion')
    convert_parser.add_argument('--bundle-version', default='0.0.1', help='Bundle version')

    # Bundle command
    bundle_parser = subparsers.add_parser('bundle', help='Create bundle from existing rules')
    bundle_parser.add_argument('--source', required=True, help='Source directory with JSON/BSON files')
    bundle_parser.add_argument('--output', required=True, help='Output bundle path (tar.gz)')
    bundle_parser.add_argument('--version', default='0.0.1', help='Bundle version')

    # Compare command
    compare_parser = subparsers.add_parser('compare', help='Compare with MongoDB')
    compare_parser.add_argument('--local', required=True, help='Local rules directory')
    compare_parser.add_argument('--mongodb-url', default='mongodb://openwatch:secure_mongo_password@localhost:27017')
    compare_parser.add_argument('--database', default='openwatch_rules')

    args = parser.parse_args()

    if args.command == 'convert':
        converter = EnhancedSCAPConverter(
            args.scap_path,
            args.output_path,
            args.dry_run,
            args.extract_variables,
            args.extract_remediation
        )
        stats = converter.convert_all_rules(args.format)

        # Create bundle if requested
        if args.create_bundle and not args.dry_run:
            bundle_path = Path(args.output_path).parent / f"openwatch-rules-bundle_v{args.bundle_version}.tar.gz"
            converter.create_bundle(Path(args.output_path), bundle_path, args.bundle_version)

    elif args.command == 'bundle':
        converter = EnhancedSCAPConverter('', '', False)
        converter.create_bundle(Path(args.source), Path(args.output), args.version)

    elif args.command == 'compare':
        converter = EnhancedSCAPConverter('', '', False)
        results = asyncio.run(converter.compare_with_mongodb(
            Path(args.local),
            args.mongodb_url,
            args.database
        ))

        # Print results
        for result in results:
            if result.status == 'new':
                print(f"[NEW] {result.rule_id}")
            elif result.status == 'modified':
                print(f"[MODIFIED] {result.rule_id} - Changed fields: {', '.join(result.changes)}")

if __name__ == '__main__':
    main()
