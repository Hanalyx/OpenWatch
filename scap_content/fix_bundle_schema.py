#!/usr/bin/env python3
"""
Fix Bundle Schema v1.0.3 → v1.0.4
Removes extra fields to match MongoDB schema
"""
import bson
import tarfile
import json
import os
import sys
from pathlib import Path
from datetime import datetime, timezone

def fix_rule(rule_dict):
    """
    Remove fields that don't exist in MongoDB schema:
    - 'name' (top-level) - keep only metadata.name
    - 'source' (top-level dict) - keep only source_file/source_hash
    - 'stig' (top-level) - should be in frameworks.stig or removed

    Add MongoDB default fields that Pydantic adds:
    - 'abstract': False
    - 'conditions': []
    - 'parameter_resolution': 'most_restrictive'
    - 'dependencies': {'requires': [], 'conflicts': [], 'related': []}
    - 'check_type': 'custom'
    - 'fix_available': False
    - 'remediation_complexity': 'medium'
    - 'remediation_risk': 'low'
    """
    fixed = rule_dict.copy()

    # Remove top-level 'name' (keep metadata.name)
    if 'name' in fixed:
        print(f"  Removing top-level 'name': {fixed['name'][:60]}...")
        del fixed['name']

    # Handle 'source' dict - extract to source_file if needed
    if 'source' in fixed and isinstance(fixed['source'], dict):
        source_dict = fixed['source']
        print(f"  Removing top-level 'source' dict with keys: {list(source_dict.keys())}")

        # Preserve source_file if not already present
        if 'source_file' not in fixed and 'source_file' in source_dict:
            fixed['source_file'] = source_dict['source_file']
            print(f"    → Extracted source_file: {fixed['source_file']}")

        # Add source_hash with default value if not present
        if 'source_hash' not in fixed:
            fixed['source_hash'] = 'unknown'

        del fixed['source']

    # Handle 'stig' - move to frameworks.stig
    if 'stig' in fixed:
        print(f"  Found top-level 'stig' with keys: {list(fixed['stig'].keys())}")

        # Ensure frameworks dict exists
        if 'frameworks' not in fixed:
            fixed['frameworks'] = {}

        # Move stig data to frameworks.stig
        if 'stig' not in fixed['frameworks']:
            fixed['frameworks']['stig'] = fixed['stig']
            print(f"    → Moved to frameworks.stig")

        del fixed['stig']

    # Add MongoDB default fields that Pydantic adds (handle both missing and None values)
    if 'abstract' not in fixed or fixed.get('abstract') is None:
        fixed['abstract'] = False

    if 'conditions' not in fixed or fixed.get('conditions') is None:
        fixed['conditions'] = []

    if 'parameter_resolution' not in fixed or fixed.get('parameter_resolution') is None:
        fixed['parameter_resolution'] = 'most_restrictive'

    if 'dependencies' not in fixed or fixed.get('dependencies') is None:
        fixed['dependencies'] = {'requires': [], 'conflicts': [], 'related': []}

    # Add missing remediation/check fields (handle both missing and None values)
    if 'check_type' not in fixed or fixed.get('check_type') is None:
        fixed['check_type'] = 'custom'

    if 'fix_available' not in fixed or fixed.get('fix_available') is None:
        fixed['fix_available'] = False

    if 'remediation_complexity' not in fixed or fixed.get('remediation_complexity') is None:
        fixed['remediation_complexity'] = 'medium'

    if 'remediation_risk' not in fixed or fixed.get('remediation_risk') is None:
        fixed['remediation_risk'] = 'low'

    # Add missing metadata fields (handle both missing and None values)
    if 'deprecated' not in fixed or fixed['deprecated'] is None:
        fixed['deprecated'] = False

    if 'scanner_type' not in fixed or fixed['scanner_type'] is None:
        fixed['scanner_type'] = 'oscap'

    # Normalize platform_implementations to match PlatformImplementation schema
    if 'platform_implementations' in fixed and isinstance(fixed['platform_implementations'], dict):
        normalized_pi = {}
        for platform, impl in fixed['platform_implementations'].items():
            if not isinstance(impl, dict):
                continue

            # Remove fields that don't exist in PlatformImplementation schema
            removed_fields = []
            if 'checktext' in impl:
                impl.pop('checktext')
                removed_fields.append('checktext')
            if 'fixtext' in impl:
                impl.pop('fixtext')
                removed_fields.append('fixtext')

            if removed_fields:
                print(f"  Removing platform_implementations.{platform} fields: {removed_fields}")

            # Add missing PlatformImplementation default fields
            if 'service_name' not in impl or impl['service_name'] is None:
                impl['service_name'] = None
            if 'check_script' not in impl or impl['check_script'] is None:
                impl['check_script'] = None
            if 'config_files' not in impl or impl['config_files'] is None:
                impl['config_files'] = []
            if 'enable_command' not in impl or impl['enable_command'] is None:
                impl['enable_command'] = None
            if 'disable_command' not in impl or impl['disable_command'] is None:
                impl['disable_command'] = None
            if 'validation_command' not in impl or impl['validation_command'] is None:
                impl['validation_command'] = None
            if 'service_dependencies' not in impl or impl['service_dependencies'] is None:
                impl['service_dependencies'] = []

            normalized_pi[platform] = impl

        fixed['platform_implementations'] = normalized_pi

    return fixed

def process_bundle(input_bundle, output_bundle, new_version):
    """Process bundle and create corrected version"""
    print(f"\n{'='*80}")
    print(f"Processing Bundle: {input_bundle}")
    print(f"Output: {output_bundle}")
    print(f"New Version: {new_version}")
    print(f"{'='*80}\n")

    # Extract input bundle
    temp_dir = Path("/tmp/bundle_fix")
    temp_dir.mkdir(exist_ok=True)

    print("Extracting input bundle...")
    with tarfile.open(input_bundle, 'r:gz') as tar:
        tar.extractall(temp_dir)

    # Read manifest
    manifest_path = temp_dir / "manifest.json"
    with open(manifest_path, 'r') as f:
        manifest = json.load(f)

    print(f"Found {manifest['rules_count']} rules in manifest")

    # Process each rule
    rules_dir = temp_dir / "rules"
    fixed_count = 0

    for rule_file in sorted(rules_dir.glob("*.bson")):
        # Read rule
        with open(rule_file, 'rb') as f:
            rule = bson.decode(f.read())

        rule_id = rule.get('rule_id', 'unknown')

        # Check if rule has obvious issues
        has_obvious_issues = 'name' in rule or 'source' in rule or 'stig' in rule

        if has_obvious_issues:
            print(f"\nFixing: {rule_id}")

        # ALWAYS fix all rules (for defaults and platform_implementations normalization)
        fixed_rule = fix_rule(rule)

        # Write fixed rule
        with open(rule_file, 'wb') as f:
            f.write(bson.encode(fixed_rule))

        fixed_count += 1

    print(f"\n{'='*80}")
    print(f"Fixed {fixed_count} rules")
    print(f"{'='*80}\n")

    # Update manifest
    manifest['version'] = new_version
    manifest['created_at'] = datetime.now(timezone.utc).isoformat()
    manifest['name'] = f"complianceascode-{manifest['product']}"

    with open(manifest_path, 'w') as f:
        json.dump(manifest, f, indent=2)

    print("Creating corrected bundle...")
    # Create output bundle
    with tarfile.open(output_bundle, 'w:gz') as tar:
        tar.add(temp_dir / "manifest.json", arcname="manifest.json")
        tar.add(temp_dir / "rules", arcname="rules")

    # Cleanup
    import shutil
    shutil.rmtree(temp_dir)

    print(f"\n{'='*80}")
    print(f"✓ Created corrected bundle: {output_bundle}")
    print(f"✓ Version: {new_version}")
    print(f"{'='*80}\n")

if __name__ == "__main__":
    input_bundle = "/home/rracine/hanalyx/scap_content/build/openwatch_bundles/rhel8/openwatch-rhel8-bundle_v1.0.3.tar.gz"
    output_bundle = "/home/rracine/hanalyx/scap_content/build/openwatch_bundles/rhel8/openwatch-rhel8-bundle_v1.0.4.tar.gz"
    new_version = "1.0.4"

    process_bundle(input_bundle, output_bundle, new_version)
    print("Done!")
