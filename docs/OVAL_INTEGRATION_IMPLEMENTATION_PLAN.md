# OpenWatch OVAL Integration - Implementation Plan (File-Based Approach)

## Executive Summary

This plan implements OVAL scanning support using a **file-based storage strategy** for OVAL definitions, while compliance rules maintain their existing versioning system.

**Key Decision**: OVAL files are implementation artifacts, not business entities. They use simple file replacement rather than complex versioning.

---

## Architecture Overview

### Storage Strategy

```
/app/data/oval_definitions/
├── rhel8/
│   ├── account_disable_post_pw_expiration.xml
│   ├── package_aide_installed.xml
│   └── ... (1,493 files - latest version)
├── rhel9/
│   ├── account_disable_post_pw_expiration.xml
│   └── ... (1,442 files - latest version)
├── ubuntu2204/
│   └── ...
└── ubuntu2404/
    └── ...
```

**Principles**:
- ✅ One OVAL file per platform (no duplication)
- ✅ New bundle uploads **overwrite** existing OVAL files
- ✅ Platform-isolated (rhel9 OVALs don't affect ubuntu OVALs)
- ✅ No versioning - always use latest
- ✅ Compliance rules store lightweight filename reference

---

## Phase 1: Bundle Creation Script

### Location
`/home/rracine/hanalyx/scap_content/build/create_oval_bundle.sh`

### Script Implementation

```bash
#!/bin/bash
# create_oval_bundle.sh - Create OpenWatch bundle with OVAL definitions

set -e

PLATFORM="${1:-rhel9}"
VERSION="${2:-0.0.2}"
BUILD_DIR="$(pwd)"
OUTPUT_DIR="openwatch_bundles/${PLATFORM}"
TEMP_DIR="${OUTPUT_DIR}/temp"

echo "=== Creating OpenWatch Bundle with OVAL ==="
echo "Platform: ${PLATFORM}"
echo "Version: ${VERSION}"
echo ""

# Clean previous build
rm -rf "${TEMP_DIR}"
mkdir -p "${TEMP_DIR}/rules"
mkdir -p "${TEMP_DIR}/oval"

# Step 1: Copy BSON rules from existing bundle
echo "Step 1: Copying BSON rules..."
EXISTING_BUNDLE="openwatch_bundles/all/bundles/openwatch-${PLATFORM}-bundle_v0.0.1"
if [ ! -d "${EXISTING_BUNDLE}/rules" ]; then
    echo "ERROR: Existing bundle not found at ${EXISTING_BUNDLE}"
    exit 1
fi

cp "${EXISTING_BUNDLE}/rules/"*.bson "${TEMP_DIR}/rules/"
RULES_COUNT=$(ls -1 "${TEMP_DIR}/rules/"*.bson | wc -l)
echo "  ✓ Copied ${RULES_COUNT} rule files"

# Step 2: Copy corresponding OVAL files
echo ""
echo "Step 2: Copying OVAL files..."
OVAL_SOURCE_DIR="${BUILD_DIR}/${PLATFORM}/checks/oval"
if [ ! -d "${OVAL_SOURCE_DIR}" ]; then
    echo "ERROR: OVAL source directory not found at ${OVAL_SOURCE_DIR}"
    exit 1
fi

OVAL_COUNT=0
MISSING_OVAL=0

for rule_file in "${TEMP_DIR}/rules/"*.bson; do
    rule_id=$(basename "$rule_file" .bson)
    # Remove 'ow-' prefix to get OVAL filename
    oval_id="${rule_id#ow-}"
    oval_source="${OVAL_SOURCE_DIR}/${oval_id}.xml"

    if [ -f "$oval_source" ]; then
        # Validate XML before copying
        if xmllint --noout "$oval_source" 2>/dev/null; then
            cp "$oval_source" "${TEMP_DIR}/oval/"
            ((OVAL_COUNT++))
        else
            echo "  ⚠ Invalid XML: ${oval_id}.xml (skipping)"
            ((MISSING_OVAL++))
        fi
    else
        ((MISSING_OVAL++))
    fi
done

echo "  ✓ Copied ${OVAL_COUNT} OVAL files"
if [ $MISSING_OVAL -gt 0 ]; then
    echo "  ⚠ ${MISSING_OVAL} rules have no corresponding OVAL file"
fi

# Step 3: Calculate OVAL coverage
OVAL_COVERAGE=$(awk "BEGIN {printf \"%.1f\", (${OVAL_COUNT}/${RULES_COUNT})*100}")

# Step 4: Create/update manifest.json
echo ""
echo "Step 3: Creating manifest..."
cat > "${TEMP_DIR}/manifest.json" <<EOF
{
  "name": "openwatch-${PLATFORM}-bundle",
  "version": "${VERSION}",
  "platform": "${PLATFORM}",
  "schema_version": "1.1",
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "rules_count": ${RULES_COUNT},
  "oval_count": ${OVAL_COUNT},
  "oval_coverage": ${OVAL_COVERAGE},
  "oval_version": "5.11",
  "capabilities": {
    "scanning": true,
    "has_oval": true
  },
  "metadata": {
    "generated_by": "create_oval_bundle.sh",
    "source": "ComplianceAsCode SCAP Security Guide"
  }
}
EOF
echo "  ✓ Manifest created"

# Step 5: Create tarball
echo ""
echo "Step 4: Creating tarball..."
BUNDLE_NAME="openwatch-${PLATFORM}-bundle_v${VERSION}.tar.gz"
BUNDLE_PATH="${OUTPUT_DIR}/${BUNDLE_NAME}"

tar -czf "${BUNDLE_PATH}" -C "${TEMP_DIR}" .
BUNDLE_SIZE=$(du -h "${BUNDLE_PATH}" | cut -f1)

echo "  ✓ Bundle created: ${BUNDLE_PATH}"
echo "  ✓ Size: ${BUNDLE_SIZE}"

# Cleanup
rm -rf "${TEMP_DIR}"

# Summary
echo ""
echo "=== Bundle Creation Complete ==="
echo "Bundle: ${BUNDLE_NAME}"
echo "Rules: ${RULES_COUNT}"
echo "OVAL Files: ${OVAL_COUNT}"
echo "Coverage: ${OVAL_COVERAGE}%"
echo "Location: ${BUNDLE_PATH}"
echo ""
echo "Upload via: Dashboard >> Content >> Upload & Synchronize Rules"
```

### Make Script Executable

```bash
chmod +x /home/rracine/hanalyx/scap_content/build/create_oval_bundle.sh
```

### Test Bundle Creation

```bash
cd /home/rracine/hanalyx/scap_content/build/

# Create RHEL9 bundle with OVAL
./create_oval_bundle.sh rhel9 0.0.2

# Verify bundle structure
tar -tzf openwatch_bundles/rhel9/openwatch-rhel9-bundle_v0.0.2.tar.gz | head -20
```

**Expected Output**:
```
manifest.json
rules/
rules/ow-account_disable_post_pw_expiration.bson
rules/ow-package_aide_installed.bson
...
oval/
oval/account_disable_post_pw_expiration.xml
oval/package_aide_installed.xml
...
```

---

## Phase 2: Backend Implementation

### File 1: MongoDB Schema Update

**File**: `/home/rracine/hanalyx/openwatch/backend/app/models/mongo_models.py`

**Changes**:

```python
class ComplianceRule(Document):
    # ... existing fields ...

    # OVAL Integration - Store filename only (not full path)
    oval_filename: Optional[str] = None  # e.g., "account_disable_post_pw_expiration.xml"
    has_oval_check: bool = False  # Quick filter flag

    # Bundle tracking
    source_bundle: Optional[str] = None  # e.g., "openwatch-rhel9-bundle"
    source_bundle_version: Optional[str] = None  # e.g., "0.0.2"

    def get_oval_path(self, platform: str) -> Optional[Path]:
        """
        Get full OVAL file path for a specific platform

        Args:
            platform: Platform identifier (rhel9, ubuntu2204, etc.)

        Returns:
            Path to OVAL file if it exists, None otherwise
        """
        if not self.oval_filename:
            return None

        oval_path = Path(f"/app/data/oval_definitions/{platform}/{self.oval_filename}")
        return oval_path if oval_path.exists() else None

    @property
    def primary_platform(self) -> Optional[str]:
        """Get the first platform from platform_implementations"""
        if not self.platform_implementations:
            return None
        return list(self.platform_implementations.keys())[0]

    class Settings:
        name = "compliance_rules"
        indexes = [
            # ... existing indexes ...
            [("has_oval_check", 1)],  # For filtering scannable rules
            [("source_bundle", 1), ("source_bundle_version", 1)]
        ]
```

**New Model**: Add bundle metadata tracking

```python
from beanie import Document
from datetime import datetime
from typing import Dict, Optional

class BundleMetadata(Document):
    """
    Track uploaded compliance bundles and their OVAL definitions

    Purpose:
    - Know which bundle version is active for each platform
    - Verify OVAL file integrity with checksums
    - Provide upload history for auditing
    """

    platform: str  # "rhel9", "ubuntu2204", etc.
    bundle_name: str  # "openwatch-rhel9-bundle"
    bundle_version: str  # "0.0.2"

    # Counts
    rules_count: int
    oval_count: int
    oval_coverage: float  # Percentage (0-100)

    # OVAL file integrity
    oval_checksums: Dict[str, str]  # {filename: sha256_hash}

    # Metadata
    uploaded_at: datetime
    uploaded_by: str
    upload_id: str

    # Capabilities
    has_oval: bool = False
    has_scanning_support: bool = False

    class Settings:
        name = "bundle_metadata"
        indexes = [
            [("platform", 1), ("uploaded_at", -1)],  # Latest per platform
            [("upload_id", 1)]
        ]
```

**Lines Modified**: ~50 lines (new fields + new model)

---

### File 2: Upload Service - OVAL Extraction

**File**: `/home/rracine/hanalyx/openwatch/backend/app/services/compliance_rules_upload_service.py`

**Add after line 199** (Phase 4: Importing rules):

```python
# ============================================================================
# Phase 4.5: Extract and Store OVAL Files (File-Based Approach)
# ============================================================================
logger.info(f"[{self.upload_id}] Phase 4.5: Extracting OVAL files")

# Get platform from manifest
platform = manifest.get('platform', 'unknown')
bundle_name = manifest.get('name', 'unknown')
bundle_version = manifest.get('version', '0.0.1')

# Define platform-specific OVAL storage (file-based, not upload-specific)
oval_storage_base = Path("/app/data/oval_definitions")
oval_storage_base.mkdir(parents=True, exist_ok=True)

oval_storage_path = oval_storage_base / platform
oval_storage_path.mkdir(parents=True, exist_ok=True)

# Check if bundle has oval/ directory
oval_dir = extracted_path / "oval"
oval_checksums = {}
oval_new_count = 0
oval_updated_count = 0
oval_unchanged_count = 0

if oval_dir.exists() and oval_dir.is_dir():
    logger.info(f"[{self.upload_id}] Found OVAL directory in bundle")

    # Create rule_id to OVAL filename mapping
    oval_mapping = {}

    for oval_file in oval_dir.glob("*.xml"):
        dest_file = oval_storage_path / oval_file.name

        # Validate XML before processing
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(oval_file)
            root = tree.getroot()

            # Verify it has at least one OVAL definition
            ns = {'oval-def': 'http://oval.mitre.org/XMLSchema/oval-definitions-5'}
            definitions = root.findall('.//oval-def:definition', ns)

            if not definitions:
                logger.warning(f"[{self.upload_id}] OVAL file has no definitions: {oval_file.name}")
                continue

        except ET.ParseError as e:
            logger.warning(f"[{self.upload_id}] Invalid OVAL XML: {oval_file.name} - {e}")
            continue

        # Calculate checksum
        oval_content = oval_file.read_bytes()
        checksum = hashlib.sha256(oval_content).hexdigest()
        oval_checksums[oval_file.name] = checksum

        # Check if file exists and compare
        if dest_file.exists():
            old_checksum = hashlib.sha256(dest_file.read_bytes()).hexdigest()
            if old_checksum != checksum:
                oval_updated_count += 1
                logger.info(f"[{self.upload_id}] Updating OVAL: {oval_file.name}")
            else:
                oval_unchanged_count += 1
        else:
            oval_new_count += 1
            logger.info(f"[{self.upload_id}] New OVAL: {oval_file.name}")

        # Copy/overwrite OVAL file (file-based replacement)
        shutil.copy2(oval_file, dest_file)

        # Map OVAL filename to rule_id (add 'ow-' prefix)
        oval_rule_id = f"ow-{oval_file.stem}"
        oval_mapping[oval_rule_id] = oval_file.name

    oval_file_count = len(oval_checksums)
    logger.info(
        f"[{self.upload_id}] OVAL files: {oval_new_count} new, "
        f"{oval_updated_count} updated, {oval_unchanged_count} unchanged"
    )

    # Update rules with OVAL filenames
    for rule in new_rules:
        rule_id = rule.get('rule_id')
        if rule_id in oval_mapping:
            rule['oval_filename'] = oval_mapping[rule_id]
            rule['has_oval_check'] = True

        # Add bundle tracking
        rule['source_bundle'] = bundle_name
        rule['source_bundle_version'] = bundle_version

    # Store bundle metadata
    from backend.app.models.mongo_models import BundleMetadata

    bundle_metadata = BundleMetadata(
        platform=platform,
        bundle_name=bundle_name,
        bundle_version=bundle_version,
        rules_count=len(new_rules),
        oval_count=oval_file_count,
        oval_coverage=manifest.get('oval_coverage', 0.0),
        oval_checksums=oval_checksums,
        uploaded_at=datetime.now(),
        uploaded_by='admin',  # TODO: Get from auth context
        upload_id=self.upload_id,
        has_oval=True,
        has_scanning_support=True
    )
    await bundle_metadata.insert()
    logger.info(f"[{self.upload_id}] Bundle metadata stored")

    result['oval_files_count'] = oval_file_count
    result['oval_new'] = oval_new_count
    result['oval_updated'] = oval_updated_count
    result['oval_unchanged'] = oval_unchanged_count
    result['oval_storage_path'] = str(oval_storage_path)

else:
    # No OVAL directory - check if this is expected
    logger.warning(f"[{self.upload_id}] No OVAL directory found in bundle")

    # Check bundle version - v0.0.2+ should have OVAL
    from packaging import version

    if version.parse(bundle_version) >= version.parse('0.0.2'):
        # Modern bundle should have OVAL
        result['warnings'].append({
            'phase': 'oval_extraction',
            'code': 'MISSING_OVAL_DIR',
            'message': f'Bundle {bundle_version} is missing oval/ directory',
            'severity': 'error',
            'recommendation': 'Rebuild bundle with create_oval_bundle.sh script'
        })
    else:
        # Legacy bundle (v0.0.1) - OVAL is optional
        result['warnings'].append({
            'phase': 'oval_extraction',
            'code': 'LEGACY_BUNDLE_NO_OVAL',
            'message': 'Legacy bundle lacks OVAL definitions. Scanning will be limited.',
            'severity': 'medium',
            'recommendation': 'Upload v0.0.2+ bundle for full scanning support'
        })

    # Still update rules with bundle tracking
    for rule in new_rules:
        rule['source_bundle'] = bundle_name
        rule['source_bundle_version'] = bundle_version

# Continue with existing deduplication and import logic...
```

**Add at top of file**:
```python
import shutil
import hashlib
from packaging import version
```

**Lines Added**: ~120 lines

---

### File 3: Scanner - OVAL Combining and XCCDF Generation

**File**: `/home/rracine/hanalyx/openwatch/backend/app/services/mongodb_scap_scanner.py`

#### Change 1: Add OVAL Combining Method

**Add after line 295** (after `_generate_xccdf_profile_xml`):

```python
def _generate_combined_oval_file(self, rules: List[ComplianceRule], platform: str, output_path: Path) -> Optional[str]:
    """
    Combine individual OVAL files into single OVAL definition file

    Uses file-based OVAL storage - reads from /app/data/oval_definitions/{platform}/

    Args:
        rules: List of ComplianceRule objects with oval_filename
        platform: Platform identifier (rhel9, ubuntu2204, etc.)
        output_path: Directory to write combined OVAL file

    Returns:
        Path to combined OVAL file, or None if no OVAL files found
    """
    import xml.etree.ElementTree as ET

    # Get platform OVAL directory
    platform_oval_dir = Path(f"/app/data/oval_definitions/{platform}")

    if not platform_oval_dir.exists():
        logger.warning(f"No OVAL directory for platform {platform}")
        return None

    # Filter rules that have OVAL files
    rules_with_oval = [r for r in rules if r.oval_filename]

    if not rules_with_oval:
        logger.warning("No OVAL files referenced by selected rules")
        return None

    logger.info(f"Combining OVAL from {len(rules_with_oval)} rules")

    # Collections for OVAL components (use dicts to deduplicate by ID)
    all_definitions = {}
    all_tests = {}
    all_objects = {}
    all_states = {}
    all_variables = {}

    # Track OVAL definition IDs for XCCDF reference
    oval_def_ids = {}  # {rule_id: oval_definition_id}

    # XML namespaces
    ns = {
        'oval-def': 'http://oval.mitre.org/XMLSchema/oval-definitions-5',
        'ind': 'http://oval.mitre.org/XMLSchema/oval-definitions-5#independent',
        'unix': 'http://oval.mitre.org/XMLSchema/oval-definitions-5#unix',
        'linux': 'http://oval.mitre.org/XMLSchema/oval-definitions-5#linux'
    }

    # Register namespaces
    for prefix, uri in ns.items():
        ET.register_namespace(prefix, uri)

    # Parse each OVAL file and extract components
    for rule in rules_with_oval:
        oval_file_path = platform_oval_dir / rule.oval_filename

        if not oval_file_path.exists():
            logger.warning(f"OVAL file not found: {oval_file_path}")
            continue

        try:
            tree = ET.parse(oval_file_path)
            root = tree.getroot()

            # Extract definitions (deduplicate by ID)
            for definition in root.findall('.//oval-def:definition', ns):
                def_id = definition.get('id')
                if def_id and def_id not in all_definitions:
                    all_definitions[def_id] = ET.tostring(definition, encoding='unicode')
                    # Store mapping for XCCDF reference
                    oval_def_ids[rule.rule_id] = def_id

            # Extract tests (deduplicate by ID)
            tests_parent = root.find('.//oval-def:tests', ns)
            if tests_parent is not None:
                for test in tests_parent:
                    test_id = test.get('id')
                    if test_id and test_id not in all_tests:
                        all_tests[test_id] = ET.tostring(test, encoding='unicode')

            # Extract objects (deduplicate by ID)
            objects_parent = root.find('.//oval-def:objects', ns)
            if objects_parent is not None:
                for obj in objects_parent:
                    obj_id = obj.get('id')
                    if obj_id and obj_id not in all_objects:
                        all_objects[obj_id] = ET.tostring(obj, encoding='unicode')

            # Extract states (deduplicate by ID)
            states_parent = root.find('.//oval-def:states', ns)
            if states_parent is not None:
                for state in states_parent:
                    state_id = state.get('id')
                    if state_id and state_id not in all_states:
                        all_states[state_id] = ET.tostring(state, encoding='unicode')

            # Extract variables (deduplicate by ID)
            variables_parent = root.find('.//oval-def:variables', ns)
            if variables_parent is not None:
                for var in variables_parent:
                    var_id = var.get('id')
                    if var_id and var_id not in all_variables:
                        all_variables[var_id] = ET.tostring(var, encoding='unicode')

        except Exception as e:
            logger.warning(f"Failed to parse OVAL file {oval_file_path}: {e}")
            continue

    if not all_definitions:
        logger.warning("No OVAL definitions extracted from files")
        return None

    logger.info(
        f"Extracted {len(all_definitions)} definitions, {len(all_tests)} tests, "
        f"{len(all_objects)} objects, {len(all_states)} states, {len(all_variables)} variables"
    )

    # Generate combined OVAL XML
    combined_oval = f'''<?xml version='1.0' encoding='utf-8'?>
<oval-def:oval_definitions
    xmlns:ind="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent"
    xmlns:linux="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"
    xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5"
    xmlns:oval-def="http://oval.mitre.org/XMLSchema/oval-definitions-5"
    xmlns:unix="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <oval-def:generator>
    <oval:product_name>OpenWatch MongoDB Scanner</oval:product_name>
    <oval:schema_version>5.11</oval:schema_version>
    <oval:timestamp>{datetime.now().isoformat()}</oval:timestamp>
  </oval-def:generator>
  <oval-def:definitions>
    {''.join(all_definitions.values())}
  </oval-def:definitions>
  <oval-def:tests>
    {''.join(all_tests.values())}
  </oval-def:tests>
  <oval-def:objects>
    {''.join(all_objects.values())}
  </oval-def:objects>
  <oval-def:states>
    {''.join(all_states.values())}
  </oval-def:states>
  <oval-def:variables>
    {''.join(all_variables.values())}
  </oval-def:variables>
</oval-def:oval_definitions>'''

    # Write combined OVAL file
    combined_oval_path = output_path / "combined-oval-definitions.xml"
    with open(combined_oval_path, 'w', encoding='utf-8') as f:
        f.write(combined_oval)

    logger.info(f"Generated combined OVAL file: {combined_oval_path}")

    # Store OVAL def ID mapping for later use
    self._oval_def_ids = oval_def_ids

    return str(combined_oval_path)
```

#### Change 2: Update XCCDF Generation

**Modify method** at line 245:

```python
def _generate_xccdf_profile_xml(
    self,
    rules: List[ComplianceRule],
    profile_name: str,
    platform: str,
    oval_file_path: Optional[str] = None
) -> str:
    """
    Generate XCCDF XML from MongoDB rules

    Args:
        rules: List of compliance rules
        profile_name: Name of the profile
        platform: Platform identifier
        oval_file_path: Path to combined OVAL file (if available)

    Returns:
        XCCDF XML content as string
    """

    xml_lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<xccdf:Benchmark xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2" ',
        'xmlns:xhtml="http://www.w3.org/1999/xhtml" ',
        f'id="mongodb-generated-{platform}" resolved="1" xml:lang="en-US">',
        f'  <xccdf:status>incomplete</xccdf:status>',
        f'  <xccdf:title>MongoDB Generated Profile - {profile_name}</xccdf:title>',
        f'  <xccdf:description>Profile generated from MongoDB compliance rules</xccdf:description>',
        f'  <xccdf:version>{datetime.now().strftime("%Y.%m.%d")}</xccdf:version>',
        '',
        f'  <xccdf:Profile id="mongodb_{profile_name.lower().replace(" ", "_")}">',
        f'    <xccdf:title>{profile_name}</xccdf:title>',
        f'    <xccdf:description>MongoDB-based compliance profile for {platform}</xccdf:description>',
    ]

    # Add rule selections
    for rule in rules:
        if rule.platform_implementations and platform in rule.platform_implementations:
            xml_lines.append(f'    <xccdf:select idref="{rule.scap_rule_id or rule.rule_id}" selected="true"/>')

    xml_lines.append('  </xccdf:Profile>')

    # Add rules
    for rule in rules:
        if rule.platform_implementations and platform in rule.platform_implementations:
            platform_impl = rule.platform_implementations[platform]

            xml_lines.extend([
                '',
                f'  <xccdf:Rule id="{rule.scap_rule_id or rule.rule_id}" severity="{rule.severity}">',
                f'    <xccdf:title>{rule.metadata.get("name", "Unknown Rule")}</xccdf:title>',
                f'    <xccdf:description>{rule.metadata.get("description", "No description")}</xccdf:description>',
                f'    <xccdf:rationale>{rule.metadata.get("rationale", "No rationale provided")}</xccdf:rationale>',
            ])

            # Add OVAL check reference if OVAL file exists
            if oval_file_path and rule.oval_filename:
                # Get actual OVAL definition ID from parsed files
                oval_def_id = self._oval_def_ids.get(rule.rule_id)

                if oval_def_id:
                    xml_lines.extend([
                        '    <xccdf:check system="http://oval.mitre.org/XMLSchema/oval-definitions-5">',
                        f'      <xccdf:check-content-ref name="{oval_def_id}" href="combined-oval-definitions.xml"/>',
                        '    </xccdf:check>',
                    ])
                else:
                    logger.warning(f"No OVAL definition ID found for rule {rule.rule_id}")

            xml_lines.append('  </xccdf:Rule>')

    xml_lines.append('</xccdf:Benchmark>')

    return '\n'.join(xml_lines)
```

#### Change 3: Update Scan Workflow

**Modify around line 334** in `scan_with_mongodb_rules()`:

```python
# Step 3: Generate combined OVAL file from platform OVAL directory
temp_dir = Path(tempfile.mkdtemp())
combined_oval_path = None

try:
    combined_oval_path = self._generate_combined_oval_file(resolved_rules, platform, temp_dir)

    if combined_oval_path:
        logger.info(f"Generated combined OVAL: {combined_oval_path}")
    else:
        logger.warning("No OVAL definitions available - scan will show 'Not Checked' status")
except Exception as e:
    logger.error(f"Failed to generate combined OVAL: {e}")
    combined_oval_path = None

# Step 4: Generate SCAP profile from MongoDB rules
profile_name = f"MongoDB {framework or 'Standard'} Profile"

# Generate XCCDF XML content with OVAL reference
xccdf_content = self._generate_xccdf_profile_xml(
    resolved_rules,
    profile_name,
    platform,
    oval_file_path=combined_oval_path
)

# Write XCCDF to file
xccdf_path = temp_dir / "mongodb-profile.xml"
with open(xccdf_path, 'w') as f:
    f.write(xccdf_content)

logger.info(f"Generated XCCDF profile: {xccdf_path}")

# Step 5: Execute oscap scan
oscap_cmd = [
    'oscap', 'xccdf', 'eval',
    '--profile', f"mongodb_{profile_name.lower().replace(' ', '_')}",
    '--results', str(results_file),
    '--report', str(report_file),
    str(xccdf_path)
]

if combined_oval_path:
    logger.info(f"Scan will use OVAL definitions from: {combined_oval_path}")
else:
    logger.warning("Scan will run without OVAL - results will be informational only")

# Continue with oscap execution...
```

**Lines Modified**: ~150 lines total across 3 changes

---

## Phase 3: Docker Configuration

**File**: `/home/rracine/hanalyx/openwatch/docker-compose.yml`

**Add volume mount**:

```yaml
services:
  backend:
    volumes:
      - ./openwatch/backend:/app/backend
      - ./data:/app/data
      - ./data/oval_definitions:/app/data/oval_definitions  # OVAL storage (file-based)
      - /var/run/docker.sock:/var/run/docker.sock
```

**Lines Added**: 1 line

---

## Implementation Summary

### Code Changes Required

| File | Changes | Lines | Complexity |
|------|---------|-------|------------|
| `mongo_models.py` | Add OVAL fields + BundleMetadata model | ~50 | Easy |
| `compliance_rules_upload_service.py` | OVAL extraction logic | ~120 | Medium |
| `mongodb_scap_scanner.py` | OVAL combining + XCCDF update | ~150 | Medium |
| `docker-compose.yml` | Volume mount | 1 | Trivial |
| **Total Backend** | | **~321 lines** | |
| **Bundle Script** | | **~100 lines** | Medium |

### Storage Impact

```
Before: Rules only (14,091 BSON files)
After:  Rules + OVAL per platform
- rhel8:      1,493 XML files (~45 MB)
- rhel9:      1,442 XML files (~43 MB)
- ubuntu2204: ~1,200 XML files (~36 MB)
Total OVAL:  ~130 MB for all platforms
```

**Key Point**: OVAL files stored **once per platform**, not per upload. Storage grows linearly with platforms, not uploads.

---

## Testing Plan

### Phase 1: Bundle Creation Tests

```bash
# Test 1: Create RHEL9 bundle
cd /home/rracine/hanalyx/scap_content/build/
./create_oval_bundle.sh rhel9 0.0.2

# Verify structure
tar -tzf openwatch_bundles/rhel9/openwatch-rhel9-bundle_v0.0.2.tar.gz | grep -E "(manifest|rules|oval)"

# Verify manifest
tar -xzOf openwatch_bundles/rhel9/openwatch-rhel9-bundle_v0.0.2.tar.gz manifest.json | jq .

# Expected output:
# {
#   "name": "openwatch-rhel9-bundle",
#   "version": "0.0.2",
#   "platform": "rhel9",
#   "rules_count": 2013,
#   "oval_count": 1442,
#   "oval_coverage": 71.6,
#   "capabilities": {
#     "scanning": true,
#     "has_oval": true
#   }
# }
```

### Phase 2: Upload Tests

```bash
# Test 2: Upload bundle via UI
# Navigate to: Dashboard >> Content >> Upload & Synchronize Rules
# Upload: openwatch-rhel9-bundle_v0.0.2.tar.gz

# Check backend logs
docker logs openwatch-backend --tail 50 | grep -E "Phase 4.5|OVAL"

# Expected log output:
# Phase 4.5: Extracting OVAL files
# Found OVAL directory in bundle
# OVAL files: 1442 new, 0 updated, 0 unchanged
# Bundle metadata stored

# Test 3: Verify MongoDB
docker exec openwatch-mongodb mongosh openwatch_rules --eval '
db.compliance_rules.countDocuments({has_oval_check: true})
'
# Expected: 1442 (rules with OVAL)

# Test 4: Verify OVAL files on disk
docker exec openwatch-backend ls -lh /app/data/oval_definitions/rhel9/ | head -20
# Expected: XML files with reasonable sizes (10-50 KB each)

# Test 5: Check bundle metadata
docker exec openwatch-mongodb mongosh openwatch_rules --eval '
db.bundle_metadata.find({platform: "rhel9"}).sort({uploaded_at: -1}).limit(1).pretty()
'
```

### Phase 3: Scanning Tests

```bash
# Test 6: Trigger scan via UI
# Navigate to: Host Detail >> Start Scan
# Select: Framework (any), Individual Scan

# Check backend logs
docker logs openwatch-backend -f | grep -E "OVAL|XCCDF|oscap"

# Expected log output:
# Combining OVAL from 1442 rules
# Extracted 1442 definitions, 1456 tests, 1489 objects...
# Generated combined OVAL file: /tmp/.../combined-oval-definitions.xml
# Generated XCCDF profile: /tmp/.../mongodb-profile.xml
# Scan will use OVAL definitions from: /tmp/.../combined-oval-definitions.xml

# Test 7: Verify scan results
# Check UI: Host Detail >> Scan Results
# Expected: Rules show "Pass" or "Fail" status (not "Not Checked")

# Test 8: Download scan report
# UI: Host Detail >> Scan Results >> Download HTML Report
# Expected: Report shows rule results with pass/fail counts
```

### Phase 4: Edge Case Tests

```bash
# Test 9: Upload legacy bundle (v0.0.1, no OVAL)
# Expected: Warning about limited scanning, rules still imported

# Test 10: Upload updated bundle (v0.0.3)
# Expected: OVAL files updated/overwritten, rules version incremented

# Test 11: Scan without OVAL
# Delete OVAL directory: docker exec openwatch-backend rm -rf /app/data/oval_definitions/rhel9
# Trigger scan
# Expected: Warning in logs, scan completes with "Not Checked" status

# Test 12: Multiple platforms
# Upload rhel8 bundle, then ubuntu2204 bundle
# Expected: OVAL directories isolated by platform, no conflicts
```

---

## Migration Strategy

### Scenario 1: Fresh Installation (No Existing Data)

✅ **Action**: Install OpenWatch, upload v0.0.2+ bundles with OVAL
✅ **Result**: Full scanning capability from day one

### Scenario 2: Existing Installation with v0.0.1 Bundles

**Step 1**: Update backend code (no breaking changes)
```bash
# Backend update includes backward compatibility
# Legacy bundles (v0.0.1) will work but show warnings
```

**Step 2**: Upload v0.0.2+ bundles
```bash
# New bundles add OVAL files without affecting existing rules
# Rules get new versions with oval_filename populated
```

**Step 3**: Verify scanning works
```bash
# Trigger scan - should now produce results
```

### Scenario 3: Platform-by-Platform Migration

```bash
# Week 1: Migrate RHEL9
./create_oval_bundle.sh rhel9 0.0.2
# Upload via UI

# Week 2: Migrate RHEL8
./create_oval_bundle.sh rhel8 0.0.2
# Upload via UI

# Week 3: Migrate Ubuntu
./create_oval_bundle.sh ubuntu2204 0.0.2
# Upload via UI
```

**Impact**: Each platform migrates independently, no dependencies

---

## Rollback Plan

### If OVAL Integration Fails

**Option 1: Disable OVAL Scanning** (keep rules)
```bash
# Remove OVAL directories
docker exec openwatch-backend rm -rf /app/data/oval_definitions/*

# Scans will run without OVAL (informational mode)
# Rules remain functional
```

**Option 2: Revert Code Changes**
```bash
# Checkout previous commit
git checkout <previous-commit>

# Rebuild backend
docker-compose build backend
docker-compose up -d backend
```

**Option 3: Re-upload v0.0.1 Bundles**
```bash
# Upload legacy bundles without OVAL
# System continues working as before
```

**Data Safety**:
- Rule data unaffected (OVAL is separate)
- OVAL files are additive (can be deleted without breaking rules)
- MongoDB schema changes are backward compatible (new fields are Optional)

---

## Success Criteria

### ✅ Bundle Creation
- [ ] Script creates bundles with rules/ and oval/ directories
- [ ] Manifest includes OVAL metadata (oval_count, oval_coverage)
- [ ] OVAL files validated as proper XML
- [ ] Tarball under 200 MB per platform

### ✅ Upload Process
- [ ] Bundles upload successfully via UI
- [ ] OVAL files extracted to /app/data/oval_definitions/{platform}/
- [ ] Rules have oval_filename populated
- [ ] Bundle metadata stored in MongoDB
- [ ] Upload statistics show OVAL counts

### ✅ Scanning
- [ ] Combined OVAL file generated from individual files
- [ ] XCCDF references OVAL definitions correctly
- [ ] oscap scan executes without errors
- [ ] Results show pass/fail status (not "Not Checked")
- [ ] HTML reports display rule results

### ✅ Edge Cases
- [ ] Legacy bundles (v0.0.1) work with warnings
- [ ] Multiple platform bundles don't conflict
- [ ] Missing OVAL files log warnings but don't crash
- [ ] Bundle re-upload overwrites OVAL files correctly

---

## Estimated Timeline

| Phase | Task | Time |
|-------|------|------|
| **Phase 1** | Bundle creation script | 2-3 hours |
| | Test bundle creation for all platforms | 1 hour |
| **Phase 2** | Backend schema updates | 1 hour |
| | Upload service OVAL extraction | 2-3 hours |
| | Scanner OVAL combining | 3-4 hours |
| | Scanner XCCDF updates | 1 hour |
| **Phase 3** | Docker configuration | 15 minutes |
| | Integration testing | 2-3 hours |
| | Edge case testing | 1-2 hours |
| **Total** | | **13-18 hours** |

---

## Next Steps

1. ✅ **Review this plan** - Approve file-based OVAL strategy
2. 🔨 **Create bundle script** - Test with RHEL9 first
3. 🔨 **Update MongoDB schema** - Add OVAL fields
4. 🔨 **Implement upload service** - OVAL extraction logic
5. 🔨 **Implement scanner** - OVAL combining logic
6. ✅ **Test end-to-end** - Upload bundle → Scan host → View results
7. 📝 **Document** - Update user guide with OVAL bundle instructions

---

## Questions for Review

1. ✅ **Storage Strategy**: File-based OVAL per platform (approved)
2. ❓ **Cleanup Strategy**: When to delete old OVAL files (if ever)?
3. ❓ **Monitoring**: Should we track OVAL file usage/access?
4. ❓ **Validation**: Should we validate OVAL checksums before scans?
5. ❓ **Performance**: Is on-the-fly OVAL combining fast enough, or should we cache combined files?

---

## Additional Resources

- OVAL Language Spec: https://oval.mitre.org/language/version5.11/
- XCCDF Spec: https://csrc.nist.gov/projects/security-content-automation-protocol/specifications/xccdf
- OpenSCAP Documentation: https://www.open-scap.org/resources/documentation/
- SCAP Security Guide: https://github.com/ComplianceAsCode/content

---

**Document Version**: 1.0
**Last Updated**: 2025-10-30
**Status**: Ready for Implementation
