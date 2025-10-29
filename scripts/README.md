# OpenWatch Scripts

Automation scripts for OpenWatch development and operations.

## Compliance Rules Management

### `build_compliance_rules.sh`

Automates building SCAP content from ComplianceAsCode and converting to OpenWatch format.

**Purpose:** Implements Solution 1 from [JINJA2_RULES_HANDLING_STRATEGY.md](../docs/JINJA2_RULES_HANDLING_STRATEGY.md)

**Quick Start:**
```bash
# Build and convert RHEL 8 rules
./build_compliance_rules.sh rhel8

# Build multiple products
./build_compliance_rules.sh rhel8 rhel9 ubuntu2204

# Build all supported products
./build_compliance_rules.sh all

# Show help
./build_compliance_rules.sh --help
```

**Requirements:**
- CMake, make, python3-jinja2, python3-yaml
- ComplianceAsCode cloned at `/home/rracine/hanalyx/scap_content/content`
- Docker containers running (`docker-compose up -d`)

**Output:**
- SCAP data streams: `../scap_content/build/ssg-<product>-ds.xml`
- Rendered rules: `../scap_content/build/<product>/rules/*.json`
- OpenWatch bundles: `../scap_content/build/openwatch_bundles/*.tar.gz`

**Documentation:**
- [Complete Guide](../docs/guides/BUILD_AND_BUNDLE_COMPLIANCE_RULES.md)
- [Quick Reference](../docs/guides/COMPLIANCE_RULES_QUICK_REFERENCE.md)
- [Implementation Status](../docs/JINJA2_SOLUTION_IMPLEMENTATION_STATUS.md)

**Performance:**
- First build: ~5-10 minutes
- Incremental build: ~1-2 minutes  
- Conversion: ~1-2 seconds per product
- Bundle size: ~1-2 MB compressed per product

**Supported Products:**
- RHEL 8, 9, 10
- Ubuntu 20.04, 22.04
- Oracle Linux 8, 9
- Debian 11, 12
- Fedora
