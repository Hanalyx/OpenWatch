# ADR-002: Kensa (formerly Aegis) Replaces OpenSCAP as Compliance Engine

**Status**: Accepted
**Date**: 2026-02-09 (Updated 2026-02-23 for Aegis to Kensa rename)
**Deciders**: OpenWatch team, Kensa team

## Context

OpenWatch originally used OpenSCAP for compliance scanning with a complex transformation chain:

```
ComplianceAsCode XCCDF --> MongoDB storage --> OVAL evaluation --> OpenSCAP CLI
```

This pipeline had a critical accuracy problem: only 61.94% of scan results matched direct CLI verification, a 35% accuracy gap. The root cause was data loss during the multi-stage transformation from SCAP XML to MongoDB documents and back to OVAL evaluations.

Additionally, the OpenSCAP approach required:
- MongoDB for storing parsed SCAP content (7,221 OVAL definitions)
- Complex XCCDF/OVAL parsing and transformation code
- OpenSCAP binary installed on target hosts
- Specialized parsers for SCAP result formats (XCCDF, ARF)

## Decision

Replace OpenSCAP with Kensa (formerly Aegis) as the primary compliance scanning engine.

**Kensa** is a purpose-built compliance engine that:
- Defines 338 compliance rules as YAML files
- Connects to hosts via SSH and runs checks directly
- Returns structured results with machine-verifiable evidence
- Operates as a pure measurement engine (no storage, no UI)

### Integration architecture:

OpenWatch integrates Kensa through:
1. **ORSA v2.0 Plugin Interface** - Standard plugin contract for compliance engines
2. **Credential bridge** (`app/plugins/kensa/executor.py`) - Decrypts OpenWatch credentials for Kensa SSH sessions
3. **Result storage** - Kensa findings stored in PostgreSQL `scan_findings` table

### Kensa is installed via pip (`pip install kensa`). Import pattern: `from runner.* import ...`

## Consequences

**Benefits:**
- 72.2% accuracy (matches CLI verification directly, compared to 61.94% with OpenSCAP)
- 95.1% CIS RHEL 9 coverage, 75.8% STIG RHEL 9 coverage
- Simple YAML rule format (readable, auditable, versionable)
- No MongoDB dependency for rule storage
- Multi-framework mapping per rule (CIS, STIG, NIST 800-53, PCI-DSS, FedRAMP)
- Evidence capture (command, stdout, stderr, expected vs. actual)
- Variable resolution for site-specific configuration

**Drawbacks:**
- Dependency on external Kensa project for rule updates
- OpenSCAP legacy code still exists in `services/engine/` (unused)

**Framework coverage:**

| Framework | Mapping ID | Controls |
|-----------|------------|----------|
| CIS RHEL 9 v2.0.0 | cis-rhel9-v2.0.0 | 271 |
| STIG RHEL 9 V2R7 | stig-rhel9-v2r7 | 338 |
| NIST 800-53 R5 | nist-800-53-r5 | 87 |
| PCI-DSS v4.0 | pci-dss-v4.0 | 45 |
| FedRAMP Moderate | fedramp-moderate | 87 |
