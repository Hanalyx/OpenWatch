# Phase 1: Enhanced MongoDB Schema & Framework Definitions - Technical Overview

## Executive Summary

Phase 1 of the OpenWatch Unified Compliance Architecture establishes the foundational data models and framework definitions required for cross-framework compliance management. This phase delivers a comprehensive MongoDB-based schema that supports unified compliance rules, multi-framework mapping, and platform-specific implementations across six major compliance frameworks.

## Architecture Overview

### Core Components

```
┌─────────────────────────────────────────────────────────────────┐
│                    Phase 1 Architecture                        │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │   Enhanced      │  │   Framework     │  │   Cross-Frame   │ │
│  │   MongoDB       │  │   Control       │  │   Mapping       │ │
│  │   Schema        │  │   Definitions   │  │   Engine        │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
├─────────────────────────────────────────────────────────────────┤
│              MongoDB Collections & Indexes                     │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │ NIST 800-53 R5  │  │   CIS v8.0      │  │   SRG/STIG     │ │
│  │   150+ Controls │  │   18 Controls   │  │   9+8 Controls  │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
│  ┌─────────────────┐  ┌─────────────────┐                     │
│  │ ISO 27001:2022  │  │  PCI-DSS v4.0   │                     │
│  │   16 Controls   │  │   13 Controls   │                     │
│  └─────────────────┘  └─────────────────┘                     │
└─────────────────────────────────────────────────────────────────┘
```

## Key Features & Capabilities

### 1. Enhanced MongoDB Schema (PR #1)

**UnifiedComplianceRule Model**
- Cross-framework compliance mapping with implementation status tracking
- Platform version range support (RHEL 8/9, Ubuntu 20.04/22.04/24.04)
- Compliance exceeding scenarios (e.g., FIPS crypto > CIS SHA1 prohibition)
- Framework inheritance patterns (SRG as framework, STIG as implementation)

```python
class FrameworkMapping(BaseModel):
    controls: List[str] = Field(description="Control IDs for this framework")
    implementation_status: str = Field(
        default="compliant",
        pattern="^(compliant|exceeds|partial|not_applicable)$"
    )
    enhancement_details: Optional[str] = Field(default=None)
    justification: Optional[str] = Field(default=None)
```

**Key Benefits:**
- Single rule can satisfy requirements across 5+ frameworks simultaneously
- Enhanced compliance tracking beyond simple pass/fail
- Automated justification generation for audit requirements
- Platform-specific implementation details for technical execution

### 2. Framework Control Definitions (PR #2)

**NIST 800-53 Revision 5 Integration**
- Complete control catalog with 150+ security and privacy controls
- Family-based organization (AC, AU, SC, IA, etc.)
- Priority classification (P0, P1, P2, P3) for implementation guidance
- Cross-references to CIS, ISO, and other frameworks

**CIS Controls Version 8 Integration**
- 18 critical security controls with implementation groups (IG1, IG2, IG3)
- Asset-type classification (Users, Data, Networks, etc.)
- Safeguard-level implementation details
- External framework mappings for compliance alignment

**Technical Implementation:**
```javascript
// MongoDB Collection Structure
db.framework_control_definitions.createIndex({ 
    "framework_id": 1, 
    "control_id": 1 
}, { unique: true });

// Cross-reference mapping index
db.framework_control_definitions.createIndex({ 
    "external_references.nist": 1,
    "external_references.cis": 1 
});
```

### 3. STIG/SRG Control Definitions (PR #3)

**Security Requirements Guide (SRG) Integration**
- Framework-level security requirements for general-purpose operating systems
- 9 core SRG controls with CCI mappings and NIST cross-references
- Severity classification (CAT I, CAT II, CAT III) for risk prioritization

**STIG RHEL 9 Implementation**
- Platform-specific implementation of SRG requirements
- 8 detailed STIG controls with technical implementation guidance
- Command-level remediation steps and validation procedures

**Framework Inheritance Model:**
```
SRG-OS-000001-GPOS-00001 (Requirement)
    ↓ implements
RHEL-09-412010 (Platform Implementation)
    ↓ maps to
NIST AC-11, CIS 5.2, ISO A.9.1, PCI 7.1.1
```

**Compliance Exceeding Example:**
- **Scenario**: FIPS cryptography policy exceeds CIS SHA1 prohibition
- **Implementation**: STIG requires FIPS mode, which automatically disables SHA1
- **Result**: System exceeds CIS baseline requirements through stronger implementation
- **Justification**: Automated documentation of enhanced security posture

### 4. ISO 27001 and PCI-DSS Integration (PR #4)

**ISO/IEC 27001:2022 Controls**
- 16 core controls across 14 control categories
- Implementation levels: Basic, Advanced, Comprehensive
- Evidence requirements for audit compliance
- Objective-based control descriptions

**PCI-DSS v4.0 Requirements**
- 13 key requirements across 6 requirement categories
- Validation levels from SAQ-A to Level 1 merchant requirements
- Testing procedures for compliance validation
- Customization guidance for different business models

## Cross-Framework Intelligence

### Compliance Mapping Matrix

| Control Area | NIST 800-53 | CIS v8 | SRG/STIG | ISO 27001 | PCI-DSS |
|--------------|-------------|--------|----------|-----------|---------|
| Access Control | AC-1, AC-2, AC-3 | 5.1, 5.2, 5.3 | SRG-OS-000250 | A.9.1, A.9.2 | 7.1.1, 8.1.1 |
| Cryptography | SC-13 | 3.11 | SRG-OS-000184 | A.10.1 | 3.4.1 |
| Session Management | AC-11 | 5.2 | SRG-OS-000001 | A.9.1 | 7.1.1, 8.1.1 |
| Password Policy | IA-5(1) | 5.3 | SRG-OS-000069 | A.9.2 | 8.1.1, 2.1.1 |

### Implementation Status Tracking

**Compliant**: Meets baseline framework requirements
- Standard implementation satisfying minimum control objectives
- Documentation of implementation methods and evidence

**Exceeds**: Surpasses baseline requirements
- Enhanced implementation providing additional security value
- Automatic justification for compliance reporting
- Example: FIPS crypto implementation exceeding CIS SHA1 prohibition

**Partial**: Incomplete implementation
- Identifies specific gaps requiring remediation
- Provides targeted remediation guidance

**Not Applicable**: Control not relevant to environment
- Environmental or technical exclusion documentation
- Maintains audit trail for compliance officers

## Technical Infrastructure

### MongoDB Schema Design

**Collection Structure:**
```javascript
// Framework Control Definitions
{
  framework_id: "nist_800_53_r5",
  control_id: "AC-11",
  title: "Session Lock",
  family: "Access Control",
  priority: "P1",
  external_references: {
    cis: "5.2",
    iso: "A.9.1",
    pci: "7.1.1"
  }
}

// Enhanced Models for Unified Rules
{
  rule_id: "session_lock_timeout_001",
  framework_mappings: [
    {
      framework_id: "nist_800_53_r5",
      control_ids: ["AC-11"],
      implementation_status: "compliant"
    },
    {
      framework_id: "cis_v8",
      control_ids: ["5.2"],
      implementation_status: "exceeds",
      enhancement_details: "15-minute timeout exceeds CIS baseline"
    }
  ]
}
```

**Indexing Strategy:**
- Primary: framework_id + control_id (unique constraint)
- Cross-reference: external_references fields for mapping queries
- Search: Text indexes on titles and descriptions
- Performance: Compound indexes for multi-framework queries

### Framework Loader Service

**Capabilities:**
- Automated loading of framework definitions from JSON files
- Validation of control cross-references and integrity checking
- CLI tools for framework management and validation
- Update mechanisms for framework evolution

**Usage Example:**
```bash
# Load all frameworks
python -m backend.app.cli.load_frameworks load

# Validate specific framework
python -m backend.app.cli.load_frameworks validate --framework nist_800_53_r5

# Generate summary
python -m backend.app.cli.load_frameworks summary
```

## Business Value & Compliance Benefits

### 1. Unified Compliance Management
- **Single Source of Truth**: All framework requirements in one schema
- **Consistency**: Standardized control mapping across frameworks
- **Efficiency**: Eliminate duplicate effort across compliance programs

### 2. Cross-Framework Intelligence
- **Gap Analysis**: Identify overlapping and unique requirements
- **Optimization**: Leverage stronger implementations to satisfy multiple frameworks
- **Reporting**: Automated compliance status across all frameworks

### 3. Enhanced Security Posture
- **Exceeding Compliance**: Document and leverage enhanced implementations
- **Risk Reduction**: Systematic approach to multi-framework compliance
- **Audit Readiness**: Comprehensive evidence collection and justification

### 4. Operational Efficiency
- **Automated Loading**: Framework definitions loaded via MongoDB scripts
- **Version Management**: Track framework updates and changes
- **Scalability**: MongoDB infrastructure supports large-scale deployments

## Integration Points

### Phase 2 Dependencies
Phase 1 establishes the data foundation required for Phase 2 components:

- **Unified Rule Model**: Builds on enhanced MongoDB schema
- **Rule Parsing Service**: Executes against framework control definitions
- **Platform Detection**: Validates against platform version ranges
- **Multi-Framework Scanner**: Leverages cross-framework mappings

### External System Integration
- **SCAP Content**: Framework definitions complement existing SCAP data streams
- **GRC Platforms**: Export capabilities for governance, risk, and compliance tools
- **Audit Systems**: Evidence collection and justification for compliance reporting

## Migration & Implementation

### Database Initialization
```bash
# MongoDB initialization with all frameworks
docker-compose exec mongodb mongosh --file /docker-entrypoint-initdb.d/02-framework-controls.js
```

### Framework Updates
```bash
# Load updated framework definitions
python -m backend.app.cli.load_frameworks load --framework iso_27001_2022

# Validate integrity after updates
python -m backend.app.cli.load_frameworks validate
```

## Security Considerations

### Data Protection
- MongoDB collections with appropriate access controls
- Audit logging for framework definition changes
- Version control for framework definition files

### Compliance Validation
- Automated validation of cross-references between frameworks
- Integrity checking for control mappings
- Verification of implementation status claims

## Conclusion

Phase 1 delivers a robust foundation for unified compliance management, supporting six major frameworks with sophisticated cross-framework intelligence. The enhanced MongoDB schema enables single-scan compliance assessment across multiple frameworks while maintaining detailed audit trails and justification capabilities.

The implementation demonstrates measurable improvements over traditional compliance approaches:
- **Efficiency**: Single implementation satisfying multiple framework requirements
- **Intelligence**: Automated detection of compliance exceeding scenarios
- **Scalability**: MongoDB infrastructure supporting enterprise-scale deployments
- **Auditability**: Comprehensive evidence collection and justification generation

This foundation enables Phase 2's unified scanning capabilities, delivering the user's vision of faster, more scalable compliance assessment with cross-framework intelligence.