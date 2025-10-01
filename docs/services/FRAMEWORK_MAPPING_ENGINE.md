# Framework Mapping Engine

The Framework Mapping Engine provides intelligent cross-framework control mapping and unified compliance orchestration capabilities for OpenWatch.

## Overview

This engine transforms the complexity of managing multiple compliance frameworks into unified, intelligent mappings that enable:
- Automated discovery of control relationships between frameworks
- Confidence-based mapping classification with semantic analysis
- Framework relationship analysis and optimization opportunities
- Unified implementation generation for multi-framework compliance
- Coverage analysis and gap identification across framework portfolios

## Core Components

### Mapping Classification System

```python
class MappingConfidence(str, Enum):
    HIGH = "high"           # >90% confidence - direct mapping
    MEDIUM = "medium"       # 70-90% confidence - semantic mapping  
    LOW = "low"            # 50-70% confidence - conceptual mapping
    UNCERTAIN = "uncertain" # <50% confidence - needs review

class MappingType(str, Enum):
    DIRECT = "direct"                    # One-to-one mapping
    SUBSET = "subset"                    # Framework A is subset of Framework B
    SUPERSET = "superset"                # Framework A is superset of Framework B
    OVERLAP = "overlap"                  # Partial overlap between frameworks
    EQUIVALENT = "equivalent"            # Functionally equivalent controls
    DERIVED = "derived"                  # Framework B derived from Framework A
    COMPLEMENTARY = "complementary"      # Controls complement each other
```

### Data Models

#### ControlMapping
Comprehensive mapping between controls across frameworks:
```python
@dataclass
class ControlMapping:
    source_framework: str               # Source framework ID
    source_control: str                 # Source control ID
    target_framework: str               # Target framework ID
    target_control: str                 # Target control ID
    mapping_type: MappingType           # Type of relationship
    confidence: MappingConfidence       # Confidence level
    rationale: str                      # Explanation of mapping
    evidence: List[str]                 # Supporting evidence
    implementation_notes: Optional[str] # Implementation guidance
    exceptions: List[str]               # Known exceptions
    created_at: datetime               # Mapping creation timestamp
    verified_by: Optional[str]         # Manual verification
```

#### FrameworkRelationship
Comprehensive analysis of framework relationships:
```python
@dataclass
class FrameworkRelationship:
    framework_a: str                    # First framework
    framework_b: str                    # Second framework
    overlap_percentage: float           # Percentage of overlapping controls
    common_controls: int                # Number of common controls
    framework_a_unique: int             # Controls unique to framework A
    framework_b_unique: int             # Controls unique to framework B
    relationship_type: str              # Type of relationship
    strength: float                     # Relationship strength (0-1)
    bidirectional_mappings: List[ControlMapping]
    implementation_synergies: List[str] # Opportunities for synergy
    conflict_areas: List[str]           # Potential conflicts
```

#### UnifiedImplementation
Implementation that satisfies multiple frameworks:
```python
@dataclass
class UnifiedImplementation:
    implementation_id: str              # Unique implementation identifier
    description: str                    # Implementation description
    frameworks_satisfied: List[str]     # Frameworks this implementation satisfies
    control_mappings: Dict[str, List[str]]  # Framework -> control mappings
    implementation_details: Dict[str, Any]  # Technical implementation details
    platform_specifics: Dict[Platform, PlatformImplementation]
    exceeds_frameworks: List[str]       # Frameworks where this exceeds requirements
    compliance_justification: str      # Justification for compliance claims
    risk_assessment: str               # Risk assessment
    effort_estimate: str              # Implementation effort estimate
```

## Key Features

### 1. Automated Mapping Discovery

**From Unified Rules**: Discovers mappings by analyzing shared implementations
```python
# Discover mappings between NIST and CIS
mappings = await engine.discover_control_mappings(
    "nist_800_53_r5", "cis_v8", unified_rules
)

# Example discovered mapping
{
    "source_framework": "nist_800_53_r5",
    "source_control": "AC-11",
    "target_framework": "cis_v8", 
    "target_control": "5.2",
    "mapping_type": "equivalent",
    "confidence": "high",
    "rationale": "Mapped through 1 shared unified rules",
    "evidence": ["Unified rule: session_timeout_001"]
}
```

**Confidence Calculation**: Automatic confidence assessment based on:
- Overlap ratio between control implementations
- Framework affinity scores
- Number of shared unified rules
- Implementation pattern analysis

### 2. Framework Relationship Analysis

**Comprehensive Relationship Mapping**:
```python
relationship = await engine.analyze_framework_relationship(
    "nist_800_53_r5", "cis_v8", unified_rules
)

# Results in detailed relationship analysis
{
    "relationship_type": "well_aligned",
    "strength": 0.75,
    "overlap_percentage": 68.5,
    "common_controls": 15,
    "framework_a_unique": 25,
    "framework_b_unique": 8,
    "implementation_synergies": [
        "Strong synergy in access_control: 8 aligned controls can be implemented with unified approach",
        "Exceeding compliance opportunity: cis_v8 has 3 rules that exceed baseline requirements"
    ],
    "conflict_areas": []
}
```

**Relationship Classification**:
- **Highly Aligned**: >80% overlap - frameworks work well together
- **Well Aligned**: 60-80% overlap - good compatibility with minor gaps
- **Moderately Aligned**: 40-60% overlap - significant but manageable differences
- **Loosely Aligned**: 20-40% overlap - substantial implementation differences
- **Minimally Aligned**: <20% overlap - fundamentally different approaches

### 3. Predefined Framework Mappings

**Rich Mapping Database**: Comprehensive predefined mappings covering:
- NIST 800-53 R5 ↔ CIS Controls v8
- NIST 800-53 R5 ↔ ISO/IEC 27001:2022
- SRG/STIG ↔ NIST 800-53 R5 (inheritance patterns)
- CIS Controls ↔ PCI-DSS v4.0
- ISO 27001 ↔ PCI-DSS (privacy and payment security alignment)

**Example Predefined Mapping**:
```json
{
  "source_framework": "nist_800_53_r5",
  "source_control": "AC-11",
  "target_framework": "cis_v8",
  "target_control": "5.2",
  "mapping_type": "equivalent",
  "confidence": "high",
  "rationale": "Both controls address session lock/timeout requirements",
  "evidence": [
    "NIST AC-11 requires session lock after period of inactivity",
    "CIS 5.2 requires session timeout configuration",
    "Both prevent unauthorized access to unattended sessions"
  ],
  "implementation_notes": "Both require configurable timeout period, typically 15 minutes or less"
}
```

### 4. Framework Inheritance Patterns

**SRG → STIG Hierarchy**: Handles framework inheritance relationships
```python
# Framework hierarchies
{
    "srg_os": {
        "parent": None,
        "children": ["stig_rhel8", "stig_rhel9", "stig_ubuntu20", "stig_ubuntu22"]
    }
}

# Maps SRG requirements to STIG implementations
SRG-OS-000001-GPOS-00001 (General Requirement)
    ↓ implements  
RHEL-09-412010 (RHEL 9 Implementation)
    ↓ maps to
NIST AC-11, CIS 5.2, ISO A.9.1
```

**Framework Affinity Scoring**: Predefined relationship strengths
```python
framework_affinities = {
    ("nist_800_53_r5", "iso_27001_2022"): 0.85,  # High affinity
    ("cis_v8", "nist_800_53_r5"): 0.75,          # Medium-high affinity
    ("srg_os", "nist_800_53_r5"): 0.90,          # Very high affinity (derivation)
}
```

### 5. Unified Implementation Generation

**Multi-Framework Implementations**: Single implementation satisfying multiple frameworks
```python
implementation = await engine.generate_unified_implementation(
    "session timeout", 
    ["nist_800_53_r5", "cis_v8", "iso_27001_2022"], 
    Platform.RHEL_9, 
    unified_rules
)

# Results in comprehensive implementation
{
    "implementation_id": "unified_session_timeout_001",
    "frameworks_satisfied": ["nist_800_53_r5", "cis_v8", "iso_27001_2022"],
    "control_mappings": {
        "nist_800_53_r5": ["AC-11"],
        "cis_v8": ["5.2"],
        "iso_27001_2022": ["A.9.1"]
    },
    "exceeds_frameworks": ["cis_v8"],
    "compliance_justification": "15-minute timeout meets NIST/ISO and exceeds CIS requirements",
    "effort_estimate": "Low"
}
```

### 6. Coverage Analysis and Gap Identification

**Comprehensive Coverage Assessment**:
```python
coverage = await engine.get_framework_coverage_analysis(
    ["nist_800_53_r5", "cis_v8", "iso_27001_2022"], 
    unified_rules
)

# Results in detailed coverage metrics
{
    "frameworks_analyzed": ["nist_800_53_r5", "cis_v8", "iso_27001_2022"],
    "framework_details": {
        "nist_800_53_r5": {
            "total_controls": 45,
            "total_rules": 42,
            "coverage_percentage": 93.3
        },
        "cis_v8": {
            "total_controls": 18,
            "total_rules": 17,
            "coverage_percentage": 94.4
        }
    },
    "coverage_gaps": [
        {
            "framework": "iso_27001_2022",
            "gap_percentage": 15.0,
            "missing_controls": 3
        }
    ],
    "optimization_opportunities": [
        {
            "type": "high_overlap_consolidation",
            "description": "High overlap between 2 framework pairs"
        }
    ]
}
```

## Intelligent Features

### 1. Exceeding Compliance Detection

**Automatic Enhancement Identification**:
```python
# Detects when implementations exceed baseline requirements
exceeding_patterns = [
    {
        "pattern": "fips_exceeds_cis_crypto",
        "description": "FIPS cryptography mode exceeds CIS SHA1 prohibition requirements",
        "frameworks_involved": ["stig_rhel9", "cis_v8"],
        "enhancement": "FIPS mode automatically disables weak algorithms including SHA1",
        "business_value": "Enhanced security posture beyond baseline requirements"
    }
]

# Implementation synergies identify these automatically
synergies = [
    "Exceeding compliance opportunity: cis_v8 has 5 rules that exceed baseline requirements"
]
```

### 2. Conflict Detection

**Systematic Conflict Identification**:
```python
conflicts = [
    "Mapping uncertainty: 8 control mappings have low confidence and may require manual review",
    "Implementation conflicts: 3 rules have conflicting implementation statuses across frameworks"
]
```

### 3. Optimization Recommendations

**Framework Portfolio Optimization**:
- **High Overlap Consolidation**: Frameworks with >70% overlap for unified implementation
- **Coverage Gap Prioritization**: Frameworks with <80% rule coverage for enhancement
- **Synergy Exploitation**: Implementation patterns that satisfy multiple frameworks

## Usage Examples

### Basic Framework Mapping Discovery
```python
from backend.app.services.framework_mapping_engine import FrameworkMappingEngine

engine = FrameworkMappingEngine()

# Load predefined mappings
await engine.load_predefined_mappings("predefined_mappings.json")

# Discover new mappings from unified rules
mappings = await engine.discover_control_mappings(
    "nist_800_53_r5", "cis_v8", unified_rules
)

print(f"Discovered {len(mappings)} control mappings")
for mapping in mappings[:5]:  # Show first 5
    print(f"{mapping.source_control} -> {mapping.target_control} "
          f"({mapping.confidence.value})")
```

### Framework Relationship Analysis
```python
# Analyze relationship between frameworks
relationship = await engine.analyze_framework_relationship(
    "nist_800_53_r5", "iso_27001_2022", unified_rules
)

print(f"Relationship: {relationship.relationship_type}")
print(f"Overlap: {relationship.overlap_percentage:.1f}%")
print(f"Strength: {relationship.strength:.2f}")

# Show implementation synergies
for synergy in relationship.implementation_synergies:
    print(f"✅ {synergy}")

# Show conflict areas
for conflict in relationship.conflict_areas:
    print(f"⚠️ {conflict}")
```

### Multi-Framework Coverage Analysis
```python
# Analyze coverage across framework portfolio
frameworks = ["nist_800_53_r5", "cis_v8", "iso_27001_2022", "pci_dss_v4"]
coverage = await engine.get_framework_coverage_analysis(frameworks, unified_rules)

print("Framework Coverage Analysis:")
for framework in frameworks:
    details = coverage["framework_details"][framework]
    print(f"{framework:20} {details['coverage_percentage']:6.1f}% "
          f"({details['total_rules']}/{details['total_controls']})")

# Show optimization opportunities
for opportunity in coverage["optimization_opportunities"]:
    print(f"💡 {opportunity['description']}")
```

### Unified Implementation Generation
```python
# Generate implementation for session management across multiple frameworks
implementation = await engine.generate_unified_implementation(
    "session management",
    ["nist_800_53_r5", "cis_v8", "pci_dss_v4"],
    Platform.RHEL_9,
    unified_rules
)

print(f"Implementation: {implementation.implementation_id}")
print(f"Satisfies: {', '.join(implementation.frameworks_satisfied)}")
print(f"Exceeds: {', '.join(implementation.exceeds_frameworks)}")
print(f"Effort: {implementation.effort_estimate}")

# Show control mappings
for framework, controls in implementation.control_mappings.items():
    print(f"{framework}: {', '.join(controls)}")
```

### Exceeding Compliance Analysis
```python
# Find frameworks where implementations exceed requirements
for relationship in all_relationships:
    exceeding_synergies = [
        s for s in relationship.implementation_synergies 
        if "exceeding compliance" in s.lower()
    ]
    
    if exceeding_synergies:
        print(f"{relationship.framework_a} ↔ {relationship.framework_b}:")
        for synergy in exceeding_synergies:
            print(f"  🚀 {synergy}")
```

## CLI Tool Usage

The Framework Mapping Engine includes a comprehensive CLI tool for operational use:

### Load Predefined Mappings
```bash
python -m backend.app.cli.framework_mapping load-mappings \
  --mappings-file predefined_mappings.json \
  --verbose
```

### Discover Framework Mappings
```bash
python -m backend.app.cli.framework_mapping discover \
  --source-framework nist_800_53_r5 \
  --target-framework cis_v8 \
  --rules-directory backend/app/data/unified_rules \
  --export --output nist_cis_mappings.json
```

### Analyze Framework Relationships
```bash
python -m backend.app.cli.framework_mapping analyze \
  --frameworks nist_800_53_r5 cis_v8 iso_27001_2022 pci_dss_v4 \
  --rules-directory backend/app/data/unified_rules \
  --coverage-analysis \
  --load-predefined \
  --verbose \
  --export --output framework_analysis.json
```

### Generate Unified Implementation
```bash
python -m backend.app.cli.framework_mapping implement \
  --objective "cryptographic controls" \
  --frameworks nist_800_53_r5 cis_v8 stig_rhel9 \
  --platform rhel_9 \
  --rules-directory backend/app/data/unified_rules \
  --verbose --export --output crypto_implementation.json
```

### Export Mapping Data
```bash
# Export as JSON
python -m backend.app.cli.framework_mapping export \
  --format json --output all_mappings.json

# Export as CSV for spreadsheet analysis
python -m backend.app.cli.framework_mapping export \
  --format csv --output mappings_summary.csv
```

## Integration Points

### Web Dashboard Integration
```python
# Generate mapping data for dashboard visualization
@app.get("/api/framework-mappings/{source}/{target}")
async def get_framework_mappings(source: str, target: str):
    mappings = await engine.discover_control_mappings(source, target, unified_rules)
    return {
        "source_framework": source,
        "target_framework": target,
        "mappings": [mapping.dict() for mapping in mappings],
        "total_mappings": len(mappings)
    }

# Framework relationship endpoint
@app.get("/api/framework-relationships")
async def get_framework_relationships():
    relationships = []
    for (fw_a, fw_b), relationship in engine.framework_relationships.items():
        relationships.append(relationship.dict())
    return {"relationships": relationships}
```

### Compliance Orchestration
```python
# Use mappings for unified compliance scanning
async def scan_with_unified_implementation(
    implementation: UnifiedImplementation,
    target_hosts: List[str]
):
    scan_results = []
    
    for framework in implementation.frameworks_satisfied:
        framework_scan = await execute_framework_scan(
            framework, 
            implementation.control_mappings[framework],
            target_hosts
        )
        scan_results.append(framework_scan)
    
    return aggregate_unified_results(scan_results, implementation)
```

### GRC Platform Integration
```python
# Export for external governance platforms
def export_for_grc_platform(frameworks: List[str]) -> Dict:
    return {
        "framework_mappings": engine.control_mappings,
        "relationship_matrix": {
            f"{rel.framework_a}_{rel.framework_b}": {
                "overlap_percentage": rel.overlap_percentage,
                "relationship_type": rel.relationship_type,
                "common_controls": rel.common_controls
            }
            for rel in engine.framework_relationships.values()
        },
        "coverage_summary": coverage_analysis
    }
```

## Performance Features

### Intelligent Caching
- **Relationship caching**: Framework relationships cached for rapid retrieval
- **Mapping discovery optimization**: Efficient algorithms for large rule sets
- **Coverage analysis caching**: Complex calculations cached for dashboard performance

### Scalability Features
- **Parallel analysis**: Framework pairs analyzed concurrently
- **Incremental discovery**: New mappings discovered without full recomputation
- **Memory optimization**: Large rule sets processed efficiently

## Configuration and Customization

### Framework Affinity Tuning
```python
# Customize framework relationship strengths
engine.framework_affinities[("custom_framework", "nist_800_53_r5")] = 0.8

# Add custom framework hierarchies
engine.framework_hierarchies["custom_parent"] = {
    "parent": None,
    "children": ["custom_child_1", "custom_child_2"]
}
```

### Confidence Threshold Adjustment
```python
# Adjust confidence calculation parameters
async def custom_analyze_mapping_characteristics(self, ...):
    # Custom confidence calculation logic
    if shared_count >= custom_threshold:
        confidence = MappingConfidence.HIGH
    # ... custom logic
```

### Custom Mapping Types
```python
# Extend mapping types for organization-specific needs
class CustomMappingType(str, Enum):
    REGULATORY_ALIGNMENT = "regulatory_alignment"
    INDUSTRY_SPECIFIC = "industry_specific"
    # ... custom types
```

## Business Value

### Compliance Efficiency
- **Unified mapping**: Single source of truth for cross-framework relationships
- **Automated discovery**: Reduces manual mapping effort by 80-90%
- **Confidence scoring**: Prioritizes high-confidence mappings for implementation

### Risk Management
- **Gap identification**: Systematic identification of coverage gaps
- **Conflict detection**: Early warning of implementation conflicts
- **Exceeding compliance tracking**: Leverage stronger implementations for multiple frameworks

### Strategic Planning
- **Framework portfolio optimization**: Data-driven framework selection
- **Implementation synergy identification**: Maximize compliance ROI
- **Coverage analysis**: Strategic gap filling for comprehensive compliance

### Audit Readiness
- **Comprehensive mapping documentation**: Complete audit trail of control relationships
- **Evidence-based justification**: Supporting evidence for all mapping decisions
- **Implementation traceability**: Clear path from requirements to implementation

## Future Enhancements

### Advanced Analytics
- Machine learning-based mapping confidence prediction
- Natural language processing for automated mapping discovery
- Anomaly detection for unusual framework relationships

### Extended Framework Support
- Additional compliance frameworks (SOX, GDPR, CCPA)
- Industry-specific frameworks (NERC CIP, HIPAA, FedRAMP)
- Custom organizational frameworks

### Visualization Enhancements
- Interactive framework relationship graphs
- Heat maps for control overlap visualization
- Timeline visualization for framework evolution

The Framework Mapping Engine represents a significant advancement in compliance management, providing organizations with the intelligence needed to navigate complex multi-framework environments efficiently and effectively.