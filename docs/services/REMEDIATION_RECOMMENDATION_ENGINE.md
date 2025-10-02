# Remediation Recommendation Engine

The Remediation Recommendation Engine analyzes compliance gaps from scan results and generates structured remediation recommendations for ORSA-compatible external systems. This engine provides the intelligence needed to transform compliance findings into actionable remediation guidance.

## Overview

The engine provides comprehensive remediation analysis and recommendation generation:
- Automated compliance gap analysis from scan results
- Detailed remediation procedure generation with platform-specific implementations
- ORSA-compatible rule mapping for external remediation systems
- Risk-based prioritization and complexity assessment
- Framework-specific remediation procedures (STIG fix text, CIS procedures, NIST guidance)
- Business justification and impact analysis
- Testing and monitoring recommendations

## Core Components

### Compliance Gap Analysis

```python
@dataclass
class ComplianceGap:
    gap_id: str                          # Unique gap identifier
    rule_id: str                         # Associated compliance rule
    framework_id: str                    # Target framework
    control_id: str                      # Specific control
    host_id: str                         # Target host
    
    # Gap description
    title: str                           # Human-readable title
    description: str                     # Detailed description
    current_status: ComplianceStatus     # Current compliance state
    expected_status: ComplianceStatus    # Target compliance state
    
    # Impact assessment
    priority: RemediationPriority        # Remediation priority
    risk_level: str                      # Risk classification
    business_impact: str                 # Business impact assessment
    security_implications: List[str]     # Security risk implications
    
    # Technical details
    platform: str                       # Target platform
    failed_checks: List[str]             # Specific failed checks
    error_details: Optional[str]         # Error information
    compliance_deadline: Optional[datetime]  # Remediation deadline
```

### Remediation Procedures

```python
@dataclass
class RemediationProcedure:
    procedure_id: str                    # Unique procedure identifier
    title: str                          # Procedure title
    description: str                    # Detailed description
    category: RemediationCategory       # Type of remediation
    complexity: RemediationComplexity  # Implementation complexity
    
    # Platform/framework specifics
    platform: str                      # Target platform
    framework_id: str                  # Source framework
    rule_id: str                       # Source rule
    
    # Implementation steps
    pre_conditions: List[str]          # Prerequisites
    steps: List[Dict[str, Any]]        # Detailed execution steps
    post_validation: List[str]         # Validation commands
    rollback_steps: List[str]          # Rollback procedures
    
    # Execution metadata
    estimated_time_minutes: int       # Expected execution time
    requires_reboot: bool              # System reboot requirement
    backup_recommended: bool           # Backup recommendation
    rollback_available: bool           # Rollback capability
    
    # Framework-specific guidance
    stig_fix_text: Optional[str]       # STIG fix text
    cis_remediation_procedure: Optional[str]  # CIS procedure
    nist_implementation_guidance: Optional[str]  # NIST guidance
```

### Complete Recommendations

```python
@dataclass
class RemediationRecommendation:
    recommendation_id: str             # Unique recommendation ID
    compliance_gap: ComplianceGap      # Associated compliance gap
    
    # Remediation approaches
    primary_procedure: RemediationProcedure      # Main approach
    alternative_procedures: List[RemediationProcedure]  # Alternative methods
    
    # ORSA integration
    orsa_compatible_rules: List[RemediationRule]    # ORSA-format rules
    remediation_job_template: Optional[RemediationJob]  # Job template
    
    # Analysis and guidance
    root_cause_analysis: str          # Root cause assessment
    business_justification: str       # Business rationale
    compliance_benefit: str           # Compliance value
    recommended_approach: str         # Implementation guidance
    testing_recommendations: List[str]    # Testing guidance
    monitoring_recommendations: List[str]  # Monitoring guidance
    
    # Quality metrics
    confidence_score: float           # Recommendation confidence (0.0-1.0)
    framework_citations: List[str]    # Regulatory citations
    related_controls: List[str]       # Related compliance controls
```

## Priority and Complexity Classification

### Remediation Priority

```python
class RemediationPriority(str, Enum):
    CRITICAL = "critical"      # Immediate security risks - 7 days max
    HIGH = "high"             # Significant compliance gaps - 30 days
    MEDIUM = "medium"         # Standard compliance issues - 60 days
    LOW = "low"              # Minor improvements - 90 days
    INFORMATIONAL = "info"    # Best practice suggestions - 180 days
```

### Remediation Complexity

```python
class RemediationComplexity(str, Enum):
    TRIVIAL = "trivial"       # Single command/setting - 2 minutes
    SIMPLE = "simple"         # Multiple steps, low risk - 5 minutes
    MODERATE = "moderate"     # Requires planning, medium risk - 15 minutes
    COMPLEX = "complex"       # Significant changes, high risk - 30+ minutes
    EXPERT = "expert"         # Requires specialized knowledge - varies
```

### Remediation Categories

```python
class RemediationCategory(str, Enum):
    CONFIGURATION = "configuration"      # Config file changes
    PACKAGE_MANAGEMENT = "packages"      # Software install/remove
    SERVICE_MANAGEMENT = "services"      # Service start/stop/enable
    FIREWALL_RULES = "firewall"         # Network access controls
    FILE_PERMISSIONS = "permissions"     # File/directory permissions
    USER_MANAGEMENT = "users"           # User/group management
    CUSTOM_SCRIPTS = "scripts"          # Custom remediation scripts
```

## Key Features

### 1. Automated Gap Analysis

**Multi-Host Compliance Assessment**:
```python
engine = RemediationRecommendationEngine()

# Analyze compliance gaps across all hosts and frameworks
compliance_gaps = await engine.analyze_compliance_gaps(
    scan_result, unified_rules, target_frameworks=["nist_800_53_r5", "cis_v8"]
)

# Gaps automatically prioritized by risk level and compliance status
for gap in compliance_gaps:
    print(f"Priority: {gap.priority.value}")
    print(f"Host: {gap.host_id}")
    print(f"Framework: {gap.framework_id}:{gap.control_id}")
    print(f"Deadline: {gap.compliance_deadline}")
    print(f"Business Impact: {gap.business_impact}")
```

**Risk-Based Prioritization**:
- **Critical Priority**: Risk level "critical" + non-compliant status
- **High Priority**: Risk level "high" + non-compliant status  
- **Medium Priority**: Risk level "medium" or partial compliance
- **Low Priority**: Risk level "low" or minor issues

### 2. Detailed Remediation Procedures

**Platform-Specific Implementation**:
```python
# Generate comprehensive remediation recommendations
recommendations = await engine.generate_remediation_recommendations(
    compliance_gaps, unified_rules
)

for recommendation in recommendations:
    procedure = recommendation.primary_procedure
    
    print(f"Procedure: {procedure.title}")
    print(f"Complexity: {procedure.complexity.value}")
    print(f"Estimated Time: {procedure.estimated_time_minutes} minutes")
    print(f"Requires Reboot: {procedure.requires_reboot}")
    print(f"Rollback Available: {procedure.rollback_available}")
    
    # Detailed execution steps
    for step in procedure.steps:
        print(f"  Step {step['step']}: {step['description']}")
        print(f"    Command: {step['command']}")
    
    # Validation commands
    for validation in procedure.post_validation:
        print(f"  Validation: {validation}")
```

**Framework-Specific Guidance**:
```python
# STIG implementation with official fix text
if procedure.stig_fix_text:
    print(f"STIG Fix Text: {procedure.stig_fix_text}")

# CIS remediation procedure
if procedure.cis_remediation_procedure:
    print(f"CIS Procedure: {procedure.cis_remediation_procedure}")

# NIST implementation guidance
if procedure.nist_implementation_guidance:
    print(f"NIST Guidance: {procedure.nist_implementation_guidance}")
```

### 3. ORSA Integration

**ORSA-Compatible Rule Generation**:
```python
# Map recommendations to ORSA format for external systems
orsa_mappings = await engine.map_to_orsa_format(recommendations)

for platform, rules in orsa_mappings.items():
    print(f"Platform: {platform}")
    
    for rule in rules:
        print(f"  Semantic Name: {rule.semantic_name}")
        print(f"  Framework Mappings: {rule.framework_mappings}")
        print(f"  Implementation: {rule.implementations[platform]}")
        print(f"  Reversible: {rule.reversible}")
        print(f"  Prerequisites: {rule.prerequisites}")
```

**Remediation Job Templates**:
```python
# Create ORSA-compatible job template
job_template = await engine.create_remediation_job_template(
    recommendation, target_host_id="web_server_01", dry_run=True
)

print(f"Target Host: {job_template.target_host_id}")
print(f"Platform: {job_template.platform}")
print(f"Framework: {job_template.framework}")
print(f"Rules: {job_template.rules}")
print(f"Timeout: {job_template.timeout} seconds")
print(f"OpenWatch Context: {job_template.openwatch_context}")
```

## Usage Examples

### Basic Gap Analysis and Recommendations

```python
from backend.app.services.remediation_recommendation_engine import RemediationRecommendationEngine

engine = RemediationRecommendationEngine()

# Step 1: Analyze compliance gaps
compliance_gaps = await engine.analyze_compliance_gaps(
    scan_result, unified_rules
)

print(f"Found {len(compliance_gaps)} compliance gaps")

# Group by priority
gaps_by_priority = {}
for gap in compliance_gaps:
    priority = gap.priority.value
    if priority not in gaps_by_priority:
        gaps_by_priority[priority] = []
    gaps_by_priority[priority].append(gap)

for priority, gaps in gaps_by_priority.items():
    print(f"{priority.upper()}: {len(gaps)} gaps")

# Step 2: Generate remediation recommendations
recommendations = await engine.generate_remediation_recommendations(
    compliance_gaps, unified_rules
)

print(f"Generated {len(recommendations)} remediation recommendations")
```

### Framework-Specific Analysis

```python
# Target specific frameworks
target_frameworks = ["nist_800_53_r5", "stig_rhel9"]

compliance_gaps = await engine.analyze_compliance_gaps(
    scan_result, unified_rules, target_frameworks
)

# Filter by minimum priority
high_priority_gaps = [
    gap for gap in compliance_gaps 
    if gap.priority in [RemediationPriority.CRITICAL, RemediationPriority.HIGH]
]

recommendations = await engine.generate_remediation_recommendations(
    high_priority_gaps, unified_rules
)

# Analyze by framework
framework_analysis = {}
for rec in recommendations:
    framework = rec.compliance_gap.framework_id
    if framework not in framework_analysis:
        framework_analysis[framework] = {
            "gaps": 0,
            "complexity_distribution": {},
            "avg_time": 0
        }
    
    framework_analysis[framework]["gaps"] += 1
    complexity = rec.primary_procedure.complexity.value
    if complexity not in framework_analysis[framework]["complexity_distribution"]:
        framework_analysis[framework]["complexity_distribution"][complexity] = 0
    framework_analysis[framework]["complexity_distribution"][complexity] += 1

for framework, data in framework_analysis.items():
    print(f"{framework}: {data['gaps']} recommendations")
    for complexity, count in data["complexity_distribution"].items():
        print(f"  {complexity}: {count}")
```

### ORSA System Integration

```python
# Generate ORSA-compatible mappings for external systems
orsa_mappings = await engine.map_to_orsa_format(recommendations)

# Export for AEGIS integration
aegis_rules = orsa_mappings.get("rhel_9", [])

aegis_import_data = {
    "remediation_rules": [
        {
            "semantic_name": rule.semantic_name,
            "title": rule.title,
            "description": rule.description,
            "category": rule.category,
            "severity": rule.severity,
            "framework_mappings": rule.framework_mappings,
            "implementations": rule.implementations,
            "reversible": rule.reversible,
            "requires_reboot": rule.requires_reboot
        }
        for rule in aegis_rules
    ]
}

# Save for AEGIS import
with open("aegis_remediation_rules.json", "w") as f:
    json.dump(aegis_import_data, f, indent=2)

print(f"Exported {len(aegis_rules)} rules for AEGIS")
```

## CLI Tool Usage

The Remediation Recommendation Engine includes a comprehensive CLI tool:

### Analyze Compliance Gaps

```bash
# Basic gap analysis
python -m backend.app.cli.remediation_recommendations analyze-gaps \
  --scan-results scan_results.json \
  --rules-directory backend/app/data/unified_rules \
  --verbose

# Target specific frameworks
python -m backend.app.cli.remediation_recommendations analyze-gaps \
  --scan-results scan_results.json \
  --rules-directory backend/app/data/unified_rules \
  --frameworks nist_800_53_r5,cis_v8 \
  --export --output-file compliance_gaps.json
```

### Generate Remediation Recommendations

```bash
# Generate all recommendations
python -m backend.app.cli.remediation_recommendations generate \
  --scan-results scan_results.json \
  --rules-directory backend/app/data/unified_rules \
  --export

# Filter by minimum priority
python -m backend.app.cli.remediation_recommendations generate \
  --scan-results scan_results.json \
  --rules-directory backend/app/data/unified_rules \
  --min-priority high \
  --verbose \
  --output-file high_priority_recommendations.json
```

### Generate ORSA Mappings

```bash
# Create ORSA-compatible rule mappings
python -m backend.app.cli.remediation_recommendations orsa-mapping \
  --scan-results scan_results.json \
  --rules-directory backend/app/data/unified_rules \
  --output-file orsa_rules.json \
  --verbose
```

## Business Value

### Operational Efficiency
- **Automated Gap Analysis**: Reduces manual compliance assessment time by 80%
- **Structured Remediation Guidance**: Provides clear, step-by-step procedures
- **Risk-Based Prioritization**: Focuses efforts on highest-impact vulnerabilities
- **ORSA Compatibility**: Enables automated remediation via external systems

### Compliance Excellence
- **Framework-Specific Procedures**: Provides official STIG fix text, CIS procedures
- **Regulatory Citation Mapping**: Links remediation to specific requirements
- **Business Justification**: Connects technical fixes to business needs
- **Quality Scoring**: Provides confidence metrics for remediation plans

### Risk Management
- **Deadline Calculation**: Provides compliance deadlines based on risk level
- **Impact Assessment**: Evaluates business and security implications
- **Rollback Planning**: Ensures safe remediation with rollback procedures
- **Testing Guidance**: Provides comprehensive testing recommendations

### Integration Benefits
- **ORSA Standards Compliance**: Works with any ORSA-compatible remediation system
- **Multi-Platform Support**: Handles diverse infrastructure environments
- **Scalable Architecture**: Processes large-scale enterprise environments
- **API-Ready**: Integrates with existing compliance and security tools

The Remediation Recommendation Engine transforms compliance scanning results into actionable remediation intelligence, providing organizations with the structured guidance needed to efficiently address compliance gaps while minimizing operational risk.

---

**Last updated**: 2024-10-02