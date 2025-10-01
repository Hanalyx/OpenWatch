# Result Aggregation Service

The Result Aggregation Service provides comprehensive analysis and aggregation capabilities for compliance scan results across multiple frameworks, hosts, and time periods.

## Overview

This service transforms raw scan results into actionable intelligence through:
- Multi-level aggregation (organization, framework, host, time-series)
- Compliance gap analysis and systematic failure detection
- Framework comparison and overlap analysis
- Trend analysis and performance metrics
- Dashboard data generation and export capabilities

## Core Components

### Aggregation Levels

```python
class AggregationLevel(str, Enum):
    RULE_LEVEL = "rule_level"              # Individual rule analysis
    FRAMEWORK_LEVEL = "framework_level"    # Framework-specific metrics
    HOST_LEVEL = "host_level"              # Host-specific compliance
    ORGANIZATION_LEVEL = "organization_level"  # Organization-wide view
    TIME_SERIES = "time_series"            # Historical trend analysis
```

### Data Models

#### ComplianceMetrics
Comprehensive compliance metrics with automatic percentage calculations:
```python
@dataclass
class ComplianceMetrics:
    total_rules: int
    executed_rules: int
    compliant_rules: int
    non_compliant_rules: int
    error_rules: int
    exceeds_rules: int                    # Rules that exceed baseline requirements
    partial_rules: int
    not_applicable_rules: int
    compliance_percentage: float          # Auto-calculated: (compliant + exceeds) / executed
    exceeds_percentage: float             # Auto-calculated: exceeds / executed
    error_percentage: float               # Auto-calculated: errors / executed
    execution_success_rate: float         # Auto-calculated: (executed - errors) / executed
```

#### TrendAnalysis
Trend detection with automatic direction calculation:
```python
@dataclass
class TrendAnalysis:
    metric_name: str
    current_value: float
    previous_value: Optional[float]
    trend_direction: TrendDirection       # Auto-calculated: IMPROVING/DECLINING/STABLE
    change_percentage: Optional[float]    # Auto-calculated percentage change
    time_period: str
    data_points: List[Tuple[datetime, float]]
```

#### ComplianceGap
Systematic failure identification:
```python
@dataclass
class ComplianceGap:
    gap_id: str                          # GAP-001, GAP-002, etc.
    gap_type: str                        # "systematic_failure", etc.
    severity: str                        # "critical", "high", "medium", "low"
    framework_id: str
    control_ids: List[str]
    affected_hosts: List[str]
    description: str
    impact_assessment: str
    remediation_priority: int            # 1=highest, 4=lowest
    estimated_effort: str
    remediation_guidance: List[str]
```

## Key Features

### 1. Multi-Level Aggregation

**Organization Level**: Complete organizational compliance view
```python
# Aggregates across all hosts and frameworks
aggregated = await service.aggregate_scan_results(
    scan_results, AggregationLevel.ORGANIZATION_LEVEL
)

# Provides:
# - Overall compliance percentage across all frameworks
# - Platform distribution (RHEL 9: 15 hosts, Ubuntu 22.04: 8 hosts)
# - Framework breakdown with individual compliance rates
# - Host-level metrics for detailed analysis
```

**Framework Level**: Framework-specific analysis
```python
# Groups by framework for targeted compliance assessment
aggregated = await service.aggregate_scan_results(
    scan_results, AggregationLevel.FRAMEWORK_LEVEL
)

# Provides:
# - Individual framework compliance rates
# - Framework-specific rule execution statistics
# - Cross-framework comparison opportunities
```

**Host Level**: Host-specific compliance tracking
```python
# Analyzes compliance at individual host level
aggregated = await service.aggregate_scan_results(
    scan_results, AggregationLevel.HOST_LEVEL
)

# Provides:
# - Per-host compliance percentages
# - Host-specific failure patterns
# - Infrastructure compliance distribution
```

**Time Series**: Historical trend analysis
```python
# Tracks compliance trends over time
aggregated = await service.aggregate_scan_results(
    scan_results, AggregationLevel.TIME_SERIES
)

# Provides:
# - Compliance improvement/decline trends
# - Historical data points for visualization
# - Change percentage calculations
```

### 2. Compliance Gap Analysis

Automatically identifies systematic failures across multiple hosts:

```python
# Example gap identification
{
    "gap_id": "GAP-001",
    "gap_type": "systematic_failure",
    "severity": "high",
    "framework_id": "nist_800_53_r5",
    "control_ids": ["AC-11"],
    "affected_hosts": ["host_001", "host_002", "host_003"],
    "description": "Session timeout not configured correctly across 3 hosts (75% failure rate)",
    "remediation_priority": 2,
    "remediation_guidance": [
        "Review baseline configuration across affected hosts",
        "Implement automated remediation for common failure pattern",
        "Update configuration management to prevent recurrence"
    ]
}
```

**Severity Classification**:
- **Critical**: ≥75% failure rate across hosts
- **High**: ≥50% failure rate
- **Medium**: ≥25% failure rate  
- **Low**: <25% failure rate

### 3. Framework Comparison Engine

Analyzes relationships between compliance frameworks:

```python
# Example framework comparison
{
    "framework_a": "nist_800_53_r5",
    "framework_b": "cis_v8",
    "common_controls": 25,
    "framework_a_unique": 30,
    "framework_b_unique": 15,
    "overlap_percentage": 71.4,          # 25/(25+30+15) * 100
    "compliance_correlation": 0.85,      # Statistical correlation
    "implementation_gaps": []
}
```

### 4. Intelligent Recommendations

**Priority Recommendations** (Immediate Action Required):
- Critical compliance gaps affecting multiple hosts
- Frameworks below 70% compliance threshold
- Infrastructure reliability issues (success rate <95%)

**Strategic Recommendations** (Long-term Planning):
- Opportunities to leverage exceeding compliance
- Platform standardization suggestions
- Advanced security measures for high-performing frameworks

### 5. Dashboard Data Generation

Optimized data structure for web dashboards:

```python
dashboard_data = await service.generate_compliance_dashboard_data(scan_results)

# Provides structured data for:
# - Overview metrics widget
# - Framework breakdown charts
# - Platform distribution pie charts
# - Top compliance gaps table
# - Priority/strategic recommendations
# - Performance metrics graphs
```

### 6. Export Capabilities

**JSON Export**: Complete detailed results
```python
json_data = await service.export_aggregated_results(aggregated, 'json')
# Includes all metrics, gaps, comparisons, and recommendations
```

**CSV Export**: Summary metrics for spreadsheet analysis
```python
csv_data = await service.export_aggregated_results(aggregated, 'csv')
# Framework,Compliance_Percentage,Total_Rules,Compliant_Rules,Non_Compliant_Rules,Exceeds_Rules
# nist_800_53_r5,85.50,100,80,15,5
```

## Usage Examples

### Basic Organization Analysis
```python
from backend.app.services.result_aggregation_service import ResultAggregationService, AggregationLevel

service = ResultAggregationService()

# Analyze organization-wide compliance
results = await service.aggregate_scan_results(
    scan_results, 
    AggregationLevel.ORGANIZATION_LEVEL,
    time_period="Q3 2024"
)

print(f"Overall compliance: {results.overall_metrics.compliance_percentage:.1f}%")
print(f"Frameworks analyzed: {len(results.framework_metrics)}")
print(f"Hosts scanned: {len(results.host_metrics)}")
print(f"Compliance gaps found: {len(results.compliance_gaps)}")
```

### Trend Analysis
```python
# Historical compliance tracking
historical_results = await service.aggregate_scan_results(
    historical_scans,
    AggregationLevel.TIME_SERIES,
    time_period="Last 6 months"
)

for trend in historical_results.trend_analysis:
    if trend.trend_direction == TrendDirection.IMPROVING:
        print(f"✅ {trend.metric_name}: {trend.change_percentage:+.1f}% improvement")
    elif trend.trend_direction == TrendDirection.DECLINING:
        print(f"⚠️ {trend.metric_name}: {trend.change_percentage:+.1f}% decline")
```

### Gap Remediation Prioritization
```python
# Prioritize compliance gaps by severity and impact
critical_gaps = [gap for gap in results.compliance_gaps if gap.severity == "critical"]
high_gaps = [gap for gap in results.compliance_gaps if gap.severity == "high"]

print(f"Critical gaps requiring immediate attention: {len(critical_gaps)}")
for gap in sorted(critical_gaps, key=lambda g: g.remediation_priority):
    print(f"  {gap.gap_id}: {gap.description}")
    print(f"    Affected: {len(gap.affected_hosts)} hosts")
    print(f"    Framework: {gap.framework_id}")
```

### Framework Overlap Analysis
```python
# Identify framework overlaps for optimization
for comparison in results.framework_comparisons:
    if comparison.overlap_percentage > 70:
        print(f"High overlap: {comparison.framework_a} ↔ {comparison.framework_b}")
        print(f"  Common controls: {comparison.common_controls}")
        print(f"  Overlap: {comparison.overlap_percentage:.1f}%")
        print(f"  Compliance correlation: {comparison.compliance_correlation:.2f}")
```

### Exceeding Compliance Detection
```python
# Identify opportunities for enhanced compliance reporting
exceeding_frameworks = {
    fw_id: metrics for fw_id, metrics in results.framework_metrics.items()
    if metrics.exceeds_rules > 0
}

for framework_id, metrics in exceeding_frameworks.items():
    print(f"{framework_id}: {metrics.exceeds_rules} rules exceed baseline")
    print(f"  Exceeding percentage: {metrics.exceeds_percentage:.1f}%")
```

## CLI Tool Usage

The service includes a comprehensive CLI tool for operational use:

### Analyze Scan Results
```bash
# Basic analysis
python -m backend.app.cli.result_analysis analyze \
  --scan-files scan1.json scan2.json scan3.json

# Framework-level analysis with export
python -m backend.app.cli.result_analysis analyze \
  --scan-files *.json \
  --level framework_level \
  --show-strategic \
  --show-comparisons \
  --export \
  --export-format json \
  --output compliance_report.json
```

### Generate Dashboard Data
```bash
python -m backend.app.cli.result_analysis dashboard \
  --scan-files recent_scans/*.json \
  --output dashboard.json
```

### Trend Analysis
```bash
python -m backend.app.cli.result_analysis trends \
  --scan-files historical/*.json \
  --time-period "30 days" \
  --show-data-points
```

## Performance Features

### Caching
- **Automatic caching**: Results cached for 1 hour based on scan content hash
- **Cache management**: `clear_cache()` method for manual cache clearing
- **Cache efficiency**: Reduces computation time for repeated analyses

### Indexing Strategy
- **Framework indexes**: Fast framework-specific queries
- **Host indexes**: Efficient host-level aggregation
- **Time indexes**: Optimized historical analysis

### Memory Optimization
- **Streaming aggregation**: Processes large result sets efficiently
- **Lazy evaluation**: Calculations performed only when needed
- **Garbage collection**: Automatic cleanup of intermediate results

## Integration Points

### Web Dashboard
```python
# Generate data for React dashboard components
dashboard_data = await service.generate_compliance_dashboard_data(scan_results)

# Use in dashboard API endpoints
@app.get("/api/compliance/dashboard")
async def get_dashboard_data():
    return dashboard_data
```

### Reporting Systems
```python
# Export for external reporting tools
csv_report = await service.export_aggregated_results(results, 'csv')
json_report = await service.export_aggregated_results(results, 'json')

# Integration with GRC platforms
compliance_summary = {
    'overall_compliance': results.overall_metrics.compliance_percentage,
    'framework_status': results.framework_metrics,
    'critical_gaps': [gap for gap in results.compliance_gaps if gap.severity == 'critical']
}
```

### Alerting Systems
```python
# Monitor compliance thresholds
if results.overall_metrics.compliance_percentage < 70:
    send_compliance_alert(results.priority_recommendations)

# Track trend degradation
for trend in results.trend_analysis:
    if trend.trend_direction == TrendDirection.DECLINING and trend.change_percentage < -5:
        send_trend_alert(trend)
```

## Configuration

### Service Configuration
```python
service = ResultAggregationService()
service.cache_ttl = 7200  # 2 hours cache TTL
```

### Aggregation Customization
```python
# Custom time period analysis
custom_results = await service.aggregate_scan_results(
    scan_results,
    AggregationLevel.ORGANIZATION_LEVEL,
    time_period="Post-remediation analysis"
)

# Framework-specific analysis
nist_only_results = [sr for sr in scan_results if has_nist_framework(sr)]
nist_analysis = await service.aggregate_scan_results(
    nist_only_results,
    AggregationLevel.FRAMEWORK_LEVEL
)
```

## Business Value

### Operational Efficiency
- **Unified reporting**: Single service for all compliance reporting needs
- **Automated analysis**: Reduces manual compliance assessment effort
- **Prioritized remediation**: Focus resources on highest-impact gaps

### Risk Management
- **Systematic failure detection**: Identifies infrastructure-wide compliance issues
- **Trend monitoring**: Early warning system for compliance degradation
- **Cross-framework intelligence**: Optimizes compliance investments

### Audit Readiness
- **Comprehensive documentation**: Detailed justification for all compliance statuses
- **Historical tracking**: Complete audit trail of compliance evolution
- **Framework mapping**: Clear relationships between different compliance requirements

### Strategic Planning
- **Exceeding compliance opportunities**: Leverage stronger implementations
- **Framework optimization**: Identify redundancies and synergies
- **Resource allocation**: Data-driven compliance investment decisions

## Future Enhancements

### Advanced Analytics
- Machine learning-based compliance prediction
- Anomaly detection for unusual compliance patterns
- Automated root cause analysis for systematic failures

### Integration Expansion
- Direct integration with SIEM systems for real-time alerting
- API endpoints for third-party GRC platform integration
- Automated report generation and distribution

### Visualization Enhancements
- Interactive compliance trend charts
- Heat maps for multi-dimensional compliance analysis
- Drill-down capabilities from organization to individual rule level