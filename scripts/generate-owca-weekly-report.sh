#!/bin/bash
#
# OWCA Migration Weekly Report Generator
#
# Purpose: Generate comprehensive weekly report on OWCA migration progress
#
# Usage:
#   ./scripts/generate-owca-weekly-report.sh                  # Console output
#   ./scripts/generate-owca-weekly-report.sh > report.txt     # Save to file
#   ./scripts/generate-owca-weekly-report.sh --email          # Format for email
#
# Recommended Schedule:
#   - Run weekly during Phase 3 transition period
#   - Add to cron: 0 9 * * MON /path/to/generate-owca-weekly-report.sh
#
# Related: docs/OWCA_EXTRACTION_LAYER_MIGRATION.md
#

set -e

# Configuration
REPORT_DATE=$(date +"%Y-%m-%d")
REPORT_TIME=$(date +"%H:%M:%S %Z")
REPORT_WEEK=$(date +"%Y-W%V")  # ISO week number

# Parse command line arguments
FORMAT="console"
if [ "$1" = "--email" ]; then
    FORMAT="email"
elif [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    echo "OWCA Migration Weekly Report Generator"
    echo ""
    echo "Usage:"
    echo "  $0              # Console output with colors"
    echo "  $0 --email      # Plain text format for email"
    echo "  $0 --help       # Show this help"
    echo ""
    echo "Example:"
    echo "  $0 > reports/owca-migration-$REPORT_DATE.txt"
    echo ""
    exit 0
fi

#
# Function: Print header
#
print_header() {
    if [ "$FORMAT" = "email" ]; then
        echo "========================================"
        echo "$1"
        echo "========================================"
    else
        echo ""
        echo "========================================"
        echo "$1"
        echo "========================================"
        echo ""
    fi
}

#
# Function: Print section
#
print_section() {
    if [ "$FORMAT" = "email" ]; then
        echo ""
        echo "--- $1 ---"
        echo ""
    else
        echo ""
        echo "--- $1 ---"
        echo ""
    fi
}

#
# Main Report Generation
#

print_header "OWCA Extraction Layer Migration - Weekly Report"

echo "Report Period: Week $REPORT_WEEK"
echo "Generated: $REPORT_DATE $REPORT_TIME"
echo ""

#
# Executive Summary
#

print_section "Executive Summary"

# Run monitoring script and capture key metrics
TEMP_REPORT=$(mktemp)
./scripts/monitor-owca-migration.sh > "$TEMP_REPORT" 2>&1

# Extract key metrics
DEPRECATED_IMPORTS=$(grep -c "WARN: Found" "$TEMP_REPORT" || echo "0")
XCCDF_PARSER_REFS=$(grep "Found.*XCCDFParser" "$TEMP_REPORT" | awk '{print $2}' || echo "0")
SEVERITY_CALC_REFS=$(grep "Found.*SeverityCalculator" "$TEMP_REPORT" | awk '{print $2}' || echo "0")
OWCA_SERVICE_REFS=$(grep "Found.*get_owca_service" "$TEMP_REPORT" | awk '{print $2}' || echo "0")

echo "Migration Status: Phase 3 (Transition Period)"
echo ""
echo "Key Metrics:"
echo "  - Deprecated imports found: $DEPRECATED_IMPORTS"
echo "  - OWCA XCCDFParser references: $XCCDF_PARSER_REFS"
echo "  - OWCA SeverityCalculator references: $SEVERITY_CALC_REFS"
echo "  - OWCA get_owca_service() calls: $OWCA_SERVICE_REFS"
echo ""

# Determine health status
if [ "$DEPRECATED_IMPORTS" -eq 0 ]; then
    echo "Health Status: HEALTHY"
    echo "  All application code successfully migrated to OWCA extraction layer."
    echo ""
else
    echo "Health Status: NEEDS ATTENTION"
    echo "  Some code still using deprecated /scoring module."
    echo "  Action Required: Migrate remaining code to OWCA extraction layer."
    echo ""
fi

#
# Phase Progress
#

print_section "Phase Progress"

echo "Phase 1 - Implementation: [COMPLETE]"
echo "  Completed: 2025-11-22"
echo "  Deliverables: XCCDFParser, SeverityCalculator, extraction layer integration"
echo ""

echo "Phase 2 - Testing & Documentation: [COMPLETE]"
echo "  Completed: 2025-11-22"
echo "  Deliverables: 28 unit tests, comprehensive migration guide"
echo ""

echo "Phase 3 - Transition Period: [IN PROGRESS]"
echo "  Started: 2025-11-23"
echo "  Target Duration: 2-4 weeks"
echo "  Current Week: Week $REPORT_WEEK"
echo "  Activities: Monitoring deprecation warnings, assisting migrations"
echo ""

echo "Phase 4 - Cleanup: [PENDING]"
echo "  Prerequisites:"
echo "    - Zero deprecated imports for 14+ consecutive days"
echo "    - All teams notified and prepared"
echo "    - Phase 3 completed"
echo ""

#
# Deprecation Warning Tracking
#

print_section "Deprecation Warning Tracking"

# Check application logs if Docker is running
if docker ps | grep -q "openwatch-backend"; then
    DEPRECATION_COUNT=$(docker logs openwatch-backend --tail 10000 2>&1 | \
        grep -ci "deprecat" || true)

    echo "Application Log Analysis (last 10000 lines):"
    echo "  Deprecation warnings found: $DEPRECATION_COUNT"
    echo ""

    if [ "$DEPRECATION_COUNT" -eq 0 ]; then
        echo "Status: PASS - No deprecation warnings detected"
        echo "Recommendation: Continue monitoring for 14 consecutive days before Phase 4"
    else
        echo "Status: WARN - Deprecation warnings detected"
        echo "Action Required: Investigate and migrate remaining deprecated usage"
        echo ""
        echo "Recent warnings:"
        docker logs openwatch-backend --tail 10000 2>&1 | \
            grep -i "deprecat" | tail -5 || echo "  (none in recent logs)"
    fi
else
    echo "Application Status: OFFLINE"
    echo "Note: Cannot check deprecation warnings (backend container not running)"
fi

echo ""

#
# Code Usage Analysis
#

print_section "Code Usage Analysis"

echo "Deprecated /scoring Module:"
SCORING_IMPORTS=$(grep -r "from backend\.app\.services\.scoring import" backend/ \
    --exclude-dir=__pycache__ \
    --exclude-dir=.pytest_cache \
    --exclude="*.pyc" \
    --exclude-dir=scoring \
    2>/dev/null | wc -l || echo "0")
echo "  Imports found: $SCORING_IMPORTS"
echo ""

echo "New OWCA Extraction Layer:"
PARSER_USAGE=$(grep -r "XCCDFParser" backend/ \
    --exclude-dir=__pycache__ \
    --exclude-dir=.pytest_cache \
    --exclude="*.pyc" \
    2>/dev/null | wc -l || echo "0")
echo "  XCCDFParser usage: $PARSER_USAGE occurrences"

CALCULATOR_USAGE=$(grep -r "SeverityCalculator" backend/ \
    --exclude-dir=__pycache__ \
    --exclude-dir=.pytest_cache \
    --exclude="*.pyc" \
    2>/dev/null | wc -l || echo "0")
echo "  SeverityCalculator usage: $CALCULATOR_USAGE occurrences"

SERVICE_USAGE=$(grep -r "get_owca_service" backend/ \
    --exclude-dir=__pycache__ \
    --exclude-dir=.pytest_cache \
    --exclude="*.pyc" \
    2>/dev/null | wc -l || echo "0")
echo "  get_owca_service() calls: $SERVICE_USAGE occurrences"
echo ""

#
# Test Coverage
#

print_section "Test Coverage"

if [ -f "backend/tests/unit/test_owca_extraction.py" ]; then
    TEST_COUNT=$(grep -c "def test_" backend/tests/unit/test_owca_extraction.py || echo "0")
    TEST_CLASSES=$(grep -c "^class Test" backend/tests/unit/test_owca_extraction.py || echo "0")
    TEST_LINES=$(wc -l < backend/tests/unit/test_owca_extraction.py)

    echo "OWCA Extraction Layer Test Suite:"
    echo "  Test file: backend/tests/unit/test_owca_extraction.py"
    echo "  Test classes: $TEST_CLASSES"
    echo "  Test functions: $TEST_COUNT"
    echo "  Total lines: $TEST_LINES"
else
    echo "WARNING: OWCA test file not found!"
fi

echo ""

#
# Action Items
#

print_section "Action Items for Next Week"

# Generate action items based on current state
if [ "$DEPRECATED_IMPORTS" -gt 0 ]; then
    echo "1. [HIGH] Migrate remaining $DEPRECATED_IMPORTS files using deprecated /scoring imports"
else
    echo "1. [DONE] All application code migrated to OWCA extraction layer"
fi

if [ "$DEPRECATION_COUNT" -gt 0 ]; then
    echo "2. [MEDIUM] Investigate $DEPRECATION_COUNT deprecation warnings in logs"
else
    echo "2. [DONE] No deprecation warnings in application logs"
fi

echo "3. [ONGOING] Continue monitoring application logs for deprecation warnings"
echo "4. [ONGOING] Run weekly migration reports"

# Calculate weeks until Phase 4
PHASE3_START_WEEK=$(date -d "2025-11-23" +%V 2>/dev/null || echo "$REPORT_WEEK")
CURRENT_WEEK=$(date +%V)
WEEKS_ELAPSED=$((CURRENT_WEEK - PHASE3_START_WEEK))

if [ "$WEEKS_ELAPSED" -ge 2 ] && [ "$DEPRECATED_IMPORTS" -eq 0 ] && [ "$DEPRECATION_COUNT" -eq 0 ]; then
    echo "5. [READY] Consider beginning Phase 4 cleanup (prerequisites met)"
else
    WEEKS_REMAINING=$((2 - WEEKS_ELAPSED))
    if [ "$WEEKS_REMAINING" -lt 0 ]; then
        WEEKS_REMAINING=0
    fi
    echo "5. [PENDING] Phase 4 prerequisites: $WEEKS_REMAINING weeks remaining (minimum)"
fi

echo ""

#
# Documentation and Resources
#

print_section "Documentation and Resources"

echo "Migration Guide:"
echo "  docs/OWCA_EXTRACTION_LAYER_MIGRATION.md"
echo ""

echo "Phase 4 Cleanup Checklist:"
echo "  docs/OWCA_PHASE4_CLEANUP_CHECKLIST.md"
echo ""

echo "Monitoring Tools:"
echo "  scripts/monitor-owca-migration.sh        # Daily monitoring"
echo "  scripts/generate-owca-weekly-report.sh   # Weekly reports (this script)"
echo ""

echo "Test Suite:"
echo "  backend/tests/unit/test_owca_extraction.py"
echo ""

#
# Footer
#

print_header "End of Report"

echo ""
echo "Next Report Due: $(date -d "next Monday" +"%Y-%m-%d" 2>/dev/null || echo "Next Monday")"
echo ""
echo "For questions or assistance, see:"
echo "  - Migration guide: docs/OWCA_EXTRACTION_LAYER_MIGRATION.md"
echo "  - Daily monitoring: ./scripts/monitor-owca-migration.sh"
echo ""

# Cleanup
rm -f "$TEMP_REPORT"
