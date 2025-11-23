#!/bin/bash
#
# OWCA Extraction Layer Migration Monitoring Script
#
# Purpose: Monitor deprecation warnings and track migration progress during Phase 3
#
# Usage:
#   ./scripts/monitor-owca-migration.sh                    # Full report
#   ./scripts/monitor-owca-migration.sh --deprecations     # Only deprecation warnings
#   ./scripts/monitor-owca-migration.sh --usage            # Only code usage analysis
#   ./scripts/monitor-owca-migration.sh --logs             # Check application logs
#
# Phase 3 Monitoring Goals:
# - Identify any remaining /scoring module usage
# - Track deprecation warnings in logs
# - Verify OWCA extraction layer adoption
# - Report migration progress to stakeholders
#
# Related: docs/OWCA_EXTRACTION_LAYER_MIGRATION.md
#

set -e

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
BACKEND_DIR="backend"
LOG_CONTAINER="openwatch-backend"
REPORT_DATE=$(date +"%Y-%m-%d %H:%M:%S")

# Parse command line arguments
MODE="full"
if [ "$1" = "--deprecations" ]; then
    MODE="deprecations"
elif [ "$1" = "--usage" ]; then
    MODE="usage"
elif [ "$1" = "--logs" ]; then
    MODE="logs"
elif [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    echo "OWCA Extraction Layer Migration Monitor"
    echo ""
    echo "Usage:"
    echo "  $0                 # Full migration report"
    echo "  $0 --deprecations  # Only deprecation warnings"
    echo "  $0 --usage         # Only code usage analysis"
    echo "  $0 --logs          # Check application logs"
    echo "  $0 --help          # Show this help"
    echo ""
    exit 0
fi

#
# Function: Print section header
#
print_header() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
}

#
# Function: Check for deprecated /scoring imports in codebase
#
check_deprecated_imports() {
    print_header "Deprecated /scoring Module Usage"

    echo "Scanning codebase for deprecated imports..."
    echo ""

    # Check for direct imports from /scoring
    echo -e "${YELLOW}Checking for 'from backend.app.services.scoring import'${NC}"
    SCORING_IMPORTS=$(grep -r "from backend\.app\.services\.scoring import" "$BACKEND_DIR" \
        --exclude-dir=__pycache__ \
        --exclude-dir=.pytest_cache \
        --exclude="*.pyc" \
        --exclude-dir=scoring \
        2>/dev/null || true)

    if [ -z "$SCORING_IMPORTS" ]; then
        echo -e "${GREEN}PASS: No deprecated /scoring imports found${NC}"
    else
        echo -e "${RED}WARN: Found deprecated /scoring imports:${NC}"
        echo "$SCORING_IMPORTS"
    fi

    echo ""

    # Check for XCCDFScoreExtractor (deprecated class)
    echo -e "${YELLOW}Checking for 'XCCDFScoreExtractor' usage${NC}"
    EXTRACTOR_USAGE=$(grep -r "XCCDFScoreExtractor" "$BACKEND_DIR" \
        --exclude-dir=__pycache__ \
        --exclude-dir=.pytest_cache \
        --exclude="*.pyc" \
        --exclude-dir=scoring \
        2>/dev/null || true)

    if [ -z "$EXTRACTOR_USAGE" ]; then
        echo -e "${GREEN}PASS: No XCCDFScoreExtractor usage found${NC}"
    else
        echo -e "${RED}WARN: Found XCCDFScoreExtractor usage:${NC}"
        echo "$EXTRACTOR_USAGE"
    fi

    echo ""

    # Check for SeverityWeightingService (deprecated class)
    echo -e "${YELLOW}Checking for 'SeverityWeightingService' usage${NC}"
    SERVICE_USAGE=$(grep -r "SeverityWeightingService" "$BACKEND_DIR" \
        --exclude-dir=__pycache__ \
        --exclude-dir=.pytest_cache \
        --exclude="*.pyc" \
        --exclude-dir=scoring \
        2>/dev/null || true)

    if [ -z "$SERVICE_USAGE" ]; then
        echo -e "${GREEN}PASS: No SeverityWeightingService usage found${NC}"
    else
        echo -e "${RED}WARN: Found SeverityWeightingService usage:${NC}"
        echo "$SERVICE_USAGE"
    fi

    echo ""

    # Check for RiskScoreResult (renamed to SeverityRiskResult)
    echo -e "${YELLOW}Checking for 'RiskScoreResult' usage (renamed to SeverityRiskResult)${NC}"
    RESULT_USAGE=$(grep -r "RiskScoreResult" "$BACKEND_DIR" \
        --exclude-dir=__pycache__ \
        --exclude-dir=.pytest_cache \
        --exclude="*.pyc" \
        --exclude-dir=scoring \
        2>/dev/null || true)

    if [ -z "$RESULT_USAGE" ]; then
        echo -e "${GREEN}PASS: No RiskScoreResult usage found${NC}"
    else
        echo -e "${RED}WARN: Found RiskScoreResult usage (should be SeverityRiskResult):${NC}"
        echo "$RESULT_USAGE"
    fi
}

#
# Function: Check for OWCA extraction layer usage (positive validation)
#
check_owca_usage() {
    print_header "OWCA Extraction Layer Adoption"

    echo "Verifying OWCA extraction layer usage..."
    echo ""

    # Check for XCCDFParser (new class)
    echo -e "${YELLOW}Checking for 'XCCDFParser' usage${NC}"
    PARSER_USAGE=$(grep -r "XCCDFParser" "$BACKEND_DIR" \
        --exclude-dir=__pycache__ \
        --exclude-dir=.pytest_cache \
        --exclude="*.pyc" \
        2>/dev/null | wc -l)

    echo -e "Found ${GREEN}$PARSER_USAGE${NC} references to XCCDFParser"

    # Check for SeverityCalculator (new class)
    echo -e "${YELLOW}Checking for 'SeverityCalculator' usage${NC}"
    CALCULATOR_USAGE=$(grep -r "SeverityCalculator" "$BACKEND_DIR" \
        --exclude-dir=__pycache__ \
        --exclude-dir=.pytest_cache \
        --exclude="*.pyc" \
        2>/dev/null | wc -l)

    echo -e "Found ${GREEN}$CALCULATOR_USAGE${NC} references to SeverityCalculator"

    # Check for get_owca_service usage
    echo -e "${YELLOW}Checking for 'get_owca_service' usage${NC}"
    SERVICE_USAGE=$(grep -r "get_owca_service" "$BACKEND_DIR" \
        --exclude-dir=__pycache__ \
        --exclude-dir=.pytest_cache \
        --exclude="*.pyc" \
        2>/dev/null | wc -l)

    echo -e "Found ${GREEN}$SERVICE_USAGE${NC} references to get_owca_service"

    echo ""

    # Check if extraction layer files exist
    echo -e "${YELLOW}Verifying extraction layer files${NC}"
    EXTRACTION_FILES=(
        "backend/app/services/owca/extraction/__init__.py"
        "backend/app/services/owca/extraction/xccdf_parser.py"
        "backend/app/services/owca/extraction/severity_calculator.py"
        "backend/app/services/owca/extraction/constants.py"
    )

    ALL_EXIST=true
    for file in "${EXTRACTION_FILES[@]}"; do
        if [ -f "$file" ]; then
            echo -e "${GREEN}PASS:${NC} $file"
        else
            echo -e "${RED}FAIL:${NC} $file (missing)"
            ALL_EXIST=false
        fi
    done

    if [ "$ALL_EXIST" = true ]; then
        echo ""
        echo -e "${GREEN}SUCCESS: All extraction layer files present${NC}"
    else
        echo ""
        echo -e "${RED}ERROR: Some extraction layer files missing${NC}"
    fi
}

#
# Function: Check application logs for deprecation warnings
#
check_application_logs() {
    print_header "Application Log Analysis"

    echo "Checking last 1000 lines of backend logs for deprecation warnings..."
    echo ""

    # Check if container is running
    if ! docker ps | grep -q "$LOG_CONTAINER"; then
        echo -e "${RED}ERROR: Container $LOG_CONTAINER not running${NC}"
        echo "Please start OpenWatch services first: ./start-openwatch.sh"
        return 1
    fi

    # Check for deprecation warnings
    DEPRECATION_COUNT=$(docker logs "$LOG_CONTAINER" --tail 1000 2>&1 | \
        grep -ci "deprecat" || true)

    if [ "$DEPRECATION_COUNT" -eq 0 ]; then
        echo -e "${GREEN}PASS: No deprecation warnings found in recent logs${NC}"
    else
        echo -e "${YELLOW}Found $DEPRECATION_COUNT deprecation warnings:${NC}"
        echo ""
        docker logs "$LOG_CONTAINER" --tail 1000 2>&1 | grep -i "deprecat" || true
    fi

    echo ""

    # Check for OWCA extraction layer initialization
    echo -e "${YELLOW}Checking for OWCA initialization messages${NC}"
    OWCA_INIT=$(docker logs "$LOG_CONTAINER" --tail 1000 2>&1 | \
        grep -i "owca" | grep -i "init" | tail -5 || true)

    if [ -z "$OWCA_INIT" ]; then
        echo -e "${YELLOW}No OWCA initialization messages found (this is normal)${NC}"
    else
        echo -e "${GREEN}Recent OWCA initialization:${NC}"
        echo "$OWCA_INIT"
    fi
}

#
# Function: Generate migration progress report
#
generate_progress_report() {
    print_header "Migration Progress Report"

    echo "Report Date: $REPORT_DATE"
    echo ""

    # Count files in old vs new locations
    OLD_SCORING_FILES=$(find backend/app/services/scoring -type f -name "*.py" 2>/dev/null | wc -l || echo "0")
    NEW_EXTRACTION_FILES=$(find backend/app/services/owca/extraction -type f -name "*.py" 2>/dev/null | wc -l || echo "0")

    echo -e "Old /scoring module: ${YELLOW}$OLD_SCORING_FILES${NC} files (deprecated)"
    echo -e "New extraction layer: ${GREEN}$NEW_EXTRACTION_FILES${NC} files (active)"

    echo ""

    # Check test coverage
    echo -e "${YELLOW}Test Coverage${NC}"
    if [ -f "backend/tests/unit/test_owca_extraction.py" ]; then
        TEST_COUNT=$(grep -c "def test_" backend/tests/unit/test_owca_extraction.py || echo "0")
        echo -e "Extraction layer tests: ${GREEN}$TEST_COUNT${NC} test functions"
    else
        echo -e "${RED}WARNING: No test file found for extraction layer${NC}"
    fi

    echo ""

    # Summary
    echo -e "${BLUE}Phase 3 Status Summary${NC}"
    echo -e "Phase 1 (Implementation): ${GREEN}COMPLETE${NC}"
    echo -e "Phase 2 (Testing/Docs): ${GREEN}COMPLETE${NC}"
    echo -e "Phase 3 (Transition): ${YELLOW}IN PROGRESS${NC}"
    echo -e "Phase 4 (Cleanup): ${YELLOW}PENDING${NC}"
}

#
# Main execution
#

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}OWCA Extraction Layer Migration Monitor${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo "Report Date: $REPORT_DATE"
echo "Mode: $MODE"

if [ "$MODE" = "deprecations" ] || [ "$MODE" = "full" ]; then
    check_deprecated_imports
fi

if [ "$MODE" = "usage" ] || [ "$MODE" = "full" ]; then
    check_owca_usage
fi

if [ "$MODE" = "logs" ] || [ "$MODE" = "full" ]; then
    check_application_logs
fi

if [ "$MODE" = "full" ]; then
    generate_progress_report
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Monitoring Complete${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "For more information, see: docs/OWCA_EXTRACTION_LAYER_MIGRATION.md"
echo ""
