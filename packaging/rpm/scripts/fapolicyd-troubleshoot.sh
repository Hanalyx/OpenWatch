#!/bin/bash
# OpenWatch fapolicyd Troubleshooting Tool
# Diagnose and resolve fapolicyd issues affecting OpenWatch operation

set -euo pipefail

# Configuration
RULES_FILE="/etc/fapolicyd/rules.d/90-openwatch.rules"
AUDIT_LOG="/var/log/audit/audit.log"

# Colors for output
if [ -t 1 ]; then
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    RED='\033[0;31m'
    BLUE='\033[0;34m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    GREEN=''
    YELLOW=''
    RED=''
    BLUE=''
    BOLD=''
    NC=''
fi

log_info() {
    echo -e "${BLUE}fapolicyd-troubleshoot:${NC} $1"
}

log_success() {
    echo -e "${GREEN}fapolicyd-troubleshoot:${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}fapolicyd-troubleshoot:${NC} $1"
}

log_error() {
    echo -e "${RED}fapolicyd-troubleshoot:${NC} $1"
}

log_header() {
    echo -e "${BOLD}$1${NC}"
    echo -e "${BOLD}$(echo "$1" | sed 's/./=/g')${NC}"
}

# Check fapolicyd service status
check_fapolicyd_status() {
    log_header "fapolicyd Service Status"

    if ! command -v fapolicyd >/dev/null 2>&1; then
        log_warning "fapolicyd not installed"
        echo "  Install with: sudo dnf install fapolicyd"
        return 1
    fi

    log_success "fapolicyd binary found: $(command -v fapolicyd)"

    local status
    status=$(systemctl is-active fapolicyd 2>/dev/null || echo "inactive")

    case "$status" in
        "active")
            log_success "fapolicyd service: active"
            ;;
        "inactive")
            log_warning "fapolicyd service: inactive"
            echo "  Start with: sudo systemctl start fapolicyd"
            return 1
            ;;
        *)
            log_error "fapolicyd service: $status"
            echo "  Check with: sudo systemctl status fapolicyd"
            return 1
            ;;
    esac

    # Check if fapolicyd is in permissive mode
    local mode
    if command -v fapolicyd-cli >/dev/null 2>&1; then
        mode=$(fapolicyd-cli --check-config 2>/dev/null | grep -i "permissive\|enforcing" || echo "unknown")
        echo "  Mode: $mode"
    fi

    echo ""
    return 0
}

# Check OpenWatch rules installation
check_openwatch_rules() {
    log_header "OpenWatch fapolicyd Rules"

    if [ ! -f "$RULES_FILE" ]; then
        log_error "OpenWatch rules file not found: $RULES_FILE"
        echo "  Install with: sudo /usr/share/openwatch/scripts/configure-fapolicyd.sh"
        echo ""
        return 1
    fi

    log_success "Rules file found: $RULES_FILE"

    # Check file permissions
    local perms
    perms=$(stat -c "%a" "$RULES_FILE" 2>/dev/null || echo "unknown")
    if [ "$perms" = "644" ]; then
        log_success "File permissions: $perms (correct)"
    else
        log_warning "File permissions: $perms (expected 644)"
        echo "  Fix with: sudo chmod 644 $RULES_FILE"
    fi

    # Count rules
    local rule_count
    rule_count=$(grep -c "^allow" "$RULES_FILE" 2>/dev/null || echo "0")
    echo "  Total allow rules: $rule_count"

    # Count OpenWatch-specific rules
    local ow_rules
    ow_rules=$(grep -c "openwatch\|owadm\|/usr/bin/podman\|/usr/bin/docker\|/usr/bin/oscap" "$RULES_FILE" 2>/dev/null || echo "0")
    echo "  OpenWatch-related rules: $ow_rules"

    # Show last modification time
    if command -v stat >/dev/null 2>&1; then
        local mtime
        mtime=$(stat -c "%y" "$RULES_FILE" 2>/dev/null | cut -d. -f1)
        echo "  Last modified: $mtime"
    fi

    echo ""
    return 0
}

# Check for recent fapolicyd denials
check_fapolicyd_denials() {
    log_header "Recent fapolicyd Denials"

    if [ ! -r "$AUDIT_LOG" ]; then
        log_warning "Cannot read audit log: $AUDIT_LOG"
        echo "  Run as root to access audit logs"
        echo ""
        return 1
    fi

    # Look for fapolicyd denials in the last hour
    local denials
    denials=$(ausearch -m FANOTIFY -ts recent 2>/dev/null | grep -E "openwatch|owadm|podman|docker|oscap" || echo "")

    if [ -z "$denials" ]; then
        log_success "No recent fapolicyd denials found for OpenWatch components"
    else
        log_warning "Recent fapolicyd denials found:"
        echo "$denials" | head -10
        echo ""
        echo "  Full analysis: ausearch -m FANOTIFY -ts recent | grep -E 'openwatch|owadm'"
    fi

    # Look for general fapolicyd activity
    local recent_activity
    recent_activity=$(ausearch -m FANOTIFY -ts today 2>/dev/null | wc -l || echo "0")
    echo "  Total fapolicyd events today: $recent_activity"

    echo ""
    return 0
}

# Test OpenWatch binary execution
test_openwatch_execution() {
    log_header "OpenWatch Binary Execution Test"

    # Test owadm execution
    if [ -x /usr/bin/owadm ]; then
        log_info "Testing owadm execution..."
        if timeout 10 /usr/bin/owadm --version >/dev/null 2>&1; then
            log_success "owadm execution: OK"
        else
            log_error "owadm execution: FAILED"
            echo "  Check fapolicyd rules for /usr/bin/owadm"
        fi
    else
        log_warning "owadm not found or not executable"
    fi

    # Test as openwatch user if we're root
    if [ "$EUID" -eq 0 ] && getent passwd openwatch >/dev/null 2>&1; then
        log_info "Testing owadm execution as openwatch user..."
        if sudo -u openwatch timeout 10 /usr/bin/owadm --version >/dev/null 2>&1; then
            log_success "owadm execution as openwatch: OK"
        else
            log_error "owadm execution as openwatch: FAILED"
            echo "  Check fapolicyd rules for uid=openwatch"
        fi
    fi

    echo ""
}

# Test container runtime execution
test_container_runtime() {
    log_header "Container Runtime Execution Test"

    # Test Podman
    if command -v podman >/dev/null 2>&1; then
        log_info "Testing Podman execution..."
        if timeout 10 podman --version >/dev/null 2>&1; then
            log_success "Podman execution: OK"
        else
            log_error "Podman execution: FAILED"
            echo "  Check fapolicyd rules for /usr/bin/podman"
        fi

        # Test as openwatch user
        if [ "$EUID" -eq 0 ] && getent passwd openwatch >/dev/null 2>&1; then
            log_info "Testing Podman as openwatch user..."
            if sudo -u openwatch timeout 10 podman --version >/dev/null 2>&1; then
                log_success "Podman as openwatch: OK"
            else
                log_error "Podman as openwatch: FAILED"
            fi
        fi
    else
        log_info "Podman not found"
    fi

    # Test Docker
    if command -v docker >/dev/null 2>&1; then
        log_info "Testing Docker execution..."
        if timeout 10 docker --version >/dev/null 2>&1; then
            log_success "Docker execution: OK"
        else
            log_error "Docker execution: FAILED"
            echo "  Check fapolicyd rules for /usr/bin/docker"
        fi
    else
        log_info "Docker not found"
    fi

    echo ""
}

# Test SCAP scanner execution
test_scap_execution() {
    log_header "SCAP Scanner Execution Test"

    if command -v oscap >/dev/null 2>&1; then
        log_info "Testing OpenSCAP execution..."
        if timeout 10 oscap --version >/dev/null 2>&1; then
            log_success "OpenSCAP execution: OK"
        else
            log_error "OpenSCAP execution: FAILED"
            echo "  Check fapolicyd rules for /usr/bin/oscap"
        fi

        # Test as openwatch user
        if [ "$EUID" -eq 0 ] && getent passwd openwatch >/dev/null 2>&1; then
            log_info "Testing OpenSCAP as openwatch user..."
            if sudo -u openwatch timeout 10 oscap --version >/dev/null 2>&1; then
                log_success "OpenSCAP as openwatch: OK"
            else
                log_error "OpenSCAP as openwatch: FAILED"
            fi
        fi
    else
        log_warning "OpenSCAP not found"
        echo "  Install with: sudo dnf install openscap-scanner"
    fi

    echo ""
}

# Test Python execution
test_python_execution() {
    log_header "Python Runtime Execution Test"

    if command -v python3 >/dev/null 2>&1; then
        log_info "Testing Python3 execution..."
        if timeout 10 python3 --version >/dev/null 2>&1; then
            log_success "Python3 execution: OK"
        else
            log_error "Python3 execution: FAILED"
            echo "  Check fapolicyd rules for /usr/bin/python3"
        fi

        # Test as openwatch user
        if [ "$EUID" -eq 0 ] && getent passwd openwatch >/dev/null 2>&1; then
            log_info "Testing Python3 as openwatch user..."
            if sudo -u openwatch timeout 10 python3 --version >/dev/null 2>&1; then
                log_success "Python3 as openwatch: OK"
            else
                log_error "Python3 as openwatch: FAILED"
            fi
        fi
    else
        log_warning "Python3 not found"
    fi

    echo ""
}

# Generate suggested fixes
generate_fixes() {
    log_header "Suggested Fixes"

    echo "Based on the diagnostic results, here are suggested actions:"
    echo ""

    # Check if rules file is missing
    if [ ! -f "$RULES_FILE" ]; then
        echo "1. Install OpenWatch fapolicyd rules:"
        echo "   sudo /usr/share/openwatch/scripts/configure-fapolicyd.sh"
        echo ""
    fi

    # Check if fapolicyd is inactive
    if ! systemctl is-active --quiet fapolicyd 2>/dev/null; then
        echo "2. Start fapolicyd service:"
        echo "   sudo systemctl start fapolicyd"
        echo "   sudo systemctl enable fapolicyd"
        echo ""
    fi

    # General troubleshooting steps
    echo "3. Reload fapolicyd configuration:"
    echo "   sudo systemctl reload fapolicyd"
    echo ""

    echo "4. Monitor fapolicyd denials in real-time:"
    echo "   sudo tail -f /var/log/audit/audit.log | grep FANOTIFY"
    echo ""

    echo "5. Test specific binary execution:"
    echo "   sudo -u openwatch /usr/bin/owadm --version"
    echo "   sudo -u openwatch /usr/bin/podman --version"
    echo ""

    echo "6. Temporary disable fapolicyd for testing (NOT for production):"
    echo "   sudo systemctl stop fapolicyd"
    echo "   # Test OpenWatch functionality"
    echo "   sudo systemctl start fapolicyd"
    echo ""

    echo "7. Check OpenWatch service status:"
    echo "   sudo systemctl status openwatch.target"
    echo "   journalctl -u openwatch.service -f"
    echo ""
}

# Show detailed rule analysis
show_rule_analysis() {
    log_header "fapolicyd Rule Analysis"

    if [ ! -f "$RULES_FILE" ]; then
        log_error "Rules file not found: $RULES_FILE"
        return 1
    fi

    echo "OpenWatch fapolicyd rules breakdown:"
    echo ""

    # Count different types of rules
    local binary_rules
    binary_rules=$(grep -c "path=/usr/bin/" "$RULES_FILE" 2>/dev/null || echo "0")
    echo "  Binary execution rules: $binary_rules"

    local dir_rules
    dir_rules=$(grep -c "dir=" "$RULES_FILE" 2>/dev/null || echo "0")
    echo "  Directory access rules: $dir_rules"

    local openwatch_user_rules
    openwatch_user_rules=$(grep -c "uid=openwatch" "$RULES_FILE" 2>/dev/null || echo "0")
    echo "  OpenWatch user-specific rules: $openwatch_user_rules"

    echo ""

    # Show sample rules by category
    echo "Sample rules by category:"
    echo ""

    echo "Core OpenWatch:"
    grep "owadm\|openwatch" "$RULES_FILE" 2>/dev/null | head -3 || echo "  None found"
    echo ""

    echo "Container Runtime:"
    grep -E "podman|docker|conmon|runc" "$RULES_FILE" 2>/dev/null | head -3 || echo "  None found"
    echo ""

    echo "SCAP Tools:"
    grep "oscap" "$RULES_FILE" 2>/dev/null | head -2 || echo "  None found"
    echo ""

    echo "Directory Access:"
    grep "dir=" "$RULES_FILE" 2>/dev/null | head -3 || echo "  None found"
    echo ""
}

# Run comprehensive diagnostics
run_comprehensive_diagnostics() {
    log_header "OpenWatch fapolicyd Comprehensive Diagnostics"
    echo ""

    check_fapolicyd_status
    check_openwatch_rules
    check_fapolicyd_denials
    test_openwatch_execution
    test_container_runtime
    test_scap_execution
    test_python_execution
    show_rule_analysis
    generate_fixes
}

# Show help
show_help() {
    cat << EOF
OpenWatch fapolicyd Troubleshooting Tool

Usage: $0 [command]

Commands:
    status      Check fapolicyd service status
    rules       Analyze OpenWatch fapolicyd rules
    denials     Check for recent fapolicyd denials
    test        Test execution of OpenWatch components
    fix         Show suggested fixes for common issues
    full        Run comprehensive diagnostics (default)
    help        Show this help message

Examples:
    $0              # Run full diagnostics
    $0 status       # Check fapolicyd status only
    $0 denials      # Look for recent denials
    $0 test         # Test component execution
    $0 fix          # Show fix suggestions

Note: Some operations require root privileges to access audit logs
      and test execution as the openwatch user.

EOF
}

# Main execution
main() {
    local command="${1:-full}"

    case "$command" in
        status)
            check_fapolicyd_status
            ;;
        rules)
            check_openwatch_rules
            show_rule_analysis
            ;;
        denials)
            check_fapolicyd_denials
            ;;
        test)
            test_openwatch_execution
            test_container_runtime
            test_scap_execution
            test_python_execution
            ;;
        fix)
            generate_fixes
            ;;
        full)
            run_comprehensive_diagnostics
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            log_error "Unknown command: $command"
            show_help
            exit 1
            ;;
    esac
}

# Check if we need elevated privileges
if [[ "${1:-full}" =~ ^(denials|full)$ ]] && [ "$EUID" -ne 0 ]; then
    log_warning "Some diagnostics require root privileges for complete analysis"
    echo "Run with: sudo $0 $*"
    echo ""
fi

# Allow script to be sourced for testing
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
