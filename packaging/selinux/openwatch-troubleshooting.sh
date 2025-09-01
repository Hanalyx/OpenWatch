#!/bin/bash
# OpenWatch SELinux Troubleshooting Script
# Diagnose and fix common SELinux issues with OpenWatch

set -euo pipefail

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Check SELinux status
check_selinux_status() {
    log_info "Checking SELinux status..."
    
    local selinux_status=$(getenforce 2>/dev/null || echo "Unknown")
    echo "SELinux mode: $selinux_status"
    
    case "$selinux_status" in
        "Enforcing")
            log_success "SELinux is in enforcing mode"
            return 0
            ;;
        "Permissive")
            log_warning "SELinux is in permissive mode"
            return 0
            ;;
        "Disabled")
            log_error "SELinux is disabled"
            return 1
            ;;
        *)
            log_error "Unable to determine SELinux status"
            return 1
            ;;
    esac
}

# Check if OpenWatch policy is installed
check_policy_installed() {
    log_info "Checking OpenWatch policy installation..."
    
    if semodule -l | grep -q "^openwatch"; then
        local version=$(semodule -l | grep "^openwatch" | awk '{print $2}')
        log_success "OpenWatch policy installed: version $version"
        return 0
    else
        log_error "OpenWatch policy not installed"
        echo "Install with: cd packaging/selinux && sudo ./build-policy.sh install"
        return 1
    fi
}

# Check file contexts
check_file_contexts() {
    log_info "Checking file contexts..."
    
    local paths=(
        "/usr/bin/owadm"
        "/etc/openwatch"
        "/var/lib/openwatch"
        "/var/log/openwatch"
    )
    
    local context_errors=()
    
    for path in "${paths[@]}"; do
        if [ -e "$path" ]; then
            local current_context=$(ls -Z "$path" 2>/dev/null | awk '{print $1}' || echo "unknown")
            echo "  $path: $current_context"
            
            # Check if context looks correct
            if [[ "$current_context" == *"openwatch"* ]]; then
                log_success "Correct context: $path"
            else
                context_errors+=("$path")
                log_warning "Incorrect context: $path"
            fi
        else
            log_warning "Path not found: $path"
        fi
    done
    
    if [ ${#context_errors[@]} -gt 0 ]; then
        echo ""
        log_warning "File context issues found. Fix with:"
        echo "  sudo restorecon -R ${context_errors[*]}"
        return 1
    fi
    
    return 0
}

# Find recent SELinux denials
check_recent_denials() {
    log_info "Checking for recent SELinux denials..."
    
    # Check audit log for recent denials
    local denial_count
    denial_count=$(ausearch -m AVC -ts recent 2>/dev/null | grep -c "openwatch" || echo "0")
    
    if [ "$denial_count" -eq 0 ]; then
        log_success "No recent SELinux denials found"
        return 0
    else
        log_warning "Found $denial_count recent denials involving OpenWatch"
        
        echo ""
        echo "Recent denials:"
        ausearch -m AVC -ts recent 2>/dev/null | grep "openwatch" | tail -5
        
        echo ""
        log_info "Generate policy suggestions with:"
        echo "  audit2allow -w < /var/log/audit/audit.log | grep openwatch"
        echo "  audit2allow -a | grep -A 20 -B 5 openwatch"
        
        return 1
    fi
}

# Test container operations
test_container_operations() {
    log_info "Testing container operations with SELinux..."
    
    # Test basic owadm functionality
    if command -v owadm >/dev/null 2>&1; then
        log_info "Testing owadm execution..."
        if runcon -t openwatch_t owadm --help >/dev/null 2>&1; then
            log_success "owadm executes successfully in OpenWatch context"
        else
            log_warning "owadm execution failed in OpenWatch context"
        fi
    else
        log_warning "owadm not found - install OpenWatch package first"
    fi
    
    # Test configuration file access
    if [ -f /etc/openwatch/ow.yml ]; then
        log_info "Testing configuration access..."
        if runcon -t openwatch_t cat /etc/openwatch/ow.yml >/dev/null 2>&1; then
            log_success "Configuration file accessible"
        else
            log_warning "Cannot access configuration file"
        fi
    fi
    
    # Test log file access
    local log_dir="/var/log/openwatch"
    if [ -d "$log_dir" ]; then
        log_info "Testing log directory access..."
        if runcon -t openwatch_t touch "$log_dir/selinux-test.log" 2>/dev/null; then
            rm -f "$log_dir/selinux-test.log"
            log_success "Log directory writable"
        else
            log_warning "Cannot write to log directory"
        fi
    fi
}

# Generate policy fixes for denials
generate_policy_fixes() {
    log_info "Generating policy fixes for recent denials..."
    
    local temp_file=$(mktemp)
    ausearch -m AVC -ts recent 2>/dev/null | grep "openwatch" > "$temp_file" || {
        log_info "No recent denials to process"
        rm -f "$temp_file"
        return 0
    }
    
    if [ -s "$temp_file" ]; then
        echo ""
        echo "Suggested policy additions:"
        echo "============================="
        audit2allow -w < "$temp_file"
        echo ""
        echo "Policy rules to add:"
        echo "===================="
        audit2allow < "$temp_file"
        echo ""
        log_info "Review these suggestions and add appropriate rules to openwatch.te"
    fi
    
    rm -f "$temp_file"
}

# Fix common context issues
fix_contexts() {
    log_info "Fixing common SELinux context issues..."
    
    # Restore default contexts first
    local paths=(
        "/usr/bin/owadm"
        "/etc/openwatch"
        "/var/lib/openwatch"
        "/var/log/openwatch"
    )
    
    for path in "${paths[@]}"; do
        if [ -e "$path" ]; then
            log_info "Restoring contexts for: $path"
            restorecon -R "$path"
        fi
    done
    
    # Set specific contexts for sensitive files
    if [ -f /etc/openwatch/secrets.env ]; then
        chcon -t openwatch_secret_t /etc/openwatch/secrets.env
        log_info "Set secret context for secrets.env"
    fi
    
    if [ -d /etc/openwatch/ssh ]; then
        chcon -R -t openwatch_ssh_key_t /etc/openwatch/ssh/
        log_info "Set SSH key contexts"
    fi
    
    log_success "Context fixes applied"
}

# Enable development mode
enable_dev_mode() {
    log_warning "Enabling SELinux development mode for OpenWatch..."
    log_warning "This reduces security - only use for development/testing!"
    
    # Create temporary permissive domain
    cat > /tmp/openwatch_permissive.te << 'EOF'
policy_module(openwatch_permissive, 1.0)

require {
    type openwatch_t;
}

# Make OpenWatch domain permissive for development
permissive openwatch_t;
EOF
    
    # Compile and install permissive module
    cd /tmp
    make -f /usr/share/selinux/devel/Makefile openwatch_permissive.pp
    semodule -i openwatch_permissive.pp
    rm -f openwatch_permissive.*
    
    log_success "Development mode enabled"
    log_warning "Disable with: semodule -r openwatch_permissive"
}

# Disable development mode
disable_dev_mode() {
    log_info "Disabling SELinux development mode..."
    
    semodule -r openwatch_permissive 2>/dev/null || {
        log_info "Development mode was not enabled"
        return 0
    }
    
    log_success "Development mode disabled"
}

# Show troubleshooting guide
show_troubleshooting_guide() {
    cat << 'EOF'

OpenWatch SELinux Troubleshooting Guide
=======================================

Common Issues and Solutions:

1. Service won't start with "Permission denied"
   → Check contexts: ls -Z /usr/bin/owadm /etc/openwatch/
   → Fix contexts: sudo restorecon -R /etc/openwatch/ /usr/bin/owadm

2. Container operations fail
   → Check for denials: sudo ausearch -m AVC -ts recent | grep openwatch
   → Generate fixes: sudo audit2allow -a | grep -A 10 openwatch

3. Configuration file access denied
   → Verify context: ls -Z /etc/openwatch/ow.yml
   → Should show: openwatch_conf_t
   → Fix: sudo restorecon /etc/openwatch/ow.yml

4. SSH scanning fails
   → Check SSH key contexts: ls -Z /etc/openwatch/ssh/
   → Should show: openwatch_ssh_key_t
   → Fix: sudo chcon -R -t openwatch_ssh_key_t /etc/openwatch/ssh/

5. Log access denied
   → Check log contexts: ls -Z /var/log/openwatch/
   → Should show: openwatch_log_t
   → Fix: sudo restorecon -R /var/log/openwatch/

Debug Commands:
   sudo ausearch -m AVC -ts recent          # Show recent denials
   sudo sealert -a /var/log/audit/audit.log # Analyze all denials
   sudo semodule -l | grep openwatch        # Check policy status
   sudo getsebool -a | grep openwatch       # Check booleans
   runcon -t openwatch_t owadm --help       # Test execution

For persistent issues:
   sudo ./build-policy.sh dev              # Enable permissive mode
   sudo ./build-policy.sh uninstall        # Remove policy
   sudo ./build-policy.sh install          # Reinstall policy

EOF
}

# Display usage if no arguments
if [ $# -eq 0 ]; then
    usage
    exit 0
fi

# Main execution
main() {
    local command="$1"
    
    case "$command" in
        status)
            check_selinux_status
            check_policy_installed
            check_file_contexts
            ;;
        denials)
            check_recent_denials
            ;;
        test)
            check_selinux_status || exit 1
            check_policy_installed || exit 1
            test_container_operations
            ;;
        fix)
            check_root
            fix_contexts
            ;;
        analyze)
            generate_policy_fixes
            ;;
        dev-enable)
            check_root
            enable_dev_mode
            ;;
        dev-disable)
            check_root
            disable_dev_mode
            ;;
        guide)
            show_troubleshooting_guide
            ;;
        *)
            log_error "Unknown command: $command"
            usage
            exit 1
            ;;
    esac
}

# Run main function
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi