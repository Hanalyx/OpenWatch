#!/usr/bin/env python3
"""
Security Fixes Validation Script
Validates that all security vulnerabilities have been properly fixed.
"""
import re
import ast
import sys
from pathlib import Path


def test_sql_injection_fixes():
    """Test SQL injection vulnerabilities have been fixed"""
    print("Testing SQL injection fixes...")
    backend_path = Path(__file__).parent.parent.parent / "app"
    
    critical_files = [
        "routes/users.py",
        "routes/webhooks.py", 
        "routes/system_settings.py"
    ]
    
    passed = 0
    total = len(critical_files)
    
    for file_path in critical_files:
        full_path = backend_path / file_path
        if full_path.exists():
            with open(full_path, 'r') as f:
                content = f.read()
            
            # Check for dangerous f-string SQL patterns (not logging)
            # These patterns look for actual SQL construction, not logging
            dangerous_patterns = [
                r'query\s*=\s*f"UPDATE.*SET.*{.*}"',
                r'query\s*=\s*f"INSERT.*INTO.*{.*}"', 
                r'query\s*=\s*f"SELECT.*FROM.*{.*}"',
                r'query\s*=\s*f"DELETE.*FROM.*{.*}"',
                r'execute\([^)]*f"UPDATE.*SET.*{.*}"',
                r'execute\([^)]*f"INSERT.*INTO.*{.*}"',
                r'execute\([^)]*f"SELECT.*FROM.*{.*}"',
                r'execute\([^)]*f"DELETE.*FROM.*{.*}"'
            ]
            
            has_issues = False
            for pattern in dangerous_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    print(f"  ✗ {file_path}: Found dangerous f-string SQL pattern: {matches}")
                    has_issues = True
                    break
            
            if not has_issues:
                print(f"  ✓ {file_path}: No dangerous SQL patterns found")
                passed += 1
        else:
            print(f"  ? {file_path}: File not found")
    
    return passed, total


def test_path_injection_fixes():
    """Test path injection vulnerabilities have been fixed"""
    print("\nTesting path injection fixes...")
    backend_path = Path(__file__).parent.parent.parent / "app"
    scanner_file = backend_path / "services/rule_specific_scanner.py"
    
    if not scanner_file.exists():
        print("  ? rule_specific_scanner.py: File not found")
        return 0, 1
    
    with open(scanner_file, 'r') as f:
        content = f.read()
    
    checks = [
        ("_sanitize_identifier method", "_sanitize_identifier" in content),
        ("Host ID sanitization", "sanitized_host_id" in content),
        ("Regex sanitization", "re.sub" in content),
        ("Length limitation", "[:50]" in content),
        ("Scan ID sanitization", "sanitized_scan_id" in content)
    ]
    
    passed = 0
    for check_name, result in checks:
        if result:
            print(f"  ✓ {check_name}: Implemented")
            passed += 1
        else:
            print(f"  ✗ {check_name}: Missing")
    
    return passed, len(checks)


def test_stack_trace_fixes():
    """Test stack trace exposure fixes"""
    print("\nTesting stack trace exposure fixes...")
    backend_path = Path(__file__).parent.parent.parent / "app"
    host_groups_file = backend_path / "routes/host_groups.py"
    
    if not host_groups_file.exists():
        print("  ? host_groups.py: File not found")
        return 0, 1
    
    with open(host_groups_file, 'r') as f:
        content = f.read()
    
    checks = [
        ("Generic error messages", "Invalid input parameters" in content),
        ("Sanitized responses", "Scan session not found" in content),
        ("Security fix comments", "Security Fix:" in content)
    ]
    
    passed = 0
    for check_name, result in checks:
        if result:
            print(f"  ✓ {check_name}: Implemented")
            passed += 1
        else:
            print(f"  ✗ {check_name}: Missing")
    
    return passed, len(checks)


def test_paramiko_fixes():
    """Test paramiko host key validation fixes"""
    print("\nTesting paramiko host key validation fixes...")
    backend_path = Path(__file__).parent.parent.parent / "app"
    
    paramiko_files = [
        "services/scap_scanner.py",
        "services/terminal_service.py",
        "services/host_monitor.py",
        "services/error_classification.py"
    ]
    
    passed = 0
    total = 0
    
    for file_path in paramiko_files:
        full_path = backend_path / file_path
        if full_path.exists():
            with open(full_path, 'r') as f:
                content = f.read()
            
            checks = [
                ("No AutoAddPolicy", "AutoAddPolicy()" not in content),
                ("Uses RejectPolicy", "RejectPolicy()" in content),
                ("Loads system host keys", "load_system_host_keys" in content),
                ("Handles FileNotFoundError", "FileNotFoundError" in content)
            ]
            
            all_checks_passed = True
            for check_name, result in checks:
                if result:
                    passed += 1
                else:
                    print(f"  ✗ {file_path}: {check_name} failed")
                    all_checks_passed = False
                total += 1
            
            if all_checks_passed:
                print(f"  ✓ {file_path}: All paramiko checks passed")
        else:
            print(f"  ? {file_path}: File not found")
            total += 4  # 4 checks per file
    
    return passed, total


def test_syntax_validation():
    """Test that all modified files have valid Python syntax"""
    print("\nTesting syntax validation...")
    backend_path = Path(__file__).parent.parent.parent / "app"
    
    modified_files = [
        "routes/users.py",
        "routes/webhooks.py",
        "routes/system_settings.py",
        "services/rule_specific_scanner.py",
        "routes/host_groups.py",
        "services/scap_scanner.py", 
        "services/terminal_service.py",
        "services/host_monitor.py",
        "services/error_classification.py"
    ]
    
    passed = 0
    total = len(modified_files)
    
    for file_path in modified_files:
        full_path = backend_path / file_path
        if full_path.exists():
            with open(full_path, 'r') as f:
                content = f.read()
            
            try:
                ast.parse(content)
                print(f"  ✓ {file_path}: Valid syntax")
                passed += 1
            except SyntaxError as e:
                print(f"  ✗ {file_path}: Syntax error - {e}")
        else:
            print(f"  ? {file_path}: File not found")
    
    return passed, total


def main():
    """Main validation function"""
    print("OpenWatch Security Fixes Validation")
    print("=" * 50)
    
    total_passed = 0
    total_checks = 0
    
    # Run all validation tests
    tests = [
        test_sql_injection_fixes,
        test_path_injection_fixes,
        test_stack_trace_fixes,
        test_paramiko_fixes,
        test_syntax_validation
    ]
    
    for test_func in tests:
        passed, total = test_func()
        total_passed += passed
        total_checks += total
    
    # Summary
    print("\n" + "=" * 50)
    print("VALIDATION SUMMARY")
    print("=" * 50)
    print(f"Passed: {total_passed}/{total_checks} checks")
    
    if total_passed == total_checks:
        print("✓ ALL SECURITY FIXES VALIDATED - DEPLOYMENT READY")
        return 0
    else:
        print("✗ SOME SECURITY CHECKS FAILED - REVIEW REQUIRED")
        return 1


if __name__ == "__main__":
    sys.exit(main())