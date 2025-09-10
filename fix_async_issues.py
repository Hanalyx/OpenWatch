#!/usr/bin/env python3
"""
Script to fix async/await issues reported by SonarCloud
Removes async keyword from functions that don't use async features
"""
import re
import os
from pathlib import Path

# Files with async issues based on SonarCloud report
FILES_TO_FIX = {
    "backend/app/audit_db.py": [14],
    "backend/app/auth.py": [277, 289, 408],
    "backend/app/celery_app.py": [185],
    "backend/app/database.py": [400, 410],
    "backend/app/middleware/authorization_middleware.py": [209, 356, 376, 427],
    "backend/app/middleware/metrics.py": [104, 164],
    "backend/app/plugins/interface.py": [110, 145, 164, 189, 208, 231, 250, 269],
    "backend/app/plugins/manager.py": [187, 196, 319, 341, 381],
    "backend/app/rbac.py": [331],
    "backend/app/routes/audit.py": [255],
    "backend/app/routes/capabilities.py": [195, 241, 295, 306, 373],
    "backend/app/routes/mfa.py": [89],
    "backend/app/routes/rule_scanning.py": [368, 404, 443],
    "backend/app/routes/system_settings.py": [545],
    "backend/app/routes/system_settings_unified.py": [815],
    "backend/app/routes/v1/remediation.py": [559],
    "backend/app/services/authorization_service.py": [326, 460, 524, 568, 583, 648, 816, 882],
    "backend/app/services/bulk_scan_orchestrator.py": [412, 460, 491, 521, 553, 595, 729, 772, 804],
    "backend/app/services/command_sandbox.py": [146, 168, 191, 380, 408],
}

def remove_async_from_function(content: str, line_number: int) -> str:
    """Remove async keyword from a specific function"""
    lines = content.split('\n')
    
    # Adjust for 0-based indexing
    idx = line_number - 1
    
    if idx < len(lines):
        line = lines[idx]
        # Check if this line has async def
        if 'async def' in line:
            # Replace async def with def
            lines[idx] = line.replace('async def', 'def')
            print(f"  Fixed line {line_number}: {line.strip()[:60]}...")
    
    return '\n'.join(lines)

def fix_file(filepath: str, line_numbers: list):
    """Fix async issues in a single file"""
    full_path = Path(filepath)
    if not full_path.exists():
        print(f"⚠️  File not found: {filepath}")
        return
    
    print(f"\n📄 Processing {filepath}")
    
    # Read the file
    with open(full_path, 'r') as f:
        content = f.read()
    
    # Fix each line
    for line_num in sorted(line_numbers, reverse=True):
        content = remove_async_from_function(content, line_num)
    
    # Write back
    with open(full_path, 'w') as f:
        f.write(content)
    
    print(f"✅ Fixed {len(line_numbers)} async issues")

def main():
    """Main function to fix all async issues"""
    print("🔧 Fixing async/await issues reported by SonarCloud\n")
    
    total_issues = sum(len(lines) for lines in FILES_TO_FIX.values())
    print(f"Total issues to fix: {total_issues}")
    
    for filepath, line_numbers in FILES_TO_FIX.items():
        fix_file(filepath, line_numbers)
    
    print(f"\n✨ Completed fixing {total_issues} async/await issues!")
    print("\nNext steps:")
    print("1. Review the changes with: git diff")
    print("2. Run tests to ensure nothing broke")
    print("3. Commit the changes")

if __name__ == "__main__":
    main()