#!/usr/bin/env python3
"""
CodeQL Cleanup Script - Remove Unused Imports
Fixes 15 unused import alerts automatically

Usage:
    python3 scripts/codeql_fix_unused_imports.py
    python3 scripts/codeql_fix_unused_imports.py --dry-run  # Preview changes
"""

import re
import sys
from pathlib import Path
from typing import Dict, List, Optional

# Add parent directory to path for imports
REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT))


class UnusedImportFixer:
    """Fix unused import CodeQL alerts"""

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self.fixed_count = 0
        self.repo_root = REPO_ROOT

    def remove_from_import_line(self, line: str, remove_items: List[str]) -> Optional[str]:
        """
        Remove specific items from 'from ... import ...' statement

        Returns:
            Modified line, empty string to delete line, or None if no change needed
        """
        # Match: from module import Item1, Item2, Item3
        match = re.match(r'from\s+([\w.]+)\s+import\s+(.+)', line)
        if not match:
            return None

        module = match.group(1)
        imports_str = match.group(2).strip()

        # Handle parentheses for multi-line imports
        imports_str = imports_str.strip('()')

        # Split by comma, clean up whitespace
        current_items = [item.strip() for item in re.split(r',\s*', imports_str) if item.strip()]

        # Filter out items to remove
        remaining_items = [item for item in current_items if item not in remove_items]

        # If no items remain, delete the line
        if not remaining_items:
            return ""

        # If all items remain, no change needed
        if len(remaining_items) == len(current_items):
            return None

        # Reconstruct import statement
        if len(remaining_items) == 1:
            return f"from {module} import {remaining_items[0]}\n"
        else:
            # Keep original formatting style
            return f"from {module} import {', '.join(remaining_items)}\n"

    def remove_simple_import(self, line: str, import_statement: str) -> Optional[str]:
        """
        Remove simple 'import module' statement

        Returns:
            Empty string to delete line, or None if no match
        """
        if import_statement in line and line.strip().startswith('import'):
            return ""
        return None

    def fix_file(self, file_path: str, fixes: List[Dict]) -> bool:
        """
        Apply fixes to a single file

        Args:
            file_path: Relative path from repo root
            fixes: List of fix configurations

        Returns:
            True if file was modified, False otherwise
        """
        full_path = self.repo_root / file_path

        if not full_path.exists():
            print(f"⚠️  File not found: {file_path}")
            return False

        # Read file
        with open(full_path, 'r') as f:
            lines = f.readlines()

        original_lines = lines.copy()
        modified = False

        # Apply each fix
        for fix in fixes:
            line_num = fix.get("line", 0) - 1  # Convert to 0-indexed

            if line_num >= len(lines):
                print(f"⚠️  Line {fix.get('line')} out of range in {file_path}")
                continue

            original_line = lines[line_num]

            # Handle simple import removal (e.g., "import json")
            if "simple_import" in fix:
                new_line = self.remove_simple_import(original_line, fix["simple_import"])
                if new_line is not None:
                    lines[line_num] = new_line
                    modified = True
                    if not self.dry_run:
                        print(f"  Line {fix['line']}: Removed '{fix['simple_import']}'")

            # Handle from...import removal
            elif "remove_from_import" in fix:
                new_line = self.remove_from_import_line(original_line, fix["remove_from_import"])
                if new_line is not None:
                    lines[line_num] = new_line
                    modified = True
                    if not self.dry_run:
                        items = ", ".join(fix["remove_from_import"])
                        print(f"  Line {fix['line']}: Removed {items}")

        # Show diff if dry run
        if self.dry_run and modified:
            print(f"\n📄 Would modify: {file_path}")
            for i, (old, new) in enumerate(zip(original_lines, lines)):
                if old != new:
                    print(f"  - Line {i+1}: {old.rstrip()}")
                    if new.strip():
                        print(f"  + Line {i+1}: {new.rstrip()}")
                    else:
                        print(f"  + Line {i+1}: (deleted)")

        # Write file if not dry run
        if modified and not self.dry_run:
            with open(full_path, 'w') as f:
                f.writelines(lines)
            print(f"✅ Fixed: {file_path}")
            self.fixed_count += 1
            return True

        return False

    def run(self):
        """Execute all unused import fixes"""
        print("🧹 CodeQL Cleanup - Removing Unused Imports")
        print("=" * 70)
        if self.dry_run:
            print("🔍 DRY RUN MODE - No files will be modified")
            print("=" * 70)

        # Define all fixes based on CodeQL alerts
        fixes_config = [
            {
                "file": "backend/app/routes/hosts.py",
                "fixes": [{"line": 11, "simple_import": "import json"}],
            },
            {
                "file": "backend/app/utils/query_builder.py",
                "fixes": [{"line": 26, "simple_import": "import re"}],
            },
            {
                "file": "backend/app/routes/xccdf_api.py",
                "fixes": [{"line": 10, "remove_from_import": ["AsyncIOMotorDatabase", "AsyncIOMotorClient"]}],
            },
            {
                "file": "backend/app/routes/scans_api.py",
                "fixes": [{"line": 9, "remove_from_import": ["AsyncIOMotorDatabase", "AsyncIOMotorClient"]}],
            },
            {
                "file": "backend/app/routes/scan_config_api.py",
                "fixes": [{"line": 10, "remove_from_import": ["AsyncIOMotorDatabase"]}],
            },
            {
                "file": "backend/app/services/remediation_orchestrator_service.py",
                "fixes": [{
                    "line": 24,
                    "remove_from_import": [
                        "ExecutorNotAvailableError",
                        "ExecutorValidationError",
                        "ExecutorExecutionError",
                        "UnsupportedTargetError",
                    ]
                }],
            },
            {
                "file": "backend/app/routes/remediation_api.py",
                "fixes": [{"line": 14, "remove_from_import": ["AsyncIOMotorDatabase"]}],
            },
            {
                "file": "backend/app/services/scanners/oscap_scanner.py",
                "fixes": [{"line": 18, "remove_from_import": ["XCCDFGeneratorService"]}],
            },
            {
                "file": "backend/app/tasks/monitoring_tasks.py",
                "fixes": [
                    {"line": 5, "remove_from_import": ["Optional", "Tuple"]},
                    {"line": 7, "simple_import": "from celery import Celery"},
                    {"line": 14, "remove_from_import": ["MonitoringState"]},
                    {"line": 15, "remove_from_import": ["UnifiedSSHService"]},
                ],
            },
            {
                "file": "backend/app/routes/monitoring.py",
                "fixes": [
                    {"line": 8, "remove_from_import": ["datetime"]},
                    {"line": 13, "remove_from_import": ["HostMonitoringStateMachine"]},
                    {"line": 14, "remove_from_import": ["check_host_connectivity"]},
                ],
            },
        ]

        # Process each file
        for config in fixes_config:
            print(f"\n📄 Processing: {config['file']}")
            self.fix_file(config["file"], config["fixes"])

        # Summary
        print("\n" + "=" * 70)
        if self.dry_run:
            print("🔍 Dry run complete - no files modified")
            print("   Run without --dry-run to apply changes")
        else:
            print(f"✅ Fixed {self.fixed_count} files")
            print(f"📊 Expected to resolve 15 CodeQL unused import alerts")
            print("\n📋 Next steps:")
            print("   1. Review changes: git diff")
            print("   2. Run tests: pytest backend/tests/")
            print("   3. Commit: git commit -am 'Fix CodeQL unused import alerts'")


def main():
    """Main entry point"""
    dry_run = "--dry-run" in sys.argv or "-n" in sys.argv

    fixer = UnusedImportFixer(dry_run=dry_run)
    fixer.run()


if __name__ == "__main__":
    main()
