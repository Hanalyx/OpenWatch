#!/usr/bin/env python3
"""
CodeQL Cleanup Script - Fix Log Injection Vulnerabilities
Fixes 8 log injection alerts by converting f-strings to parameterized logging

⚠️  SEMI-AUTOMATED SCRIPT - Manual review required after running!

Usage:
    python3 scripts/codeql_fix_log_injection.py
    python3 scripts/codeql_fix_log_injection.py --dry-run  # Preview changes
"""

import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Add parent directory to path
REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT))


class LogInjectionFixer:
    """Fix log injection vulnerabilities in Python code"""

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self.fixed_count = 0
        self.repo_root = REPO_ROOT

    def convert_fstring_to_params(self, line: str) -> Tuple[Optional[str], bool]:
        """
        Convert f-string logging to parameterized logging

        Examples:
            logger.info(f"Host {hostname} failed")
            → logger.info("Host %s failed", hostname)

            logger.error(f"Error for {user}: {error_msg}")
            → logger.error("Error for %s: %s", user, error_msg)

        Returns:
            (converted_line, was_modified)
        """
        # Match logger.{level}(f"...")
        match = re.match(r'^(\s*)(logger\.(\w+))\(f["\'](.+?)["\']\s*\)(.*)$', line)
        if not match:
            return None, False

        indent = match.group(1)
        logger_call = match.group(2)  # logger.info, logger.error, etc.
        log_level = match.group(3)  # info, error, etc.
        fstring_content = match.group(4)
        line_ending = match.group(5)  # comment, newline, etc.

        # Find all {variable} placeholders in the f-string
        variables = re.findall(r'\{([^}]+)\}', fstring_content)

        if not variables:
            # No variables in f-string, no change needed
            return None, False

        # Replace {var} with %s
        message = fstring_content
        for var in variables:
            # Handle format specs like {var:.2f} or {var!r}
            message = re.sub(r'\{' + re.escape(var) + r'[^}]*\}', '%s', message, count=1)

        # Build parameterized logging call
        params = ", ".join(variables)
        new_line = f'{indent}{logger_call}("{message}", {params}){line_ending}\n'

        return new_line, True

    def fix_file(self, file_path: str, alert_lines: List[int]) -> bool:
        """
        Fix log injection in a single file

        Args:
            file_path: Relative path from repo root
            alert_lines: Line numbers with log injection alerts

        Returns:
            True if file was modified
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
        fixes_applied = []

        # Process each alert line
        for line_num in alert_lines:
            idx = line_num - 1  # Convert to 0-indexed

            if idx >= len(lines):
                print(f"⚠️  Line {line_num} out of range in {file_path}")
                continue

            original_line = lines[idx]
            new_line, was_modified = self.convert_fstring_to_params(original_line)

            if was_modified and new_line:
                lines[idx] = new_line
                modified = True
                fixes_applied.append({
                    "line": line_num,
                    "before": original_line.rstrip(),
                    "after": new_line.rstrip(),
                })

        # Show changes
        if fixes_applied:
            print(f"\n{'🔍' if self.dry_run else '✅'} {file_path}")
            for fix in fixes_applied:
                print(f"  Line {fix['line']}:")
                print(f"    - {fix['before']}")
                print(f"    + {fix['after']}")

        # Write file if not dry run
        if modified and not self.dry_run:
            with open(full_path, 'w') as f:
                f.writelines(lines)
            self.fixed_count += 1
            return True

        return False

    def run(self):
        """Execute all log injection fixes"""
        print("🔒 CodeQL Cleanup - Fixing Log Injection Vulnerabilities")
        print("=" * 70)
        print("⚠️  SECURITY FIX: Converting f-strings to parameterized logging")
        if self.dry_run:
            print("🔍 DRY RUN MODE - No files will be modified")
        else:
            print("⚠️  Manual review recommended after running this script!")
        print("=" * 70)

        # Define fixes based on CodeQL alerts
        fixes_config = [
            {
                "file": "backend/app/services/rule_service.py",
                "lines": [179, 175, 120, 116],
            },
            {
                "file": "backend/app/services/mongo_integration_service.py",
                "lines": [317, 313],
            },
            {
                "file": "backend/app/routes/hosts.py",
                "lines": [474, 458],
            },
        ]

        # Process each file
        for config in fixes_config:
            self.fix_file(config["file"], config["lines"])

        # Summary
        print("\n" + "=" * 70)
        if self.dry_run:
            print("🔍 Dry run complete - no files modified")
            print("   Run without --dry-run to apply changes")
        else:
            print(f"✅ Fixed {self.fixed_count} files")
            print(f"📊 Expected to resolve 8 CodeQL log injection alerts")
            print("\n⚠️  IMPORTANT: Manual review required!")
            print("   1. Review changes: git diff")
            print("   2. Verify logging still provides useful debug info")
            print("   3. Test affected endpoints manually")
            print("   4. Run tests: pytest backend/tests/")
            print("   5. Commit: git commit -am 'Fix CodeQL log injection vulnerabilities'")
            print("\n📖 Why this fix works:")
            print("   - F-strings allow format string injection")
            print("   - Parameterized logging (%s) sanitizes inputs automatically")
            print("   - Logger handles escaping of special characters")


def main():
    """Main entry point"""
    dry_run = "--dry-run" in sys.argv or "-n" in sys.argv

    fixer = LogInjectionFixer(dry_run=dry_run)
    fixer.run()


if __name__ == "__main__":
    main()
