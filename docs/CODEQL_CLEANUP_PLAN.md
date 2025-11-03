# CodeQL & SonarCube Technical Debt Cleanup Plan

**Status:** Ready for Execution
**Date Created:** October 20, 2025
**Total Alerts:** 30 open alerts (NOT 5000+ as initially estimated)
**Estimated Cleanup Time:** 4-6 hours

---

## Executive Summary

Good news! The actual technical debt is **much smaller** than anticipated:
- **30 open CodeQL alerts** (not 5000+)
- **0 dismissed alerts** (nothing hidden)
- **All alerts from Oct 19-20, 2025** (recent scan)

Most alerts are **low-priority unused imports** (15 alerts) that can be auto-fixed in minutes.
The remaining **15 alerts** require manual review for security and correctness.

---

## Alert Breakdown by Priority

### 🔴 HIGH PRIORITY (14 alerts) - Security & Correctness Issues

#### 1. Log Injection Vulnerabilities (8 alerts) - **SECURITY CRITICAL**
**Severity:** Error
**Rule:** `py/log-injection`
**Risk:** User-provided values in logs can enable log forging, injection attacks, or information disclosure.

**Affected Files:**
- `backend/app/services/rule_service.py` (4 alerts)
  - Line 179: Log injection via user-provided value
  - Line 175: Log injection via user-provided value
  - Line 120: Log injection via user-provided value
  - Line 116: Log injection via user-provided value
- `backend/app/services/mongo_integration_service.py` (2 alerts)
  - Line 317: Log injection via user-provided value
  - Line 313: Log injection via user-provided value
- `backend/app/routes/hosts.py` (2 alerts)
  - Line 474: Log injection via user-provided value
  - Line 458: Log injection via user-provided value

**Fix Strategy:**
```python
# ❌ BEFORE (vulnerable):
logger.info(f"Processing rule: {rule_id}")
logger.error(f"Failed for host: {hostname}")

# ✅ AFTER (safe):
logger.info("Processing rule: %s", rule_id)
logger.error("Failed for host: %s", hostname)
```

**Why This Works:**
- Using `%s` placeholders prevents format string injection
- Logger automatically sanitizes parameters
- User input cannot inject newlines or control characters

---

#### 2. Uninitialized Local Variables (4 alerts) - **CORRECTNESS CRITICAL**
**Severity:** Error
**Rule:** `py/uninitialized-local-variable`
**Risk:** Variables may be used before being assigned, causing NameError exceptions.

**Affected Files:**
- `backend/app/services/unified_ssh_service.py` (1 alert)
  - Line 1362: `auth_method_used` may be uninitialized
- `backend/app/routes/hosts.py` (3 alerts)
  - Line 407: `metadata` may be uninitialized
  - Line 406: `credential_data` may be uninitialized
  - Line 397: `get_auth_service` may be uninitialized

**Fix Strategy:**
```python
# ❌ BEFORE:
if some_condition:
    auth_method_used = "ssh_key"
# Later usage may fail if condition is False
logger.info(f"Used: {auth_method_used}")

# ✅ AFTER:
auth_method_used = None  # Initialize with default
if some_condition:
    auth_method_used = "ssh_key"
logger.info(f"Used: {auth_method_used or 'unknown'}")
```

---

#### 3. Wrong Arguments (2 alerts) - **CORRECTNESS CRITICAL**
**Severity:** Error
**Rule:** `py/call/wrong-arguments`
**Risk:** Calling methods with incorrect number of arguments causes TypeError exceptions.

**Affected Files:**
- `backend/app/services/mongo_integration_service.py` (2 alerts)
  - Line 296: `MockComplianceRule.find()` called with too many arguments
  - Line 271: `MockComplianceRule.find()` called with too many arguments

**Fix Strategy:**
```python
# Need to review MockComplianceRule.find() signature
# Either:
# 1. Fix method calls to match signature
# 2. Update method signature to accept arguments
# 3. Replace mock with actual implementation
```

---

### 🟡 MEDIUM PRIORITY (1 alert) - Code Quality Issue

#### 4. Multiple Definition / Unnecessary Assignment (1 alert)
**Severity:** Warning
**Rule:** `py/multiple-definition`
**Risk:** Code inefficiency, potential logic error.

**Affected Files:**
- `backend/app/services/unified_ssh_service.py` (1 alert)
  - Line 1702: Assignment to `fingerprint` is unnecessary (redefined before use)

**Fix Strategy:**
```python
# ❌ BEFORE:
fingerprint = None
# ... some code ...
fingerprint = calculate_fingerprint(key)  # Previous assignment was wasted

# ✅ AFTER:
# ... some code ...
fingerprint = calculate_fingerprint(key)  # Only assign when needed
```

---

### 🟢 LOW PRIORITY (15 alerts) - Unused Imports

#### 5. Unused Imports (15 alerts) - **AUTO-FIXABLE**
**Severity:** Note
**Rule:** `py/unused-import`
**Risk:** Code clutter, minimal performance impact.

**Affected Files:**
- `backend/app/routes/hosts.py` (1 alert)
  - Line 11: `import json` not used
- `backend/app/utils/query_builder.py` (1 alert)
  - Line 26: `import re` not used
- `backend/app/api/v1/endpoints/xccdf_api.py` (1 alert)
  - Line 10: `AsyncIOMotorDatabase`, `AsyncIOMotorClient` not used
- `backend/app/api/v1/endpoints/scans_api.py` (1 alert)
  - Line 9: `AsyncIOMotorDatabase`, `AsyncIOMotorClient` not used
- `backend/app/api/v1/endpoints/scan_config_api.py` (1 alert)
  - Line 10: `AsyncIOMotorDatabase` not used
- `backend/app/services/remediation_orchestrator_service.py` (1 alert)
  - Line 24: 4 executor error classes not used
- `backend/app/api/v1/endpoints/remediation_api.py` (1 alert)
  - Line 14: `AsyncIOMotorDatabase` not used
- `backend/app/services/scanners/oscap_scanner.py` (1 alert)
  - Line 18: `XCCDFGeneratorService` not used
- `backend/app/tasks/monitoring_tasks.py` (4 alerts)
  - Line 15: `UnifiedSSHService` not used
  - Line 14: `MonitoringState` not used
  - Line 7: `Celery` not used
  - Line 5: `Optional`, `Tuple` not used
- `backend/app/routes/monitoring.py` (3 alerts)
  - Line 14: `check_host_connectivity` not used
  - Line 13: `HostMonitoringStateMachine` not used
  - Line 8: `datetime` not used

**Fix Strategy:** Automated removal script (provided below)

---

## Cleanup Execution Plan

### Phase 1: Quick Wins - Unused Imports (30 minutes)
**Impact:** Fixes 15 of 30 alerts (50% reduction)
**Risk:** Very low (imports not used)
**Method:** Automated script + verification

### Phase 2: Security Fixes - Log Injection (1-2 hours)
**Impact:** Fixes 8 critical security alerts
**Risk:** Medium (requires testing)
**Method:** Replace f-strings with parameterized logging

### Phase 3: Correctness Fixes - Uninitialized Variables (1-2 hours)
**Impact:** Fixes 4 error-level alerts
**Risk:** Medium (requires logic review)
**Method:** Add default initializations + testing

### Phase 4: Fix Wrong Arguments (1 hour)
**Impact:** Fixes 2 error-level alerts
**Risk:** Medium (requires API review)
**Method:** Review MockComplianceRule implementation

### Phase 5: Code Quality - Multiple Definition (30 minutes)
**Impact:** Fixes 1 warning
**Risk:** Low
**Method:** Remove unnecessary assignment

---

## Automated Cleanup Scripts

### Script 1: Remove Unused Imports

```python
#!/usr/bin/env python3
"""
CodeQL Cleanup Script - Remove Unused Imports
Fixes 15 unused import alerts automatically
"""

import re
from pathlib import Path

UNUSED_IMPORTS = [
    {
        "file": "backend/app/routes/hosts.py",
        "line": 11,
        "remove": "import json",
    },
    {
        "file": "backend/app/utils/query_builder.py",
        "line": 26,
        "remove": "import re",
    },
    {
        "file": "backend/app/api/v1/endpoints/xccdf_api.py",
        "line": 10,
        "remove": ["AsyncIOMotorDatabase", "AsyncIOMotorClient"],
        "from_import": "motor.motor_asyncio",
    },
    {
        "file": "backend/app/api/v1/endpoints/scans_api.py",
        "line": 9,
        "remove": ["AsyncIOMotorDatabase", "AsyncIOMotorClient"],
        "from_import": "motor.motor_asyncio",
    },
    {
        "file": "backend/app/api/v1/endpoints/scan_config_api.py",
        "line": 10,
        "remove": ["AsyncIOMotorDatabase"],
        "from_import": "motor.motor_asyncio",
    },
    {
        "file": "backend/app/services/remediation_orchestrator_service.py",
        "line": 24,
        "remove": [
            "ExecutorNotAvailableError",
            "ExecutorValidationError",
            "ExecutorExecutionError",
            "UnsupportedTargetError",
        ],
        "from_import": "backend.app.services.remediation_executor_service",
    },
    {
        "file": "backend/app/api/v1/endpoints/remediation_api.py",
        "line": 14,
        "remove": ["AsyncIOMotorDatabase"],
        "from_import": "motor.motor_asyncio",
    },
    {
        "file": "backend/app/services/scanners/oscap_scanner.py",
        "line": 18,
        "remove": ["XCCDFGeneratorService"],
        "from_import": "backend.app.services.xccdf_generator_service",
    },
    {
        "file": "backend/app/tasks/monitoring_tasks.py",
        "lines": [5, 7, 14, 15],
        "remove": ["Optional", "Tuple", "Celery", "MonitoringState", "UnifiedSSHService"],
    },
    {
        "file": "backend/app/routes/monitoring.py",
        "lines": [8, 13, 14],
        "remove": ["datetime", "HostMonitoringStateMachine", "check_host_connectivity"],
    },
]

def remove_from_import(line: str, remove_items: list) -> str:
    """Remove specific items from 'from ... import ...' statement"""
    # Parse: from module import Item1, Item2, Item3
    match = re.match(r'from\s+([\w.]+)\s+import\s+(.+)', line)
    if not match:
        return line

    module = match.group(1)
    imports = match.group(2)

    # Parse import list (handle parentheses and commas)
    items = []
    for item in re.split(r',\s*', imports.strip('()')):
        item = item.strip()
        if item and item not in remove_items:
            items.append(item)

    # Return None if no items remain (delete line)
    if not items:
        return None

    # Reconstruct import statement
    if len(items) == 1:
        return f"from {module} import {items[0]}\n"
    else:
        return f"from {module} import {', '.join(items)}\n"

def clean_file(file_path: str, remove_config: dict):
    """Remove unused imports from a file"""
    path = Path(file_path)
    if not path.exists():
        print(f"⚠️  File not found: {file_path}")
        return False

    with open(path, 'r') as f:
        lines = f.readlines()

    modified = False

    # Handle simple import removal
    if "remove" in remove_config and isinstance(remove_config["remove"], str):
        target_line = remove_config["line"] - 1  # 0-indexed
        if target_line < len(lines):
            if remove_config["remove"] in lines[target_line]:
                lines[target_line] = ""  # Remove entire line
                modified = True

    # Handle from...import removal
    elif "from_import" in remove_config:
        target_line = remove_config["line"] - 1
        if target_line < len(lines):
            new_line = remove_from_import(lines[target_line], remove_config["remove"])
            if new_line != lines[target_line]:
                lines[target_line] = new_line or ""
                modified = True

    # Handle multiple line removal
    elif "lines" in remove_config:
        for line_num in sorted(remove_config["lines"], reverse=True):
            target_line = line_num - 1
            if target_line < len(lines):
                for item in remove_config["remove"]:
                    if item in lines[target_line]:
                        lines[target_line] = ""
                        modified = True
                        break

    if modified:
        with open(path, 'w') as f:
            f.writelines(lines)
        print(f"✅ Fixed: {file_path}")
        return True
    else:
        print(f"⏭️  No changes needed: {file_path}")
        return False

def main():
    print("🧹 CodeQL Cleanup - Removing Unused Imports")
    print("=" * 60)

    fixed_count = 0
    for config in UNUSED_IMPORTS:
        if clean_file(config["file"], config):
            fixed_count += 1

    print("=" * 60)
    print(f"✅ Fixed {fixed_count} files")
    print(f"📊 Expected to resolve 15 CodeQL alerts")

if __name__ == "__main__":
    main()
```

---

### Script 2: Fix Log Injection Vulnerabilities

```python
#!/usr/bin/env python3
"""
CodeQL Cleanup Script - Fix Log Injection Vulnerabilities
Fixes 8 log injection alerts by converting f-strings to parameterized logging
"""

import re
from pathlib import Path

LOG_INJECTION_FIXES = [
    {
        "file": "backend/app/services/rule_service.py",
        "fixes": [
            {"line": 179, "pattern": r'logger\.(\w+)\(f"([^"]*)\{([^}]+)\}([^"]*)"\)', "replace": r'logger.\1("\2%s\4", \3)'},
            {"line": 175, "pattern": r'logger\.(\w+)\(f"([^"]*)\{([^}]+)\}([^"]*)"\)', "replace": r'logger.\1("\2%s\4", \3)'},
            {"line": 120, "pattern": r'logger\.(\w+)\(f"([^"]*)\{([^}]+)\}([^"]*)"\)', "replace": r'logger.\1("\2%s\4", \3)'},
            {"line": 116, "pattern": r'logger\.(\w+)\(f"([^"]*)\{([^}]+)\}([^"]*)"\)', "replace": r'logger.\1("\2%s\4", \3)'},
        ],
    },
    {
        "file": "backend/app/services/mongo_integration_service.py",
        "fixes": [
            {"line": 317, "pattern": r'logger\.(\w+)\(f"([^"]*)\{([^}]+)\}([^"]*)"\)', "replace": r'logger.\1("\2%s\4", \3)'},
            {"line": 313, "pattern": r'logger\.(\w+)\(f"([^"]*)\{([^}]+)\}([^"]*)"\)', "replace": r'logger.\1("\2%s\4", \3)'},
        ],
    },
    {
        "file": "backend/app/routes/hosts.py",
        "fixes": [
            {"line": 474, "pattern": r'logger\.(\w+)\(f"([^"]*)\{([^}]+)\}([^"]*)"\)', "replace": r'logger.\1("\2%s\4", \3)'},
            {"line": 458, "pattern": r'logger\.(\w+)\(f"([^"]*)\{([^}]+)\}([^"]*)"\)', "replace": r'logger.\1("\2%s\4", \3)'},
        ],
    },
]

def fix_log_injection(file_path: str, fixes: list):
    """Fix log injection vulnerabilities by converting f-strings to parameterized logging"""
    path = Path(file_path)
    if not path.exists():
        print(f"⚠️  File not found: {file_path}")
        return False

    with open(path, 'r') as f:
        lines = f.readlines()

    modified = False
    for fix in fixes:
        line_num = fix["line"] - 1  # 0-indexed
        if line_num < len(lines):
            original = lines[line_num]
            # Convert f-string to parameterized logging
            # This is a simplified version - manual review still recommended
            new_line = re.sub(fix["pattern"], fix["replace"], original)
            if new_line != original:
                lines[line_num] = new_line
                modified = True
                print(f"  Line {fix['line']}: {original.strip()[:60]}...")
                print(f"       → {new_line.strip()[:60]}...")

    if modified:
        with open(path, 'w') as f:
            f.writelines(lines)
        print(f"✅ Fixed: {file_path}")
        return True
    else:
        print(f"⚠️  Manual review needed: {file_path}")
        return False

def main():
    print("🔒 CodeQL Cleanup - Fixing Log Injection Vulnerabilities")
    print("=" * 60)
    print("⚠️  WARNING: This is a semi-automated fix.")
    print("   Manual review required after running this script!")
    print("=" * 60)

    fixed_count = 0
    for config in LOG_INJECTION_FIXES:
        print(f"\n📄 Processing: {config['file']}")
        if fix_log_injection(config["file"], config["fixes"]):
            fixed_count += 1

    print("\n" + "=" * 60)
    print(f"✅ Fixed {fixed_count} files")
    print(f"📊 Expected to resolve 8 CodeQL log injection alerts")
    print("\n⚠️  NEXT STEPS:")
    print("   1. Review changes with: git diff")
    print("   2. Test affected endpoints")
    print("   3. Commit if tests pass")

if __name__ == "__main__":
    main()
```

---

## Manual Review Checklist

### For Log Injection Fixes
- [ ] Verify all f-string conversions preserve intended logging behavior
- [ ] Test that error messages still provide useful debugging information
- [ ] Confirm no sensitive data is logged (even with parameterized logging)
- [ ] Run backend tests: `pytest backend/tests/`

### For Uninitialized Variables
- [ ] Review code flow to understand when variables might be uninitialized
- [ ] Add appropriate default values (None, empty string, empty list, etc.)
- [ ] Add defensive checks before variable usage
- [ ] Test all code paths (success and error cases)

### For Wrong Arguments
- [ ] Review `MockComplianceRule.find()` method signature
- [ ] Determine if mock needs updating or calls need fixing
- [ ] Consider replacing mock with actual Beanie model queries
- [ ] Test MongoDB queries after fixes

---

## Testing Requirements

### Unit Tests
```bash
# Run all backend tests
cd /home/rracine/hanalyx/openwatch/backend
pytest tests/ -v

# Run specific test files for affected modules
pytest tests/test_rule_service.py -v
pytest tests/test_mongo_integration.py -v
pytest tests/test_hosts.py -v
```

### Integration Tests
```bash
# Test host endpoints
curl -X GET http://localhost:8000/api/hosts/ \
  -H "Authorization: Bearer $TOKEN"

# Test rule service endpoints
curl -X GET http://localhost:8000/api/v1/compliance-rules/ \
  -H "Authorization: Bearer $TOKEN"

# Test monitoring endpoints
curl -X GET http://localhost:8000/api/monitoring/state \
  -H "Authorization: Bearer $TOKEN"
```

### Security Validation
```bash
# Re-run CodeQL scan after fixes
gh api repos/Hanalyx/OpenWatch/code-scanning/alerts \
  --jq '.[] | select(.state == "open") | .number' | wc -l

# Should show reduced alert count after fixes
```

---

## Estimated Timeline

| Phase | Task | Estimated Time | Alerts Fixed |
|-------|------|----------------|--------------|
| 1 | Remove unused imports (automated) | 30 min | 15 |
| 2 | Fix log injection (semi-automated + review) | 1-2 hours | 8 |
| 3 | Fix uninitialized variables (manual) | 1-2 hours | 4 |
| 4 | Fix wrong arguments (manual + testing) | 1 hour | 2 |
| 5 | Fix multiple definition (manual) | 30 min | 1 |
| **TOTAL** | **Full cleanup** | **4-6 hours** | **30** |

---

## Success Criteria

- [ ] All 30 CodeQL alerts resolved or dismissed with justification
- [ ] Zero new alerts introduced by fixes
- [ ] All backend unit tests passing
- [ ] All affected API endpoints tested manually
- [ ] No security vulnerabilities remain
- [ ] Code review completed by team member
- [ ] Changes deployed to staging environment
- [ ] CodeQL dashboard shows 0 open alerts

---

## Risk Mitigation

### Backup Strategy
```bash
# Create backup branch before starting
cd /home/rracine/hanalyx/openwatch
git checkout -b codeql-cleanup-backup
git checkout -b codeql-cleanup

# Work on codeql-cleanup branch
# Can always revert to codeql-cleanup-backup if needed
```

### Incremental Approach
1. Fix unused imports first (low risk, high impact)
2. Commit and push after each phase
3. Run tests after each commit
4. Deploy to staging between phases
5. Monitor for regressions

### Rollback Plan
```bash
# If issues arise after deployment:
git revert <commit-hash>
git push origin refactor/codeql-cleanup

# Or full rollback:
git reset --hard codeql-cleanup-backup
git push origin refactor/codeql-cleanup --force
```

---

## SonarCube Integration

**Note:** This plan focuses on CodeQL alerts. For SonarCube:

1. **Check Current State:**
```bash
# Get SonarCube project key
# Access SonarCube dashboard at configured URL
```

2. **Expected Overlap:**
- SonarCube likely flags the same unused imports
- SonarCube may have additional code smell alerts
- Security hotspots should align with CodeQL findings

3. **Post-CodeQL Cleanup:**
- Re-run SonarCube analysis
- Address SonarCube-specific alerts (code smells, duplications)
- Configure quality gates for future PRs

---

## Continuous Prevention

### Pre-Commit Hooks
```bash
# Add flake8 for unused imports
pip install flake8
echo "flake8 backend/ --select=F401" > .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

### CI/CD Integration
```yaml
# .github/workflows/code-quality.yml
name: Code Quality
on: [push, pull_request]
jobs:
  codeql:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: github/codeql-action/init@v2
      - uses: github/codeql-action/analyze@v2

  sonarcloud:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: SonarSource/sonarcloud-github-action@master
```

### Developer Guidelines
1. **Always use parameterized logging:**
   - ✅ `logger.info("Message: %s", user_input)`
   - ❌ `logger.info(f"Message: {user_input}")`

2. **Initialize variables before use:**
   - ✅ `result = None` at function start
   - ❌ Conditional initialization only

3. **Remove unused imports:**
   - Run `autoflake --remove-all-unused-imports --in-place file.py`

---

**Last Updated:** October 20, 2025
**Maintained By:** OpenWatch Development Team
**Related Documents:**
- [QueryBuilder Guide](/docs/QUERYBUILDER_EXPLANATION.md)
- [Migration Roadmap](/docs/MIGRATION_ROADMAP.md)
- [Security Best Practices](/docs/SECURITY.md)
