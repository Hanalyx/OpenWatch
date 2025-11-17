# Unused Variables Remediation Guide

**Status**: Ready for systematic manual review
**Total Warnings**: 439 `@typescript-eslint/no-unused-vars`
**Last Updated**: 2025-11-16
**Related**: LINTING_REMEDIATION_PLAN.md

---

## Overview

This document provides a systematic approach to fixing 439 unused variable warnings in the OpenWatch frontend codebase. These warnings do not affect functionality but impact code quality, bundle size, and maintainability.

## Warning Categories

### 1. Unused Imports (Estimated ~200 warnings)

**Pattern**: Import statement that is never referenced in the file.

**Example**:
```typescript
// BEFORE (warning):
import { Divider, Grid, Chip } from '@mui/material';
// Only Grid is used, Divider and Chip are unused

// AFTER (fixed):
import { Grid } from '@mui/material';
```

**Fix Strategy**:
- ✅ **SAFE**: Can be removed without any functional impact
- ⚠️ **Check**: Ensure not used in commented code or future use

**Impact**: Reduces bundle size, improves tree-shaking

### 2. Unused Error Variables in Catch Blocks (Estimated ~50 warnings)

**Pattern**: Error variable in catch block that isn't logged or handled.

**Example**:
```typescript
// BEFORE (warning):
try {
  await fetchData();
} catch (error) {  // 'error' is defined but never used
  setLoading(false);
}

// AFTER (fixed - Option 1: Log it):
try {
  await fetchData();
} catch (error) {
  console.error('Failed to fetch data:', error);
  setLoading(false);
}

// AFTER (fixed - Option 2: Prefix with underscore):
try {
  await fetchData();
} catch (_error) {  // Underscore indicates intentionally unused
  setLoading(false);
}
```

**Fix Strategy**:
- ✅ **PREFERRED**: Log the error (better for debugging)
- ✅ **ACCEPTABLE**: Prefix with `_` if error is truly not needed
- ❌ **AVOID**: Removing error variable (breaks catch syntax)

**Security Note**: Per CLAUDE.md, logging errors is preferred for security auditing and debugging. Only use `_` prefix if error genuinely contains no useful information.

### 3. Unused Function Parameters (Estimated ~80 warnings)

**Pattern**: Function parameter that isn't used in the function body.

**Example**:
```typescript
// BEFORE (warning):
const handleClick = (event, index) => {  // 'event' is never used
  setSelectedIndex(index);
};

// AFTER (fixed):
const handleClick = (_event, index) => {  // Prefix indicates intentionally unused
  setSelectedIndex(index);
};
```

**Fix Strategy**:
- ✅ **SAFE**: Prefix with `_` to preserve function signature
- ❌ **DON'T**: Remove parameter (may break callbacks expecting specific signature)

**Why Preserve**: Many callback signatures (e.g., event handlers) require specific parameters even if not all are used.

### 4. Unused Helper Functions (Estimated ~60 warnings)

**Pattern**: Function defined but never called.

**Example**:
```typescript
// BEFORE (warning):
const getSeverityColor = (severity: string) => {  // Assigned but never used
  switch (severity) {
    case 'critical': return 'error';
    case 'high': return 'warning';
    default: return 'info';
  }
};
```

**Fix Strategy**:
- ⚠️ **MANUAL REVIEW REQUIRED**: Could be future use or dead code
- Option 1: Remove if truly unused (check git history for intent)
- Option 2: Prefix with `_` if planned for future use
- Option 3: Export and use immediately if should be active

**Check Before Removing**:
1. Git history: `git log -p --all -S 'getSeverityColor'`
2. Related issues/PRs mentioning the function
3. Similar patterns in other files (may indicate future refactoring)

### 5. Unused Constants (Estimated ~49 warnings)

**Pattern**: Constant declared but never referenced.

**Example**:
```typescript
// BEFORE (warning):
const PIE_COLORS = ['#4CAF50', '#2196F3', '#FF9800'];  // Never used

// AFTER (fixed):
// Remove entirely if truly unused, or use it in the visualization
```

**Fix Strategy**:
- ⚠️ **MANUAL REVIEW REQUIRED**: May indicate incomplete feature
- Check if constant was meant to be used nearby
- Check git history for original intent
- Remove only if clearly dead code

---

## Systematic Remediation Process

### Phase 1: Low-Hanging Fruit (Estimated: 200 warnings, 2-3 hours)

**Target**: Unused imports only

**Process**:
```bash
# For each file with unused imports:
1. Run: npx eslint --fix src/path/to/file.tsx
2. Review diff to ensure only imports removed
3. Verify file still compiles: npm run build
4. Commit in batches of 10 files
```

**Expected Outcome**: ~200 warnings fixed, no functional changes

### Phase 2: Error Handling Improvements (Estimated: 50 warnings, 1-2 hours)

**Target**: Unused error variables in catch blocks

**Process**:
```bash
# For each unused error variable:
1. Decide: Should this error be logged?
2. If YES: Add console.error() statement
3. If NO: Prefix with underscore
4. Commit in batches (by error handling improvement)
```

**Expected Outcome**: Improved error visibility + ~50 warnings fixed

### Phase 3: Function Signatures (Estimated: 80 warnings, 1 hour)

**Target**: Unused function parameters

**Process**:
```bash
# For each unused parameter:
1. Verify parameter is required by callback signature
2. Prefix with underscore
3. Add comment if signature constraint is non-obvious
4. Commit in batches
```

**Example**:
```typescript
// Callback signature requires (event, index) even if event unused
const handleRowClick = (_event: React.MouseEvent, index: number) => {
  setSelectedRow(index);
};
```

**Expected Outcome**: ~80 warnings fixed, clearer intent

### Phase 4: Dead Code Analysis (Estimated: 109 warnings, 3-4 hours)

**Target**: Unused functions and constants

**Process**:
```bash
# For each unused function/constant:
1. Run: git log -p --all -S 'functionName'
2. Check: Is this incomplete feature or dead code?
3. Decision:
   - Dead code: Remove
   - Future use: Add TODO comment + prefix with _
   - Incomplete: Create issue + keep
4. Commit individually with explanation
```

**Expected Outcome**: Cleaner codebase, documented future work

---

## File-by-File Tracking

### High Priority Files (10+ warnings each)

| File | Warnings | Category Focus | Estimated Time |
|------|----------|----------------|----------------|
| *To be populated during remediation* | | | |

---

## Success Criteria

- [ ] All 439 unused variable warnings addressed
- [ ] No functionality broken (verified by tests)
- [ ] Error logging improved where appropriate
- [ ] Dead code removed with git history check
- [ ] Future-use code documented with TODOs
- [ ] All changes reviewed and committed

---

## Safety Checklist

Before committing any unused variable fix:

- [ ] File compiles without errors
- [ ] Related tests still pass
- [ ] No functional code removed (only unused declarations)
- [ ] Error handling not degraded (errors logged or intentionally ignored)
- [ ] Function signatures preserved (callbacks)
- [ ] Git diff reviewed line-by-line

---

## Automation Opportunities

### ESLint Auto-Fix

ESLint can automatically fix some patterns:

```bash
# Fix unused imports automatically
npx eslint --fix --rule '@typescript-eslint/no-unused-vars: [error]' src/
```

**Limitations**:
- Cannot determine if unused function is dead code vs future use
- Cannot decide if error should be logged vs ignored
- Requires manual review for safety

### Custom Script

See `scripts/fix-unused-vars.sh` for guidance on systematic manual review.

---

## Estimated Timeline

| Phase | Description | Warnings Fixed | Time Estimate |
|-------|-------------|----------------|---------------|
| 1 | Unused imports | ~200 | 2-3 hours |
| 2 | Error variables | ~50 | 1-2 hours |
| 3 | Function parameters | ~80 | 1 hour |
| 4 | Dead code analysis | ~109 | 3-4 hours |
| **Total** | | **439** | **7-10 hours** |

---

## Related Documentation

- [LINTING_REMEDIATION_PLAN.md](./LINTING_REMEDIATION_PLAN.md) - Overall linting strategy
- [CLAUDE.md](../CLAUDE.md) - Coding standards and security requirements

---

## Notes

- This remediation is **code quality only** - no functional changes expected
- All fixes should follow CLAUDE.md standards for comments and clarity
- Prioritize error logging improvements over mechanical fixes
- Document any uncertain decisions with TODO comments

**Status**: Ready to begin Phase 1 (Unused Imports)
