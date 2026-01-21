# Epic E4: Frontend Refactoring

**Epic ID**: E4
**Priority**: P2 (Medium)
**Phase**: 3-4 (Week 5-8)
**Owner**: AI (Claude) with Human review
**Status**: Not Started
**Depends On**: E1 (Route changes may affect API calls)

---

## 1. Epic Summary

Extract oversized components, standardize state management patterns, and centralize API response handling to improve frontend maintainability.

---

## 2. Problem Statement

The frontend has:
- **3 components exceeding 2,000 lines** (ScanDetail, Hosts, AddHost)
- **Inconsistent state management** (Redux thunks vs services vs React Query)
- **Scattered API response mapping** (snake_case → camelCase in multiple files)
- **No global error boundary integration**

This creates:
- Difficult testing of large components
- Developer confusion about which pattern to use
- Duplicated transformation logic
- Poor error handling UX

---

## 3. Goals

| Goal | Metric | Target |
|------|--------|--------|
| Reduce component size | Components >1000 LOC | 0 |
| Standardize state | State patterns | 2 (Redux UI, RQ server) |
| Centralize API handling | Response adapters | 1 per domain |
| Improve error handling | Global error boundary | Yes |

---

## 4. Current State Analysis

### 4.1 Oversized Components

| Component | Lines | Issue |
|-----------|-------|-------|
| `ScanDetail.tsx` | 2,289 | Progress, results, actions all in one |
| `Hosts.tsx` | 2,014 | Table, grid, import, filters all in one |
| `AddHost.tsx` | 1,866 | Multi-step form in single file |

### 4.2 State Management Patterns

| Pattern | Usage | Files |
|---------|-------|-------|
| Redux async thunks | Host operations | `hostSlice.ts` |
| Direct fetch services | Scan operations | `scanService.ts` |
| React Query | Frameworks | `useFrameworks.ts` |

### 4.3 API Response Handling

Snake_case to camelCase transformation exists in:
- `Dashboard.tsx`
- `Hosts.tsx`
- `useHostData.ts`
- Various other components

---

## 5. User Stories

### Story E4-S1: Extract ScanDetail Components
**Priority**: P1 | **Points**: 5 | **Status**: Not Started

**As a** developer,
**I want** ScanDetail broken into smaller components,
**So that** each part is testable and maintainable.

**Acceptance Criteria**:
- [ ] `pages/scans/ScanDetail/` directory created
- [ ] `index.tsx` - Orchestration only (~200 LOC)
- [ ] `ScanProgress.tsx` - Progress tracking UI
- [ ] `ResultsOverview.tsx` - Summary statistics
- [ ] `RuleResults.tsx` - Rule-by-rule results
- [ ] `HostResults.tsx` - Per-host breakdown
- [ ] `ScanActions.tsx` - Retry, export, cancel
- [ ] `hooks/useScanPolling.ts` - Polling logic
- [ ] `hooks/useScanResults.ts` - Results fetching
- [ ] Original functionality preserved
- [ ] All tests pass

**Target Structure**:
```
pages/scans/ScanDetail/
├── index.tsx              # Main orchestration
├── ScanProgress.tsx       # Progress bar, status
├── ResultsOverview.tsx    # Stats cards
├── RuleResults.tsx        # Rules table
├── HostResults.tsx        # Hosts breakdown
├── ScanActions.tsx        # Action buttons
├── types.ts               # Local types
└── hooks/
    ├── useScanPolling.ts
    └── useScanResults.ts
```

---

### Story E4-S2: Extract Hosts Page Components
**Priority**: P1 | **Points**: 5 | **Status**: Not Started

**As a** developer,
**I want** Hosts page broken into smaller components,
**So that** each view mode is independent.

**Acceptance Criteria**:
- [ ] `pages/hosts/Hosts/` directory created
- [ ] `index.tsx` - Orchestration only
- [ ] `HostTable.tsx` - Table view
- [ ] `HostGrid.tsx` - Grid/card view
- [ ] `HostFilters.tsx` - Filter UI
- [ ] `BulkImport.tsx` - Import dialog
- [ ] `hooks/useHostActions.ts` - CRUD operations
- [ ] Original functionality preserved
- [ ] All tests pass

---

### Story E4-S3: Extract AddHost Form Components
**Priority**: P2 | **Points**: 4 | **Status**: Not Started

**As a** developer,
**I want** AddHost form split by section,
**So that** form logic is modular.

**Acceptance Criteria**:
- [ ] `pages/hosts/AddHost/` directory created
- [ ] `index.tsx` - Form orchestration
- [ ] `IdentificationStep.tsx` - Hostname, IP, display name
- [ ] `AuthenticationStep.tsx` - SSH credentials
- [ ] `ConfigurationStep.tsx` - SCAP configuration
- [ ] `hooks/useAddHostForm.ts` - Form state
- [ ] Original functionality preserved
- [ ] All tests pass

---

### Story E4-S4: Create API Response Adapters
**Priority**: P1 | **Points**: 4 | **Status**: Not Started

**As a** developer,
**I want** centralized API response transformation,
**So that** snake_case → camelCase is consistent.

**Acceptance Criteria**:
- [ ] `services/adapters/` directory created
- [ ] `services/adapters/index.ts` - Exports all adapters
- [ ] `services/adapters/hostAdapter.ts` - Host response mapping
- [ ] `services/adapters/scanAdapter.ts` - Scan response mapping
- [ ] `services/adapters/ruleAdapter.ts` - Rule response mapping
- [ ] `services/adapters/frameworkAdapter.ts` - Framework mapping
- [ ] All components use adapters instead of inline transformation
- [ ] Type safety preserved

**Adapter Pattern**:
```typescript
// services/adapters/hostAdapter.ts
import type { Host } from '@/types/host';

interface ApiHostResponse {
  id: string;
  hostname: string;
  display_name: string;
  ip_address: string;
  operating_system: string;
  compliance_score: number;
  // ... other snake_case fields
}

export function adaptHostResponse(api: ApiHostResponse): Host {
  return {
    id: api.id,
    hostname: api.hostname,
    displayName: api.display_name,
    ipAddress: api.ip_address,
    operatingSystem: api.operating_system,
    complianceScore: api.compliance_score,
    // ... other mappings
  };
}

export function adaptHostsResponse(apis: ApiHostResponse[]): Host[] {
  return apis.map(adaptHostResponse);
}
```

---

### Story E4-S5: Standardize State Management
**Priority**: P1 | **Points**: 5 | **Status**: Not Started

**As a** developer,
**I want** consistent state management patterns,
**So that** I know which tool to use when.

**Acceptance Criteria**:
- [ ] Document created: `frontend/STATE_MANAGEMENT.md`
- [ ] Guidelines established:
  - Redux: UI state only (theme, modals, auth session, notifications)
  - React Query: ALL server state (hosts, scans, rules, frameworks)
- [ ] `hostSlice.ts` refactored to remove async thunks
- [ ] Host data fetching moved to React Query hooks
- [ ] No state management pattern mixing
- [ ] All tests pass

**Pattern Documentation**:
```markdown
# State Management Guidelines

## Redux (UI State)
Use for:
- Authentication session (token, user)
- UI preferences (theme, sidebar state)
- Notifications/toasts
- Modal state

Do NOT use for:
- Server data (hosts, scans, rules)
- Loading states for API calls
- Error states for API calls

## React Query (Server State)
Use for:
- All API data fetching
- Cache management
- Loading/error states
- Optimistic updates

Benefits:
- Automatic caching
- Background refetching
- Loading/error states built-in
- Deduplication of requests
```

---

### Story E4-S6: Implement Global Error Boundary
**Priority**: P2 | **Points**: 3 | **Status**: Not Started

**As a** user,
**I want** graceful error handling,
**So that** the app doesn't crash unexpectedly.

**Acceptance Criteria**:
- [ ] Global `ErrorBoundary` wraps App
- [ ] Error boundary catches render errors
- [ ] User-friendly error message displayed
- [ ] Error logged for debugging
- [ ] Recovery option (reload) provided
- [ ] Integration with Redux error state (if applicable)

---

### Story E4-S7: Add Frontend Component Tests
**Priority**: P2 | **Points**: 4 | **Status**: Not Started

**As a** developer,
**I want** unit tests for extracted components,
**So that** refactoring is safe.

**Acceptance Criteria**:
- [ ] Tests for ScanProgress, ResultsOverview
- [ ] Tests for HostTable, HostFilters
- [ ] Tests for API adapters
- [ ] Tests for custom hooks
- [ ] 60% coverage on new components

---

### Story E4-S8: Centralize localStorage Access
**Priority**: P2 | **Points**: 2 | **Status**: Not Started

**As a** developer,
**I want** localStorage access centralized,
**So that** keys are consistent.

**Acceptance Criteria**:
- [ ] `services/storage.ts` created
- [ ] All localStorage keys defined as constants
- [ ] Type-safe get/set functions
- [ ] All direct localStorage calls migrated
- [ ] Single source of truth for storage keys

**Implementation**:
```typescript
// services/storage.ts
const STORAGE_KEYS = {
  AUTH_TOKEN: 'auth_token',
  REFRESH_TOKEN: 'refresh_token',
  USER: 'auth_user',
  SESSION_EXPIRY: 'session_expiry',
  THEME: 'themeMode',
} as const;

export function getAuthToken(): string | null {
  return localStorage.getItem(STORAGE_KEYS.AUTH_TOKEN);
}

export function setAuthToken(token: string): void {
  localStorage.setItem(STORAGE_KEYS.AUTH_TOKEN, token);
}

// ... other typed accessors
```

---

## 6. Dependencies

```mermaid
graph TD
    E1[Epic E1: Routes] --> S4[E4-S4: Adapters]
    S4 --> S1[E4-S1: ScanDetail]
    S4 --> S2[E4-S2: Hosts]
    S4 --> S3[E4-S3: AddHost]
    S5[E4-S5: State Mgmt] --> S1
    S5 --> S2
    S1 --> S7[E4-S7: Tests]
    S2 --> S7
    S3 --> S7
    S6[E4-S6: Error Boundary] --> S7
    S8[E4-S8: Storage] --> S5
```

**Execution Order**:
1. S4 (Adapters) - Foundation for other work
2. S5, S8 (State management, storage - parallel)
3. S1, S2, S3 (Component extraction - can be parallel)
4. S6 (Error boundary)
5. S7 (Tests)

---

## 7. Risks and Mitigations

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| Breaking existing functionality | High | Medium | Test thoroughly after each change |
| State migration issues | Medium | Medium | Gradual migration, not big bang |
| Performance regression | Medium | Low | Profile before/after |
| Styling breaks | Low | Medium | Visual testing |

---

## 8. Acceptance Criteria (Epic Level)

- [ ] No components exceed 1000 LOC
- [ ] State management documented and consistent
- [ ] API adapters in place for all domains
- [ ] Global error boundary implemented
- [ ] localStorage access centralized
- [ ] 60% test coverage on new code

---

## 9. Definition of Done

- [ ] All stories completed
- [ ] Code reviewed and approved
- [ ] Tests pass
- [ ] No visual regressions
- [ ] Documentation updated
- [ ] Committed with proper messages

---

## 10. Component Size Guidelines

After this epic, all components should follow:

| Component Type | Max Lines | Rationale |
|----------------|-----------|-----------|
| Page (orchestration) | 300 | Composition only |
| Feature component | 500 | Single feature |
| Reusable component | 200 | Design system |
| Custom hook | 150 | Single concern |
| Adapter/utility | 100 | Pure transformation |

If a component exceeds these limits, it should be split.
