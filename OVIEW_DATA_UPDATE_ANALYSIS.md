# /OView Data Update Analysis

## Current Update Mechanisms

### Security Audit Tab

#### Current Behavior:
1. **Initial Load**: Data loads on component mount via `useEffect(() => { loadAuditEvents(); }, [])`
2. **Filter Changes**: Data automatically reloads when ANY filter changes via `useEffect` dependency array
3. **Manual Refresh**: User clicks refresh button → calls `handleRefresh()` → reloads events and stats
4. **Pagination**: Triggers new API call when page changes

**Update Triggers:**
```typescript
useEffect(() => {
  loadAuditEvents();
}, [page, rowsPerPage, searchQuery, actionFilter, resourceFilter, severityFilter, userFilter, dateFrom, dateTo]);
```

**Problem**: ❌ **Full component re-render on every filter change**
- Every filter keystroke triggers API call
- No debouncing or throttling
- Stats cards reload unnecessarily (they don't change with filters)
- Table re-renders completely even if data structure hasn't changed

#### What Happens:
```
User types "admin" in search box:
1. "a" → API call → Full table re-render
2. "ad" → API call → Full table re-render
3. "adm" → API call → Full table re-render
4. "admi" → API call → Full table re-render
5. "admin" → API call → Full table re-render
```

---

### Host Monitoring Tab

#### Current Behavior:
1. **Initial Load**: Data loads on component mount via `useEffect(() => { fetchMonitoringData(); }, [])`
2. **Filter Changes**: ✅ **Client-side filtering** - no API calls, only React state updates
3. **Manual Refresh**: Parent calls `hostMonitoringRef.current?.refresh()` → reloads all data
4. **Pagination**: ✅ **Client-side pagination** - no API calls, only state updates

**Update Triggers:**
```typescript
useEffect(() => {
  fetchMonitoringData();
}, []); // Only loads once on mount

// Filtering logic:
const filteredHosts = allHosts.filter(host => {
  const matchesSearch = !searchQuery ||
    host.hostname.toLowerCase().includes(searchQuery.toLowerCase()) ||
    host.ip_address.toLowerCase().includes(searchQuery.toLowerCase());
  const matchesState = !stateFilter || host.current_state === stateFilter;
  return matchesSearch && matchesState;
});

// Pagination logic:
const paginatedHosts = filteredHosts.slice(
  page * rowsPerPage,
  page * rowsPerPage + rowsPerPage
);
```

**Better Approach**: ✅ **Client-side filtering is efficient**
- No unnecessary API calls
- Only table rows re-render
- Stats cards don't re-render when filtering
- Smooth, instantaneous filtering

---

## Issues Identified

### Security Audit Tab Issues:

1. **❌ No Debouncing on Search Input**
   - Every keystroke triggers API call
   - Should wait until user stops typing (300-500ms delay)

2. **❌ Stats Cards Reload Unnecessarily**
   - Stats don't change when filtering events
   - `loadAuditStats()` called in `handleRefresh()` even though filters don't affect stats
   - Should load stats separately on mount only

3. **❌ Full Table Re-renders**
   - React re-renders entire table on every state change
   - Should use `React.memo()` for row components
   - Should use `useMemo()` for filtered data

4. **❌ No Automatic Real-Time Updates**
   - User must manually click refresh
   - No polling or WebSocket updates for new audit events
   - Critical events could be missed

5. **❌ Filter State Not Persisted**
   - If user switches tabs and comes back, filters reset
   - Page number resets to 0

### Host Monitoring Tab Issues:

1. **❌ No Automatic Real-Time Updates**
   - User must manually click refresh
   - Host states could change but user won't know
   - No polling interval for state updates

2. **❌ Stats Cards Reload Unnecessarily on Refresh**
   - Full `fetchMonitoringData()` reloads everything
   - Should separate stats refresh from host list refresh

3. **❌ Filter State Not Persisted**
   - If user switches tabs and comes back, filters reset
   - Page number resets to 0

4. **✅ Good: Client-side filtering is efficient**
   - No API calls on filter changes
   - Instant response

---

## Recommended React-Native Data Update Pattern

### Principle: **Smart Component Updates**
- Only fetch data that changed
- Use client-side filtering when dataset is reasonable (<1000 items)
- Debounce user inputs
- Use React.memo() and useMemo() to prevent unnecessary re-renders
- Implement automatic polling or WebSocket for real-time data
- Persist filter state when switching tabs

### Ideal Architecture:

```typescript
// SECURITY AUDIT TAB - Improved Pattern

// 1. Separate stats loading (once on mount)
useEffect(() => {
  loadAuditStats();
}, []); // Stats never reload

// 2. Debounced search input
const debouncedSearchQuery = useDebounce(searchQuery, 500); // Wait 500ms after typing stops

// 3. Smart data fetching
useEffect(() => {
  loadAuditEvents();
}, [page, rowsPerPage, debouncedSearchQuery, actionFilter, resourceFilter, severityFilter]);

// 4. Memoized filtered data (if doing client-side filtering)
const filteredEvents = useMemo(() => {
  return events.filter(event => /* filtering logic */);
}, [events, searchQuery, actionFilter, resourceFilter]);

// 5. Memoized table rows
const EventRow = React.memo(({ event }: { event: AuditEvent }) => (
  <TableRow key={event.id} hover>
    {/* row content */}
  </TableRow>
));

// 6. Automatic polling for real-time updates
useEffect(() => {
  const interval = setInterval(() => {
    loadAuditEvents(); // Refresh every 30 seconds
    loadAuditStats(); // Refresh stats every 30 seconds
  }, 30000);
  return () => clearInterval(interval);
}, []);
```

```typescript
// HOST MONITORING TAB - Improved Pattern

// 1. Separate stats from host list
const fetchStats = async () => {
  const stateResponse = await api.get('/api/monitoring/hosts/status');
  setStateDistribution(stateResponse.data || stateResponse);
};

const fetchHosts = async () => {
  const hostsResponse = await api.get('/api/hosts/');
  // ... load host details
  setAllHosts(hostDetails);
};

// 2. Initial load
useEffect(() => {
  fetchStats();
  fetchHosts();
}, []);

// 3. Automatic polling for real-time monitoring
useEffect(() => {
  const interval = setInterval(() => {
    fetchStats(); // Refresh stats every 30 seconds
    fetchHosts(); // Refresh host states every 30 seconds
  }, 30000);
  return () => clearInterval(interval);
}, []);

// 4. Expose separate refresh functions
useImperativeHandle(ref, () => ({
  refresh: async () => {
    await Promise.all([fetchStats(), fetchHosts()]);
  },
  refreshStats: fetchStats,
  refreshHosts: fetchHosts
}));

// 5. Client-side filtering (already good!)
const filteredHosts = useMemo(() => {
  return allHosts.filter(host => {
    const matchesSearch = !searchQuery ||
      host.hostname.toLowerCase().includes(searchQuery.toLowerCase()) ||
      host.ip_address.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesState = !stateFilter || host.current_state === stateFilter;
    return matchesSearch && matchesState;
  });
}, [allHosts, searchQuery, stateFilter]);
```

---

## Specific Problems with Current Implementation

### Problem 1: Stats Cards Flash/Reload Unnecessarily

**Current Behavior:**
```typescript
const handleRefresh = async () => {
  if (activeTab === 0) {
    loadAuditEvents();    // ← Good
    loadAuditStats();     // ← BAD: Stats don't change with filters
  }
};
```

**Solution:**
- Stats should only load on mount
- Refresh button should only reload events table (respecting current filters)
- Add separate "Refresh All" button if stats need manual refresh

### Problem 2: Search Input Triggers Too Many API Calls

**Current Behavior:**
```typescript
<TextField
  value={searchQuery}
  onChange={(e) => setSearchQuery(e.target.value)} // ← Triggers useEffect immediately
/>

useEffect(() => {
  loadAuditEvents(); // ← Called on every keystroke
}, [searchQuery]);
```

**Solution:**
```typescript
import { useDebounce } from '../../hooks/useDebounce';

const [searchQuery, setSearchQuery] = useState('');
const debouncedSearchQuery = useDebounce(searchQuery, 500);

useEffect(() => {
  loadAuditEvents();
}, [debouncedSearchQuery]); // ← Only calls after user stops typing for 500ms
```

### Problem 3: No Real-Time Updates

**Current Behavior:**
- Data only updates when user manually clicks refresh
- Critical security events could occur but user won't see them
- Host monitoring states could change but user won't know

**Solution:**
```typescript
// Add automatic polling
useEffect(() => {
  const interval = setInterval(() => {
    if (activeTab === 0) {
      loadAuditEvents(); // Refresh audit events every 30s
    } else if (activeTab === 1) {
      hostMonitoringRef.current?.refresh(); // Refresh monitoring every 30s
    }
  }, 30000);

  return () => clearInterval(interval);
}, [activeTab]);
```

### Problem 4: Filter State Lost on Tab Switch

**Current Behavior:**
```typescript
// User on Security Audit tab:
// - Sets search query to "admin"
// - Sets severity filter to "error"
// - Goes to page 3

// Switches to Host Monitoring tab
// Switches back to Security Audit tab

// Result: All filters reset, back to page 1
```

**Solution:**
- Filters and pagination state already persist (they're in parent component)
- ✅ This is actually working correctly
- Only issue: User expects data to be fresh when switching back (solution: automatic polling)

---

## Summary: What Needs to Change

### Security Audit Tab:
1. ✅ **Add debouncing to search input** (500ms delay)
2. ✅ **Separate stats loading** (only on mount, not on filter changes)
3. ✅ **Add automatic polling** (every 30 seconds)
4. ✅ **Use React.memo() for table rows** (prevent unnecessary re-renders)
5. ✅ **Use useMemo() for filtered data** (optimize performance)

### Host Monitoring Tab:
1. ✅ **Add automatic polling** (every 30 seconds)
2. ✅ **Separate stats refresh from host list refresh** (allow granular updates)
3. ✅ **Use useMemo() for filtered data** (optimize performance)
4. ✅ **Add visual indicator for last update time** (show "Last updated: 5 seconds ago")

### Both Tabs:
1. ✅ **Add loading state per component** (stats cards vs table vs filters)
2. ✅ **Add "Last Updated" timestamp** (show when data was last refreshed)
3. ✅ **Add pause/resume button for auto-refresh** (let user control polling)
4. ✅ **Add visual feedback on data refresh** (subtle animation or indicator)

---

## Desired User Experience

**User Interaction Flow:**

```
1. User navigates to /OView
   → Stats cards load (once)
   → Events/hosts table loads (once)
   → Automatic polling starts (every 30s)

2. User types in search box
   → Debounced: waits 500ms after user stops typing
   → API call fetches filtered data
   → Only table updates, stats cards don't flash

3. User changes filter dropdown
   → API call fetches filtered data immediately (no debounce needed)
   → Only table updates, stats cards don't flash

4. User switches to another tab
   → Filters and page number persist
   → Automatic polling continues for visible tab only

5. User switches back to previous tab
   → Filters and page number still set
   → Fresh data already loaded (via polling)

6. User clicks manual refresh
   → Immediate refresh of current tab's data
   → Visual feedback (spinner or checkmark)
   → Reset polling timer

7. User leaves tab idle
   → Automatic polling continues every 30s
   → New data appears without user intervention
   → Subtle visual indicator (e.g., "Updated 3s ago")
```

---

## Next Steps

1. Create `useDebounce` custom hook
2. Refactor Security Audit tab data loading
3. Add automatic polling to both tabs
4. Add "Last Updated" timestamp UI
5. Add pause/resume auto-refresh controls
6. Optimize with React.memo() and useMemo()
7. Test performance with large datasets
