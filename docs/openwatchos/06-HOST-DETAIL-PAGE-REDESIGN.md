# 06 - Host Detail Page Redesign

**Last Updated**: 2026-02-18
**Status**: Mostly Complete (Exceptions and Alerts integration pending)
**Part of**: OpenWatch OS Transformation

---

## Table of Contents

1. [Overview](#overview)
2. [Design Principles](#design-principles)
3. [What Changed](#what-changed)
4. [Component Architecture](#component-architecture)
5. [Page Layout](#page-layout)
6. [Summary Cards](#summary-cards)
7. [Tabs](#tabs)
8. [Data Sources and API Endpoints](#data-sources-and-api-endpoints)
9. [Type System](#type-system)
10. [React Query Integration](#react-query-integration)
11. [Phase Breakdown](#phase-breakdown)
12. [Implementation Status](#implementation-status)
13. [File Inventory](#file-inventory)

---

## Overview

The Host Detail Page Redesign is a core part of the OpenWatch OS Transformation, which shifts
OpenWatch from a manual-scan SCAP scanner into an auto-scan centric Compliance Operating System.

The old Host Detail page was built around manual scan workflows. It had prominent "Start New Scan",
"Establish Baseline", and "Run Aegis Scan" buttons, a basic compliance state view, and a scan
history table with a "Start First Scan" call-to-action. It treated each host as a passive target
that operators triggered scans against.

The redesigned page removes all manual scan buttons and instead treats every host as a continuously
monitored endpoint. Compliance scans run automatically via the Adaptive Compliance Scheduler.
The page now surfaces six summary cards for at-a-glance status and nine tabs for deep inspection
of compliance findings, installed packages, running services, user accounts, network configuration,
audit events, scan history, and a live SSH terminal.

---

## Design Principles

### Auto-Scan Centric

Scans are not something operators trigger -- they happen automatically on adaptive schedules with
a maximum 48-hour interval. The page reflects this by:

- Removing all "Start Scan" and "Run Scan" buttons from the header and tabs
- Showing auto-scan status (enabled/paused, last scan, next scan, interval) as a first-class
  summary card
- Displaying compliance state as a living metric that updates after each automatic scan
- Using language like "Awaiting first scan" instead of "Start First Scan"

### Clean UI

Following the OpenWatch OS UI design principles:

- **Purposeful icons only**: Status dots (8px colored circles) for online/offline and
  enabled/disabled states. No decorative icons on cards. Tab icons use Material-UI icons
  sparingly and only where they contribute to scannability.
- **Clean color usage**: Dark background, white/gray text hierarchy. Color is reserved for
  status indicators (success green, error red, warning amber) and is applied to text and small
  dots, not to large blocks or card backgrounds.
- **No color blocks for cards**: All cards use the default paper background. Data is presented
  as plain text with label-value pairs.
- **Readability first**: Clear typography hierarchy using MUI variants (h3 for scores, h6 for
  card headings, body2 for data, caption for timestamps). Adequate whitespace via MUI spacing
  units.

### Data as Plain Text

Summary cards and tab content display data as simple label-value pairs:

```
OS: Red Hat Enterprise Linux 9.4
Kernel: 5.14.0-362.el9.x86_64
Uptime: 14d 7h
Memory: 15.6 GB
```

No boxed elements, no gradient effects, no competing colors. The data speaks for itself.

### Skeleton Loading States

Every card and tab implements skeleton loading states using MUI `Skeleton` components. When data
is loading, the card shows placeholder shapes that match the final layout dimensions. This prevents
layout shift and communicates loading progress without spinners on every card.

---

## What Changed

### Removed

- "Start New Scan" button from header
- "Establish Baseline" button from header
- "Run Aegis Scan" button from Compliance State tab
- "Start First Scan" button from Scan History tab
- Monolithic single-component page structure

### Added

- `HostDetailHeader` -- simplified header with back navigation, host title, IP/OS/kernel subtitle,
  and status chip (no scan buttons)
- `HostSummaryCards` -- six summary cards in a responsive 3-column grid
- `ComplianceCard` -- compliance score, pass/fail counts, critical findings
- `SystemHealthCard` -- OS, kernel, uptime, memory, CPU from server intelligence
- `AutoScanCard` -- enabled/paused status, last/next scan, interval, failures
- `ExceptionsCard` -- active and pending compliance exception counts
- `AlertsCard` -- active alert count with severity breakdown
- `ConnectivityCard` -- online/offline status, SSH connection details
- `OverviewTab` -- system info, hardware, server intelligence summary, compliance trend chart
- `ComplianceTab` -- full findings table with search, filter by status, severity breakdown
- `PackagesTab` -- installed packages with search and pagination
- `ServicesTab` -- system services with status filtering and search
- `UsersTab` -- user accounts with sudo filtering, system account toggle, security indicators
- `NetworkTab` -- sub-tabs for interfaces, firewall rules, and routes
- `AuditLogTab` -- placeholder for future audit log collection
- `HistoryTab` -- scan history table with compliance trend chart
- `TerminalTab` -- embedded SSH terminal via `HostTerminal` component
- `hostDetailAdapter.ts` -- API adapter with snake_case to camelCase transformation
- `useHostDetail.ts` -- React Query hooks for all host detail data
- `types/hostDetail.ts` -- TypeScript type definitions for all host detail data

---

## Component Architecture

### Page Layout

```
HostDetail (index.tsx)
|
+-- HostDetailHeader
|     Back button, hostname/display name, IP/OS/kernel subtitle, StatusChip
|
+-- HostSummaryCards
|     |
|     +-- Row 1: ComplianceCard | SystemHealthCard | AutoScanCard
|     +-- Row 2: ExceptionsCard | AlertsCard       | ConnectivityCard
|
+-- Tabs (MUI Tabs, scrollable)
      |
      +-- Tab 0: OverviewTab
      +-- Tab 1: ComplianceTab
      +-- Tab 2: PackagesTab
      +-- Tab 3: ServicesTab
      +-- Tab 4: UsersTab
      +-- Tab 5: NetworkTab (sub-tabs: Interfaces, Firewall, Routes)
      +-- Tab 6: AuditLogTab
      +-- Tab 7: HistoryTab
      +-- Tab 8: TerminalTab
```

### Data Flow

The main `HostDetail` component fetches all data and passes it down:

1. **Basic host data** is fetched via a direct `api.get(/api/hosts/{id})` call in a `useEffect`
2. **Compliance state** via `useComplianceState(id)` React Query hook
3. **Schedule data** via `useHostSchedule(id)` React Query hook
4. **System info** via `useSystemInfo(id)` React Query hook
5. **Intelligence summary** via `useIntelligenceSummary(id)` React Query hook
6. **Scan history** via `useScanHistory(id)` React Query hook

Summary cards receive data as props from the parent. Tab components that need paginated data
(Packages, Services, Users, Network) fetch their own data via dedicated React Query hooks,
taking `hostId` as a prop.

### Barrel Exports

Both the `cards/` and `tabs/` directories use barrel export files (`index.ts`) so the main
page component can import all components from a single path:

```typescript
import { ComplianceCard, SystemHealthCard, ... } from './cards';
import { OverviewTab, ComplianceTab, ... } from './tabs';
```

---

## Summary Cards

All six cards are rendered in a responsive MUI Grid with `spacing={2}`. Each card uses
`minHeight: 180` for visual consistency. Cards display skeleton loaders while data is being
fetched and graceful empty states when no data is available.

### 1. Compliance Card

**File**: `frontend/src/pages/hosts/HostDetail/cards/ComplianceCard.tsx`

Displays compliance posture from the most recent Aegis scan.

| Field | Source |
|-------|--------|
| Compliance score (percentage) | `complianceState.complianceScore` |
| Compliance label (Compliant/Mostly Compliant/Partial/Low/Critical) | Derived from score thresholds |
| Passed count | `complianceState.passed` |
| Failed count | `complianceState.failed` |
| Critical findings count | `complianceState.severitySummary.critical.failed` |
| Last scan date | `complianceState.scanDate` |

Score color thresholds: >= 80% green, >= 60% amber, < 60% red.

### 2. System Health Card

**File**: `frontend/src/pages/hosts/HostDetail/cards/SystemHealthCard.tsx`

Displays OS and hardware information from server intelligence collection.

| Field | Source |
|-------|--------|
| Operating system | `systemInfo.osPrettyName` or `systemInfo.osName` |
| Kernel release | `systemInfo.kernelRelease` |
| Uptime | `systemInfo.uptimeSeconds` (formatted as days/hours/minutes) |
| Total memory | `systemInfo.memoryTotalMb` (formatted as GB) |
| CPU cores | `systemInfo.cpuCores` |

### 3. Auto-Scan Card

**File**: `frontend/src/pages/hosts/HostDetail/cards/AutoScanCard.tsx`

Displays compliance scheduler status for this host.

| Field | Source |
|-------|--------|
| Enabled/Maintenance Mode status | `schedule.maintenanceMode` (inverted for enabled) |
| Status indicator dot | Green if enabled, amber if maintenance mode |
| Last scan completed | `schedule.lastScanCompleted` (relative time) |
| Next scheduled scan | `schedule.nextScheduledScan` (relative time) |
| Current interval | `schedule.currentIntervalMinutes` |
| Maintenance until | `schedule.maintenanceUntil` (shown only if set) |
| Consecutive failures | `schedule.consecutiveScanFailures` (shown only if > 0) |

### 4. Exceptions Card

**File**: `frontend/src/pages/hosts/HostDetail/cards/ExceptionsCard.tsx`

Displays compliance exception counts for governance tracking. Requires OpenWatch+ for full
functionality.

| Field | Source |
|-------|--------|
| Active exception count | `exceptionsActive` prop |
| Pending approval count | `exceptionsPending` prop |
| Expiring soon count | `exceptionsExpiringSoon` prop |

**Note**: Currently receives placeholder values (0) from the parent component. Requires
integration with the exceptions API (`/api/compliance/exceptions`) filtered by host.

### 5. Alerts Card

**File**: `frontend/src/pages/hosts/HostDetail/cards/AlertsCard.tsx`

Displays active alert counts and severity breakdown.

| Field | Source |
|-------|--------|
| Active alert count | `alertsActive` prop |
| Critical alert count | `alertsCritical` prop |
| High alert count | `alertsHigh` prop |
| Most recent alert message | `recentAlertMessage` prop |
| Most recent alert time | `recentAlertTime` prop |

Alert count color: red if any critical, amber if any high, default otherwise.

**Note**: Currently receives placeholder values (0) from the parent component. Requires
integration with the alerts API (`/api/compliance/alerts`) filtered by host.

### 6. Connectivity Card

**File**: `frontend/src/pages/hosts/HostDetail/cards/ConnectivityCard.tsx`

Displays host connection status and SSH configuration.

| Field | Source |
|-------|--------|
| Online/Offline status | `host.status` |
| Status indicator dot | Green if online, red if offline |
| SSH connection string | `host.username@host.hostname:host.port` |
| IP address | `host.ipAddress` |
| Authentication method | `host.authMethod` (SSH Key / Password / Stored Credential) |
| Last connectivity check | `host.lastCheck` |

---

## Tabs

### Tab 0: Overview

**File**: `frontend/src/pages/hosts/HostDetail/tabs/OverviewTab.tsx`

A dashboard-style overview with four content cards in a 2x2 grid:

1. **System Information** -- OS, kernel, architecture, hostname/FQDN, primary IP, uptime.
   Uses MUI `List` with `ListItem`/`ListItemText` for label-value pairs.
2. **Hardware & Resources** -- CPU model/cores/threads, memory, disk usage (used/total/free),
   SELinux status and mode, firewall status and service.
3. **Server Intelligence** -- Summary counts of collected data: packages installed, services
   (running/total), users (total with sudo count), network interfaces, listening ports, firewall
   rules. Includes last collection timestamp.
4. **Compliance Trend** -- Line chart of compliance scores over time using the
   `ComplianceTrendChart` component. Data is derived from scan history.

**Data sources**: `systemInfo`, `intelligenceSummary`, `scanHistory` (all passed as props).

### Tab 1: Compliance

**File**: `frontend/src/pages/hosts/HostDetail/tabs/ComplianceTab.tsx`

Detailed compliance findings from the most recent Aegis scan.

**Summary section** (top): Four cards showing compliance score, passed count, failed count,
and severity breakdown (Critical/High/Medium/Low as chips with tooltips showing pass/fail counts).

**Filters**: Search by rule title, rule ID, or detail text. Filter chips for All/Failed/Passed.

**Findings table**: Columns are Status (icon), Severity (colored chip), Rule ID (monospace),
Title, and Detail (truncated to 300px). Uses `useMemo` for filtered results.

**Data source**: `complianceState` (passed as prop from parent).

### Tab 2: Packages

**File**: `frontend/src/pages/hosts/HostDetail/tabs/PackagesTab.tsx`

Searchable, paginated table of installed packages.

**Columns**: Package Name, Version (monospace), Release (monospace), Architecture, Repository.

**Features**: Text search with debounced server-side filtering, server-side pagination
(10/25/50/100 rows per page), total package count display.

**Data source**: `usePackages(hostId, { search, limit, offset })` hook, which calls
`GET /api/hosts/{id}/packages`.

### Tab 3: Services

**File**: `frontend/src/pages/hosts/HostDetail/tabs/ServicesTab.tsx`

Searchable, filterable, paginated table of system services.

**Columns**: Service Name (with display name subtitle), Status (colored chip: running/stopped/
failed/unknown), Enabled (Yes/No), Type, User (monospace), Listening Ports (chips showing
port/protocol, limited to 3 with overflow count).

**Features**: Text search, toggle button group for status filtering (All/Running/Stopped/Failed),
server-side pagination, total service count display.

**Data source**: `useServices(hostId, { search, status, limit, offset })` hook, which calls
`GET /api/hosts/{id}/services`.

### Tab 4: Users

**File**: `frontend/src/pages/hosts/HostDetail/tabs/UsersTab.tsx`

Searchable, filterable, paginated table of user accounts with security-relevant indicators.

**Columns**: Username (with "system" chip for system accounts), UID (monospace), Groups
(truncated), Shell (monospace), Sudo (ALL/NOPASSWD/Limited chips with color coding), Status
(Locked/No password/SSH key count chips), Last Login.

**Features**: Text search, "Show system accounts" toggle switch, "Sudo users only" toggle
switch, server-side pagination, total user count display.

**Security indicators**:
- NOPASSWD sudo: Red chip with warning icon (security risk)
- ALL sudo: Amber chip (elevated privilege)
- Locked accounts: Red "Locked" chip
- SSH key count displayed when > 0

**Data source**: `useUsers(hostId, { search, includeSystem, hasSudo, limit, offset })` hook,
which calls `GET /api/hosts/{id}/users`.

### Tab 5: Network

**File**: `frontend/src/pages/hosts/HostDetail/tabs/NetworkTab.tsx`

Three sub-tabs for network configuration, each with its own data source:

**Sub-tab: Interfaces** -- Table of network interfaces. Columns: Interface name, Status
(dot + Up/Down), IP Addresses (monospace with CIDR notation), MAC Address (monospace), Type,
MTU. Data from `useNetwork(hostId)` calling `GET /api/hosts/{id}/network`.

**Sub-tab: Firewall** -- Table of firewall rules. Columns: Rule number, Chain, Action (colored
chip: accept=green, drop/reject=red), Protocol, Source (monospace), Destination (monospace),
Port. Data from `useFirewall(hostId)` calling `GET /api/hosts/{id}/firewall`.

**Sub-tab: Routes** -- Table of network routes. Columns: Destination (monospace, with "default"
chip for default routes), Gateway (monospace), Interface, Metric, Type. Data from
`useRoutes(hostId)` calling `GET /api/hosts/{id}/routes`.

Each sub-tab label shows the count of items (e.g., "Interfaces (3)").

### Tab 6: Audit Log

**File**: `frontend/src/pages/hosts/HostDetail/tabs/AuditLogTab.tsx`

**Status**: Placeholder. Displays an informational alert stating that audit log collection is
not yet enabled. Will display security audit events (login attempts, privilege escalations,
file access) once audit log collection is configured.

### Tab 7: History

**File**: `frontend/src/pages/hosts/HostDetail/tabs/HistoryTab.tsx`

Scan history with compliance trend visualization.

**Scan table columns**: Scan Name (with content name subtitle), Status (icon + colored chip,
with progress bar for running scans), Compliance Score (colored chip), Issues (severity chips:
Critical/High/Medium), Started (timestamp), Duration (calculated), Actions (view details icon
button linking to `/scans/{scanId}`).

**Compliance Trend Chart**: Rendered below the table when there are 2+ completed scans. Uses
the `ComplianceTrendChart` component at 300px height.

**Note**: No "Start Scan" button. Empty state says "Compliance scans run automatically based
on the adaptive schedule."

**Data source**: `scanHistory` array (passed as prop from parent).

### Tab 8: Terminal

**File**: `frontend/src/pages/hosts/HostDetail/tabs/TerminalTab.tsx`

Thin wrapper around the `HostTerminal` component (`frontend/src/components/terminal/HostTerminal`).
Renders the terminal in a fixed 600px height container. Passes `hostId`, `hostname`, and
`ipAddress` to the terminal component.

---

## Data Sources and API Endpoints

### Endpoints Used by the Host Detail Page

| Data | Endpoint | Method | Adapter Function |
|------|----------|--------|------------------|
| Basic host info | `/api/hosts/{id}` | GET | Direct `api.get()` in component |
| Compliance state | `/api/scans/aegis/compliance-state/{hostId}` | GET | `fetchComplianceState()` |
| Host schedule | `/api/compliance/scheduler/hosts/{hostId}` | GET | `fetchHostSchedule()` |
| System info | `/api/hosts/{id}/system-info` | GET | `fetchSystemInfo()` |
| Intelligence summary | `/api/hosts/{id}/intelligence/summary` | GET | `fetchIntelligenceSummary()` |
| Packages | `/api/hosts/{id}/packages` | GET | `fetchPackages()` |
| Services | `/api/hosts/{id}/services` | GET | `fetchServices()` |
| Users | `/api/hosts/{id}/users` | GET | `fetchUsers()` |
| Network interfaces | `/api/hosts/{id}/network` | GET | `fetchNetwork()` |
| Firewall rules | `/api/hosts/{id}/firewall` | GET | `fetchFirewall()` |
| Routes | `/api/hosts/{id}/routes` | GET | `fetchRoutes()` |
| Scan history | `/api/scans/?host_id={id}` | GET | `fetchScanHistory()` |

### Endpoints Needed (Not Yet Integrated)

| Data | Endpoint | Purpose |
|------|----------|---------|
| Host exceptions | `/api/compliance/exceptions?host_id={id}` | ExceptionsCard data |
| Host alerts | `/api/compliance/alerts?host_id={id}` | AlertsCard data |
| Alert stats | `/api/compliance/alerts/stats` | AlertsCard severity breakdown |

### Query String Parameters

Paginated endpoints (packages, services, users, network, firewall, routes) support:

| Parameter | Type | Description |
|-----------|------|-------------|
| `search` | string | Text search filter |
| `limit` | integer | Page size (default varies) |
| `offset` | integer | Pagination offset |

Additional filters by endpoint:

- **Services**: `status` (running/stopped/failed)
- **Users**: `include_system` (boolean), `has_sudo` (boolean)
- **Network**: `interface_type` (string), `is_up` (boolean)
- **Firewall**: `chain` (string), `action` (string), `firewall_type` (string)
- **Routes**: `is_default` (boolean)

---

## Type System

All type definitions live in `frontend/src/types/hostDetail.ts`. The file defines interfaces
for every data structure used across the Host Detail page, grouped by domain:

- **Compliance**: `ComplianceFinding`, `SeveritySummary`, `ComplianceState`
- **Scheduler**: `HostSchedule`, `SchedulerStatus`, `ScheduledScan`
- **System Info**: `SystemInfo`, `ServerIntelligenceSummary`
- **Intelligence**: `Package`, `PackagesResponse`, `Service`, `ListeningPort`, `ServicesResponse`,
  `User`, `UsersResponse`, `NetworkInterface`, `IpAddress`, `NetworkResponse`, `FirewallRule`,
  `FirewallResponse`, `Route`, `RoutesResponse`
- **Exceptions**: `ComplianceException`, `ExceptionsSummary`
- **Alerts**: `ComplianceAlert`, `AlertsSummary`
- **Scan History**: `ScanHistoryItem`, `ScanResults`, `ScanHistoryResponse`
- **Combined**: `HostDetailData` (aggregate interface for the full page data)

### API Adapter Pattern

The adapter file (`frontend/src/services/adapters/hostDetailAdapter.ts`) handles the
transformation between the backend snake_case API responses and the frontend camelCase
TypeScript types. Each backend response type has a corresponding `Api*` interface and an
`adapt*` function:

```
Backend (snake_case)          Adapter Function           Frontend (camelCase)
ApiComplianceState    -->  adaptComplianceState()  -->  ComplianceState
ApiHostSchedule       -->  adaptHostSchedule()     -->  HostSchedule
ApiSystemInfo         -->  adaptSystemInfo()       -->  SystemInfo
ApiPackage            -->  adaptPackage()          -->  Package
ApiService            -->  adaptService()          -->  Service
ApiUser               -->  adaptUser()             -->  User
ApiNetworkInterface   -->  adaptNetworkInterface() -->  NetworkInterface
ApiFirewallRule       -->  adaptFirewallRule()     -->  FirewallRule
ApiRoute              -->  adaptRoute()            -->  Route
ApiScanHistoryItem    -->  adaptScanHistoryItem()  -->  ScanHistoryItem
```

---

## React Query Integration

All data fetching uses React Query via hooks defined in `frontend/src/hooks/useHostDetail.ts`.

### Query Key Structure

All keys are namespaced under `['hostDetail', ...]` for targeted invalidation:

```
['hostDetail', 'compliance', hostId]
['hostDetail', 'schedule', hostId]
['hostDetail', 'systemInfo', hostId]
['hostDetail', 'intelligenceSummary', hostId]
['hostDetail', 'packages', hostId, { search, limit, offset }]
['hostDetail', 'services', hostId, { search, status, limit, offset }]
['hostDetail', 'users', hostId, { search, includeSystem, hasSudo, limit, offset }]
['hostDetail', 'network', hostId, params]
['hostDetail', 'firewall', hostId, params]
['hostDetail', 'routes', hostId, params]
['hostDetail', 'scanHistory', hostId]
```

### Stale Time Configuration

| Hook | Stale Time | Rationale |
|------|-----------|-----------|
| `useComplianceState` | 60 seconds | Updates after each scan |
| `useHostSchedule` | 30 seconds | Schedule changes frequently |
| `useSystemInfo` | 5 minutes | System info changes rarely |
| `useIntelligenceSummary` | 60 seconds | Counts update after scans |
| `usePackages` | 5 minutes | Packages change infrequently |
| `useServices` | 5 minutes | Services change infrequently |
| `useUsers` | 5 minutes | Users change infrequently |
| `useNetwork` | 5 minutes | Network config changes infrequently |
| `useFirewall` | 5 minutes | Firewall rules change infrequently |
| `useRoutes` | 5 minutes | Routes change infrequently |
| `useScanHistory` | 30 seconds | Scans complete and start frequently |

### Invalidation

The `useInvalidateHostDetail()` hook invalidates all host-specific queries for a given host ID.
This is used after a scan completes or when data is known to have changed.

---

## Phase Breakdown

### Phase 0: Backend Data Fix

Established a single source of truth for host compliance data. The Aegis compliance state
endpoint (`/api/scans/aegis/compliance-state/{hostId}`) became the authoritative source for
compliance score, findings, and severity breakdown.

### Phase 1: Page Structure and Header

Created the `HostDetail/` directory structure with `index.tsx`, `HostDetailHeader.tsx`, and the
`cards/` and `tabs/` subdirectories. Removed manual scan buttons from the header. Added the
back navigation button and the IP/OS/kernel subtitle with `StatusChip`.

### Phase 2: Summary Cards

Built all six summary cards (`ComplianceCard`, `SystemHealthCard`, `AutoScanCard`,
`ExceptionsCard`, `AlertsCard`, `ConnectivityCard`) with the `HostSummaryCards` container
component. Implemented skeleton loading states for each card.

### Phase 3: Core Tabs

Built the `OverviewTab` and `ComplianceTab`. The Overview tab integrated the system info,
hardware, server intelligence summary, and compliance trend chart. The Compliance tab
implemented the full findings table with search and filter.

### Phase 4: Server Intelligence Tabs

Built the `PackagesTab`, `ServicesTab`, `UsersTab`, and `NetworkTab` (with sub-tabs). Each tab
implemented search, filtering, and server-side pagination.

### Phase 5: History, Audit, and Terminal Tabs

Built `HistoryTab` with the scan history table and compliance trend chart. Created the
`AuditLogTab` placeholder. Wrapped the existing `HostTerminal` component in `TerminalTab`.

### Phase 6: Data Layer

Created the type definitions (`types/hostDetail.ts`), API adapter
(`services/adapters/hostDetailAdapter.ts`), and React Query hooks (`hooks/useHostDetail.ts`).
Wired all components to use the new data layer.

---

## Implementation Status

### Complete

| Component | Status | Notes |
|-----------|--------|-------|
| `HostDetail/index.tsx` | Complete | Main page with all hooks and tab panels |
| `HostDetailHeader.tsx` | Complete | No scan buttons, IP/OS/kernel subtitle |
| `HostSummaryCards.tsx` | Complete | 6-card grid container |
| `ComplianceCard.tsx` | Complete | Score, pass/fail, critical findings |
| `SystemHealthCard.tsx` | Complete | OS, kernel, uptime, memory, CPU |
| `AutoScanCard.tsx` | Complete | Schedule status, last/next scan |
| `ExceptionsCard.tsx` | Complete | UI complete, receives props |
| `AlertsCard.tsx` | Complete | UI complete, receives props |
| `ConnectivityCard.tsx` | Complete | Online/offline, SSH details |
| `OverviewTab.tsx` | Complete | System info, hardware, intelligence, trend |
| `ComplianceTab.tsx` | Complete | Findings table with search/filter |
| `PackagesTab.tsx` | Complete | Search, pagination |
| `ServicesTab.tsx` | Complete | Search, status filter, pagination |
| `UsersTab.tsx` | Complete | Search, sudo filter, system toggle |
| `NetworkTab.tsx` | Complete | Interfaces, firewall, routes sub-tabs |
| `AuditLogTab.tsx` | Placeholder | Waiting for audit log collection backend |
| `HistoryTab.tsx` | Complete | Scan table, trend chart |
| `TerminalTab.tsx` | Complete | Wraps HostTerminal component |
| `types/hostDetail.ts` | Complete | All type definitions |
| `adapters/hostDetailAdapter.ts` | Complete | All transformation functions |
| `hooks/useHostDetail.ts` | Complete | All React Query hooks |
| `cards/index.ts` | Complete | Barrel export |
| `tabs/index.ts` | Complete | Barrel export |

### Remaining Work

| Item | Priority | Description |
|------|----------|-------------|
| Exceptions API integration | P2 | Wire ExceptionsCard to `/api/compliance/exceptions` filtered by host |
| Alerts API integration | P2 | Wire AlertsCard to `/api/compliance/alerts` filtered by host |
| Audit Log collection | P3 | Implement backend audit log collection, then populate AuditLogTab |
| Exception detail drawer | P3 | Click-through from ExceptionsCard to view/manage exceptions |
| Alert detail drawer | P3 | Click-through from AlertsCard to acknowledge/resolve alerts |
| Scan result deep-link | P3 | Link from ComplianceTab findings to scan result detail view |

---

## File Inventory

### Frontend Files

```
frontend/src/
  pages/hosts/HostDetail/
    index.tsx                    -- Main page component (257 LOC)
    HostDetailHeader.tsx         -- Header with back nav and status (67 LOC)
    HostSummaryCards.tsx         -- 6-card grid container (141 LOC)
    cards/
      index.ts                  -- Barrel export
      ComplianceCard.tsx         -- Compliance score card (117 LOC)
      SystemHealthCard.tsx       -- System health card (122 LOC)
      AutoScanCard.tsx           -- Auto-scan status card (151 LOC)
      ExceptionsCard.tsx         -- Exceptions count card (87 LOC)
      AlertsCard.tsx             -- Alerts count card (119 LOC)
      ConnectivityCard.tsx       -- Connectivity status card (125 LOC)
    tabs/
      index.ts                  -- Barrel export
      OverviewTab.tsx            -- Overview dashboard (317 LOC)
      ComplianceTab.tsx          -- Compliance findings (328 LOC)
      PackagesTab.tsx            -- Installed packages (166 LOC)
      ServicesTab.tsx            -- System services (247 LOC)
      UsersTab.tsx               -- User accounts (263 LOC)
      NetworkTab.tsx             -- Network config with sub-tabs (295 LOC)
      AuditLogTab.tsx            -- Audit log placeholder (37 LOC)
      HistoryTab.tsx             -- Scan history (274 LOC)
      TerminalTab.tsx            -- SSH terminal wrapper (30 LOC)
  hooks/
    useHostDetail.ts             -- React Query hooks (383 LOC)
  services/adapters/
    hostDetailAdapter.ts         -- API adapter with transformations (779 LOC)
  types/
    hostDetail.ts                -- Type definitions (509 LOC)
  constants/
    refresh.ts                   -- Refresh interval constants (171 LOC)
  components/
    design-system/               -- StatusChip used by header
    baselines/
      ComplianceTrendChart.tsx   -- Trend chart used by OverviewTab and HistoryTab
    terminal/
      HostTerminal.tsx           -- SSH terminal used by TerminalTab
```
