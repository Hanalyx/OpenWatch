# OpenWatch Design System Component Guide

## Quick Start

```typescript
import { 
  StatCard, 
  StatusChip, 
  ComplianceRing, 
  DashboardLayout,
  FilterToolbar,
  DataGrid,
  EmptyState 
} from '../../components/design-system';
```

## Core Components

### StatCard
Display key metrics with trend indicators and icons.

```tsx
<StatCard
  title="Hosts Online"
  value="12/15"
  color="success"
  icon={<Computer />}
  trend="up"
  trendValue="80%"
  onClick={() => navigate('/hosts')}
/>
```

**Props:**
- `title` - Card header text
- `value` - Main metric value
- `color` - Theme color ('primary' | 'success' | 'warning' | 'error' | 'info')
- `icon` - Icon component to display
- `trend` - Direction indicator ('up' | 'down' | 'flat')
- `trendValue` - Additional trend information
- `onClick` - Click handler for interactivity

### StatusChip
Unified status indicators with consistent styling and icons.

```tsx
<StatusChip 
  status="online" 
  size="small"
  variant="filled"
/>
```

**Status Types:**
- **System:** 'online' | 'offline' | 'maintenance' | 'scanning' | 'pending'
- **General:** 'success' | 'error' | 'warning' | 'info'
- **Severity:** 'critical' | 'high' | 'medium' | 'low'
- **Compliance:** 'compliant' | 'non-compliant' | 'unknown'

### ComplianceRing
Visual compliance score display with trend indicators.

```tsx
<ComplianceRing
  score={85}
  size="medium"
  trend="up"
  tooltip="Security compliance score improving"
/>
```

**Sizes:** 'small' (48px) | 'medium' (64px) | 'large' (80px)

## Layout Components

### DashboardLayout
Standard layout for dashboard pages with statistics, toolbar, and content areas.

```tsx
<DashboardLayout
  title="Host Management"
  subtitle="Monitor and manage your infrastructure"
  statistics={<StatisticsRow />}
  toolbar={<FilterControls />}
  fab={{
    icon: <Add />,
    onClick: () => setShowAddDialog(true),
    tooltip: "Add New Host"
  }}
>
  <HostsGrid />
</DashboardLayout>
```

### PageTemplate
Consistent page structure with breadcrumbs, header, and content.

```tsx
<PageTemplate
  title="System Configuration"
  subtitle="Manage OpenWatch settings"
  breadcrumbs={[
    { label: 'Dashboard', href: '/' },
    { label: 'Settings', href: '/settings' },
    { label: 'System' }
  ]}
  actions={<SaveButton />}
  maxWidth="lg"
>
  <ConfigurationForm />
</PageTemplate>
```

## Pattern Components

### FilterToolbar
Standardized filtering and view controls.

```tsx
<FilterToolbar
  searchQuery={searchQuery}
  onSearchChange={setSearchQuery}
  searchPlaceholder="Search hosts..."
  viewMode={viewMode}
  onViewModeChange={setViewMode}
  groupBy={groupBy}
  onGroupByChange={setGroupBy}
  groupOptions={[
    { value: 'status', label: 'By Status' },
    { value: 'team', label: 'By Team' }
  ]}
  selectedCount={selectedItems.length}
  onClearSelection={() => setSelectedItems([])}
  bulkActions={<BulkActionButtons />}
/>
```

### DataGrid
Responsive grid with grouping and collapsible sections.

```tsx
<DataGrid
  groups={processedGroups}
  renderItem={(host) => <HostCard host={host} />}
  columns={{ xs: 12, sm: 6, md: 4, lg: 3 }}
  spacing={2}
  onGroupToggle={handleGroupToggle}
  emptyState={
    <EmptyState
      type="no-data"
      title="No hosts found"
      action={{
        label: "Add Host",
        onClick: () => setShowAddDialog(true)
      }}
    />
  }
/>
```

### EmptyState
Consistent empty states with clear actions.

```tsx
<EmptyState
  type="no-results"
  title="No matching hosts"
  description="Try adjusting your search criteria"
  action={{
    label: "Clear Filters",
    onClick: clearAllFilters
  }}
  secondaryAction={{
    label: "Add New Host",
    onClick: showAddDialog
  }}
/>
```

**Types:** 'no-data' | 'no-results' | 'error' | 'custom'

## Design Patterns

### Statistics Dashboard
```tsx
<Grid container spacing={2}>
  <Grid item xs={12} sm={6} md={3}>
    <StatCard
      title="Total Hosts"
      value={stats.total}
      color="primary"
      icon={<Computer />}
    />
  </Grid>
  <Grid item xs={12} sm={6} md={3}>
    <StatCard
      title="Compliance"
      value={`${stats.compliance}%`}
      color={stats.compliance >= 90 ? 'success' : 'warning'}
      icon={<Security />}
      trend={stats.complianceTrend}
    />
  </Grid>
</Grid>
```

### Status Display
```tsx
<Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
  <StatusChip status={host.status} size="small" />
  <ComplianceRing score={host.compliance} size="small" />
  <Typography variant="body2">
    Last scanned: {formatDate(host.lastScan)}
  </Typography>
</Box>
```

### Bulk Actions
```tsx
{selectedItems.length > 0 && (
  <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
    <Chip label={`${selectedItems.length} selected`} />
    <Button startIcon={<Scanner />}>Scan Selected</Button>
    <Button startIcon={<Delete />} color="error">
      Remove Selected
    </Button>
  </Box>
)}
```

## Color Usage

### Status Colors
- **Success/Online:** Use for positive states, successful operations 
- **Warning/Maintenance:** Use for attention-needed states, in-progress operations
- **Error/Offline:** Use for critical issues, failed operations
- **Info/Scanning:** Use for informational states, active processes

### Severity Levels
- **Critical:** Immediate action required, system at risk
- **High:** Important issues needing prompt attention  
- **Medium:** Issues that should be addressed soon
- **Low:** Minor issues or informational items

## Responsive Guidelines

### Breakpoints
- **Mobile:** < 600px - Single column, simplified UI
- **Tablet:** 600-960px - Two columns, touch-friendly  
- **Desktop:** 960-1280px - Full features, multi-column
- **Wide:** > 1280px - Maximum content width

### Grid Columns
```tsx
// Responsive host cards
<Grid item xs={12} sm={6} md={4} lg={3} xl={3}>
  <HostCard />
</Grid>

// Dashboard statistics  
<Grid item xs={12} sm={6} md={2.4}>
  <StatCard />
</Grid>
```

## Accessibility

### Keyboard Navigation
- All interactive elements support Tab navigation
- Focus indicators are clearly visible
- Logical tab order is maintained

### Screen Readers
- StatusChip includes aria-labels for status
- StatCard provides descriptive content
- EmptyState includes helpful context

### Color Contrast
- All text meets WCAG AA standards (4.5:1 ratio)
- Status indicators don't rely solely on color
- Focus states are highly visible

## Performance Considerations

### Component Optimization
- Use React.memo for frequently re-rendered components
- Implement virtualization for large data grids
- Lazy load heavy pattern components

### Bundle Size
- Import only needed components: `import { StatCard } from './design-system'`
- Tree-shaking eliminates unused components
- Icons are loaded on-demand

## Best Practices

### Component Selection
- **StatCard:** For key metrics and dashboard summaries
- **StatusChip:** For any status or state indication  
- **ComplianceRing:** For percentage/score visualization
- **DataGrid:** For collections of similar items
- **EmptyState:** When no data is available

### Layout Patterns
- Use **DashboardLayout** for data-heavy management pages
- Use **PageTemplate** for forms and configuration pages
- Combine **FilterToolbar** with **DataGrid** for searchable lists

### Error Handling
- Always provide EmptyState for no-data scenarios
- Use error-type EmptyState for failed requests
- Include recovery actions in error states

### Mobile Experience  
- Test all components on mobile breakpoints
- Ensure touch targets are at least 44px
- Simplify complex layouts on small screens