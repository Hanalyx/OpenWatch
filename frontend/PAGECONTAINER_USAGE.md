# PageContainer Component - Usage Guide

## Overview

The `PageContainer` component provides centralized, theme-controlled spacing for all OpenWatch pages. It eliminates the need for repetitive `Box`, `Container`, and spacing definitions (`mb: 3`, `py: 2`, etc.) on every page.

## Design Philosophy

**Before PageContainer:**
```tsx
// Every page repeated this boilerplate:
<Box>
  <Box sx={{ mb: 3 }}>
    <Typography variant="h4">Page Title</Typography>
    <Typography variant="body1" color="text.secondary">Description</Typography>
  </Box>
  <YourContent />
</Box>
```

**With PageContainer:**
```tsx
// Clean, DRY approach:
<PageContainer title="Page Title" subtitle="Description">
  <YourContent />
</PageContainer>
```

## Spacing Architecture

### Layout Component (`components/layout/Layout.tsx`)
- Provides `p: 3` (24px padding) on main content area
- Applies to ALL pages globally

### PageContainer Component
- Adds `mb: 3` (24px margin-bottom) to header section only
- Provides optional standard header or custom header
- No padding - relies on Layout

### Result
- **Consistent 24px padding** around all page content (from Layout)
- **Consistent 24px gap** between header and content (from PageContainer)
- **No repetition** of spacing code across pages

---

## Usage Patterns

### Pattern 1: Standard Header (Simple Pages)

**Use case:** Most list/overview pages (Hosts, Scans, Users, Settings, etc.)

**Example:**
```tsx
import { PageContainer } from '../../components/layout';
import { Person as PersonIcon } from '@mui/icons-material';

const Users = () => {
  return (
    <PageContainer
      title="User Management"
      subtitle="Manage user accounts, roles, and permissions"
      icon={<PersonIcon />}
    >
      {/* Your page content */}
      <Card>
        <UserTable />
      </Card>
    </PageContainer>
  );
};
```

**What you get:**
- Automatic header with icon
- Title (h4)
- Subtitle (body1, text.secondary)
- 24px margin below header
- No manual spacing needed

---

### Pattern 2: Header with Actions

**Use case:** Pages with header action buttons (e.g., "Add User", "Create Scan")

**Example:**
```tsx
import { PageContainer } from '../../components/layout';
import { Button } from '@mui/material';
import { Add as AddIcon } from '@mui/icons-material';

const Hosts = () => {
  const [dialogOpen, setDialogOpen] = useState(false);

  return (
    <PageContainer
      title="Host Management"
      subtitle="Monitor and manage your infrastructure"
      actions={
        <Button
          variant="contained"
          startIcon={<AddIcon />}
          onClick={() => setDialogOpen(true)}
        >
          Add Host
        </Button>
      }
    >
      {/* Your page content */}
      <HostTable />
      <AddHostDialog open={dialogOpen} onClose={() => setDialogOpen(false)} />
    </PageContainer>
  );
};
```

**What you get:**
- Standard header on left
- Actions (buttons, etc.) aligned to right
- Responsive layout

---

### Pattern 3: Custom Header (Complex Pages)

**Use case:** Pages with complex headers (back buttons, tabs, chips, custom layout)

**Example - Scan Detail Page:**
```tsx
import { PageContainer } from '../../components/layout';
import { useNavigate } from 'react-router-dom';
import { IconButton, Typography, Chip, Button } from '@mui/material';
import { ArrowBack, Refresh, Download } from '@mui/icons-material';

const ScanDetail = () => {
  const navigate = useNavigate();

  const customHeader = (
    <Box display="flex" justifyContent="space-between" alignItems="center">
      <Box display="flex" alignItems="center" gap={2}>
        <IconButton onClick={() => navigate('/scans')}>
          <ArrowBack />
        </IconButton>
        <Typography variant="h4">Scan Details</Typography>
        <Chip label="COMPLETED" color="success" size="small" />
      </Box>
      <Box display="flex" gap={1}>
        <Button variant="outlined" startIcon={<Refresh />}>Refresh</Button>
        <Button variant="outlined" startIcon={<Download />}>Export</Button>
      </Box>
    </Box>
  );

  return (
    <PageContainer header={customHeader}>
      {/* Your page content */}
      <ScanTabs />
    </PageContainer>
  );
};
```

**What you get:**
- Full control over header layout
- Automatic 24px margin-bottom
- No need to manually add `mb: 3`

---

### Pattern 4: No Header (Content Only)

**Use case:** Pages that don't need a header (e.g., embedded views, dashboards with custom layouts)

**Example:**
```tsx
import { PageContainer } from '../../components/layout';

const Dashboard = () => {
  return (
    <PageContainer>
      {/* Your page content - no header */}
      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <StatCard title="Total Hosts" value={125} />
        </Grid>
        <Grid item xs={12} md={6}>
          <StatCard title="Active Scans" value={3} />
        </Grid>
      </Grid>
    </PageContainer>
  );
};
```

**What you get:**
- Just the wrapper `<Box>`
- No header, no extra margin
- Spacing controlled by Layout

---

## Migration Guide

### Before (Old Pattern):

```tsx
import { Box, Typography } from '@mui/material';

const OldPage = () => {
  return (
    <Box>  {/* ← Repetitive wrapper */}
      <Box sx={{ mb: 3 }}>  {/* ← Repetitive spacing */}
        <Typography variant="h4" gutterBottom>
          Page Title
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Page description
        </Typography>
      </Box>
      <YourContent />
    </Box>
  );
};
```

### After (PageContainer Pattern):

```tsx
import { PageContainer } from '../../components/layout';

const NewPage = () => {
  return (
    <PageContainer title="Page Title" subtitle="Page description">
      <YourContent />
    </PageContainer>
  );
};
```

### Code Reduction:
- **Before:** 12 lines of boilerplate
- **After:** 3 lines
- **Savings:** 75% reduction in repetitive code

---

## API Reference

### PageContainer Props

| Prop | Type | Required | Description |
|------|------|----------|-------------|
| `children` | `React.ReactNode` | Yes | Page content to render |
| `title` | `string` | No | Page title (renders standard header) |
| `subtitle` | `string` | No | Page subtitle (below title) |
| `icon` | `React.ReactNode` | No | Icon to display before title |
| `actions` | `React.ReactNode` | No | Action buttons/elements (right side of header) |
| `header` | `React.ReactNode` | No | Custom header (overrides standard header) |
| `sx` | `SxProps<Theme>` | No | Additional styling for wrapper |

### Prop Priority:
1. If `header` is provided → use custom header
2. Else if `title` is provided → use standard header
3. Else → no header, just wrapper

---

## Benefits

### 1. **Consistency**
- All pages have identical spacing (24px padding, 24px header margin)
- No accidental inconsistencies from manual spacing

### 2. **Maintainability**
- Single source of truth for page layout
- Change spacing globally by updating PageContainer or Layout
- No need to update 10+ files for spacing tweaks

### 3. **Developer Experience**
- Less boilerplate to write
- Clearer page structure
- Easier to review (no spacing noise in diffs)

### 4. **Theme-Driven**
- Spacing controlled by theme values (`theme.spacing(3)`)
- Easy to adjust for different screen sizes
- Responsive by default

---

## Theme Integration

### Current Theme Spacing:
```tsx
// MUI default theme
theme.spacing(1) = 8px
theme.spacing(3) = 24px

// Layout (components/layout/Layout.tsx):
<Box component="main" sx={{ p: 3 }}>  // 24px padding

// PageContainer:
<Box sx={{ mb: 3 }}>  // 24px margin-bottom for header
```

### Future Customization:
To adjust spacing globally, modify:
1. **Layout padding:** `Layout.tsx` → `sx={{ p: 3 }}` → change to `p: 2` (16px) or `p: 4` (32px)
2. **Header margin:** `PageContainer.tsx` → `sx={{ mb: 3 }}` → change to `mb: 2` or `mb: 4`
3. **Theme spacing:** Create custom MUI theme with different spacing scale

---

## Examples by Page Type

### List Pages (Hosts, Scans, Users):
```tsx
<PageContainer title="Hosts" subtitle="Manage infrastructure" actions={<AddButton />}>
  <FiltersCard />
  <HostTable />
  <Pagination />
</PageContainer>
```

### Detail Pages (ScanDetail, HostDetail):
```tsx
<PageContainer header={<CustomHeaderWithBackButton />}>
  <Tabs />
  <TabContent />
</PageContainer>
```

### Settings Pages:
```tsx
<PageContainer title="Settings" subtitle="Configure system preferences">
  <Tabs />
  <SettingsForm />
</PageContainer>
```

### Dashboard/Overview:
```tsx
<PageContainer>
  <Grid container spacing={3}>
    <StatCards />
    <Charts />
  </Grid>
</PageContainer>
```

---

## FAQs

### Q: Can I still use custom spacing if needed?
**A:** Yes! Use the `sx` prop:
```tsx
<PageContainer title="Page" sx={{ mb: 5 }}>
  <Content />
</PageContainer>
```

### Q: What if I need different header layouts per page?
**A:** Use the `header` prop with your custom layout:
```tsx
<PageContainer header={<YourComplexHeader />}>
  <Content />
</PageContainer>
```

### Q: Does this replace Container/Box everywhere?
**A:** For page-level wrappers, yes. For layout within pages (grids, cards), use Box/Container as normal.

### Q: Can I use this with existing pages without breaking them?
**A:** Yes! PageContainer is backward compatible. Migrate pages incrementally.

---

## Conversion Checklist

When migrating a page to PageContainer:

- [ ] Remove outer `<Box>` wrapper
- [ ] Remove `<Container maxWidth="xl">` wrapper
- [ ] Remove header `<Box sx={{ mb: 3 }}>` wrapper
- [ ] Extract title/subtitle to PageContainer props
- [ ] Extract action buttons to `actions` prop
- [ ] Wrap content in `<PageContainer>`
- [ ] Test spacing visually
- [ ] Verify no double margins/padding

---

## Next Steps

1. **Pilot Migration:** Migrate 2-3 simple pages (Users, Settings) to validate
2. **Document Issues:** Note any edge cases or challenges
3. **Full Migration:** Update all remaining pages
4. **Cleanup:** Remove redundant spacing code from all pages
5. **Documentation:** Update developer guide with PageContainer patterns

---

**Last Updated:** 2025-01-07
**Component Location:** `/frontend/src/components/layout/PageContainer.tsx`
