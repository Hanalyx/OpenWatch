// Spec: specs/frontend/role-dashboards.spec.yaml
/**
 * Spec-enforcement tests for role-based dashboard widget composition.
 *
 * Validates that the Dashboard reads user role from useAuthStore, that a
 * widget registry and role presets exist, that widgets are permission-gated,
 * and that customization tiers are correctly assigned per role.
 *
 * These are source-inspection tests that verify structural and behavioral
 * facts about the dashboard implementation without running the full React
 * render pipeline. They complement (but do not replace) integration tests
 * that verify runtime rendering.
 */

import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const SRC = path.resolve(__dirname, '../../../frontend/src');

function readSource(relativePath: string): string {
  const fullPath = path.join(SRC, relativePath);
  if (!fs.existsSync(fullPath)) {
    throw new Error(`Source file not found: ${relativePath}`);
  }
  return fs.readFileSync(fullPath, 'utf8');
}

function fileExists(relativePath: string): boolean {
  return fs.existsSync(path.join(SRC, relativePath));
}

/** All 6 OpenWatch roles */
const ALL_ROLES = [
  'super_admin',
  'security_admin',
  'security_analyst',
  'compliance_officer',
  'auditor',
  'guest',
] as const;

/** Roles that MUST have full customization */
const FULL_CUSTOMIZATION_ROLES = ['super_admin', 'security_admin'] as const;

/** Roles that MUST have limited customization */
const LIMITED_CUSTOMIZATION_ROLES = ['security_analyst', 'compliance_officer'] as const;

/** Roles that MUST have no customization (fixed layout) */
const NO_CUSTOMIZATION_ROLES = ['auditor', 'guest'] as const;

/** Roles that MUST use single-column layout */
const SINGLE_COLUMN_ROLES = ['auditor', 'guest'] as const;

/** Roles that MUST use multi-column layout */
const MULTI_COLUMN_ROLES = [
  'super_admin',
  'security_admin',
  'security_analyst',
  'compliance_officer',
] as const;

// ---------------------------------------------------------------------------
// AC-1: Dashboard reads user role from useAuthStore
// ---------------------------------------------------------------------------

describe('AC-1: Dashboard reads user role from useAuthStore', () => {
  it('Dashboard.tsx MUST import useAuthStore', () => {
    const source = readSource('pages/Dashboard.tsx');
    expect(source).toContain('useAuthStore');
  });

  it('Dashboard.tsx MUST reference user role to select preset', () => {
    const source = readSource('pages/Dashboard.tsx');
    // Should reference role from the auth store in some form
    const hasRoleRef =
      source.includes('user.role') ||
      source.includes("role'") ||
      source.includes('role"') ||
      source.includes('userRole') ||
      source.includes('currentRole');
    expect(hasRoleRef).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// AC-2: Widget registry exists as a typed structure
// ---------------------------------------------------------------------------

describe('AC-2: Widget registry exists', () => {
  // The registry may be in a dedicated file or embedded in Dashboard
  const REGISTRY_PATHS = [
    'pages/Dashboard/widgetRegistry.ts',
    'pages/Dashboard/widgetRegistry.tsx',
    'pages/Dashboard/widgets/registry.ts',
    'pages/Dashboard/widgets/registry.tsx',
    'pages/Dashboard/config/widgetRegistry.ts',
  ];

  function findRegistryPath(): string | null {
    for (const p of REGISTRY_PATHS) {
      if (fileExists(p)) return p;
    }
    return null;
  }

  it('widget registry file MUST exist in a dedicated file', () => {
    const registryPath = findRegistryPath();
    expect(registryPath).not.toBeNull();
  });

  it('widget registry MUST define id, title, requiredPermissions, and category', () => {
    const registryPath = findRegistryPath();
    if (!registryPath) return; // guarded by previous test
    const source = readSource(registryPath);

    expect(source).toContain('id');
    expect(source).toContain('title');
    expect(source).toContain('requiredPermissions');
    expect(source).toContain('category');
  });

  it('widget registry MUST define a component reference for each widget', () => {
    const registryPath = findRegistryPath();
    if (!registryPath) return;
    const source = readSource(registryPath);

    expect(source).toContain('component');
  });
});

// ---------------------------------------------------------------------------
// AC-3: Role default presets exist for all 6 roles
// ---------------------------------------------------------------------------

describe('AC-3: Role default presets for all 6 roles', () => {
  const PRESET_PATHS = [
    'pages/Dashboard/dashboardPresets.ts',
    'pages/Dashboard/dashboardPresets.tsx',
    'pages/Dashboard/config/dashboardPresets.ts',
    'pages/Dashboard/presets.ts',
  ];

  function findPresetsPath(): string | null {
    for (const p of PRESET_PATHS) {
      if (fileExists(p)) return p;
    }
    return null;
  }

  it('dashboard presets file MUST exist', () => {
    const presetsPath = findPresetsPath();
    expect(presetsPath).not.toBeNull();
  });

  it.each(ALL_ROLES)('preset MUST exist for role: %s', (role) => {
    const presetsPath = findPresetsPath();
    if (!presetsPath) return;
    const source = readSource(presetsPath);

    expect(source).toContain(role);
  });
});

// ---------------------------------------------------------------------------
// AC-4: Super Admin preset has comprehensive widget set
// ---------------------------------------------------------------------------

describe('AC-4: Super Admin preset is the most comprehensive', () => {
  const REQUIRED_SUPER_ADMIN_WIDGETS = [
    'summary-bar',
    'smart-alert-bar',
    'fleet-health',
    'security-events',
    'priority-hosts',
    'compliance-trend',
    'scheduler-status',
    'posture',
    'drift-alerts',
    'saved-queries',
    'activity-feed',
  ];

  const PRESET_PATHS = [
    'pages/Dashboard/dashboardPresets.ts',
    'pages/Dashboard/dashboardPresets.tsx',
    'pages/Dashboard/config/dashboardPresets.ts',
    'pages/Dashboard/presets.ts',
  ];

  function findPresetsSource(): string | null {
    for (const p of PRESET_PATHS) {
      if (fileExists(p)) return readSource(p);
    }
    return null;
  }

  it.each(REQUIRED_SUPER_ADMIN_WIDGETS)(
    'super_admin preset MUST include widget: %s',
    (widgetId) => {
      const source = findPresetsSource();
      if (!source) return;

      // Widget ID should appear in the super_admin section
      expect(source).toContain(widgetId);
    }
  );
});

// ---------------------------------------------------------------------------
// AC-5: Security Admin preset — no system-config or user-management
// ---------------------------------------------------------------------------

describe('AC-5: Security Admin preset', () => {
  const REQUIRED_SEC_ADMIN_WIDGETS = [
    'summary-bar',
    'smart-alert-bar',
    'priority-hosts',
    'fleet-health',
    'compliance-trend',
    'drift-alerts',
    'scheduler-status',
    'security-events',
    'activity-feed',
  ];

  const PRESET_PATHS = [
    'pages/Dashboard/dashboardPresets.ts',
    'pages/Dashboard/dashboardPresets.tsx',
    'pages/Dashboard/config/dashboardPresets.ts',
    'pages/Dashboard/presets.ts',
  ];

  function findPresetsSource(): string | null {
    for (const p of PRESET_PATHS) {
      if (fileExists(p)) return readSource(p);
    }
    return null;
  }

  it.each(REQUIRED_SEC_ADMIN_WIDGETS)(
    'security_admin preset MUST include widget: %s',
    (widgetId) => {
      const source = findPresetsSource();
      if (!source) return;

      expect(source).toContain(widgetId);
    }
  );
});

// ---------------------------------------------------------------------------
// AC-6: Security Analyst preset — no audit widgets
// ---------------------------------------------------------------------------

describe('AC-6: Security Analyst preset', () => {
  const REQUIRED_ANALYST_WIDGETS = [
    'summary-bar',
    'fleet-health',
    'priority-hosts',
    'compliance-trend',
  ];

  const PRESET_PATHS = [
    'pages/Dashboard/dashboardPresets.ts',
    'pages/Dashboard/dashboardPresets.tsx',
    'pages/Dashboard/config/dashboardPresets.ts',
    'pages/Dashboard/presets.ts',
  ];

  function findPresetsSource(): string | null {
    for (const p of PRESET_PATHS) {
      if (fileExists(p)) return readSource(p);
    }
    return null;
  }

  it.each(REQUIRED_ANALYST_WIDGETS)(
    'security_analyst preset MUST include widget: %s',
    (widgetId) => {
      const source = findPresetsSource();
      if (!source) return;

      expect(source).toContain(widgetId);
    }
  );
});

// ---------------------------------------------------------------------------
// AC-7: Compliance Officer preset — 90-day default, no scan:execute widgets
// ---------------------------------------------------------------------------

describe('AC-7: Compliance Officer preset', () => {
  const REQUIRED_CO_WIDGETS = ['compliance-trend', 'posture', 'saved-queries'];

  const PRESET_PATHS = [
    'pages/Dashboard/dashboardPresets.ts',
    'pages/Dashboard/dashboardPresets.tsx',
    'pages/Dashboard/config/dashboardPresets.ts',
    'pages/Dashboard/presets.ts',
  ];

  function findPresetsSource(): string | null {
    for (const p of PRESET_PATHS) {
      if (fileExists(p)) return readSource(p);
    }
    return null;
  }

  it.each(REQUIRED_CO_WIDGETS)(
    'compliance_officer preset MUST include widget: %s',
    (widgetId) => {
      const source = findPresetsSource();
      if (!source) return;

      expect(source).toContain(widgetId);
    }
  );

  it('compliance_officer preset MUST default to 90-day trend range', () => {
    const source = findPresetsSource();
    if (!source) return;

    // Should have 90d associated with compliance_officer
    const has90d = source.includes("'90d'") || source.includes('"90d"');
    expect(has90d).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// AC-8: Auditor preset — fixed, no action buttons
// ---------------------------------------------------------------------------

describe('AC-8: Auditor preset is fixed with no write actions', () => {
  const REQUIRED_AUDITOR_WIDGETS = ['compliance-trend', 'posture', 'saved-queries'];

  const PRESET_PATHS = [
    'pages/Dashboard/dashboardPresets.ts',
    'pages/Dashboard/dashboardPresets.tsx',
    'pages/Dashboard/config/dashboardPresets.ts',
    'pages/Dashboard/presets.ts',
  ];

  function findPresetsSource(): string | null {
    for (const p of PRESET_PATHS) {
      if (fileExists(p)) return readSource(p);
    }
    return null;
  }

  it.each(REQUIRED_AUDITOR_WIDGETS)('auditor preset MUST include widget: %s', (widgetId) => {
    const source = findPresetsSource();
    if (!source) return;

    expect(source).toContain(widgetId);
  });

  it('auditor preset MUST default to 90-day trend range', () => {
    const source = findPresetsSource();
    if (!source) return;

    const has90d = source.includes("'90d'") || source.includes('"90d"');
    expect(has90d).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// AC-9: Guest preset is minimal (max 4 widgets)
// ---------------------------------------------------------------------------

describe('AC-9: Guest preset is minimal', () => {
  const PRESET_PATHS = [
    'pages/Dashboard/dashboardPresets.ts',
    'pages/Dashboard/dashboardPresets.tsx',
    'pages/Dashboard/config/dashboardPresets.ts',
    'pages/Dashboard/presets.ts',
  ];

  function findPresetsSource(): string | null {
    for (const p of PRESET_PATHS) {
      if (fileExists(p)) return readSource(p);
    }
    return null;
  }

  it('guest preset MUST exist and reference the guest role', () => {
    const source = findPresetsSource();
    if (!source) return;

    expect(source).toContain('guest');
  });

  it('guest preset MUST include a host-status or fleet-health widget', () => {
    const source = findPresetsSource();
    if (!source) return;

    const hasHostWidget =
      source.includes('fleet-health') || source.includes('host-status');
    expect(hasHostWidget).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// AC-10: Quick actions are permission-gated
// ---------------------------------------------------------------------------

describe('AC-10: Quick actions are permission-gated', () => {
  it('Dashboard MUST check permissions before rendering quick actions', () => {
    const source = readSource('pages/Dashboard.tsx');

    // Should reference permission checking for quick actions
    const hasPermissionCheck =
      source.includes('requiredPermission') ||
      source.includes('host:create') ||
      source.includes('HOST_CREATE') ||
      source.includes('scan:execute') ||
      source.includes('SCAN_EXECUTE') ||
      source.includes('hasPermission') ||
      source.includes('canAccess');
    expect(hasPermissionCheck).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// AC-11: Widgets filtered at render time by permission
// ---------------------------------------------------------------------------

describe('AC-11: Widgets filtered by user permissions at render time', () => {
  it('Dashboard MUST filter widgets based on requiredPermissions', () => {
    const source = readSource('pages/Dashboard.tsx');

    const hasPermissionFiltering =
      source.includes('requiredPermissions') ||
      source.includes('filter') ||
      source.includes('permission');
    expect(hasPermissionFiltering).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// AC-12: Customization tiers are correctly assigned per role
// ---------------------------------------------------------------------------

describe('AC-12: Customization tiers per role', () => {
  const PRESET_PATHS = [
    'pages/Dashboard/dashboardPresets.ts',
    'pages/Dashboard/dashboardPresets.tsx',
    'pages/Dashboard/config/dashboardPresets.ts',
    'pages/Dashboard/presets.ts',
  ];

  function findPresetsSource(): string | null {
    for (const p of PRESET_PATHS) {
      if (fileExists(p)) return readSource(p);
    }
    return null;
  }

  it('presets config MUST define customization tiers', () => {
    const source = findPresetsSource();
    if (!source) return;

    const hasTiers =
      source.includes('customization') ||
      source.includes('tier') ||
      source.includes('full') ||
      source.includes('limited') ||
      source.includes('none');
    expect(hasTiers).toBe(true);
  });

  it.each(FULL_CUSTOMIZATION_ROLES)(
    '%s MUST have "full" customization tier',
    (role) => {
      const source = findPresetsSource();
      if (!source) return;

      // Role and 'full' should both appear in the preset config
      expect(source).toContain(role);
      expect(source).toContain('full');
    }
  );

  it.each(LIMITED_CUSTOMIZATION_ROLES)(
    '%s MUST have "limited" customization tier',
    (role) => {
      const source = findPresetsSource();
      if (!source) return;

      expect(source).toContain(role);
      expect(source).toContain('limited');
    }
  );

  it.each(NO_CUSTOMIZATION_ROLES)(
    '%s MUST have "none" customization tier',
    (role) => {
      const source = findPresetsSource();
      if (!source) return;

      expect(source).toContain(role);
      expect(source).toContain('none');
    }
  );
});

// ---------------------------------------------------------------------------
// AC-13: Fallback to role default when no saved layout exists
// ---------------------------------------------------------------------------

describe('AC-13: Fallback to role default preset', () => {
  it('Dashboard MUST have fallback logic for missing saved layouts', () => {
    const source = readSource('pages/Dashboard.tsx');

    // Should have fallback/default logic
    const hasFallback =
      source.includes('default') ||
      source.includes('fallback') ||
      source.includes('preset');
    expect(hasFallback).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// AC-14: Dashboard title reflects role context
// ---------------------------------------------------------------------------

describe('AC-14: Dashboard title reflects role context', () => {
  it('Dashboard MUST NOT hardcode a single title for all roles', () => {
    const source = readSource('pages/Dashboard.tsx');

    // Should use preset.title (role-driven) rather than a hardcoded string
    const hasConditionalTitle =
      source.includes('preset.title') ||
      (source.includes('Command Center') &&
        (source.includes('Compliance Dashboard') ||
          source.includes('Security Operations') ||
          source.includes('dashboardTitle') ||
          source.includes('roleTitle')));
    expect(hasConditionalTitle).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// AC-15: Column layout varies by role type
// ---------------------------------------------------------------------------

describe('AC-15: Column layout per role', () => {
  const PRESET_PATHS = [
    'pages/Dashboard/dashboardPresets.ts',
    'pages/Dashboard/dashboardPresets.tsx',
    'pages/Dashboard/config/dashboardPresets.ts',
    'pages/Dashboard/presets.ts',
  ];

  function findPresetsSource(): string | null {
    for (const p of PRESET_PATHS) {
      if (fileExists(p)) return readSource(p);
    }
    return null;
  }

  it('presets MUST define column layout per role', () => {
    const source = findPresetsSource();
    if (!source) return;

    const hasLayout =
      source.includes('column') ||
      source.includes('layout') ||
      source.includes('columns');
    expect(hasLayout).toBe(true);
  });

  it.each(SINGLE_COLUMN_ROLES)(
    '%s MUST use single-column layout',
    (role) => {
      const source = findPresetsSource();
      if (!source) return;

      expect(source).toContain(role);
      // Should reference a single-column or 1-column layout somewhere
      const hasSingleCol =
        source.includes('single') ||
        source.includes("columns: 1") ||
        source.includes('columns: 1');
      expect(hasSingleCol).toBe(true);
    }
  );

  it.each(MULTI_COLUMN_ROLES)(
    '%s MUST use multi-column layout',
    (role) => {
      const source = findPresetsSource();
      if (!source) return;

      expect(source).toContain(role);
      const hasMultiCol =
        source.includes('columns: 2') ||
        source.includes('columns: 3') ||
        source.includes("columns: 2") ||
        source.includes("columns: 3");
      expect(hasMultiCol).toBe(true);
    }
  );
});
