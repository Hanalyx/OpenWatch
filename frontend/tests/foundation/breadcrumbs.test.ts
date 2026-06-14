// @spec frontend-foundation
//
// AC traceability (this file):
//   AC-19  every top-level page sets + clears its topbar breadcrumb

import { describe, expect, test } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

// Each top-level navigation page and its expected crumb chain (matching
// the openwatch-v1 prototypes: Reports lives under Compliance, the rest
// under Infrastructure; Dashboard is a single crumb).
const PAGES: { file: string; crumbs: string[] }[] = [
  { file: 'src/pages/HostsListPage.tsx', crumbs: ['Infrastructure', 'Hosts'] },
  { file: 'src/pages/dashboard/DashboardPage.tsx', crumbs: ['Dashboard'] },
  { file: 'src/pages/activity/ActivityPage.tsx', crumbs: ['Infrastructure', 'Activity'] },
  { file: 'src/pages/scans/ScansPage.tsx', crumbs: ['Infrastructure', 'Scans'] },
  { file: 'src/pages/groups/GroupsPage.tsx', crumbs: ['Infrastructure', 'Groups'] },
  { file: 'src/pages/reports/ReportsPage.tsx', crumbs: ['Compliance', 'Reports'] },
];

describe('frontend-foundation — page breadcrumbs', () => {
  // @ac AC-19
  test('frontend-foundation/AC-19 — every top-level page sets + clears its breadcrumb', () => {
    for (const { file, crumbs } of PAGES) {
      const src = readFileSync(resolve(process.cwd(), file), 'utf8');
      // Sets its crumbs via the store, in a useEffect with a clearing cleanup.
      expect(src, file).toMatch(/useBreadcrumbStore/);
      expect(src, file).toMatch(/setCrumbs\(\[/);
      expect(src, file).toMatch(/return \(\) => setCrumbs\(\[\]\)/);
      // Carries the right crumb labels.
      for (const label of crumbs) {
        expect(src, file).toMatch(new RegExp(`label: '${label}'`));
      }
    }
  });
});
