// @spec frontend-notifications
//
// AC traceability (source inspection):
//   AC-01  useNotificationStore: zustand store with unreadReports (init 0),
//          bumpReportReady (increments), clearReports (resets to 0)
//   AC-02  TopBar NotificationBell renders a badge only when unreadReports > 0,
//          clears + navigates to /reports on click, is not the disabled stub,
//          no em-dash

import { describe, expect, test } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const STORE_SRC = readFileSync(resolve(process.cwd(), 'src/store/useNotificationStore.ts'), 'utf8');
const TOPBAR_SRC = readFileSync(resolve(process.cwd(), 'src/components/shell/TopBar.tsx'), 'utf8');

function stripComments(s: string): string {
  return s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
}

describe('frontend-notifications — notification bell', () => {
  // @ac AC-01
  test('frontend-notifications/AC-01 — useNotificationStore shape (counter + bump + clear)', () => {
    // A zustand store.
    expect(STORE_SRC).toMatch(/create<NotificationState>\(/);
    // unreadReports initialised to 0.
    expect(STORE_SRC).toMatch(/unreadReports:\s*0/);
    // bumpReportReady increments the counter.
    expect(STORE_SRC).toMatch(
      /bumpReportReady:\s*\(\)\s*=>\s*set\(\(s\)\s*=>\s*\(\{\s*unreadReports:\s*s\.unreadReports\s*\+\s*1/,
    );
    // clearReports resets it to 0.
    expect(STORE_SRC).toMatch(/clearReports:\s*\(\)\s*=>\s*set\(\{\s*unreadReports:\s*0/);
  });

  // @ac AC-02
  test('frontend-notifications/AC-02 — TopBar bell renders badge, clears + navigates on click', () => {
    // Reads the unread counter from the store.
    expect(TOPBAR_SRC).toContain('useNotificationStore');
    expect(TOPBAR_SRC).toMatch(/useNotificationStore\(\(s\)\s*=>\s*s\.unreadReports\)/);
    // Badge renders only when unread > 0.
    expect(TOPBAR_SRC).toMatch(/unread > 0 &&/);
    // Click clears the counter and navigates to /reports.
    expect(TOPBAR_SRC).toMatch(/clearReports\(\)/);
    expect(TOPBAR_SRC).toMatch(/navigate\(\{\s*to:\s*'\/reports'\s*\}\)/);
    // The bell is no longer the disabled "coming soon" stub.
    expect(TOPBAR_SRC).not.toContain('Notifications (coming soon)');
    // No em-dash in the bell copy.
    expect(stripComments(TOPBAR_SRC).includes('—')).toBe(false);
  });
});
