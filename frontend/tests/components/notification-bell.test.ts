// @spec frontend-notifications
//
// AC traceability (source inspection):
//   AC-01  useNotifications: useNotificationFeed queries the feed; mark-read /
//          mark-all mutations POST the :read endpoints + invalidate the key
//   AC-02  TopBar NotificationBell renders a badge from the feed unread_count,
//          toggles a drawer, marks items read; not the disabled stub; no em-dash

import { describe, expect, test } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const HOOK_SRC = readFileSync(resolve(process.cwd(), 'src/hooks/useNotifications.ts'), 'utf8');
const TOPBAR_SRC = readFileSync(resolve(process.cwd(), 'src/components/shell/TopBar.tsx'), 'utf8');

function stripComments(s: string): string {
  return s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
}

describe('frontend-notifications — durable notification bell', () => {
  // @ac AC-01
  test('frontend-notifications/AC-01 — useNotifications queries the feed + mark-read mutations', () => {
    // Feed query against the durable endpoint, under the shared key.
    expect(HOOK_SRC).toContain("api.GET('/api/v1/notifications/feed'");
    expect(HOOK_SRC).toMatch(/\['notifications',\s*'feed'\]/);
    // Mark-read + mark-all mutations POST the :read endpoints.
    expect(HOOK_SRC).toContain("api.POST('/api/v1/notifications/feed/{id}:read'");
    expect(HOOK_SRC).toContain("api.POST('/api/v1/notifications/feed:read-all'");
    // And invalidate the feed key on success so the badge refreshes.
    expect(HOOK_SRC).toMatch(/invalidateQueries\(\{\s*queryKey:\s*NOTIFICATIONS_KEY/);
  });

  // @ac AC-02
  test('frontend-notifications/AC-02 — TopBar bell renders badge from feed, drawer, mark read', () => {
    // Reads unread_count from the durable feed (not a session counter).
    expect(TOPBAR_SRC).toContain('useNotificationFeed');
    expect(TOPBAR_SRC).toMatch(/unread_count/);
    // Badge only when unread > 0.
    expect(TOPBAR_SRC).toMatch(/unread > 0 &&/);
    // Drawer + read mutations are wired.
    expect(TOPBAR_SRC).toContain('useMarkNotificationRead');
    expect(TOPBAR_SRC).toContain('useMarkAllNotificationsRead');
    expect(TOPBAR_SRC).toMatch(/role="dialog"/);
    // The old session-counter store is gone.
    expect(TOPBAR_SRC).not.toContain('useNotificationStore');
    // The bell is not the disabled "coming soon" stub.
    expect(TOPBAR_SRC).not.toContain('Notifications (coming soon)');
    // No em-dash in the bell copy.
    expect(stripComments(TOPBAR_SRC).includes('—')).toBe(false);
  });
});
