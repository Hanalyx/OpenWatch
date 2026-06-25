// Shared fixtures for the frontend-shell-account-menu spec test files.
//
// The spec's seven ACs were originally exercised in a single test file
// (topbar-account-menu.test.tsx). specter v0.13.2's `coverage --strict`
// walker has a bug that only credits the first @ac annotation per
// source file even when ingest captures all of them as passed. The
// workaround is one test file per AC. Pure helpers (no vi.mock — those
// must stay in each test file so vitest's hoister handles them) live
// here so the per-AC files stay small.

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createElement } from 'react';
import { render } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { useAuthStore } from '@/store/useAuthStore';
import { TopBar } from '@/components/shell/TopBar';

// renderTopBar renders the TopBar inside a QueryClientProvider — the bell now
// reads the durable notification feed via TanStack Query (frontend-notifications
// v2.0.0), so a client must be present. Each call gets a fresh client.
export function renderTopBar() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(createElement(QueryClientProvider, { client: qc }, createElement(TopBar)));
}

// Module-level source snapshot of TopBar.tsx, read once. AC-01 asserts
// against this string directly (source inspection); the others use the
// rendered component.
export const TOPBAR_SRC = readFileSync(
  resolve(process.cwd(), 'src/components/shell/TopBar.tsx'),
  'utf8',
);

// signIn populates useAuthStore with a fixture identity so the
// avatar button renders. AC-07 deliberately skips this call to
// assert the no-identity render branch.
export function signIn() {
  useAuthStore.setState({
    identity: {
      id: 'u-1',
      username: 'fixture',
      email: 'fixture@local',
      role: 'admin',
      permissions: ['host:read'],
      mfaEnabled: false,
    },
    loading: false,
  });
}

// clearAuth is the shared beforeEach hook. navigateMock / logoutPostSpy
// resets stay in their per-file scope because vi.fn instances are file-
// local when declared in test files.
export function clearAuth() {
  useAuthStore.getState().clear();
}
