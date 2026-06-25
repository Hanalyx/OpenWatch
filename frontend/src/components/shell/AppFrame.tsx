import { useEffect } from 'react';
import { Outlet } from '@tanstack/react-router';
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';
import { ErrorBoundary } from './ErrorBoundary';
import { usePreferencesStore } from '@/store/usePreferencesStore';
import { useIdleLogout } from '@/hooks/useIdleLogout';

// AppFrame — the persistent shell that wraps every authenticated route.
//
// Spec: frontend-foundation C-08, C-09, AC-10; frontend-session-idle.

export function AppFrame() {
  // Reconcile per-user UI preferences with the server once the
  // authenticated shell mounts (system-user-preferences). Best-effort: a
  // failed fetch leaves the localStorage-cached values in place.
  const hydratePreferences = usePreferencesStore((s) => s.hydrateFromServer);
  useEffect(() => {
    void hydratePreferences();
  }, [hydratePreferences]);

  // Enforce the operator-configured idle timeout against REAL user activity
  // (background polling slides the server-side window, so a client timer is
  // what actually terminates an unattended session). Spec frontend-session-idle.
  useIdleLogout();

  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: '56px 1fr',
        minHeight: '100vh',
      }}
    >
      <Sidebar />
      <main>
        <TopBar />
        <ErrorBoundary>
          <Outlet />
        </ErrorBoundary>
      </main>
    </div>
  );
}
