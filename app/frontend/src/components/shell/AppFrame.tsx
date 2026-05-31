import { Outlet } from '@tanstack/react-router';
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';
import { ErrorBoundary } from './ErrorBoundary';

// AppFrame — the persistent shell that wraps every authenticated route.
//
// Spec: frontend-foundation C-08, C-09, AC-10.

export function AppFrame() {
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
