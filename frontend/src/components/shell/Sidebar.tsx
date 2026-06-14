import { Link, useLocation } from '@tanstack/react-router';
import {
  LayoutDashboard,
  Server,
  Boxes,
  Search,
  Activity,
  BarChart3,
  Terminal,
  Settings as SettingsIcon,
} from 'lucide-react';
import { Tooltip } from '@mui/material';
import owIcon from '@/assets/openwatch-icon.png';

// Sidebar — 56px-wide icon rail. Sticky, full-viewport-height. The
// only chrome that persists across every page.
//
// Spec: frontend-foundation (shell). Active state per route.

interface NavItem {
  to: string;
  label: string;
  icon: React.ReactNode;
  // enabled is false for destinations whose route is not yet in the
  // route table (frontend/src/routes/router.tsx). Those entries render
  // as disabled "coming soon" controls instead of Links, so the rail
  // never points at a path that resolves to not-found.
  // Spec: frontend-foundation C-12 / AC-18.
  enabled: boolean;
}

const navItems: NavItem[] = [
  { to: '/dashboard', label: 'Dashboard', icon: <LayoutDashboard size={18} />, enabled: true },
  { to: '/hosts', label: 'Hosts', icon: <Server size={18} />, enabled: true },
  { to: '/groups', label: 'Groups', icon: <Boxes size={18} />, enabled: true },
  { to: '/scans', label: 'Scans', icon: <Search size={18} />, enabled: true },
  { to: '/activity', label: 'Activity', icon: <Activity size={18} />, enabled: true },
  { to: '/reports', label: 'Reports', icon: <BarChart3 size={18} />, enabled: true },
  { to: '/terminal', label: 'Terminal', icon: <Terminal size={18} />, enabled: false },
];

export function Sidebar() {
  const location = useLocation();
  const currentPath = location.pathname;

  return (
    <aside
      style={{
        background: 'var(--ow-bg-1)',
        borderRight: '1px solid var(--ow-line)',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        padding: '14px 0',
        gap: 4,
        position: 'sticky',
        top: 0,
        height: '100vh',
        width: 56,
      }}
      aria-label="Primary navigation"
    >
      <Link to="/dashboard" aria-label="OpenWatch home">
        <div
          style={{
            width: 32,
            height: 32,
            borderRadius: 8,
            background: '#fff',
            display: 'grid',
            placeItems: 'center',
            overflow: 'hidden',
            marginBottom: 12,
            boxShadow: '0 0 0 1px rgba(255,255,255,0.10), 0 4px 16px rgba(0,0,0,0.35)',
          }}
        >
          <img
            src={owIcon}
            alt=""
            style={{ width: '84%', height: '84%', objectFit: 'contain', display: 'block' }}
          />
        </div>
      </Link>

      {navItems.map((item) => {
        // Unbuilt destinations render as a disabled control with a
        // "coming soon" affordance — never a Link to a missing route.
        // A native disabled <button> is keyboard-correct and axe-clean;
        // it is wrapped in a span so the Tooltip still fires on hover
        // (disabled elements emit no pointer events of their own).
        if (!item.enabled) {
          return (
            <Tooltip key={item.to} title={`${item.label} (coming soon)`} placement="right">
              <span style={{ display: 'inline-flex' }}>
                <button
                  type="button"
                  disabled
                  aria-label={`${item.label} (coming soon)`}
                  style={{
                    width: 40,
                    height: 40,
                    display: 'grid',
                    placeItems: 'center',
                    borderRadius: 8,
                    border: 'none',
                    background: 'transparent',
                    color: 'var(--ow-fg-3)',
                    opacity: 0.45,
                    cursor: 'default',
                  }}
                >
                  {item.icon}
                </button>
              </span>
            </Tooltip>
          );
        }

        const isActive = currentPath.startsWith(item.to);
        return (
          <Tooltip key={item.to} title={item.label} placement="right">
            <Link
              to={item.to}
              aria-label={item.label}
              aria-current={isActive ? 'page' : undefined}
              style={{
                width: 40,
                height: 40,
                display: 'grid',
                placeItems: 'center',
                borderRadius: 8,
                color: isActive ? 'var(--ow-fg-0)' : 'var(--ow-fg-2)',
                background: isActive ? 'var(--ow-bg-3)' : 'transparent',
                boxShadow: isActive ? 'inset 2px 0 0 var(--ow-info)' : undefined,
                transition: 'all var(--ow-motion-fast)',
              }}
            >
              {item.icon}
            </Link>
          </Tooltip>
        );
      })}

      <div style={{ flex: 1 }} />

      <Tooltip title="Settings" placement="right">
        <Link
          to="/settings"
          aria-label="Settings"
          aria-current={currentPath.startsWith('/settings') ? 'page' : undefined}
          style={{
            width: 40,
            height: 40,
            display: 'grid',
            placeItems: 'center',
            borderRadius: 8,
            color: currentPath.startsWith('/settings') ? 'var(--ow-fg-0)' : 'var(--ow-fg-2)',
            background: currentPath.startsWith('/settings') ? 'var(--ow-bg-3)' : 'transparent',
          }}
        >
          <SettingsIcon size={18} />
        </Link>
      </Tooltip>
    </aside>
  );
}
