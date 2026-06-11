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

// Sidebar — 56px-wide icon rail. Sticky, full-viewport-height. The
// only chrome that persists across every page.
//
// Spec: frontend-foundation (shell). Active state per route.

interface NavItem {
  to: string;
  label: string;
  icon: React.ReactNode;
}

const navItems: NavItem[] = [
  { to: '/', label: 'Dashboard', icon: <LayoutDashboard size={18} /> },
  { to: '/hosts', label: 'Hosts', icon: <Server size={18} /> },
  { to: '/groups', label: 'Groups', icon: <Boxes size={18} /> },
  { to: '/scans', label: 'Scans', icon: <Search size={18} /> },
  { to: '/activity', label: 'Activity', icon: <Activity size={18} /> },
  { to: '/reports', label: 'Reports', icon: <BarChart3 size={18} /> },
  { to: '/terminal', label: 'Terminal', icon: <Terminal size={18} /> },
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
      <Link to="/" aria-label="OpenWatch home">
        <div
          style={{
            width: 32,
            height: 32,
            borderRadius: 8,
            background: 'linear-gradient(135deg, var(--ow-info), var(--ow-brand-2))',
            display: 'grid',
            placeItems: 'center',
            fontWeight: 700,
            color: 'white',
            marginBottom: 12,
          }}
        >
          ow
        </div>
      </Link>

      {navItems.map((item) => {
        const isActive = item.to === '/' ? currentPath === '/' : currentPath.startsWith(item.to);
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
