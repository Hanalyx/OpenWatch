import { useMemo, useState, type ReactNode } from 'react';
import { Link, useLocation } from '@tanstack/react-router';
import {
  Search,
  Clock,
  Lock,
  ShieldCheck,
  Bell,
  LayoutGrid,
  Users,
  ScrollText,
  User,
  SlidersHorizontal,
  Info,
  Shield,
} from 'lucide-react';

// SettingsLayout — 260px left nav + main pane.
//
// Direct port of the prototype's .settings-shell / .settings-nav block.
// Nav search filters items by label (client-side only); the
// prototype's full-document settings search is deferred.

interface NavItem {
  id: string;
  label: string;
  icon: ReactNode;
  to:
    | '/settings/profile'
    | '/settings/preferences'
    | '/settings/credentials'
    | '/settings/users'
    | '/settings/scanning'
    | '/settings/policies'
    | '/settings/notifications'
    | '/settings/integrations'
    | '/settings/security'
    | '/settings/audit'
    | '/settings/about';
  count?: number;
  pip?: 'warn' | 'crit';
}

interface NavGroup {
  title: string;
  items: NavItem[];
}

const NAV_GROUPS: NavGroup[] = [
  {
    title: 'Workspace',
    items: [
      {
        id: 'scanning',
        label: 'Scanning & monitoring',
        icon: <Clock size={14} />,
        to: '/settings/scanning',
      },
      {
        id: 'credentials',
        label: 'SSH & credentials',
        icon: <Lock size={14} />,
        to: '/settings/credentials',
      },
      {
        id: 'policies',
        label: 'Compliance policies',
        icon: <ShieldCheck size={14} />,
        to: '/settings/policies',
      },
      {
        id: 'notifications',
        label: 'Notifications',
        icon: <Bell size={14} />,
        to: '/settings/notifications',
      },
      {
        id: 'integrations',
        label: 'Integrations',
        icon: <LayoutGrid size={14} />,
        to: '/settings/integrations',
      },
    ],
  },
  {
    title: 'Access',
    items: [
      { id: 'users', label: 'Users & teams', icon: <Users size={14} />, to: '/settings/users' },
      {
        id: 'security',
        label: 'Security & auth',
        icon: <Shield size={14} />,
        to: '/settings/security',
        pip: 'warn',
      },
      { id: 'audit', label: 'Audit log', icon: <ScrollText size={14} />, to: '/settings/audit' },
    ],
  },
  {
    title: 'Personal',
    items: [
      { id: 'profile', label: 'Profile', icon: <User size={14} />, to: '/settings/profile' },
      {
        id: 'preferences',
        label: 'Preferences',
        icon: <SlidersHorizontal size={14} />,
        to: '/settings/preferences',
      },
      { id: 'about', label: 'About', icon: <Info size={14} />, to: '/settings/about' },
    ],
  },
];

export function SettingsLayout({ children }: { children: ReactNode }) {
  const [search, setSearch] = useState('');
  const location = useLocation();
  const path = location.pathname;

  const filteredGroups = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return NAV_GROUPS;
    return NAV_GROUPS.map((g) => ({
      ...g,
      items: g.items.filter((it) => it.label.toLowerCase().includes(q)),
    })).filter((g) => g.items.length > 0);
  }, [search]);

  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: '260px 1fr',
        alignItems: 'start',
        minHeight: 'calc(100vh - 60px)',
      }}
    >
      <nav
        aria-label="Settings categories"
        style={{
          background: 'var(--ow-bg-1)',
          borderRight: '1px solid var(--ow-line)',
          position: 'sticky',
          top: 60,
          height: 'calc(100vh - 60px)',
          overflowY: 'auto',
          padding: '18px 14px',
        }}
      >
        <div
          style={{
            height: 32,
            background: 'var(--ow-bg-2)',
            border: '1px solid var(--ow-line)',
            borderRadius: 6,
            display: 'flex',
            alignItems: 'center',
            padding: '0 10px',
            gap: 8,
            color: 'var(--ow-fg-2)',
            marginBottom: 14,
          }}
        >
          <Search size={14} />
          <input
            type="search"
            placeholder="Search settings…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            aria-label="Search settings"
            style={{
              flex: 1,
              background: 'transparent',
              border: 0,
              outline: 0,
              color: 'var(--ow-fg-0)',
              fontFamily: 'inherit',
              fontSize: 13,
            }}
          />
        </div>

        {filteredGroups.map((group) => (
          <div key={group.title} style={{ marginBottom: 14 }}>
            <h4
              style={{
                margin: '0 8px 6px',
                fontSize: 10,
                fontWeight: 600,
                color: 'var(--ow-fg-3)',
                textTransform: 'uppercase',
                letterSpacing: '0.08em',
              }}
            >
              {group.title}
            </h4>
            {group.items.map((item) => {
              const isActive = path === item.to;
              return (
                <Link
                  key={item.id}
                  to={item.to}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 10,
                    padding: '7px 10px',
                    borderRadius: 6,
                    color: isActive ? 'var(--ow-fg-0)' : 'var(--ow-fg-1)',
                    background: isActive ? 'var(--ow-bg-3)' : 'transparent',
                    fontSize: 13,
                    fontWeight: isActive ? 500 : 400,
                    textDecoration: 'none',
                    transition: 'background 100ms',
                  }}
                >
                  <span
                    style={{
                      color: isActive ? 'var(--ow-info)' : 'var(--ow-fg-3)',
                      flexShrink: 0,
                      display: 'inline-flex',
                    }}
                  >
                    {item.icon}
                  </span>
                  <span style={{ flex: 1 }}>{item.label}</span>
                  {item.count != null && (
                    <span
                      style={{
                        marginLeft: 'auto',
                        fontSize: 11,
                        color: isActive ? 'var(--ow-info)' : 'var(--ow-fg-3)',
                        background: isActive ? 'var(--ow-info-bg)' : 'var(--ow-bg-3)',
                        padding: '1px 7px',
                        borderRadius: 'var(--ow-radius-full)',
                        fontVariantNumeric: 'tabular-nums',
                      }}
                    >
                      {item.count}
                    </span>
                  )}
                  {item.pip && (
                    <span
                      style={{
                        width: 6,
                        height: 6,
                        borderRadius: '50%',
                        background: item.pip === 'warn' ? 'var(--ow-warn)' : 'var(--ow-crit)',
                        marginLeft: 'auto',
                      }}
                    />
                  )}
                </Link>
              );
            })}
          </div>
        ))}
      </nav>

      <div
        style={{
          padding: '24px 32px 96px',
          maxWidth: 1100,
          width: '100%',
        }}
      >
        {children}
      </div>
    </div>
  );
}
