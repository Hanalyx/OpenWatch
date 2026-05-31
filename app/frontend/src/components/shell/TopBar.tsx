import { Sun, Moon, Monitor, Bell } from 'lucide-react';
import { useAuthStore } from '@/store/useAuthStore';
import { useBreadcrumbStore } from '@/store/useBreadcrumbStore';
import { useColorSchemeStore, type ColorScheme } from '@/store/useColorSchemeStore';

// TopBar — sticky header with breadcrumb, theme toggle, notifications, avatar.
// Matches the prototype's `.topbar` block (Host Management.html lines 99-115).

export function TopBar() {
  const identity = useAuthStore((s) => s.identity);
  const crumbs = useBreadcrumbStore((s) => s.crumbs);
  const initial =
    identity?.username?.[0]?.toUpperCase() ??
    identity?.email?.[0]?.toUpperCase() ??
    '?';

  return (
    <header
      style={{
        position: 'sticky',
        top: 0,
        zIndex: 30,
        background: 'color-mix(in oklab, var(--ow-bg-0) 92%, transparent)',
        backdropFilter: 'blur(8px)',
        borderBottom: '1px solid var(--ow-line)',
      }}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          padding: '14px 28px',
          gap: 16,
        }}
      >
        <Breadcrumbs crumbs={crumbs} />
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 8, alignItems: 'center' }}>
          <ThemeIconToggle />
          <NotificationBell />
          {identity && (
            <div
              aria-label={`Account: ${identity.username}`}
              title={identity.username}
              style={{
                width: 30,
                height: 30,
                background: 'var(--ow-info)',
                color: 'var(--ow-info-on)',
                borderRadius: '50%',
                display: 'grid',
                placeItems: 'center',
                fontWeight: 600,
                fontSize: 13,
              }}
            >
              {initial}
            </div>
          )}
        </div>
      </div>
    </header>
  );
}

function Breadcrumbs({ crumbs }: { crumbs: { label: string; href?: string }[] }) {
  if (crumbs.length === 0) return <div />;
  return (
    <nav
      aria-label="Breadcrumb"
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 8,
        color: 'var(--ow-fg-2)',
        fontSize: 13,
      }}
    >
      {crumbs.map((c, i) => {
        const isLast = i === crumbs.length - 1;
        const color = isLast ? 'var(--ow-fg-0)' : 'var(--ow-fg-2)';
        // Plain anchors here — TanStack Router would require typed
        // `to` props; breadcrumbs come from arbitrary page state.
        const node = c.href && !isLast ? (
          <a href={c.href} style={{ color, textDecoration: 'none' }}>
            {c.label}
          </a>
        ) : (
          <span style={{ color }}>{c.label}</span>
        );
        return (
          <span key={i} style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
            {i > 0 && <span style={{ color: 'var(--ow-fg-3)' }}>/</span>}
            {node}
          </span>
        );
      })}
    </nav>
  );
}

// Compact theme toggle — single sun/moon/monitor icon that cycles
// light → dark → system → light. The Zustand color-scheme store owns
// the data-mui-color-scheme attribute on <html>; setMode writes it
// synchronously and persists to localStorage.
function ThemeIconToggle() {
  const mode = useColorSchemeStore((s) => s.mode);
  const setMode = useColorSchemeStore((s) => s.setMode);

  const next: Record<ColorScheme, ColorScheme> = {
    light: 'dark',
    dark: 'system',
    system: 'light',
  };
  const icon =
    mode === 'light' ? <Sun size={14} /> : mode === 'dark' ? <Moon size={14} /> : <Monitor size={14} />;
  const label = `Theme: ${mode} (click to switch)`;

  return (
    <button
      type="button"
      onClick={() => setMode(next[mode])}
      aria-label={label}
      title={label}
      style={iconBtn}
    >
      {icon}
    </button>
  );
}

function NotificationBell() {
  // The /activity route is deferred (see app/docs/activity_and_os_intelligence.md).
  // Render the bell with the unread indicator; click is a no-op for now.
  return (
    <button
      type="button"
      aria-label="Notifications (coming soon)"
      title="Notifications"
      style={{ ...iconBtn, position: 'relative', cursor: 'not-allowed', opacity: 0.85 }}
      disabled
    >
      <Bell size={14} />
      <span
        style={{
          position: 'absolute',
          top: 6,
          right: 6,
          width: 7,
          height: 7,
          background: 'var(--ow-crit)',
          borderRadius: '50%',
          boxShadow: '0 0 0 2px var(--ow-bg-0)',
        }}
      />
    </button>
  );
}

const iconBtn: React.CSSProperties = {
  width: 30,
  height: 30,
  borderRadius: 6,
  background: 'var(--ow-bg-1)',
  border: '1px solid var(--ow-line)',
  color: 'var(--ow-fg-2)',
  display: 'inline-grid',
  placeItems: 'center',
  textDecoration: 'none',
  cursor: 'pointer',
};
