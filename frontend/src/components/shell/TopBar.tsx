import { useCallback, useEffect, useRef, useState } from 'react';
import { useNavigate } from '@tanstack/react-router';
import { Sun, Moon, Monitor, Bell, LogOut } from 'lucide-react';
import api from '@/api/client';
import { useAuthStore } from '@/store/useAuthStore';
import { useBreadcrumbStore } from '@/store/useBreadcrumbStore';
import { useColorSchemeStore, type ColorScheme } from '@/store/useColorSchemeStore';

// TopBar — sticky header with breadcrumb, theme toggle, notifications,
// and the account menu (button + dropdown with Sign out).
// Matches the prototype's `.topbar` block (Host Management.html lines 99-115).
//
// Spec: frontend-shell-account-menu v1.0.0.

export function TopBar() {
  const identity = useAuthStore((s) => s.identity);
  const crumbs = useBreadcrumbStore((s) => s.crumbs);

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
          {identity && <AccountMenu username={identity.username} email={identity.email} />}
        </div>
      </div>
    </header>
  );
}

// AccountMenu — avatar button + popover menu.
// Spec C-01..C-04. Sign out path: api.POST /auth/logout -> clear
// identity -> navigate to /login (order matters; the API call needs
// the still-valid cookie).
function AccountMenu({ username, email }: { username: string; email: string }) {
  const [open, setOpen] = useState(false);
  const navigate = useNavigate();
  const clearIdentity = useAuthStore((s) => s.clear);
  const wrapperRef = useRef<HTMLDivElement>(null);
  const initial = (username[0] ?? email[0] ?? '?').toUpperCase();

  // Close on Escape (anywhere in the document) AND on click outside
  // the menu wrapper. Spec C-04.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false);
    };
    const onMouseDown = (e: MouseEvent) => {
      if (!wrapperRef.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('keydown', onKey);
    document.addEventListener('mousedown', onMouseDown);
    return () => {
      document.removeEventListener('keydown', onKey);
      document.removeEventListener('mousedown', onMouseDown);
    };
  }, [open]);

  const onSignOut = useCallback(async () => {
    // Spec C-03: API first while the cookie is still valid; local
    // clear + redirect run regardless of API result. A backend session
    // that lingers is acceptable; a UI that thinks it's logged in
    // while the backend has revoked is not.
    try {
      await api.POST('/api/v1/auth/logout', {});
    } catch {
      // best-effort
    }
    clearIdentity();
    setOpen(false);
    navigate({ to: '/login' });
  }, [clearIdentity, navigate]);

  return (
    <div ref={wrapperRef} style={{ position: 'relative' }}>
      <button
        type="button"
        aria-label={`Account: ${username}`}
        aria-haspopup="menu"
        aria-expanded={open}
        title={username}
        onClick={() => setOpen((v) => !v)}
        style={{
          width: 30,
          height: 30,
          background: 'var(--ow-info)',
          color: 'var(--ow-info-on)',
          border: '1px solid var(--ow-line)',
          borderRadius: '50%',
          display: 'grid',
          placeItems: 'center',
          fontWeight: 600,
          fontSize: 13,
          cursor: 'pointer',
          padding: 0,
        }}
      >
        {initial}
      </button>
      {open && (
        <div
          role="menu"
          aria-label={`Account menu for ${username}`}
          style={{
            position: 'absolute',
            top: 38,
            right: 0,
            minWidth: 200,
            background: 'var(--ow-bg-1)',
            border: '1px solid var(--ow-line)',
            borderRadius: 8,
            boxShadow: '0 8px 24px rgba(0,0,0,0.25)',
            padding: '6px 0',
            zIndex: 40,
          }}
        >
          <div
            style={{
              padding: '8px 12px 10px',
              borderBottom: '1px solid var(--ow-line)',
              fontSize: 12,
            }}
          >
            <div style={{ color: 'var(--ow-fg-0)', fontWeight: 500 }}>{username}</div>
            <div style={{ color: 'var(--ow-fg-3)' }}>{email}</div>
          </div>
          <button
            type="button"
            role="menuitem"
            onClick={onSignOut}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              width: '100%',
              padding: '8px 12px',
              background: 'transparent',
              border: 0,
              color: 'var(--ow-fg-0)',
              textAlign: 'left',
              fontSize: 13,
              cursor: 'pointer',
            }}
          >
            <LogOut size={13} /> Sign out
          </button>
        </div>
      )}
    </div>
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
        const node =
          c.href && !isLast ? (
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
    mode === 'light' ? (
      <Sun size={14} />
    ) : mode === 'dark' ? (
      <Moon size={14} />
    ) : (
      <Monitor size={14} />
    );
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
