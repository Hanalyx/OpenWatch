import { useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { UserPlus } from 'lucide-react';
import api from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import { useBreadcrumbStore } from '@/store/useBreadcrumbStore';
import { useAuthStore } from '@/store/useAuthStore';
import { SettingsLayout } from '@/components/settings/SettingsLayout';
import {
  PageHead,
  Section,
  SettingCard,
  Btn,
  StatusPill,
} from '@/components/settings/primitives';
import { ForbiddenPage } from '@/pages/ForbiddenPage';

// Settings → Users & teams.
//
// Wired to GET /api/v1/users (admin-gated). Member detail page +
// invite flow deferred to follow-up.

interface UserRow {
  id: string;
  username: string;
  email: string;
  role: string;
  is_active?: boolean;
  mfa_enabled?: boolean;
  created_at: string;
  last_login_at?: string | null;
}

export function UsersPage() {
  const setCrumbs = useBreadcrumbStore((s) => s.setCrumbs);
  const isAdmin = useAuthStore((s) => s.hasPermission('admin'));
  useEffect(() => {
    setCrumbs([{ label: 'Settings' }, { label: 'Users & teams' }]);
    return () => setCrumbs([]);
  }, [setCrumbs]);

  const usersQuery = useQuery({
    queryKey: ['users'],
    queryFn: async () => {
      const { data, error } = await api.GET('/api/v1/users');
      if (error) throw error;
      return (data as { users: UserRow[] }).users ?? [];
    },
    enabled: isAdmin,
    retry: 0,
  });

  if (!isAdmin) {
    // RBAC gate: viewers / operators don't get the user roster.
    return <ForbiddenPage />;
  }

  return (
    <SettingsLayout>
      <PageHead
        title="Users & teams"
        description="Workspace members and their roles. Only admins can invite new members."
        actions={
          <Btn variant="primary" disabled>
            <UserPlus size={14} /> Invite member
          </Btn>
        }
      />

      <Section title="Members">
        {usersQuery.isLoading && (
          <SettingCard>
            <div style={{ padding: 20, color: 'var(--ow-fg-2)', fontSize: 13 }}>Loading…</div>
          </SettingCard>
        )}
        {usersQuery.isError && (
          <SettingCard>
            <div
              role="alert"
              style={{
                padding: 20,
                color: 'var(--ow-fg-1)',
                background: 'var(--ow-crit-bg)',
                borderLeft: '3px solid var(--ow-crit)',
                fontSize: 13,
              }}
            >
              <strong>Failed to load members.</strong>{' '}
              {apiErrorMessage(usersQuery.error, '')}{' '}
              <button
                type="button"
                onClick={() => usersQuery.refetch()}
                style={{
                  marginLeft: 12,
                  background: 'transparent',
                  border: 0,
                  color: 'var(--ow-info)',
                  cursor: 'pointer',
                  textDecoration: 'underline',
                }}
              >
                Retry
              </button>
            </div>
          </SettingCard>
        )}
        {usersQuery.data && usersQuery.data.length === 0 && (
          <SettingCard>
            <div
              style={{
                padding: 32,
                textAlign: 'center',
                color: 'var(--ow-fg-2)',
                fontSize: 13,
              }}
            >
              No members yet.
            </div>
          </SettingCard>
        )}
        {usersQuery.data && usersQuery.data.length > 0 && (
          <SettingCard>
            {usersQuery.data.map((user, i) => (
              <UserRow key={user.id} user={user} isFirst={i === 0} />
            ))}
          </SettingCard>
        )}
      </Section>
    </SettingsLayout>
  );
}

function UserRow({ user, isFirst }: { user: UserRow; isFirst: boolean }) {
  const initials = user.username
    .split(/[\s._-]/)
    .map((s) => s[0]?.toUpperCase() ?? '')
    .slice(0, 2)
    .join('');
  const status: 'ok' | 'warn' | 'crit' = user.is_active === false ? 'crit' : 'ok';
  const statusLabel = user.is_active === false ? 'Disabled' : 'Active';
  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: '1fr 110px 90px auto',
        gap: 16,
        alignItems: 'center',
        padding: '14px 20px',
        borderTop: isFirst ? 'none' : '1px solid var(--ow-line)',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, minWidth: 0 }}>
        <div
          style={{
            width: 32,
            height: 32,
            borderRadius: '50%',
            background: 'var(--ow-bg-3)',
            color: 'var(--ow-fg-1)',
            display: 'grid',
            placeItems: 'center',
            fontWeight: 600,
            fontSize: 12,
            flexShrink: 0,
          }}
        >
          {initials || '?'}
        </div>
        <div style={{ minWidth: 0 }}>
          <div style={{ fontWeight: 500 }}>{user.username}</div>
          <div
            style={{
              color: 'var(--ow-fg-3)',
              fontSize: 11,
              marginTop: 2,
              fontFamily: 'var(--ow-font-mono)',
            }}
          >
            {user.email}
          </div>
        </div>
      </div>
      <span
        style={{
          fontSize: 12,
          color: 'var(--ow-fg-1)',
          textTransform: 'capitalize',
        }}
      >
        {user.role}
      </span>
      <StatusPill tier={status}>{statusLabel}</StatusPill>
      <Btn size="sm" disabled>
        Manage
      </Btn>
    </div>
  );
}
