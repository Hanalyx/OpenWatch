import { useAuthStore, type Identity } from '@/store/useAuthStore';
import api from './client';

// bootstrapAuth — fetches GET /auth/me at app boot to populate the
// auth store before route guards evaluate. Non-blocking; failure
// leaves identity null and the guard redirects to /login.
//
// The /auth/me response only includes {id, username, email, role}.
// The frontend extends this with permissions via a second call to
// /auth/me/permissions; for v0 we synthesize a minimal permission
// set from role (admin → all, others → host:read only). Real
// permission fetching lands when the permissions endpoint stabilizes.
//
// Spec: frontend-foundation C-06 (guarded routes redirect without
// identity), frontend-auth-login (session cookie is the auth credential).

function permissionsForRole(role: string): string[] {
  // Best-effort role → permission mapping until /auth/me/permissions
  // is wired. Matches the backend's RBAC registry baseline.
  if (role === 'admin' || role === 'super_admin') {
    return [
      'host:read',
      'host:write',
      'host:delete',
      'credential:read',
      'credential:write',
      'credential:delete',
      'scan:read',
      'audit:read',
      'notification:read',
      'notification:write',
      'notification:delete',
      'notification:test',
      'admin',
    ];
  }
  if (role === 'operator' || role === 'security') {
    return ['host:read', 'host:write', 'credential:read', 'credential:write', 'scan:read'];
  }
  // scan:read is a universal read permission (every built-in role grants
  // it), so even the viewer baseline can reach the /scans evidence surface.
  return ['host:read', 'scan:read'];
}

export async function bootstrapAuth(): Promise<void> {
  const setLoading = useAuthStore.getState().setLoading;
  const setIdentity = useAuthStore.getState().setIdentity;

  // Dev escape hatch — when running in Vite dev mode, set
  // localStorage["__ow_dev_admin"] to "1" to bypass the /auth/me call
  // and load a synthetic admin identity. Lets designers/developers
  // smoke-test guarded routes without a running backend.
  if (
    import.meta.env.DEV &&
    typeof localStorage !== 'undefined' &&
    localStorage.getItem('__ow_dev_admin') === '1'
  ) {
    setIdentity({
      id: '00000000-0000-0000-0000-000000000001',
      username: 'dev-admin',
      email: 'dev@local',
      role: 'admin',
      permissions: [
        'host:read',
        'host:write',
        'host:delete',
        'credential:read',
        'credential:write',
        'scan:read',
        'audit:read',
        'notification:read',
        'notification:write',
        'notification:delete',
        'notification:test',
        'admin',
      ],
      mfaEnabled: false,
    });
    return;
  }

  setLoading(true);
  try {
    const { data, response } = await api.GET('/api/v1/auth/me');
    if (response.ok && data) {
      const me = data as {
        id: string;
        username: string;
        email: string;
        role: string;
        mfa_enabled?: boolean;
      };
      const identity: Identity = {
        id: me.id,
        username: me.username,
        email: me.email,
        role: me.role,
        permissions: permissionsForRole(me.role),
        mfaEnabled: !!me.mfa_enabled,
      };
      setIdentity(identity);
    } else {
      setIdentity(null);
    }
  } catch {
    setIdentity(null);
  }
}
