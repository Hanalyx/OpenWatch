import { create } from 'zustand';

// Auth store — identity cache and session lifecycle hooks.
//
// Per app/docs/frontend_architecture_adr.md D-08, the browser
// frontend uses session-cookie auth. The session cookie itself is
// HttpOnly and not readable from JS; this store mirrors the identity
// returned by GET /api/v1/auth/me so components can render
// permission-gated UI without re-fetching on every render.
//
// IMPORTANT: this store MUST NEVER hold access_token or refresh_token.
// Those values exist in the login response body but are for API
// consumers; the browser ignores them.
//
// Spec: frontend-auth-login C-02, AC-02.

export interface Identity {
  id: string;
  username: string;
  email: string;
  role: string;
  permissions: string[];
  mfaEnabled: boolean;
}

interface AuthStore {
  identity: Identity | null;
  loading: boolean;

  setIdentity: (identity: Identity | null) => void;
  setLoading: (loading: boolean) => void;
  hasPermission: (permission: string) => boolean;
  clear: () => void;
}

export const useAuthStore = create<AuthStore>((set, get) => ({
  identity: null,
  loading: true,

  setIdentity: (identity) => set({ identity, loading: false }),
  setLoading: (loading) => set({ loading }),

  hasPermission: (permission) => {
    const id = get().identity;
    if (!id) return false;
    return id.permissions.includes(permission);
  },

  clear: () => set({ identity: null, loading: false }),
}));
