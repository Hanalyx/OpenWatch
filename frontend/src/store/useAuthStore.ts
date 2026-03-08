import { create } from 'zustand';
import {
  storageClearAuth,
  storageGet,
  storageGetJSON,
  storageSet,
  StorageKeys,
} from '../services/storage';

interface User {
  id: string;
  username: string;
  email: string;
  role: string;
  mfaEnabled: boolean;
}

interface AuthState {
  user: User | null;
  token: string | null;
  refreshToken: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
  mfaRequired: boolean;
  sessionExpiry: number | null;
}

interface LoginPayload {
  user: User;
  token: string;
  refreshToken: string;
  expiresIn: number;
}

interface AuthActions {
  loginSuccess: (payload: LoginPayload) => void;
  loginFailure: (message: string) => void;
  logout: () => void;
  clearError: () => void;
  setMfaRequired: (required: boolean) => void;
  setLoading: (loading: boolean) => void;
  refreshTokenSuccess: (payload: {
    token: string;
    refreshToken?: string;
    expiresIn: number;
  }) => void;
  checkSessionExpiry: () => void;
}

const loadPersistedAuthState = (): Partial<AuthState> => {
  try {
    const token = storageGet(StorageKeys.AUTH_TOKEN);
    const refreshToken = storageGet(StorageKeys.REFRESH_TOKEN);
    const user = storageGetJSON<User>(StorageKeys.AUTH_USER);
    const sessionExpiryStr = storageGet(StorageKeys.SESSION_EXPIRY);

    if (token && user) {
      const sessionExpiry = sessionExpiryStr ? parseInt(sessionExpiryStr) : null;

      if (!sessionExpiry || sessionExpiry > Date.now()) {
        return { user, token, refreshToken, isAuthenticated: true, sessionExpiry };
      } else {
        storageClearAuth();
      }
    }
  } catch (error) {
    console.warn('Failed to load persisted auth state:', error);
  }
  return {};
};

const persistedState = loadPersistedAuthState();

const initialState: AuthState = {
  user: null,
  token: null,
  refreshToken: null,
  isAuthenticated: false,
  isLoading: false,
  error: null,
  mfaRequired: false,
  sessionExpiry: null,
  ...persistedState,
};

export const useAuthStore = create<AuthState & AuthActions>()((set) => ({
  ...initialState,

  loginSuccess: (payload) => {
    const sessionExpiry = Date.now() + payload.expiresIn * 1000;
    storageSet(StorageKeys.AUTH_TOKEN, payload.token);
    storageSet(StorageKeys.REFRESH_TOKEN, payload.refreshToken);
    storageSet(StorageKeys.AUTH_USER, JSON.stringify(payload.user));
    storageSet(StorageKeys.SESSION_EXPIRY, sessionExpiry.toString());
    set({
      isLoading: false,
      isAuthenticated: true,
      user: payload.user,
      token: payload.token,
      refreshToken: payload.refreshToken,
      sessionExpiry,
      error: null,
      mfaRequired: false,
    });
  },

  loginFailure: (message) => {
    set({
      isLoading: false,
      error: message,
      isAuthenticated: false,
      mfaRequired: message.includes('MFA required'),
    });
  },

  logout: () => {
    storageClearAuth();
    set({
      user: null,
      token: null,
      refreshToken: null,
      isAuthenticated: false,
      sessionExpiry: null,
      error: null,
      mfaRequired: false,
    });
  },

  clearError: () => set({ error: null }),

  setMfaRequired: (required) => set({ mfaRequired: required }),

  setLoading: (loading) => set({ isLoading: loading }),

  refreshTokenSuccess: (payload) => {
    const sessionExpiry = Date.now() + payload.expiresIn * 1000;
    storageSet(StorageKeys.AUTH_TOKEN, payload.token);
    storageSet(StorageKeys.SESSION_EXPIRY, sessionExpiry.toString());
    // Store rotated refresh token if provided (H-2: refresh token rotation)
    if (payload.refreshToken) {
      storageSet(StorageKeys.REFRESH_TOKEN, payload.refreshToken);
      set({ token: payload.token, refreshToken: payload.refreshToken, sessionExpiry, error: null });
    } else {
      set({ token: payload.token, sessionExpiry, error: null });
    }
  },

  checkSessionExpiry: () => {
    set((state) => {
      if (state.sessionExpiry && state.sessionExpiry <= Date.now()) {
        storageClearAuth();
        return {
          user: null,
          token: null,
          refreshToken: null,
          isAuthenticated: false,
          sessionExpiry: null,
          error: 'Session expired. Please login again.',
        };
      }
      return state;
    });
  },
}));
