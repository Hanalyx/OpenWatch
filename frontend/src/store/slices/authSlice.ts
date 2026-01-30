import { createSlice, type PayloadAction } from '@reduxjs/toolkit';
import {
  storageClearAuth,
  storageGet,
  storageGetJSON,
  storageSet,
  StorageKeys,
} from '../../services/storage';

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

// Load persisted auth state from localStorage
const loadPersistedAuthState = (): Partial<AuthState> => {
  try {
    const token = storageGet(StorageKeys.AUTH_TOKEN);
    const refreshToken = storageGet(StorageKeys.REFRESH_TOKEN);
    const user = storageGetJSON<User>(StorageKeys.AUTH_USER);
    const sessionExpiryStr = storageGet(StorageKeys.SESSION_EXPIRY);

    if (token && user) {
      const sessionExpiry = sessionExpiryStr ? parseInt(sessionExpiryStr) : null;

      // Check if session is still valid
      if (!sessionExpiry || sessionExpiry > Date.now()) {
        return {
          user,
          token,
          refreshToken,
          isAuthenticated: true,
          sessionExpiry,
        };
      } else {
        // Session expired, clear localStorage
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

// Simplified auth actions - async thunks will be added later
interface LoginPayload {
  user: User;
  token: string;
  refreshToken: string;
  expiresIn: number;
}

const authSlice = createSlice({
  name: 'auth',
  initialState,
  reducers: {
    loginSuccess: (state, action: PayloadAction<LoginPayload>) => {
      state.isLoading = false;
      state.isAuthenticated = true;
      state.user = action.payload.user;
      state.token = action.payload.token;
      state.refreshToken = action.payload.refreshToken;
      state.sessionExpiry = Date.now() + action.payload.expiresIn * 1000;
      state.error = null;
      state.mfaRequired = false;

      // Persist to localStorage
      storageSet(StorageKeys.AUTH_TOKEN, action.payload.token);
      storageSet(StorageKeys.REFRESH_TOKEN, action.payload.refreshToken);
      storageSet(StorageKeys.AUTH_USER, JSON.stringify(action.payload.user));
      storageSet(StorageKeys.SESSION_EXPIRY, state.sessionExpiry.toString());
    },
    loginFailure: (state, action: PayloadAction<string>) => {
      state.isLoading = false;
      state.error = action.payload;
      state.isAuthenticated = false;
      if (action.payload.includes('MFA required')) {
        state.mfaRequired = true;
      }
    },
    logout: (state) => {
      state.user = null;
      state.token = null;
      state.refreshToken = null;
      state.isAuthenticated = false;
      state.sessionExpiry = null;
      state.error = null;
      state.mfaRequired = false;

      // Clear from localStorage
      storageClearAuth();
    },
    clearError: (state) => {
      state.error = null;
    },
    setMfaRequired: (state, action: PayloadAction<boolean>) => {
      state.mfaRequired = action.payload;
    },
    setLoading: (state, action: PayloadAction<boolean>) => {
      state.isLoading = action.payload;
    },
    refreshTokenSuccess: (state, action: PayloadAction<{ token: string; expiresIn: number }>) => {
      state.token = action.payload.token;
      state.sessionExpiry = Date.now() + action.payload.expiresIn * 1000;
      state.error = null; // Clear any existing errors on successful refresh

      // Update localStorage
      storageSet(StorageKeys.AUTH_TOKEN, action.payload.token);
      storageSet(StorageKeys.SESSION_EXPIRY, state.sessionExpiry.toString());
    },
    checkSessionExpiry: (state) => {
      if (state.sessionExpiry && state.sessionExpiry <= Date.now()) {
        // Session expired, logout
        state.user = null;
        state.token = null;
        state.refreshToken = null;
        state.isAuthenticated = false;
        state.sessionExpiry = null;
        state.error = 'Session expired. Please login again.';

        // Clear localStorage
        storageClearAuth();
      }
    },
  },
});

export const {
  loginSuccess,
  loginFailure,
  logout,
  clearError,
  setMfaRequired,
  setLoading,
  refreshTokenSuccess,
  checkSessionExpiry,
} = authSlice.actions;
export default authSlice.reducer;
