import { createSlice, PayloadAction } from '@reduxjs/toolkit';

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
    const token = localStorage.getItem('auth_token');
    const refreshToken = localStorage.getItem('refresh_token');
    const userStr = localStorage.getItem('auth_user');
    const sessionExpiryStr = localStorage.getItem('session_expiry');

    if (token && userStr) {
      const user = JSON.parse(userStr);
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
        localStorage.removeItem('auth_token');
        localStorage.removeItem('refresh_token');
        localStorage.removeItem('auth_user');
        localStorage.removeItem('session_expiry');
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
      try {
        localStorage.setItem('auth_token', action.payload.token);
        localStorage.setItem('refresh_token', action.payload.refreshToken);
        localStorage.setItem('auth_user', JSON.stringify(action.payload.user));
        localStorage.setItem('session_expiry', state.sessionExpiry.toString());
      } catch (error) {
        console.warn('Failed to persist auth state:', error);
      }
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
      try {
        localStorage.removeItem('auth_token');
        localStorage.removeItem('refresh_token');
        localStorage.removeItem('auth_user');
        localStorage.removeItem('session_expiry');
      } catch (error) {
        console.warn('Failed to clear auth state from localStorage:', error);
      }
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
      try {
        localStorage.setItem('auth_token', action.payload.token);
        localStorage.setItem('session_expiry', state.sessionExpiry.toString());
      } catch (error) {
        console.warn('Failed to persist refreshed token:', error);
      }
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
        try {
          localStorage.removeItem('auth_token');
          localStorage.removeItem('refresh_token');
          localStorage.removeItem('auth_user');
          localStorage.removeItem('session_expiry');
        } catch (error) {
          console.warn('Failed to clear expired session:', error);
        }
      }
    },
  },
});

export const { loginSuccess, loginFailure, logout, clearError, setMfaRequired, setLoading, refreshTokenSuccess, checkSessionExpiry } = authSlice.actions;
export default authSlice.reducer;