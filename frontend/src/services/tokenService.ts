import { store } from '../store';
import { refreshTokenSuccess, logout, checkSessionExpiry } from '../store/slices/authSlice';

class TokenService {
  private refreshTimer: NodeJS.Timeout | null = null;
  private autoRefreshPaused: boolean = false;

  // Check token expiry and refresh if needed
  async checkAndRefreshToken(): Promise<boolean> {
    const state = store.getState().auth;

    if (!state.token || !state.refreshToken) {
      return false;
    }

    // Skip auto-refresh if paused (during manual session management)
    if (this.autoRefreshPaused) {
      return true;
    }

    // Check if token will expire in the next 5 minutes
    const fiveMinutes = 5 * 60 * 1000;
    if (state.sessionExpiry && state.sessionExpiry - Date.now() < fiveMinutes) {
      return await this.refreshToken();
    }

    return true;
  }

  // Refresh the access token using refresh token
  async refreshToken(manual: boolean = false): Promise<boolean> {
    const state = store.getState().auth;

    if (!state.refreshToken) {
      console.warn('[SECURITY] No refresh token available');
      if (!manual) {
        store.dispatch(logout());
      }
      return false;
    }

    try {
      const response = await fetch('/api/auth/refresh', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          refresh_token: state.refreshToken,
        }),
      });

      if (!response.ok) {
        if (response.status === 401 || response.status === 403) {
          // Refresh token is invalid or expired - security critical
          console.warn('[SECURITY] Refresh token rejected by server - forcing logout');
          if (!manual) {
            store.dispatch(logout());
          }
          return false;
        }
        throw new Error(`Failed to refresh token: ${response.status} ${response.statusText}`);
      }

      const data = await response.json();

      // Validate response structure
      if (!data.access_token || !data.expires_in) {
        console.error('[SECURITY] Invalid refresh response structure');
        if (!manual) {
          store.dispatch(logout());
        }
        return false;
      }

      store.dispatch(
        refreshTokenSuccess({
          token: data.access_token,
          expiresIn: data.expires_in,
        })
      );

      console.log('[SECURITY] Token refreshed successfully');
      return true;
    } catch (error) {
      console.error('[SECURITY] Token refresh failed:', error);
      // For security, any refresh failure should logout user unless manual
      if (!manual) {
        store.dispatch(logout());
      }
      return false;
    }
  }

  // Start automatic token refresh
  startTokenRefreshTimer() {
    this.stopTokenRefreshTimer();

    // Check every minute for token refresh, but don't auto-logout
    this.refreshTimer = setInterval(() => {
      this.checkAndRefreshToken();
    }, 60000);

    // Also check immediately
    this.checkAndRefreshToken();

    // Security: Monitor for tab focus to check session validity
    this.monitorTabFocus();
  }

  // Security: Monitor tab focus to validate session on return
  private monitorTabFocus() {
    if (typeof window !== 'undefined') {
      const handleFocus = () => {
        // When user returns to tab, immediately validate session
        this.checkAndRefreshToken();
      };

      window.addEventListener('focus', handleFocus);

      // Clean up listener when timer stops
      const originalStop = this.stopTokenRefreshTimer.bind(this);
      this.stopTokenRefreshTimer = () => {
        window.removeEventListener('focus', handleFocus);
        originalStop();
      };
    }
  }

  // Stop automatic token refresh
  stopTokenRefreshTimer() {
    if (this.refreshTimer) {
      clearInterval(this.refreshTimer);
      this.refreshTimer = null;
    }
  }

  // Pause/resume automatic token refresh
  pauseAutoRefresh() {
    this.autoRefreshPaused = true;
  }

  resumeAutoRefresh() {
    this.autoRefreshPaused = false;
  }

  // Get current token
  getToken(): string | null {
    return store.getState().auth.token;
  }

  // Add Authorization header to requests
  getAuthHeaders(): HeadersInit {
    const token = store.getState().auth.token;
    return token ? { Authorization: `Bearer ${token}` } : {};
  }

  // Enhanced fetch with automatic token refresh
  async authenticatedFetch(url: string, options: RequestInit = {}): Promise<Response> {
    // Check and refresh token before making request
    const tokenValid = await this.checkAndRefreshToken();

    if (!tokenValid) {
      throw new Error('Authentication failed');
    }

    // Add auth headers
    const authHeaders = this.getAuthHeaders();
    const mergedOptions: RequestInit = {
      ...options,
      headers: {
        ...authHeaders,
        ...options.headers,
      },
    };

    const response = await fetch(url, mergedOptions);

    // If we get 401, try refreshing token once
    if (response.status === 401) {
      const refreshed = await this.refreshToken();

      if (refreshed) {
        // Retry the request with new token
        const newAuthHeaders = this.getAuthHeaders();
        const retryOptions: RequestInit = {
          ...options,
          headers: {
            ...newAuthHeaders,
            ...options.headers,
          },
        };

        return await fetch(url, retryOptions);
      }
    }

    return response;
  }
}

export const tokenService = new TokenService();
export default tokenService;
