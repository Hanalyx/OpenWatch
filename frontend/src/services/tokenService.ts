import { store } from '../store';
import { refreshTokenSuccess, logout, checkSessionExpiry } from '../store/slices/authSlice';

class TokenService {
  private refreshTimer: NodeJS.Timeout | null = null;

  // Check token expiry and refresh if needed
  async checkAndRefreshToken(): Promise<boolean> {
    const state = store.getState().auth;
    
    if (!state.token || !state.refreshToken) {
      return false;
    }

    // Check if token will expire in the next 5 minutes
    const fiveMinutes = 5 * 60 * 1000;
    if (state.sessionExpiry && state.sessionExpiry - Date.now() < fiveMinutes) {
      return await this.refreshToken();
    }

    return true;
  }

  // Refresh the access token using refresh token
  async refreshToken(): Promise<boolean> {
    const state = store.getState().auth;
    
    if (!state.refreshToken) {
      store.dispatch(logout());
      return false;
    }

    try {
      const response = await fetch('/api/auth/refresh', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${state.refreshToken}`,
        },
      });

      if (!response.ok) {
        if (response.status === 401 || response.status === 403) {
          // Refresh token is invalid or expired
          store.dispatch(logout());
          return false;
        }
        throw new Error('Failed to refresh token');
      }

      const data = await response.json();
      store.dispatch(refreshTokenSuccess({
        token: data.access_token,
        expiresIn: data.expires_in,
      }));

      return true;
    } catch (error) {
      console.error('Token refresh failed:', error);
      store.dispatch(logout());
      return false;
    }
  }

  // Start automatic token refresh
  startTokenRefreshTimer() {
    this.stopTokenRefreshTimer();
    
    // Check every minute
    this.refreshTimer = setInterval(() => {
      store.dispatch(checkSessionExpiry());
      this.checkAndRefreshToken();
    }, 60000);

    // Also check immediately
    this.checkAndRefreshToken();
  }

  // Stop automatic token refresh
  stopTokenRefreshTimer() {
    if (this.refreshTimer) {
      clearInterval(this.refreshTimer);
      this.refreshTimer = null;
    }
  }

  // Get current token
  getToken(): string | null {
    return store.getState().auth.token;
  }

  // Add Authorization header to requests
  getAuthHeaders(): HeadersInit {
    const token = store.getState().auth.token;
    return token ? { 'Authorization': `Bearer ${token}` } : {};
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