import axios, { AxiosInstance, AxiosRequestConfig, AxiosError } from 'axios';

// Use empty string for development (relies on Vite proxy) or explicit URL for production
const API_BASE_URL = import.meta.env.VITE_API_URL || (import.meta.env.DEV ? '' : '');

class ApiClient {
  private instance: AxiosInstance;
  private isRefreshing = false;
  private failedQueue: Array<{
    resolve: (token: string) => void;
    reject: (error: any) => void;
  }> = [];

  constructor() {
    this.instance = axios.create({
      baseURL: API_BASE_URL,
      timeout: 30000,
      withCredentials: true,
    });

    this.setupInterceptors();
  }

  private processQueue(error: any, token: string | null = null) {
    this.failedQueue.forEach((prom) => {
      if (error) {
        prom.reject(error);
      } else {
        prom.resolve(token!);
      }
    });
    this.failedQueue = [];
  }

  private setupInterceptors() {
    // Request interceptor
    this.instance.interceptors.request.use(
      async (config) => {
        // Get token from localStorage first, then fall back to Redux store if available
        let token = localStorage.getItem('auth_token');
        
        // Try Redux store if localStorage token not found
        if (!token && typeof window !== 'undefined' && (window as any).__REDUX_STORE__) {
          const store = (window as any).__REDUX_STORE__;
          const state = store.getState();
          token = state.auth?.token;
        }

        // Development helper: auto-login if no token found and we're in development
        if (!token && import.meta.env.DEV) {
          try {
            console.log('[DEV] No auth token found, attempting auto-login...');
            const loginResponse = await fetch('/api/auth/login', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ username: 'admin', password: 'admin123' })
            });
            
            if (loginResponse.ok) {
              const loginData = await loginResponse.json();
              token = loginData.access_token;
              
              // Store token for future requests
              localStorage.setItem('auth_token', token || '');
              localStorage.setItem('refresh_token', loginData.refresh_token);
              localStorage.setItem('auth_user', JSON.stringify(loginData.user));
              localStorage.setItem('session_expiry', (Date.now() + loginData.expires_in * 1000).toString());
              
              console.log('[DEV] Auto-login successful');
            }
          } catch (loginError) {
            console.warn('[DEV] Auto-login failed:', loginError);
          }
        }
        
        if (token && config.headers) {
          config.headers.Authorization = `Bearer ${token}`;
        }

        // Add security headers
        config.headers['X-Requested-With'] = 'XMLHttpRequest';
        config.headers['X-CSRF-Token'] = this.getCsrfToken();

        // Set Content-Type for JSON requests only (not for FormData)
        if (config.data && !(config.data instanceof FormData)) {
          config.headers['Content-Type'] = 'application/json';
        }

        return config;
      },
      (error) => {
        return Promise.reject(error);
      }
    );

    // Enhanced response interceptor
    this.instance.interceptors.response.use(
      (response) => response,
      async (error: AxiosError) => {
        // Network error (no response)
        if (!error.response) {
          const networkError = new Error('Unable to connect to the server. Please check your network connection.');
          (networkError as any).code = 'NETWORK_ERROR';
          (networkError as any).isNetworkError = true;
          return Promise.reject(networkError);
        }

        // Authentication errors
        if (error.response?.status === 401) {
          // Clear tokens from both places
          localStorage.removeItem('auth_token');
          if (typeof window !== 'undefined' && (window as any).__REDUX_STORE__) {
            // Could dispatch logout action here if needed
          }
          window.location.href = '/login';
        }

        // Add additional context to error
        const enhancedError = new Error(error.message || 'API request failed');
        (enhancedError as any).response = error.response;
        (enhancedError as any).status = error.response?.status;
        (enhancedError as any).statusText = error.response?.statusText;
        
        return Promise.reject(enhancedError);
      }
    );
  }

  private getCsrfToken(): string {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta?.getAttribute('content') || '';
  }

  // API methods
  async get<T = any>(url: string, config?: AxiosRequestConfig): Promise<T> {
    const response = await this.instance.get<T>(url, config);
    return response.data;
  }

  async post<T = any>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> {
    const response = await this.instance.post<T>(url, data, config);
    return response.data;
  }

  async put<T = any>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> {
    const response = await this.instance.put<T>(url, data, config);
    return response.data;
  }

  async patch<T = any>(url: string, data?: any, config?: AxiosRequestConfig): Promise<T> {
    const response = await this.instance.patch<T>(url, data, config);
    return response.data;
  }

  async delete<T = any>(url: string, config?: AxiosRequestConfig): Promise<T> {
    const response = await this.instance.delete<T>(url, config);
    return response.data;
  }

  // File upload
  async uploadFile(url: string, file: File, onProgress?: (progress: number) => void): Promise<any> {
    const formData = new FormData();
    formData.append('file', file);

    const config: AxiosRequestConfig = {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
      onUploadProgress: (progressEvent) => {
        if (onProgress && progressEvent.total) {
          const progress = Math.round((progressEvent.loaded * 100) / progressEvent.total);
          onProgress(progress);
        }
      },
    };

    return this.post(url, formData, config);
  }
}

export const api = new ApiClient();