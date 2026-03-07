import axios, { type AxiosInstance, type AxiosRequestConfig, type AxiosError } from 'axios';
import { storageGet, storageSet, storageRemove, StorageKeys } from './storage';

// Use empty string for development (relies on Vite proxy) or explicit URL for production
const API_BASE_URL = import.meta.env.VITE_API_URL || (import.meta.env.DEV ? '' : '');

/**
 * Failed request queue entry for token refresh coordination
 * Used to queue failed requests while token refresh is in progress
 */
interface QueuedRequest {
  resolve: (token: string) => void;
  reject: (error: Error) => void;
}

/**
 * Enhanced network error with additional properties
 * Standard Error extended with custom error metadata
 */
interface NetworkError extends Error {
  code?: string;
  isNetworkError?: boolean;
  response?: unknown;
  status?: number;
  statusText?: string;
}

class ApiClient {
  private instance: AxiosInstance;
  private isRefreshing = false;
  private failedQueue: QueuedRequest[] = [];

  constructor() {
    this.instance = axios.create({
      baseURL: API_BASE_URL,
      timeout: 30000,
      withCredentials: true,
    });

    this.setupInterceptors();
  }

  /**
   * Process queued requests after token refresh completes
   * Either resolves with new token or rejects with error
   */
  private processQueue(error: Error | null, token: string | null = null) {
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
        let token = storageGet(StorageKeys.AUTH_TOKEN);

        // Development helper: auto-login if no token found and we're in development
        if (!token && import.meta.env.DEV) {
          try {
            // Development mode: Auto-login with default credentials for testing
            const loginResponse = await fetch('/api/auth/login', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ username: 'admin', password: 'admin123' }),
            });

            if (loginResponse.ok) {
              const loginData = await loginResponse.json();
              token = loginData.access_token;

              // Store token for future requests
              storageSet(StorageKeys.AUTH_TOKEN, token || '');
              storageSet(StorageKeys.REFRESH_TOKEN, loginData.refresh_token);
              storageSet(StorageKeys.AUTH_USER, JSON.stringify(loginData.user));
              storageSet(
                StorageKeys.SESSION_EXPIRY,
                (Date.now() + loginData.expires_in * 1000).toString()
              );

              // Development mode: Auto-login completed successfully
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
        // Network error (no response) - create type-safe enhanced error
        if (!error.response) {
          const networkError: NetworkError = Object.assign(
            new Error('Unable to connect to the server. Please check your network connection.'),
            {
              code: 'NETWORK_ERROR',
              isNetworkError: true,
            }
          );
          return Promise.reject(networkError);
        }

        // Authentication errors
        if (error.response?.status === 401) {
          storageRemove(StorageKeys.AUTH_TOKEN);
          window.location.href = '/login';
        }

        // Add additional context to error - type-safe property assignment
        const enhancedError: NetworkError = Object.assign(
          new Error(error.message || 'API request failed'),
          {
            response: error.response,
            status: error.response?.status,
            statusText: error.response?.statusText,
          }
        );

        return Promise.reject(enhancedError);
      }
    );
  }

  private getCsrfToken(): string {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta?.getAttribute('content') || '';
  }

  /**
   * HTTP GET request
   * Generic T defaults to unknown - callers should specify expected response type
   */
  async get<T = unknown>(url: string, config?: AxiosRequestConfig): Promise<T> {
    const response = await this.instance.get<T>(url, config);
    return response.data;
  }

  /**
   * HTTP POST request
   * Accepts any JSON-serializable data, returns typed response
   */
  async post<T = unknown>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<T> {
    const response = await this.instance.post<T>(url, data, config);
    return response.data;
  }

  /**
   * HTTP PUT request
   * Accepts any JSON-serializable data, returns typed response
   */
  async put<T = unknown>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<T> {
    const response = await this.instance.put<T>(url, data, config);
    return response.data;
  }

  /**
   * HTTP PATCH request
   * Accepts any JSON-serializable data, returns typed response
   */
  async patch<T = unknown>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<T> {
    const response = await this.instance.patch<T>(url, data, config);
    return response.data;
  }

  /**
   * HTTP DELETE request
   * Generic T defaults to unknown - callers should specify expected response type
   */
  async delete<T = unknown>(url: string, config?: AxiosRequestConfig): Promise<T> {
    const response = await this.instance.delete<T>(url, config);
    return response.data;
  }

  /**
   * File upload with progress tracking
   * Returns unknown response - callers should specify expected type via generic
   */
  async uploadFile<T = unknown>(
    url: string,
    file: File,
    onProgress?: (progress: number) => void
  ): Promise<T> {
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

    return this.post<T>(url, formData, config);
  }
}

export const api = new ApiClient();
