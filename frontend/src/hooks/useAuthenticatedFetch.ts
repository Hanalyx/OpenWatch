import { useCallback } from 'react';
import { useAppSelector } from './redux';
import { tokenService } from '../services/tokenService';

export const useAuthenticatedFetch = () => {
  const isAuthenticated = useAppSelector((state) => state.auth.isAuthenticated);

  const authenticatedFetch = useCallback(
    async (url: string, options: RequestInit = {}): Promise<Response> => {
      if (!isAuthenticated) {
        throw new Error('Not authenticated');
      }

      return await tokenService.authenticatedFetch(url, options);
    },
    [isAuthenticated]
  );

  const get = useCallback((url: string) => authenticatedFetch(url), [authenticatedFetch]);

  /**
   * HTTP POST request with authenticated fetch
   * Accepts any JSON-serializable data for request body
   */
  const post = useCallback(
    (url: string, data?: Record<string, unknown>) =>
      authenticatedFetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: data ? JSON.stringify(data) : undefined,
      }),
    [authenticatedFetch]
  );

  /**
   * HTTP PUT request with authenticated fetch
   * Accepts any JSON-serializable data for request body
   */
  const put = useCallback(
    (url: string, data?: Record<string, unknown>) =>
      authenticatedFetch(url, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: data ? JSON.stringify(data) : undefined,
      }),
    [authenticatedFetch]
  );

  const del = useCallback(
    (url: string) => authenticatedFetch(url, { method: 'DELETE' }),
    [authenticatedFetch]
  );

  return {
    authenticatedFetch,
    get,
    post,
    put,
    delete: del,
  };
};

export default useAuthenticatedFetch;
