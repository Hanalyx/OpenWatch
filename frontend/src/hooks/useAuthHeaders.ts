/**
 * Unified Authentication Headers Hook
 * 
 * Consolidates authentication token access patterns across the application.
 * Replaces 52+ instances of direct localStorage.getItem('auth_token') calls
 * with a centralized, consistent approach.
 */

import { useMemo } from 'react';
import { useSelector } from 'react-redux';
import { RootState } from '../store';

interface AuthHeaders {
  'Authorization'?: string;
  'Content-Type': string;
}

interface AuthHeadersResult {
  headers: AuthHeaders;
  isAuthenticated: boolean;
  token: string | null;
}

/**
 * Hook for getting authenticated headers for API requests
 * 
 * @returns Object containing headers, authentication status, and token
 */
export const useAuthHeaders = (): AuthHeadersResult => {
  // Try to get token from Redux store first (preferred)
  const storeToken = useSelector((state: RootState) => state.auth?.token);
  
  // Fallback to localStorage for backwards compatibility
  const localToken = useMemo(() => {
    if (typeof window !== 'undefined') {
      return localStorage.getItem('auth_token');
    }
    return null;
  }, []);

  // Use store token if available, otherwise fallback to localStorage
  const token = storeToken || localToken;
  const isAuthenticated = !!token;

  const headers = useMemo((): AuthHeaders => {
    const baseHeaders: AuthHeaders = {
      'Content-Type': 'application/json'
    };

    if (token) {
      baseHeaders['Authorization'] = `Bearer ${token}`;
    }

    return baseHeaders;
  }, [token]);

  return {
    headers,
    isAuthenticated,
    token
  };
};

/**
 * Utility function for non-hook contexts
 * Use this in service classes or utility functions where hooks can't be used
 */
export const getAuthHeaders = (): AuthHeaders => {
  let token: string | null = null;

  // Try localStorage (most reliable in non-React contexts)
  if (typeof window !== 'undefined') {
    token = localStorage.getItem('auth_token');
  }

  const headers: AuthHeaders = {
    'Content-Type': 'application/json'
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  return headers;
};

/**
 * Check if user is authenticated
 */
export const isUserAuthenticated = (): boolean => {
  if (typeof window === 'undefined') return false;
  return !!localStorage.getItem('auth_token');
};

/**
 * Get raw token without Bearer prefix
 */
export const getAuthToken = (): string | null => {
  if (typeof window === 'undefined') return null;
  return localStorage.getItem('auth_token');
};