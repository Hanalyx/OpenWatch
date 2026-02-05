/**
 * Custom test utilities for rendering components with providers.
 *
 * Wraps components in Redux Provider + MemoryRouter for tests.
 */
import React, { type PropsWithChildren } from 'react';
import { render, type RenderOptions } from '@testing-library/react';
import { configureStore, type EnhancedStore } from '@reduxjs/toolkit';
import { Provider } from 'react-redux';
import { MemoryRouter } from 'react-router-dom';
import authReducer from '../store/slices/authSlice';

// Auth state type for testing (matches authSlice)
interface AuthState {
  user: { id: string; username: string; email: string; role: string; mfaEnabled: boolean } | null;
  token: string | null;
  refreshToken: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
  mfaRequired: boolean;
  sessionExpiry: number | null;
}

// Test-specific root state (subset of full RootState)
interface TestRootState {
  auth: AuthState;
}

interface ExtendedRenderOptions extends Omit<RenderOptions, 'queries'> {
  preloadedState?: Partial<TestRootState>;
  store?: EnhancedStore;
  route?: string;
}

export function renderWithProviders(
  ui: React.ReactElement,
  {
    preloadedState = {},
    store = configureStore({
      reducer: { auth: authReducer },
      preloadedState: preloadedState as TestRootState,
    }),
    route = '/',
    ...renderOptions
  }: ExtendedRenderOptions = {}
) {
  function Wrapper({ children }: PropsWithChildren<object>): React.JSX.Element {
    return (
      <Provider store={store}>
        <MemoryRouter initialEntries={[route]}>{children}</MemoryRouter>
      </Provider>
    );
  }

  return { store, ...render(ui, { wrapper: Wrapper, ...renderOptions }) };
}

export { screen, waitFor, act } from '@testing-library/react';
export { default as userEvent } from '@testing-library/user-event';
