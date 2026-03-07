/**
 * Custom test utilities for rendering components with providers.
 *
 * Wraps components in Redux Provider (ruleSlice) + MemoryRouter for tests.
 * Auth state is in Zustand (useAuthStore) — set it directly in tests as needed.
 */
import React, { type PropsWithChildren } from 'react';
import { render, type RenderOptions } from '@testing-library/react';
import { configureStore, type EnhancedStore } from '@reduxjs/toolkit';
import { Provider } from 'react-redux';
import { MemoryRouter } from 'react-router-dom';
import ruleReducer from '../store/slices/ruleSlice';

interface ExtendedRenderOptions extends Omit<RenderOptions, 'queries'> {
  store?: EnhancedStore;
  route?: string;
}

export function renderWithProviders(
  ui: React.ReactElement,
  {
    store = configureStore({ reducer: { rules: ruleReducer } }),
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
