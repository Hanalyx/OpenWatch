/**
 * Custom test utilities for rendering components with providers.
 *
 * Wraps components in MemoryRouter for tests.
 * Auth state is in Zustand (useAuthStore) — set it directly in tests as needed.
 */
import React, { type PropsWithChildren } from 'react';
import { render, type RenderOptions } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';

interface ExtendedRenderOptions extends Omit<RenderOptions, 'queries'> {
  route?: string;
}

export function renderWithProviders(
  ui: React.ReactElement,
  { route = '/', ...renderOptions }: ExtendedRenderOptions = {}
) {
  function Wrapper({ children }: PropsWithChildren<object>): React.JSX.Element {
    return <MemoryRouter initialEntries={[route]}>{children}</MemoryRouter>;
  }

  return render(ui, { wrapper: Wrapper, ...renderOptions });
}

export { screen, waitFor, act } from '@testing-library/react';
export { default as userEvent } from '@testing-library/user-event';
