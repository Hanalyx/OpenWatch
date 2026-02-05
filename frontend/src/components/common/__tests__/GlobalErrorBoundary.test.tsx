import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import GlobalErrorBoundary from '../GlobalErrorBoundary';

// Component that throws on render
function ThrowingChild({ error }: { error: Error }): React.ReactElement {
  throw error;
}

// Suppress React error boundary console.error noise during tests
beforeEach(() => {
  vi.spyOn(console, 'error').mockImplementation(() => {});
});

describe('GlobalErrorBoundary', () => {
  describe('when no error occurs', () => {
    it('renders children normally', () => {
      render(
        <GlobalErrorBoundary>
          <div>Hello World</div>
        </GlobalErrorBoundary>
      );
      expect(screen.getByText('Hello World')).toBeInTheDocument();
    });
  });

  describe('level="page" (default)', () => {
    it('shows full-page error with Application Error heading', () => {
      render(
        <GlobalErrorBoundary level="page">
          <ThrowingChild error={new Error('Page crash')} />
        </GlobalErrorBoundary>
      );
      expect(screen.getByText('Application Error')).toBeInTheDocument();
      expect(screen.getByText('Page crash')).toBeInTheDocument();
    });

    it('shows Reload Page and Go to Home buttons', () => {
      render(
        <GlobalErrorBoundary level="page">
          <ThrowingChild error={new Error('boom')} />
        </GlobalErrorBoundary>
      );
      expect(screen.getByRole('button', { name: /reload page/i })).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /go to home/i })).toBeInTheDocument();
    });

    it('calls window.location.reload on Reload Page click', () => {
      const reloadMock = vi.fn();
      Object.defineProperty(window, 'location', {
        value: { ...window.location, reload: reloadMock, href: '' },
        writable: true,
      });

      render(
        <GlobalErrorBoundary level="page">
          <ThrowingChild error={new Error('boom')} />
        </GlobalErrorBoundary>
      );
      fireEvent.click(screen.getByRole('button', { name: /reload page/i }));
      expect(reloadMock).toHaveBeenCalled();
    });
  });

  describe('level="route"', () => {
    it('shows compact error panel with Something went wrong heading', () => {
      render(
        <GlobalErrorBoundary level="route">
          <ThrowingChild error={new Error('Route crash')} />
        </GlobalErrorBoundary>
      );
      expect(screen.getByText('Something went wrong')).toBeInTheDocument();
      expect(screen.getByText('Route crash')).toBeInTheDocument();
    });

    it('shows Try Again and Go Home buttons', () => {
      render(
        <GlobalErrorBoundary level="route">
          <ThrowingChild error={new Error('oops')} />
        </GlobalErrorBoundary>
      );
      expect(screen.getByRole('button', { name: /try again/i })).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /go home/i })).toBeInTheDocument();
    });

    it('shows explanatory text about rest of app working', () => {
      render(
        <GlobalErrorBoundary level="route">
          <ThrowingChild error={new Error('oops')} />
        </GlobalErrorBoundary>
      );
      expect(
        screen.getByText(/this section encountered an error.*rest of the application/i)
      ).toBeInTheDocument();
    });
  });
});
