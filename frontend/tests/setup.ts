import '@testing-library/jest-dom/vitest';
import { afterEach } from 'vitest';
import { cleanup } from '@testing-library/react';

// Global Vitest setup. Adds RTL matchers and ensures the rendered tree
// is torn down between tests.

afterEach(() => {
  cleanup();
  // Reset module state that lives in module-level singletons.
  try {
    localStorage.clear();
  } catch {
    // Some environments fail to clear; ignore.
  }
});

// jsdom doesn't ship matchMedia. The no-FOUC script and color-scheme
// store both call it; provide a minimal stub so tests don't crash.
if (typeof window !== 'undefined' && !window.matchMedia) {
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    value: (query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false,
    }),
  });
}
