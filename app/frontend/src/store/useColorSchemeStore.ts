import { create } from 'zustand';

// Color-scheme store — single source of truth for the user's theme intent.
//
// On every state change (initial load AND setMode), this store directly
// writes the data-mui-color-scheme attribute on <html>. The CSS
// variables in globals.css are scoped to that attribute, so switching
// it instantly switches the rendered theme. Persistence is to
// localStorage["ow-color-scheme"]; that's the same key the no-FOUC
// script in index.html reads at page load.
//
// MUI's CssVarsProvider does the same job in theory, but in practice
// its setMode call wasn't propagating cleanly with our color-vars
// setup. This store gives us a deterministic, debuggable path.
//
// Spec: frontend-foundation C-01..C-03, AC-01..AC-05.

export type ColorScheme = 'light' | 'dark' | 'system';

const STORAGE_KEY = 'ow-color-scheme';
const ATTR = 'data-mui-color-scheme';

function loadStored(): ColorScheme {
  if (typeof localStorage === 'undefined') return 'system';
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    if (v === 'light' || v === 'dark' || v === 'system') return v;
  } catch {
    /* localStorage may be unavailable (privacy mode); fall through */
  }
  return 'system';
}

function resolveActual(mode: ColorScheme): 'light' | 'dark' {
  if (mode !== 'system') return mode;
  if (typeof window === 'undefined') return 'dark';
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function applyToDOM(mode: ColorScheme) {
  if (typeof document === 'undefined') return;
  const resolved = resolveActual(mode);
  document.documentElement.setAttribute(ATTR, resolved);
  document.documentElement.style.colorScheme = resolved;
}

interface ColorSchemeStore {
  mode: ColorScheme;
  resolved: 'light' | 'dark';
  setMode: (mode: ColorScheme) => void;
}

const initialMode = loadStored();
applyToDOM(initialMode);

// Live-react to OS preference changes when mode === 'system'.
if (typeof window !== 'undefined') {
  const mq = window.matchMedia('(prefers-color-scheme: dark)');
  mq.addEventListener('change', () => {
    const current = useColorSchemeStore.getState().mode;
    if (current === 'system') {
      const resolved = resolveActual('system');
      document.documentElement.setAttribute(ATTR, resolved);
      document.documentElement.style.colorScheme = resolved;
      useColorSchemeStore.setState({ resolved });
    }
  });
}

export const useColorSchemeStore = create<ColorSchemeStore>((set) => ({
  mode: initialMode,
  resolved: resolveActual(initialMode),
  setMode: (mode) => {
    try {
      localStorage.setItem(STORAGE_KEY, mode);
    } catch {
      /* best-effort */
    }
    applyToDOM(mode);
    set({ mode, resolved: resolveActual(mode) });
  },
}));
