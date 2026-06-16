import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { CssVarsProvider } from '@mui/material/styles';
import { RouterProvider } from '@tanstack/react-router';
import { QueryClient, QueryCache, MutationCache, QueryClientProvider } from '@tanstack/react-query';

import { theme } from '@/theme/theme';
import { router } from '@/routes/router';
import { bootstrapAuth } from '@/api/auth-bootstrap';
import { redirectOnAuthError } from '@/api/auth-error-redirect';
import { useLiveEvents } from '@/hooks/useLiveEvents';
// Importing the color-scheme store at boot ensures its module-level
// init code (loadStored + applyToDOM + matchMedia listener) runs
// before React mounts.
import '@/store/useColorSchemeStore';

// Self-hosted fonts (airgap-safe): bundled by Vite from @fontsource, so the
// app fetches NOTHING from fonts.googleapis.com / gstatic.com at runtime.
// Weights mirror the former Google Fonts request: Inter 400/500/600/700,
// JetBrains Mono 400/500.
import '@fontsource/inter/400.css';
import '@fontsource/inter/500.css';
import '@fontsource/inter/600.css';
import '@fontsource/inter/700.css';
import '@fontsource/jetbrains-mono/400.css';
import '@fontsource/jetbrains-mono/500.css';

import './theme/globals.css';

// Entry point.
//
// Color scheme — the Zustand useColorSchemeStore owns the
// data-mui-color-scheme attribute on <html>. The CSS variables in
// globals.css are scoped to that attribute and switch instantly. MUI's
// CssVarsProvider is kept so MUI components reading theme.palette.*
// still get sensible values, but it does not control the attribute.
// CssBaseline is intentionally NOT mounted — it bakes a particular
// scheme into the body background which fights the variable-driven
// switching. globals.css supplies the equivalent body / box-sizing
// reset.
//
// Spec: frontend-foundation AC-16 (CssVarsProvider wraps the tree).

// Global safety net: every failed query and mutation passes through
// redirectOnAuthError, so an expired/invalid session always lands the
// user on /login instead of a raw error envelope. See auth-error-redirect.
const queryClient = new QueryClient({
  queryCache: new QueryCache({ onError: redirectOnAuthError }),
  mutationCache: new MutationCache({ onError: redirectOnAuthError }),
  defaultOptions: {
    queries: { staleTime: 30_000, refetchOnWindowFocus: false },
  },
});

bootstrapAuth();

const rootElement = document.getElementById('root');
if (!rootElement) throw new Error('Root element #root not found');

// AppShell — a tiny component so useLiveEvents can mount under
// QueryClientProvider (hooks must run inside the provider tree).
// One SSE connection per browser tab, kept open for the whole session.
function AppShell() {
  useLiveEvents();
  return <RouterProvider router={router} />;
}

createRoot(rootElement).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <CssVarsProvider theme={theme} defaultMode="system">
        <AppShell />
      </CssVarsProvider>
    </QueryClientProvider>
  </StrictMode>,
);
