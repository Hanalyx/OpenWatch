import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { CssVarsProvider } from '@mui/material/styles';
import { RouterProvider } from '@tanstack/react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

import { theme } from '@/theme/theme';
import { router } from '@/routes/router';
import { bootstrapAuth } from '@/api/auth-bootstrap';
// Importing the color-scheme store at boot ensures its module-level
// init code (loadStored + applyToDOM + matchMedia listener) runs
// before React mounts.
import '@/store/useColorSchemeStore';

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

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { staleTime: 30_000, refetchOnWindowFocus: false },
  },
});

bootstrapAuth();

const rootElement = document.getElementById('root');
if (!rootElement) throw new Error('Root element #root not found');

createRoot(rootElement).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <CssVarsProvider theme={theme} defaultMode="system">
        <RouterProvider router={router} />
      </CssVarsProvider>
    </QueryClientProvider>
  </StrictMode>,
);
