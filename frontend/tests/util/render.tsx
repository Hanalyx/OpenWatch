import { render } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { createRootRoute, createRoute, createRouter, RouterProvider } from '@tanstack/react-router';
import type { ReactNode } from 'react';

// Shared test helper — renders a component inside a TanStack Router +
// React Query environment. Each render gets a fresh QueryClient so
// tests don't leak cached data between cases.

export function renderWithProviders(node: ReactNode) {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false, staleTime: 0 },
      mutations: { retry: false },
    },
  });

  const rootRoute = createRootRoute({ component: () => <>{node}</> });
  const router = createRouter({
    routeTree: rootRoute.addChildren([
      createRoute({
        getParentRoute: () => rootRoute,
        path: '/',
        component: () => <>{node}</>,
      }),
    ]),
  });

  return render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
}
