import {
  createRootRoute,
  createRoute,
  createRouter,
  Navigate,
  Outlet,
  redirect,
} from '@tanstack/react-router';
import { AppFrame } from '@/components/shell/AppFrame';
import { useAuthStore } from '@/store/useAuthStore';
import { LoginPage } from '@/pages/LoginPage';
import { HostsListPage } from '@/pages/HostsListPage';
import { HostDetailPage } from '@/pages/HostDetailPage';
import { AddHostPage } from '@/pages/AddHostPage';
import { HomePage } from '@/pages/HomePage';
import { DashboardPage } from '@/pages/dashboard/DashboardPage';
import { GroupsPage } from '@/pages/groups/GroupsPage';
import { ActivityPage } from '@/pages/activity/ActivityPage';
import { ScansPage } from '@/pages/scans/ScansPage';
import { ScanDetailPage } from '@/pages/scans/ScanDetailPage';
import { ReportsPage } from '@/pages/reports/ReportsPage';
import { ForbiddenPage } from '@/pages/ForbiddenPage';
import { ProfilePage } from '@/pages/settings/ProfilePage';
import { PreferencesPage } from '@/pages/settings/PreferencesPage';
import { CredentialsPage } from '@/pages/settings/CredentialsPage';
import { UsersPage } from '@/pages/settings/UsersPage';
import { ScanningPage } from '@/pages/settings/ScanningPage';
import { IntegrationsPage, SecurityPage, AboutPage } from '@/pages/settings/StubbedPages';
import { NotificationsPage } from '@/pages/settings/NotificationsPage';
import { AuditPage } from '@/pages/settings/AuditPage';
import { PoliciesPage } from '@/pages/settings/PoliciesPage';

// Top-level route table.
//
// Spec: frontend-foundation C-06 (auth redirect), C-07 (RBAC 403),
//       AC-08, AC-09, AC-17.
//
// The route tree has two sub-trees:
//   /login                 — anonymous-only.
//   everything else        — wrapped in AppFrame and gated.
//
// Guards run via beforeLoad. Authenticated requests without the
// required permission render ForbiddenPage rather than redirect.

const rootRoute = createRootRoute({
  component: () => <Outlet />,
});

const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/login',
  component: LoginPage,
});

// Authenticated tree — wraps AppFrame and gates entry.
const protectedRoute = createRoute({
  getParentRoute: () => rootRoute,
  id: 'protected',
  beforeLoad: ({ location }) => {
    const id = useAuthStore.getState().identity;
    if (!id) {
      throw redirect({
        to: '/login',
        search: { return_to: location.href },
      });
    }
  },
  component: AppFrame,
});

// Public, non-login landing at "/". It sits under the root route (NOT
// the protected subtree): no AppFrame, no auth guard. Its "Enter
// console" CTA routes to /login.
const publicHomeRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/',
  component: HomePage,
});

// Authenticated dashboard home, moved off "/" to /dashboard so "/" can
// host the public homepage. The post-login default destination is
// /dashboard. The fleet endpoints its widgets read enforce system:read
// server-side (widgets surface a 403 as an error state); the frontend
// identity model does not track system:read, so no extra route guard is
// added beyond the protectedRoute auth gate.
const dashboardRoute = createRoute({
  getParentRoute: () => protectedRoute,
  path: 'dashboard',
  component: DashboardPage,
});

// Unified activity feed. Read-only feed + alert-source lifecycle actions;
// host_id deep-link via search params.
const activityRoute = createRoute({
  getParentRoute: () => protectedRoute,
  path: 'activity',
  component: ActivityPage,
});

// Fleet scan overview (coverage + compliance change history).
const scansRoute = createRoute({
  getParentRoute: () => protectedRoute,
  path: 'scans',
  component: ScansPage,
});

// Durable scan detail + per-rule evidence/OSCAL drill-down. The evidence
// surface is gated scan:read (the server enforces it too); a compliance
// officer reaches it without host:read.
const scanDetailRoute = createRoute({
  getParentRoute: () => protectedRoute,
  path: 'scans/$scanId',
  beforeLoad: () => {
    if (!useAuthStore.getState().hasPermission('scan:read')) {
      throw redirect({ to: '/_forbidden' });
    }
  },
  component: ScanDetailPage,
});

// Compliance report library. GET /api/v1/reports enforces host:read
// server-side; generate enforces host:write. Gate the route on host:read.
const reportsRoute = createRoute({
  getParentRoute: () => protectedRoute,
  path: 'reports',
  beforeLoad: () => {
    if (!useAuthStore.getState().hasPermission('host:read')) {
      throw redirect({ to: '/_forbidden' });
    }
  },
  component: ReportsPage,
});

const hostsListRoute = createRoute({
  getParentRoute: () => protectedRoute,
  path: 'hosts',
  beforeLoad: () => {
    if (!useAuthStore.getState().hasPermission('host:read')) {
      throw redirect({ to: '/_forbidden' });
    }
  },
  component: HostsListPage,
});

// Groups overview. GET /api/v1/groups enforces host:read server-side;
// mutations enforce host:write. Gate the route on host:read.
const groupsRoute = createRoute({
  getParentRoute: () => protectedRoute,
  path: 'groups',
  beforeLoad: () => {
    if (!useAuthStore.getState().hasPermission('host:read')) {
      throw redirect({ to: '/_forbidden' });
    }
  },
  component: GroupsPage,
});

const addHostRoute = createRoute({
  getParentRoute: () => protectedRoute,
  path: 'hosts/new',
  beforeLoad: () => {
    if (!useAuthStore.getState().hasPermission('host:write')) {
      throw redirect({ to: '/_forbidden' });
    }
  },
  component: AddHostPage,
});

const hostDetailRoute = createRoute({
  getParentRoute: () => protectedRoute,
  path: 'hosts/$hostId',
  beforeLoad: () => {
    if (!useAuthStore.getState().hasPermission('host:read')) {
      throw redirect({ to: '/_forbidden' });
    }
  },
  component: HostDetailPage,
});

const settingsIndexRoute = createRoute({
  getParentRoute: () => protectedRoute,
  path: 'settings',
  component: () => <Navigate to="/settings/profile" />,
});

const settingsProfileRoute = createRoute({
  getParentRoute: () => protectedRoute,
  path: 'settings/profile',
  component: ProfilePage,
});

const settingsPreferencesRoute = createRoute({
  getParentRoute: () => protectedRoute,
  path: 'settings/preferences',
  component: PreferencesPage,
});

const settingsCredentialsRoute = createRoute({
  getParentRoute: () => protectedRoute,
  path: 'settings/credentials',
  beforeLoad: () => {
    if (!useAuthStore.getState().hasPermission('credential:read')) {
      throw redirect({ to: '/_forbidden' });
    }
  },
  component: CredentialsPage,
});

const settingsUsersRoute = createRoute({
  getParentRoute: () => protectedRoute,
  path: 'settings/users',
  component: UsersPage,
});

const settingsScanningRoute = createRoute({
  getParentRoute: () => protectedRoute,
  path: 'settings/scanning',
  component: ScanningPage,
});

const settingsPoliciesRoute = createRoute({
  getParentRoute: () => protectedRoute,
  path: 'settings/policies',
  component: PoliciesPage,
});

const settingsNotificationsRoute = createRoute({
  getParentRoute: () => protectedRoute,
  path: 'settings/notifications',
  component: NotificationsPage,
});

const settingsIntegrationsRoute = createRoute({
  getParentRoute: () => protectedRoute,
  path: 'settings/integrations',
  component: IntegrationsPage,
});

const settingsSecurityRoute = createRoute({
  getParentRoute: () => protectedRoute,
  path: 'settings/security',
  component: SecurityPage,
});

const settingsAuditRoute = createRoute({
  getParentRoute: () => protectedRoute,
  path: 'settings/audit',
  component: AuditPage,
});

const settingsAboutRoute = createRoute({
  getParentRoute: () => protectedRoute,
  path: 'settings/about',
  component: AboutPage,
});

const forbiddenRoute = createRoute({
  getParentRoute: () => protectedRoute,
  path: '_forbidden',
  component: ForbiddenPage,
});

const routeTree = rootRoute.addChildren([
  loginRoute,
  publicHomeRoute,
  protectedRoute.addChildren([
    dashboardRoute,
    activityRoute,
    scansRoute,
    scanDetailRoute,
    reportsRoute,
    hostsListRoute,
    groupsRoute,
    addHostRoute,
    hostDetailRoute,
    settingsIndexRoute,
    settingsProfileRoute,
    settingsPreferencesRoute,
    settingsCredentialsRoute,
    settingsUsersRoute,
    settingsScanningRoute,
    settingsPoliciesRoute,
    settingsNotificationsRoute,
    settingsIntegrationsRoute,
    settingsSecurityRoute,
    settingsAuditRoute,
    settingsAboutRoute,
    forbiddenRoute,
  ]),
]);

export const router = createRouter({
  routeTree,
  defaultPreload: 'intent',
});

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router;
  }
}
