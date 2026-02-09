import React, { useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { useAppSelector, useAppDispatch } from './hooks/redux';
import { checkSessionExpiry } from './store/slices/authSlice';
import CustomThemeProvider from './contexts/ThemeContext';
import { tokenService } from './services/tokenService';
import GlobalErrorBoundary from './components/common/GlobalErrorBoundary';

// Create React Query client
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
      staleTime: 5 * 60 * 1000, // 5 minutes
    },
  },
});
import SessionManager from './components/auth/SessionManager';
import PrivateRoute from './components/common/PrivateRoute';
import PublicRoute from './components/common/PublicRoute';
import Layout from './components/layout/Layout';
import Login from './pages/auth/Login';
import Register from './pages/auth/Register';
import MFASetup from './pages/auth/MFASetup';
import Dashboard from './pages/Dashboard';
import Hosts from './pages/hosts/Hosts';
import HostDetail from './pages/hosts/HostDetail';
import AddHost from './pages/hosts/AddHost';
import ComplianceGroups from './pages/host-groups/ComplianceGroups';
import Content from './pages/content/Content';
import { FrameworksPage } from './pages/content/FrameworksPage';
import { FrameworkDetailPage } from './pages/content/FrameworkDetailPage';
import { TemplatesPage } from './pages/content/TemplatesPage';
import { TemplateEditorPage } from './pages/content/TemplateEditorPage';
import Scans from './pages/scans/Scans';
import ScanDetail from './pages/scans/ScanDetail';
import ComplianceScanWizard from './pages/scans/ComplianceScanWizard';
import Users from './pages/users/Users';
import OView from './pages/oview/OView';
import Settings from './pages/settings/Settings';
import { AuditQueriesPage, AuditQueryBuilderPage, AuditExportsPage } from './pages/audit';

function App() {
  const dispatch = useAppDispatch();
  const isAuthenticated = useAppSelector((state) => state.auth.isAuthenticated);

  useEffect(() => {
    // Check session expiry on app load
    dispatch(checkSessionExpiry());

    // Start token refresh timer if authenticated
    if (isAuthenticated) {
      tokenService.startTokenRefreshTimer();
    } else {
      tokenService.stopTokenRefreshTimer();
    }

    // Cleanup on unmount
    return () => {
      tokenService.stopTokenRefreshTimer();
    };
  }, [dispatch, isAuthenticated]);

  return (
    <GlobalErrorBoundary level="page">
      <QueryClientProvider client={queryClient}>
        <CustomThemeProvider>
          <Router>
            <Routes>
              {/* Public routes */}
              <Route element={<PublicRoute />}>
                <Route path="/login" element={<Login />} />
                <Route path="/register" element={<Register />} />
                <Route path="/mfa-setup" element={<MFASetup />} />
              </Route>

              {/* Private routes */}
              <Route element={<PrivateRoute />}>
                <Route
                  element={
                    <GlobalErrorBoundary level="route">
                      <Layout />
                    </GlobalErrorBoundary>
                  }
                >
                  <Route path="/" element={<Dashboard />} />
                  <Route path="/hosts" element={<Hosts />} />
                  <Route path="/hosts/add-host" element={<AddHost />} />
                  <Route path="/hosts/:id" element={<HostDetail />} />
                  <Route path="/host-groups" element={<ComplianceGroups />} />
                  <Route path="/content" element={<Content />} />
                  <Route path="/content/frameworks" element={<FrameworksPage />} />
                  <Route
                    path="/content/frameworks/:framework/:version"
                    element={<FrameworkDetailPage />}
                  />
                  <Route path="/content/templates" element={<TemplatesPage />} />
                  <Route path="/content/templates/new" element={<TemplateEditorPage />} />
                  <Route path="/content/templates/:id" element={<TemplateEditorPage />} />
                  <Route path="/scans" element={<Scans />} />
                  <Route path="/scans/create" element={<ComplianceScanWizard />} />
                  <Route path="/scans/:id" element={<ScanDetail />} />
                  <Route path="/users" element={<Users />} />
                  <Route path="/oview" element={<OView />} />
                  <Route path="/settings" element={<Settings />} />
                  <Route path="/audit/queries" element={<AuditQueriesPage />} />
                  <Route path="/audit/queries/new" element={<AuditQueryBuilderPage />} />
                  <Route path="/audit/queries/:queryId/edit" element={<AuditQueryBuilderPage />} />
                  <Route
                    path="/audit/queries/:queryId/execute"
                    element={<AuditQueryBuilderPage />}
                  />
                  <Route path="/audit/exports" element={<AuditExportsPage />} />
                </Route>
              </Route>

              {/* Redirect to login if not authenticated */}
              <Route
                path="*"
                element={
                  isAuthenticated ? <Navigate to="/" replace /> : <Navigate to="/login" replace />
                }
              />
            </Routes>
            <SessionManager />
          </Router>
        </CustomThemeProvider>
      </QueryClientProvider>
    </GlobalErrorBoundary>
  );
}

export default App;
