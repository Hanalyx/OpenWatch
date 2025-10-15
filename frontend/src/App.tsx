import React, { useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { useAppSelector, useAppDispatch } from './hooks/redux';
import { checkSessionExpiry } from './store/slices/authSlice';
import CustomThemeProvider from './contexts/ThemeContext';
import { tokenService } from './services/tokenService';

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
import HostsEnhanced from './pages/hosts/HostsEnhanced';
import HostDetail from './pages/hosts/HostDetail';
import AddHost from './pages/hosts/AddHost';
import ComplianceGroups from './pages/host-groups/ComplianceGroups';
import Content from './pages/content/Content';
import { FrameworksPage } from './pages/Content/FrameworksPage';
import { FrameworkDetailPage } from './pages/Content/FrameworkDetailPage';
import { TemplatesPage } from './pages/Content/TemplatesPage';
import { TemplateEditorPage } from './pages/Content/TemplateEditorPage';
import Scans from './pages/scans/Scans';
import ComplianceScans from './pages/scans/ComplianceScans';
import ScanDetail from './pages/scans/ScanDetail';
import NewScan from './pages/scans/NewScan';
import NewScapScan from './pages/scans/NewScapScan';
import Users from './pages/users/Users';
import OView from './pages/oview/OView';
import Settings from './pages/settings/Settings';

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
    <QueryClientProvider client={queryClient}>
      <CustomThemeProvider>
        <Router
          future={{
            v7_startTransition: true,
            v7_relativeSplatPath: true
          }}
        >
          <Routes>
            {/* Public routes */}
            <Route element={<PublicRoute />}>
              <Route path="/login" element={<Login />} />
              <Route path="/register" element={<Register />} />
              <Route path="/mfa-setup" element={<MFASetup />} />
            </Route>

            {/* Private routes */}
            <Route element={<PrivateRoute />}>
              <Route element={<Layout />}>
                <Route path="/" element={<Dashboard />} />
                <Route path="/hosts" element={<HostsEnhanced />} />
                <Route path="/hosts/add-host" element={<AddHost />} />
                <Route path="/hosts/:id" element={<HostDetail />} />
                <Route path="/host-groups" element={<ComplianceGroups />} />
                <Route path="/content" element={<Content />} />
                <Route path="/content/frameworks" element={<FrameworksPage />} />
                <Route path="/content/frameworks/:framework/:version" element={<FrameworkDetailPage />} />
                <Route path="/content/templates" element={<TemplatesPage />} />
                <Route path="/content/templates/new" element={<TemplateEditorPage />} />
                <Route path="/content/templates/:id" element={<TemplateEditorPage />} />
                <Route path="/scans" element={<Scans />} />
                <Route path="/scans/compliance" element={<ComplianceScans />} />
                <Route path="/scans/new" element={<NewScan />} />
                <Route path="/scans/new-scap" element={<NewScapScan />} />
                <Route path="/scans/:id" element={<ScanDetail />} />
                <Route path="/users" element={<Users />} />
                <Route path="/oview" element={<OView />} />
                <Route path="/settings" element={<Settings />} />
              </Route>
            </Route>

            {/* Redirect to login if not authenticated */}
            <Route 
              path="*" 
              element={
                isAuthenticated ? 
                  <Navigate to="/" replace /> : 
                  <Navigate to="/login" replace />
              } 
            />
          </Routes>
          <SessionManager />
        </Router>
      </CustomThemeProvider>
    </QueryClientProvider>
  );
}

export default App;