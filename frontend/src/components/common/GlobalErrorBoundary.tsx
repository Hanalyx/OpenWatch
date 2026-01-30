import React, { Component, type ReactNode } from 'react';
import { Box, Typography, Button, Paper, Container } from '@mui/material';
import { Refresh, Home, BugReport } from '@mui/icons-material';

interface GlobalErrorBoundaryProps {
  children: ReactNode;
  /** If true, renders a compact inline error instead of a full-page error. */
  level?: 'page' | 'route';
}

interface GlobalErrorBoundaryState {
  hasError: boolean;
  error?: Error;
  errorInfo?: React.ErrorInfo;
}

/**
 * Application-wide error boundary that catches unhandled React rendering errors.
 *
 * Usage:
 * - level="page" (default): Full-page error screen with reload/home buttons.
 *   Wrap at the app root in App.tsx.
 * - level="route": Compact error panel for route-level boundaries.
 *   Wrap around <Outlet /> in Layout.tsx or around individual routes.
 */
class GlobalErrorBoundary extends Component<GlobalErrorBoundaryProps, GlobalErrorBoundaryState> {
  constructor(props: GlobalErrorBoundaryProps) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(error: Error): Partial<GlobalErrorBoundaryState> {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    this.setState({ errorInfo });
    console.error('[GlobalErrorBoundary] Uncaught error:', error, errorInfo);
  }

  handleReload = () => {
    window.location.reload();
  };

  handleGoHome = () => {
    window.location.href = '/';
  };

  handleRetry = () => {
    this.setState({ hasError: false, error: undefined, errorInfo: undefined });
  };

  render() {
    if (!this.state.hasError) {
      return this.props.children;
    }

    const level = this.props.level ?? 'page';

    if (level === 'route') {
      return (
        <Box sx={{ p: 4 }}>
          <Paper sx={{ p: 3, maxWidth: 600, mx: 'auto' }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
              <BugReport color="error" />
              <Typography variant="h6">Something went wrong</Typography>
            </Box>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              This section encountered an error. The rest of the application should still work.
            </Typography>
            {this.state.error && (
              <Typography
                variant="body2"
                sx={{ fontFamily: 'monospace', mb: 2, p: 1, bgcolor: 'grey.100', borderRadius: 1 }}
              >
                {this.state.error.message}
              </Typography>
            )}
            <Box sx={{ display: 'flex', gap: 1 }}>
              <Button
                variant="contained"
                size="small"
                startIcon={<Refresh />}
                onClick={this.handleRetry}
              >
                Try Again
              </Button>
              <Button
                variant="outlined"
                size="small"
                startIcon={<Home />}
                onClick={this.handleGoHome}
              >
                Go Home
              </Button>
            </Box>
          </Paper>
        </Box>
      );
    }

    // Full-page error (level="page")
    return (
      <Container maxWidth="sm">
        <Box
          sx={{
            minHeight: '100vh',
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'center',
            alignItems: 'center',
            textAlign: 'center',
            py: 4,
          }}
        >
          <BugReport sx={{ fontSize: 64, color: 'error.main', mb: 2 }} />
          <Typography variant="h4" gutterBottom>
            Application Error
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            An unexpected error occurred. Please try reloading the page.
          </Typography>
          {this.state.error && (
            <Paper
              variant="outlined"
              sx={{
                p: 2,
                mb: 3,
                maxWidth: '100%',
                overflow: 'auto',
                bgcolor: 'grey.50',
              }}
            >
              <Typography variant="body2" sx={{ fontFamily: 'monospace', wordBreak: 'break-word' }}>
                {this.state.error.message}
              </Typography>
            </Paper>
          )}
          <Box sx={{ display: 'flex', gap: 2 }}>
            <Button variant="contained" startIcon={<Refresh />} onClick={this.handleReload}>
              Reload Page
            </Button>
            <Button variant="outlined" startIcon={<Home />} onClick={this.handleGoHome}>
              Go to Home
            </Button>
          </Box>
        </Box>
      </Container>
    );
  }
}

export default GlobalErrorBoundary;
