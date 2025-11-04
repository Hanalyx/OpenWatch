import React from 'react';
import { Box, Grid, Toolbar, Paper, Typography, Button, IconButton, Fab } from '@mui/material';
import { Add } from '@mui/icons-material';

interface DashboardLayoutProps {
  title?: string;
  subtitle?: string;
  statistics?: React.ReactNode;
  toolbar?: React.ReactNode;
  children: React.ReactNode;
  fab?: {
    icon?: React.ReactNode;
    onClick?: () => void;
    tooltip?: string;
  };
  actions?: React.ReactNode;
}

const DashboardLayout: React.FC<DashboardLayoutProps> = ({
  title,
  subtitle,
  statistics,
  toolbar,
  children,
  fab,
  actions,
}) => {
  return (
    <Box sx={{ height: '100vh', display: 'flex', flexDirection: 'column' }}>
      {/* Page Header */}
      {(title || actions) && (
        <Box sx={{ mb: 2, p: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <Box>
              {title && (
                <Typography variant="h4" fontWeight="bold" gutterBottom>
                  {title}
                </Typography>
              )}
              {subtitle && (
                <Typography variant="body1" color="text.secondary">
                  {subtitle}
                </Typography>
              )}
            </Box>
            {actions && <Box sx={{ display: 'flex', gap: 1 }}>{actions}</Box>}
          </Box>
        </Box>
      )}

      {/* Statistics Section */}
      {statistics && <Box sx={{ mb: 2 }}>{statistics}</Box>}

      {/* Toolbar Section */}
      {toolbar && (
        <Paper sx={{ mb: 2 }}>
          <Toolbar sx={{ gap: 2 }}>{toolbar}</Toolbar>
        </Paper>
      )}

      {/* Main Content */}
      <Box sx={{ flexGrow: 1, overflow: 'auto', p: 2 }}>{children}</Box>

      {/* Floating Action Button */}
      {fab && (
        <Fab
          color="primary"
          aria-label={fab.tooltip || 'Action'}
          sx={{ position: 'fixed', bottom: 16, right: 16 }}
          onClick={fab.onClick}
        >
          {fab.icon || <Add />}
        </Fab>
      )}
    </Box>
  );
};

export default DashboardLayout;
