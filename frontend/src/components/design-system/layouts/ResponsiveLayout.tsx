import React from 'react';
import {
  Box,
  Container,
  Grid,
  Paper,
  Typography,
  useMediaQuery,
  useTheme,
  Fab,
  Skeleton,
  Stack,
} from '@mui/material';
import { type SxProps, type Theme } from '@mui/material/styles';

interface ResponsiveLayoutProps {
  title?: string;
  subtitle?: string;
  headerActions?: React.ReactNode;
  children: React.ReactNode;

  // Layout configuration
  maxWidth?: 'xs' | 'sm' | 'md' | 'lg' | 'xl' | false;
  disableGutters?: boolean;

  // Statistics/metrics section
  statistics?: {
    content: React.ReactNode;
    loading?: boolean;
    columns?: { xs?: number; sm?: number; md?: number; lg?: number; xl?: number };
  };

  // Sidebar configuration
  sidebar?: {
    content: React.ReactNode;
    width?: { xs?: number; sm?: number; md?: number; lg?: number };
    position?: 'left' | 'right';
    collapsible?: boolean;
  };

  // Floating action button
  fab?: {
    icon: React.ReactNode;
    onClick: () => void;
    tooltip?: string;
    color?: 'primary' | 'secondary' | 'default';
    position?: { bottom?: number; right?: number; left?: number };
  };

  // Loading state
  loading?: boolean;

  // Custom styling
  sx?: SxProps<Theme>;
}

const ResponsiveLayout: React.FC<ResponsiveLayoutProps> = ({
  title,
  subtitle,
  headerActions,
  children,
  maxWidth = 'xl',
  disableGutters = false,
  statistics,
  sidebar,
  fab,
  loading = false,
  sx,
}) => {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('sm'));
  const isTablet = useMediaQuery(theme.breakpoints.down('md'));
  const _isDesktop = useMediaQuery(theme.breakpoints.up('lg'));

  // Responsive configuration based on screen size
  const getResponsiveConfig = () => {
    if (isMobile) {
      return {
        headerPadding: 2,
        contentPadding: 1,
        statisticsColumns: statistics?.columns?.xs || 1,
        sidebarEnabled: false, // Collapse sidebar on mobile
        titleVariant: 'h5' as const,
        subtitleVariant: 'body2' as const,
      };
    } else if (isTablet) {
      return {
        headerPadding: 3,
        contentPadding: 2,
        statisticsColumns: statistics?.columns?.sm || 2,
        sidebarEnabled: !sidebar?.collapsible,
        titleVariant: 'h4' as const,
        subtitleVariant: 'body1' as const,
      };
    } else {
      return {
        headerPadding: 4,
        contentPadding: 3,
        statisticsColumns: statistics?.columns?.lg || 4,
        sidebarEnabled: true,
        titleVariant: 'h3' as const,
        subtitleVariant: 'h6' as const,
      };
    }
  };

  const config = getResponsiveConfig();

  // Loading skeleton component
  const LoadingSkeleton = () => (
    <Box>
      <Skeleton variant="rectangular" height={60} sx={{ mb: 2, borderRadius: 2 }} />
      <Grid container spacing={2}>
        {[...Array(config.statisticsColumns)].map((_, index) => (
          <Grid item xs={12} sm={6} md={3} key={index}>
            <Skeleton variant="rectangular" height={120} sx={{ borderRadius: 2 }} />
          </Grid>
        ))}
      </Grid>
      <Skeleton variant="rectangular" height={400} sx={{ mt: 2, borderRadius: 2 }} />
    </Box>
  );

  if (loading) {
    return (
      <Container maxWidth={maxWidth} disableGutters={disableGutters} sx={sx}>
        <LoadingSkeleton />
      </Container>
    );
  }

  return (
    <Container
      maxWidth={maxWidth}
      disableGutters={disableGutters}
      sx={{
        minHeight: '100vh',
        display: 'flex',
        flexDirection: 'column',
        ...sx,
      }}
    >
      {/* Page Header */}
      {(title || headerActions) && (
        <Box
          sx={{
            p: config.headerPadding,
            pb: statistics ? 2 : config.headerPadding,
          }}
        >
          <Stack
            direction={isMobile ? 'column' : 'row'}
            justifyContent="space-between"
            alignItems={isMobile ? 'flex-start' : 'center'}
            spacing={2}
          >
            <Box>
              {title && (
                <Typography
                  variant={config.titleVariant}
                  fontWeight="bold"
                  gutterBottom={!!subtitle}
                  sx={{
                    background: `linear-gradient(45deg, ${theme.palette.primary.main} 30%, ${theme.palette.secondary.main} 90%)`,
                    backgroundClip: 'text',
                    WebkitBackgroundClip: 'text',
                    WebkitTextFillColor: 'transparent',
                  }}
                >
                  {title}
                </Typography>
              )}
              {subtitle && (
                <Typography
                  variant={config.subtitleVariant}
                  color="text.secondary"
                  sx={{ maxWidth: { xs: '100%', sm: '60%' } }}
                >
                  {subtitle}
                </Typography>
              )}
            </Box>
            {headerActions && (
              <Box
                sx={{
                  display: 'flex',
                  gap: 1,
                  flexWrap: 'wrap',
                  justifyContent: isMobile ? 'flex-start' : 'flex-end',
                  width: isMobile ? '100%' : 'auto',
                }}
              >
                {headerActions}
              </Box>
            )}
          </Stack>
        </Box>
      )}

      {/* Statistics Section */}
      {statistics && (
        <Box sx={{ px: config.contentPadding, pb: 2 }}>
          {statistics.loading ? (
            <Grid container spacing={2}>
              {[...Array(config.statisticsColumns)].map((_, index) => (
                <Grid item xs={12} sm={6} md={12 / config.statisticsColumns} key={index}>
                  <Skeleton variant="rectangular" height={120} sx={{ borderRadius: 2 }} />
                </Grid>
              ))}
            </Grid>
          ) : (
            statistics.content
          )}
        </Box>
      )}

      {/* Main Content Area */}
      <Box sx={{ flexGrow: 1, p: config.contentPadding }}>
        {sidebar && config.sidebarEnabled ? (
          <Grid container spacing={3}>
            {/* Sidebar */}
            <Grid
              item
              xs={sidebar.width?.xs || 12}
              sm={sidebar.width?.sm || 4}
              md={sidebar.width?.md || 3}
              lg={sidebar.width?.lg || 3}
              order={sidebar.position === 'right' ? 2 : 1}
            >
              <Paper
                elevation={1}
                sx={{
                  p: 2,
                  height: 'fit-content',
                  position: 'sticky',
                  top: theme.spacing(2),
                }}
              >
                {sidebar.content}
              </Paper>
            </Grid>

            {/* Main Content */}
            <Grid
              item
              xs={12 - (sidebar.width?.xs || 0)}
              sm={12 - (sidebar.width?.sm || 4)}
              md={12 - (sidebar.width?.md || 3)}
              lg={12 - (sidebar.width?.lg || 3)}
              order={sidebar.position === 'right' ? 1 : 2}
            >
              {children}
            </Grid>
          </Grid>
        ) : (
          children
        )}
      </Box>

      {/* Floating Action Button */}
      {fab && (
        <Fab
          color={fab.color || 'primary'}
          aria-label={fab.tooltip || 'Action'}
          sx={{
            position: 'fixed',
            bottom: fab.position?.bottom || 16,
            right: fab.position?.right || 16,
            left: fab.position?.left,
            // Adjust size on mobile
            width: isMobile ? 48 : 56,
            height: isMobile ? 48 : 56,
          }}
          onClick={fab.onClick}
        >
          {fab.icon}
        </Fab>
      )}
    </Container>
  );
};

export default ResponsiveLayout;
