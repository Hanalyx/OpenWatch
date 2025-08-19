import React from 'react';
import {
  Box,
  Typography,
  Breadcrumbs,
  Link,
  useTheme,
  alpha,
} from '@mui/material';
import { NavigateNext } from '@mui/icons-material';

interface BreadcrumbItem {
  label: string;
  href?: string;
  onClick?: () => void;
}

interface PageTemplateProps {
  title: string;
  subtitle?: string;
  breadcrumbs?: BreadcrumbItem[];
  actions?: React.ReactNode;
  children: React.ReactNode;
  maxWidth?: 'xs' | 'sm' | 'md' | 'lg' | 'xl' | false;
  disablePadding?: boolean;
  headerBackground?: boolean;
}

const PageTemplate: React.FC<PageTemplateProps> = ({
  title,
  subtitle,
  breadcrumbs,
  actions,
  children,
  maxWidth = 'lg',
  disablePadding = false,
  headerBackground = false,
}) => {
  const theme = useTheme();

  return (
    <Box
      sx={{
        minHeight: '100vh',
        backgroundColor: theme.palette.background.default,
      }}
    >
      {/* Header Section */}
      <Box
        sx={{
          backgroundColor: headerBackground 
            ? alpha(theme.palette.primary.main, 0.02)
            : 'transparent',
          borderBottom: headerBackground 
            ? `1px solid ${alpha(theme.palette.primary.main, 0.1)}`
            : 'none',
          py: 3,
          px: disablePadding ? 0 : 3,
        }}
      >
        <Box
          sx={{
            maxWidth: maxWidth ? `${theme.breakpoints.values[maxWidth]}px` : 'none',
            mx: 'auto',
          }}
        >
          {/* Breadcrumbs */}
          {breadcrumbs && breadcrumbs.length > 0 && (
            <Breadcrumbs
              separator={<NavigateNext fontSize="small" />}
              sx={{ mb: 2 }}
            >
              {breadcrumbs.map((item, index) => (
                <Link
                  key={index}
                  color={index === breadcrumbs.length - 1 ? 'textPrimary' : 'inherit'}
                  href={item.href}
                  onClick={item.onClick}
                  sx={{
                    cursor: item.href || item.onClick ? 'pointer' : 'default',
                    textDecoration: 'none',
                    '&:hover': {
                      textDecoration: item.href || item.onClick ? 'underline' : 'none',
                    },
                  }}
                >
                  {item.label}
                </Link>
              ))}
            </Breadcrumbs>
          )}

          {/* Title and Actions */}
          <Box
            sx={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: 2,
            }}
          >
            <Box>
              <Typography
                variant="h3"
                component="h1"
                fontWeight="bold"
                color="text.primary"
                gutterBottom
              >
                {title}
              </Typography>
              {subtitle && (
                <Typography
                  variant="h6"
                  color="text.secondary"
                  sx={{ mt: -1 }}
                >
                  {subtitle}
                </Typography>
              )}
            </Box>

            {actions && (
              <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
                {actions}
              </Box>
            )}
          </Box>
        </Box>
      </Box>

      {/* Content Section */}
      <Box
        sx={{
          px: disablePadding ? 0 : 3,
          py: disablePadding ? 0 : 3,
        }}
      >
        <Box
          sx={{
            maxWidth: maxWidth ? `${theme.breakpoints.values[maxWidth]}px` : 'none',
            mx: 'auto',
          }}
        >
          {children}
        </Box>
      </Box>
    </Box>
  );
};

export default PageTemplate;