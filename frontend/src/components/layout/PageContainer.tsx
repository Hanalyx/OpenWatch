import React from 'react';
import { Box, Typography, SxProps, Theme } from '@mui/material';

interface PageContainerProps {
  children: React.ReactNode;
  /**
   * Page title - if provided, renders standard header
   * For custom headers, omit this and include header in children
   */
  title?: string;
  subtitle?: string;
  icon?: React.ReactNode;
  actions?: React.ReactNode;
  /**
   * Custom header component - use this for complex headers
   * (e.g., with back buttons, tabs, custom layouts)
   */
  header?: React.ReactNode;
  /**
   * Additional sx props for the wrapper
   */
  sx?: SxProps<Theme>;
}

/**
 * PageContainer - Standardized page wrapper with consistent spacing
 *
 * Provides uniform spacing and layout for all OpenWatch pages.
 * Eliminates need for repetitive Box/Container wrappers on each page.
 *
 * The Layout component provides p: 3 (24px) padding on all sides.
 * This component only adds mb: 3 (24px) to the header section.
 *
 * Usage Option 1 - Standard Header:
 *   <PageContainer title="Page Title" subtitle="Description">
 *     <YourPageContent />
 *   </PageContainer>
 *
 * Usage Option 2 - Custom Header:
 *   <PageContainer header={<YourCustomHeader />}>
 *     <YourPageContent />
 *   </PageContainer>
 *
 * Usage Option 3 - No Header (just spacing):
 *   <PageContainer>
 *     <YourPageContent />
 *   </PageContainer>
 */
const PageContainer: React.FC<PageContainerProps> = ({
  children,
  title,
  subtitle,
  icon,
  actions,
  header,
  sx,
}) => {
  return (
    <Box sx={sx}>
      {/* Custom Header - takes precedence over standard header */}
      {header && <Box sx={{ mb: 3 }}>{header}</Box>}

      {/* Standard Header - Only renders if title provided and no custom header */}
      {!header && title && (
        <Box sx={{ mb: 3 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              {icon}
              <Typography variant="h4" component="h1" gutterBottom={!!subtitle}>
                {title}
              </Typography>
            </Box>
            {actions && <Box>{actions}</Box>}
          </Box>
          {subtitle && (
            <Typography variant="body1" color="text.secondary">
              {subtitle}
            </Typography>
          )}
        </Box>
      )}

      {/* Page Content */}
      <Box>{children}</Box>
    </Box>
  );
};

export default PageContainer;
