import React from 'react';
import {
  Box,
  Typography,
  Button,
  useTheme,
  alpha,
} from '@mui/material';
import {
  Inbox,
  Search,
  Add,
  ErrorOutline,
} from '@mui/icons-material';

export type EmptyStateType = 'no-data' | 'no-results' | 'error' | 'custom';

interface EmptyStateProps {
  type?: EmptyStateType;
  title?: string;
  description?: string;
  icon?: React.ReactNode;
  action?: {
    label: string;
    onClick: () => void;
    variant?: 'text' | 'outlined' | 'contained';
    color?: 'primary' | 'secondary' | 'inherit';
  };
  secondaryAction?: {
    label: string;
    onClick: () => void;
    variant?: 'text' | 'outlined' | 'contained';
  };
  illustration?: React.ReactNode;
  maxWidth?: number;
}

const EmptyState: React.FC<EmptyStateProps> = ({
  type = 'no-data',
  title,
  description,
  icon,
  action,
  secondaryAction,
  illustration,
  maxWidth = 400,
}) => {
  const theme = useTheme();

  const getDefaultContent = (type: EmptyStateType) => {
    switch (type) {
      case 'no-data':
        return {
          icon: <Inbox sx={{ fontSize: 64 }} />,
          title: 'No data available',
          description: 'There are no items to display at the moment.',
        };
      case 'no-results':
        return {
          icon: <Search sx={{ fontSize: 64 }} />,
          title: 'No results found',
          description: 'Try adjusting your search or filter criteria.',
        };
      case 'error':
        return {
          icon: <ErrorOutline sx={{ fontSize: 64 }} />,
          title: 'Something went wrong',
          description: 'We encountered an error while loading the data.',
        };
      default:
        return {
          icon: <Inbox sx={{ fontSize: 64 }} />,
          title: 'Empty',
          description: 'No content available.',
        };
    }
  };

  const defaultContent = getDefaultContent(type);
  const displayIcon = icon || defaultContent.icon;
  const displayTitle = title || defaultContent.title;
  const displayDescription = description || defaultContent.description;

  return (
    <Box
      sx={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        textAlign: 'center',
        py: 8,
        px: 4,
        maxWidth,
        mx: 'auto',
      }}
    >
      {/* Illustration or Icon */}
      {illustration ? (
        illustration
      ) : (
        <Box
          sx={{
            mb: 3,
            color: alpha(theme.palette.text.secondary, 0.5),
          }}
        >
          {displayIcon}
        </Box>
      )}

      {/* Title */}
      <Typography
        variant="h5"
        fontWeight="medium"
        color="text.primary"
        gutterBottom
        sx={{ mb: 1 }}
      >
        {displayTitle}
      </Typography>

      {/* Description */}
      <Typography
        variant="body1"
        color="text.secondary"
        sx={{ mb: 4, maxWidth: 300 }}
      >
        {displayDescription}
      </Typography>

      {/* Actions */}
      {(action || secondaryAction) && (
        <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap', justifyContent: 'center' }}>
          {action && (
            <Button
              variant={action.variant || 'contained'}
              color={action.color || 'primary'}
              onClick={action.onClick}
              startIcon={type === 'no-data' ? <Add /> : undefined}
            >
              {action.label}
            </Button>
          )}
          {secondaryAction && (
            <Button
              variant={secondaryAction.variant || 'outlined'}
              onClick={secondaryAction.onClick}
            >
              {secondaryAction.label}
            </Button>
          )}
        </Box>
      )}
    </Box>
  );
};

export default EmptyState;