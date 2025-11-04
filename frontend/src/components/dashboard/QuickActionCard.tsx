import React from 'react';
import {
  Card,
  CardContent,
  Box,
  Typography,
  IconButton,
  Badge,
  useTheme,
  alpha,
} from '@mui/material';
import { ArrowForward } from '@mui/icons-material';

interface QuickActionCardProps {
  title: string;
  subtitle: string;
  icon: React.ReactNode;
  color?: 'primary' | 'secondary' | 'success' | 'error' | 'warning' | 'info';
  onClick: () => void;
  badge?: number;
  disabled?: boolean;
}

const QuickActionCard: React.FC<QuickActionCardProps> = ({
  title,
  subtitle,
  icon,
  color = 'primary',
  onClick,
  badge,
  disabled = false,
}) => {
  const theme = useTheme();

  return (
    <Card
      sx={{
        height: '100%',
        cursor: disabled ? 'not-allowed' : 'pointer',
        transition: 'all 0.3s ease',
        '&:hover': disabled
          ? {}
          : {
              transform: 'translateY(-4px)',
              boxShadow: theme.shadows[8],
              '& .action-arrow': {
                transform: 'translateX(4px)',
              },
            },
      }}
      onClick={disabled ? undefined : onClick}
    >
      <CardContent>
        <Box sx={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
          <Box sx={{ flex: 1 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 1 }}>
              <Badge badgeContent={badge} color="error">
                <Box
                  sx={{
                    p: 1.5,
                    borderRadius: 2,
                    bgcolor: alpha(theme.palette[color].main, 0.1),
                    color: theme.palette[color].main,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                  }}
                >
                  {icon}
                </Box>
              </Badge>
            </Box>
            <Typography variant="h6" gutterBottom>
              {title}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              {subtitle}
            </Typography>
          </Box>
          <IconButton
            size="small"
            className="action-arrow"
            sx={{
              transition: 'transform 0.3s ease',
              color: theme.palette[color].main,
            }}
            disabled={disabled}
          >
            <ArrowForward />
          </IconButton>
        </Box>
      </CardContent>
    </Card>
  );
};

export default QuickActionCard;
