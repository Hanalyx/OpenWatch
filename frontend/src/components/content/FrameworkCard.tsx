import React from 'react';
import {
  Card,
  CardContent,
  Typography,
  Box,
  Chip,
  LinearProgress,
  Grid,
  List,
  ListItem,
  ListItemText,
  Tooltip,
  IconButton,
} from '@mui/material';
import {
  Security,
  Shield,
  Assignment,
  HealthAndSafety,
  CorporateFare,
  Payment,
  ExpandMore,
  ExpandLess,
} from '@mui/icons-material';

interface FrameworkCategory {
  name: string;
  count: number;
  percentage: number;
}

interface FrameworkCardProps {
  name: string;
  version: string;
  ruleCount: number;
  categories: FrameworkCategory[];
  platforms: string[];
  coverage: number;
  description?: string;
  onClick?: () => void;
}

const frameworkIcons: Record<string, React.ElementType> = {
  NIST: Security,
  CIS: Shield,
  STIG: Assignment,
  HIPAA: HealthAndSafety,
  'ISO 27001': CorporateFare,
  'PCI-DSS': Payment,
};

const frameworkColors: Record<string, string> = {
  NIST: '#1976d2',
  CIS: '#388e3c',
  STIG: '#f57c00',
  HIPAA: '#7b1fa2',
  'ISO 27001': '#5d4037',
  'PCI-DSS': '#c62828',
};

export const FrameworkCard: React.FC<FrameworkCardProps> = ({
  name,
  version,
  ruleCount,
  categories,
  platforms,
  coverage,
  description,
  onClick,
}) => {
  const [expanded, setExpanded] = React.useState(false);
  const IconComponent = frameworkIcons[name] || Security;
  const frameworkColor = frameworkColors[name] || '#757575';

  const handleExpandClick = (e: React.MouseEvent) => {
    e.stopPropagation();
    setExpanded(!expanded);
  };

  const getCoverageColor = (coverage: number) => {
    if (coverage >= 80) return 'success';
    if (coverage >= 60) return 'warning';
    return 'error';
  };

  const formatDescription = (framework: string) => {
    const descriptions: Record<string, string> = {
      NIST: 'National Institute of Standards and Technology cybersecurity framework providing comprehensive security controls.',
      CIS: 'Center for Internet Security controls offering prioritized cybersecurity best practices.',
      STIG: 'Security Technical Implementation Guides providing detailed security configuration standards.',
      HIPAA:
        'Health Insurance Portability and Accountability Act security and privacy requirements.',
      'ISO 27001': 'International standard for information security management systems.',
      'PCI-DSS':
        'Payment Card Industry Data Security Standard for organizations handling card payments.',
    };
    return (
      descriptions[framework] || 'Compliance framework with security controls and requirements.'
    );
  };

  return (
    <Card
      sx={{
        height: '100%',
        cursor: onClick ? 'pointer' : 'default',
        transition: 'all 0.2s ease-in-out',
        '&:hover': onClick
          ? {
              transform: 'translateY(-2px)',
              boxShadow: 3,
            }
          : {},
        border: `2px solid ${frameworkColor}20`,
      }}
      onClick={onClick}
    >
      <CardContent>
        {/* Header */}
        <Box display="flex" alignItems="center" justifyContent="space-between" mb={2}>
          <Box display="flex" alignItems="center" gap={1}>
            <IconComponent sx={{ color: frameworkColor, fontSize: 28 }} />
            <Box>
              <Typography
                variant="h6"
                component="div"
                sx={{ color: frameworkColor, fontWeight: 600 }}
              >
                {name}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Version {version}
              </Typography>
            </Box>
          </Box>
          <Tooltip title={expanded ? 'Show less' : 'Show more details'}>
            <IconButton size="small" onClick={handleExpandClick}>
              {expanded ? <ExpandLess /> : <ExpandMore />}
            </IconButton>
          </Tooltip>
        </Box>

        {/* Description */}
        <Typography variant="body2" color="text.secondary" mb={2} sx={{ lineHeight: 1.4 }}>
          {description || formatDescription(name)}
        </Typography>

        {/* Rule Count */}
        <Box display="flex" alignItems="center" justifyContent="space-between" mb={2}>
          <Typography variant="body2" color="text.secondary">
            Total Rules
          </Typography>
          <Chip
            label={ruleCount.toLocaleString()}
            variant="outlined"
            size="small"
            sx={{
              borderColor: frameworkColor,
              color: frameworkColor,
              fontWeight: 600,
            }}
          />
        </Box>

        {/* Coverage */}
        <Box mb={2}>
          <Box display="flex" alignItems="center" justifyContent="space-between" mb={1}>
            <Typography variant="body2" color="text.secondary">
              Implementation Coverage
            </Typography>
            <Typography variant="body2" sx={{ fontWeight: 600, color: frameworkColor }}>
              {coverage}%
            </Typography>
          </Box>
          <LinearProgress
            variant="determinate"
            value={coverage}
            color={getCoverageColor(coverage)}
            sx={{ height: 6, borderRadius: 3 }}
          />
        </Box>

        {/* Platform Support */}
        <Box mb={expanded ? 2 : 0}>
          <Typography variant="body2" color="text.secondary" gutterBottom>
            Supported Platforms
          </Typography>
          <Box display="flex" gap={0.5} flexWrap="wrap">
            {platforms.slice(0, expanded ? platforms.length : 3).map((platform) => (
              <Chip
                key={platform}
                label={platform.toUpperCase()}
                size="small"
                variant="outlined"
                sx={{ fontSize: '0.7rem', height: 20 }}
              />
            ))}
            {!expanded && platforms.length > 3 && (
              <Chip
                label={`+${platforms.length - 3}`}
                size="small"
                variant="outlined"
                sx={{ fontSize: '0.7rem', height: 20, opacity: 0.7 }}
              />
            )}
          </Box>
        </Box>

        {/* Expanded Content */}
        {expanded && (
          <Box>
            {/* Category Breakdown */}
            <Typography variant="body2" color="text.secondary" gutterBottom sx={{ mt: 2 }}>
              Rule Categories
            </Typography>
            <List dense sx={{ py: 0 }}>
              {categories.slice(0, 5).map((category, index) => (
                <ListItem key={index} sx={{ px: 0, py: 0.5 }}>
                  <ListItemText
                    primary={
                      <Box display="flex" justifyContent="space-between" alignItems="center">
                        <Typography variant="body2" sx={{ fontSize: '0.8rem' }}>
                          {category.name}
                        </Typography>
                        <Box display="flex" alignItems="center" gap={1}>
                          <Typography variant="body2" sx={{ fontSize: '0.8rem', minWidth: 35 }}>
                            {category.count}
                          </Typography>
                          <Typography
                            variant="body2"
                            color="text.secondary"
                            sx={{ fontSize: '0.75rem', minWidth: 40 }}
                          >
                            ({category.percentage}%)
                          </Typography>
                        </Box>
                      </Box>
                    }
                  />
                </ListItem>
              ))}
              {categories.length > 5 && (
                <ListItem sx={{ px: 0, py: 0.5 }}>
                  <ListItemText
                    primary={
                      <Typography
                        variant="body2"
                        color="text.secondary"
                        sx={{ fontSize: '0.8rem', fontStyle: 'italic' }}
                      >
                        +{categories.length - 5} more categories
                      </Typography>
                    }
                  />
                </ListItem>
              )}
            </List>
          </Box>
        )}
      </CardContent>
    </Card>
  );
};
