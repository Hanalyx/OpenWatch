import React, { useState, useEffect } from 'react';
import {
  Button,
  Menu,
  MenuItem,
  ListItemIcon,
  ListItemText,
  Divider,
  Chip,
  Box,
  Typography,
  CircularProgress,
  Tooltip,
} from '@mui/material';
import {
  PlayArrow,
  Security,
  CheckCircle,
  BugReport,
  Settings,
  Schedule,
  AutoAwesome,
  Speed,
} from '@mui/icons-material';

interface ScanTemplate {
  id?: string;
  profile_id?: string;
  name: string;
  description?: string;
  icon?: React.ReactNode;
  color?: 'primary' | 'success' | 'warning' | 'error';
  estimatedDuration?: string;
  estimated_duration?: string;
  ruleCount?: number;
  rule_count?: number;
  isRecommended?: boolean;
  confidence?: number;
  reasoning?: string[];
}

interface QuickScanDropdownProps {
  hostId: string;
  hostName: string;
  disabled?: boolean;
  onScanStarted?: (scanId: string, scanName: string) => void;
  onError?: (error: string) => void;
}

const QuickScanDropdown: React.FC<QuickScanDropdownProps> = ({
  hostId,
  hostName,
  disabled = false,
  onScanStarted,
  onError,
}) => {
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [loading, setLoading] = useState(false);
  const [loadingScan, setLoadingScan] = useState<string | null>(null);
  const [templates, setTemplates] = useState<ScanTemplate[]>([]);
  // Recommended scan profile based on host characteristics
  const [recommendedProfile, setRecommendedProfile] = useState<ScanTemplate | null>(null);

  const open = Boolean(anchorEl);

  // Default scan templates
  const defaultTemplates: ScanTemplate[] = [
    {
      id: 'auto',
      name: 'Smart Scan',
      description: 'AI-powered profile selection based on host characteristics',
      icon: <AutoAwesome />,
      color: 'primary',
      estimatedDuration: '8-15 min',
      isRecommended: true,
    },
    {
      id: 'essential',
      name: 'Essential Security',
      description: 'Quick security baseline check',
      icon: <Speed />,
      color: 'success',
      estimatedDuration: '5-8 min',
      ruleCount: 120,
    },
    {
      id: 'xccdf_org.ssgproject.content_profile_cui',
      name: 'CUI Compliance',
      description: 'Controlled Unclassified Information compliance',
      icon: <CheckCircle />,
      color: 'primary',
      estimatedDuration: '10-15 min',
      ruleCount: 180,
    },
    {
      id: 'xccdf_org.ssgproject.content_profile_stig',
      name: 'STIG Security',
      description: 'Security Technical Implementation Guide',
      icon: <Security />,
      color: 'error',
      estimatedDuration: '15-25 min',
      ruleCount: 340,
    },
    {
      id: 'xccdf_org.ssgproject.content_profile_cis',
      name: 'CIS Benchmark',
      description: 'Center for Internet Security baseline',
      icon: <BugReport />,
      color: 'warning',
      estimatedDuration: '12-18 min',
      ruleCount: 200,
    },
  ];

  // Load intelligent profile recommendation when component mounts or hostId changes
  // ESLint disable: loadProfileRecommendation function is not memoized to avoid complex dependency chain
  useEffect(() => {
    loadProfileRecommendation();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hostId]);

  const handleClick = (event: React.MouseEvent<HTMLButtonElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  const loadProfileRecommendation = async () => {
    try {
      // This would call the intelligence service to get recommendations
      // For now, using mock data based on host characteristics

      // In a real implementation:
      // const response = await fetch(`/api/scans/hosts/${hostId}/profile-suggestion`, {
      //   headers: { 'Authorization': `Bearer ${localStorage.getItem('auth_token')}` }
      // });
      // const recommendation = await response.json();

      // Mock recommendation for demo
      const mockRecommendation = {
        profile_id: 'xccdf_org.ssgproject.content_profile_cui',
        name: 'CUI Compliance',
        confidence: 0.85,
        reasoning: ['Production environment detected', 'RHEL 8 system'],
        estimated_duration: '10-15 min',
        rule_count: 180,
      };

      setRecommendedProfile(mockRecommendation);

      // Update templates with recommendation
      const updatedTemplates = defaultTemplates.map((template) => ({
        ...template,
        isRecommended: template.id === mockRecommendation.profile_id || template.id === 'auto',
      }));

      setTemplates(updatedTemplates);
    } catch (error) {
      console.error('Failed to load profile recommendation:', error);
      setTemplates(defaultTemplates);
    }
  };

  const handleScanStart = async (templateId: string, templateName: string) => {
    try {
      setLoadingScan(templateId);
      setLoading(true);

      const response = await fetch(`/api/scans/hosts/${hostId}/quick-scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${localStorage.getItem('auth_token')}`,
        },
        body: JSON.stringify({
          template_id: templateId,
          priority: 'normal',
          name: `${templateName} - ${hostName}`,
          email_notify: false,
        }),
      });

      if (response.ok) {
        const data = await response.json();

        // Show success feedback
        if (onScanStarted) {
          onScanStarted(data.id, data.suggested_profile?.name || templateName);
        }

        handleClose();
      } else {
        const errorData = await response.json();
        const errorMessage =
          typeof errorData.detail === 'string'
            ? errorData.detail
            : errorData.detail?.message || 'Failed to start scan';

        if (onError) {
          onError(errorMessage);
        }
      }
    } catch (error) {
      // Handle scan execution errors with proper type checking
      const errorMessage = error instanceof Error ? error.message : 'Failed to start scan';
      if (onError) {
        onError(errorMessage);
      }
    } finally {
      setLoading(false);
      setLoadingScan(null);
    }
  };

  const getMenuItemContent = (template: ScanTemplate) => (
    <>
      <ListItemIcon sx={{ color: `${template.color}.main` }}>
        {loadingScan === template.id ? <CircularProgress size={20} /> : template.icon}
      </ListItemIcon>
      <ListItemText
        primary={
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Typography variant="body2" fontWeight={template.isRecommended ? 'bold' : 'normal'}>
              {template.name}
            </Typography>
            {template.isRecommended && (
              <Chip
                label="Recommended"
                size="small"
                color="primary"
                variant="outlined"
                sx={{ height: 20, fontSize: '0.7rem' }}
              />
            )}
          </Box>
        }
        secondary={
          <Box>
            <Typography variant="caption" color="text.secondary" display="block">
              {template.description}
            </Typography>
            <Box sx={{ display: 'flex', gap: 1, mt: 0.5 }}>
              <Chip
                label={template.estimatedDuration}
                size="small"
                variant="outlined"
                sx={{ height: 18, fontSize: '0.65rem' }}
                icon={<Schedule sx={{ fontSize: '0.8rem' }} />}
              />
              {template.ruleCount && (
                <Chip
                  label={`${template.ruleCount} rules`}
                  size="small"
                  variant="outlined"
                  sx={{ height: 18, fontSize: '0.65rem' }}
                />
              )}
            </Box>
          </Box>
        }
      />
    </>
  );

  return (
    <>
      <Tooltip title="Start quick scan with intelligent defaults">
        <Button
          variant="contained"
          size="small"
          startIcon={<PlayArrow />}
          onClick={handleClick}
          disabled={disabled || loading}
          sx={{ minWidth: 120 }}
        >
          {loading ? 'Starting...' : 'Quick Scan'}
        </Button>
      </Tooltip>

      <Menu
        anchorEl={anchorEl}
        open={open}
        onClose={handleClose}
        PaperProps={{
          sx: {
            minWidth: 320,
            maxWidth: 400,
            '& .MuiMenuItem-root': {
              py: 1.5,
            },
          },
        }}
        transformOrigin={{
          vertical: 'top',
          horizontal: 'left',
        }}
        anchorOrigin={{
          vertical: 'bottom',
          horizontal: 'left',
        }}
      >
        <Box sx={{ px: 2, py: 1, borderBottom: 1, borderColor: 'divider' }}>
          <Typography variant="subtitle2" fontWeight="bold">
            Quick Scan - {hostName}
          </Typography>
          {recommendedProfile && recommendedProfile.confidence && (
            <Typography variant="caption" color="text.secondary">
              Recommended: {recommendedProfile.name} (
              {Math.round(recommendedProfile.confidence * 100)}% confidence)
            </Typography>
          )}
        </Box>

        {templates.map((template) => (
          <MenuItem
            key={template.id || template.profile_id}
            onClick={() => handleScanStart(template.id || template.profile_id || '', template.name)}
            disabled={loadingScan !== null}
            sx={{
              backgroundColor: template.isRecommended ? 'action.hover' : 'inherit',
              '&:hover': {
                backgroundColor: template.isRecommended ? 'action.selected' : 'action.hover',
              },
            }}
          >
            {getMenuItemContent(template)}
          </MenuItem>
        ))}

        <Divider />

        <MenuItem onClick={handleClose} sx={{ justifyContent: 'center', py: 1 }}>
          <ListItemIcon sx={{ minWidth: 'auto', mr: 1 }}>
            <Settings fontSize="small" />
          </ListItemIcon>
          <ListItemText
            primary={
              <Typography variant="body2" color="text.secondary">
                Advanced Scan Options
              </Typography>
            }
          />
        </MenuItem>
      </Menu>
    </>
  );
};

export default QuickScanDropdown;
