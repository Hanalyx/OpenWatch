import React, { useState, useEffect } from 'react';
import {
  Button,
  Menu,
  MenuItem,
  ListItemIcon,
  ListItemText,
  Divider,
  Typography,
  Box,
  Chip,
  CircularProgress,
  Alert
} from '@mui/material';
import {
  PlayArrow,
  Scanner,
  Security,
  BugReport,
  Settings,
  ExpandMore,
  Schedule,
  CheckCircle
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';

interface ScanTemplate {
  id: string;
  name: string;
  description: string;
  icon: React.ReactNode;
  color: 'primary' | 'success' | 'warning' | 'error';
  isDefault?: boolean;
  contentId: number;
  profileId: string;
  estimatedDuration: string;
  lastUsed?: string;
}

interface QuickScanMenuProps {
  hostId: string;
  hostName: string;
  onScanStart: (templateId: string) => void;
  disabled?: boolean;
}

const QuickScanMenu: React.FC<QuickScanMenuProps> = ({
  hostId,
  hostName,
  onScanStart,
  disabled = false
}) => {
  const navigate = useNavigate();
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [templates, setTemplates] = useState<ScanTemplate[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const open = Boolean(anchorEl);

  useEffect(() => {
    if (open) {
      fetchScanTemplates();
    }
  }, [open, hostId]);

  const fetchScanTemplates = async () => {
    try {
      setLoading(true);
      const response = await fetch(`/api/scan-templates/host/${hostId}`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
        }
      });

      if (response.ok) {
        const data = await response.json();
        setTemplates(data.templates || getDefaultTemplates());
      } else {
        // Use default templates if API fails
        setTemplates(getDefaultTemplates());
      }
    } catch (err) {
      console.error('Failed to fetch scan templates:', err);
      setTemplates(getDefaultTemplates());
      setError('Using default templates');
    } finally {
      setLoading(false);
    }
  };

  const getDefaultTemplates = (): ScanTemplate[] => [
    {
      id: 'quick-compliance',
      name: 'Quick Compliance',
      description: 'Fast SCAP compliance check',
      icon: <CheckCircle />,
      color: 'success',
      isDefault: true,
      contentId: 1,
      profileId: 'xccdf_org.ssgproject.content_profile_cui',
      estimatedDuration: '5-10 min'
    },
    {
      id: 'security-audit',
      name: 'Security Audit',
      description: 'Comprehensive security scan',
      icon: <Security />,
      color: 'error',
      contentId: 1,
      profileId: 'xccdf_org.ssgproject.content_profile_stig',
      estimatedDuration: '15-25 min'
    },
    {
      id: 'vulnerability-scan',
      name: 'Vulnerability Scan',
      description: 'Check for known vulnerabilities',
      icon: <BugReport />,
      color: 'warning',
      contentId: 1,
      profileId: 'xccdf_org.ssgproject.content_profile_cis',
      estimatedDuration: '10-15 min'
    }
  ];

  const handleMenuOpen = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleMenuClose = () => {
    setAnchorEl(null);
    setError(null);
  };

  const handleTemplateSelect = async (template: ScanTemplate) => {
    handleMenuClose();
    
    try {
      // Start scan immediately with template
      const response = await fetch('/api/scans/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
        },
        body: JSON.stringify({
          name: `${template.name} - ${hostName}`,
          host_id: hostId,
          content_id: template.contentId,
          profile_id: template.profileId,
          scan_options: {
            template_id: template.id,
            quick_scan: true
          }
        })
      });

      if (response.ok) {
        const scanData = await response.json();
        onScanStart(template.id);
        // Navigate to scan detail to show progress
        navigate(`/scans/${scanData.scan_id}`);
      } else {
        throw new Error('Failed to start scan');
      }
    } catch (err) {
      console.error('Failed to start quick scan:', err);
      setError('Failed to start scan');
    }
  };

  const handleCustomScan = () => {
    handleMenuClose();
    navigate('/scans/new', { state: { hostId } });
  };

  const defaultTemplate = templates.find(t => t.isDefault);

  return (
    <>
      <Button
        variant="contained"
        startIcon={<PlayArrow />}
        endIcon={templates.length > 1 ? <ExpandMore /> : undefined}
        onClick={templates.length === 1 || !defaultTemplate ? handleCustomScan : 
                 templates.length > 1 ? handleMenuOpen : 
                 () => handleTemplateSelect(defaultTemplate)}
        disabled={disabled}
        sx={{ minWidth: 140 }}
      >
        {templates.length === 1 ? 'Scan Now' : 'Quick Scan'}
      </Button>

      <Menu
        anchorEl={anchorEl}
        open={open}
        onClose={handleMenuClose}
        PaperProps={{
          sx: { minWidth: 300, maxWidth: 400 }
        }}
        transformOrigin={{ horizontal: 'right', vertical: 'top' }}
        anchorOrigin={{ horizontal: 'right', vertical: 'bottom' }}
      >
        {error && (
          <Alert severity="warning" sx={{ m: 1, mb: 0 }}>
            {error}
          </Alert>
        )}

        {loading ? (
          <Box sx={{ display: 'flex', justifyContent: 'center', p: 2 }}>
            <CircularProgress size={24} />
          </Box>
        ) : (
          <>
            <Box sx={{ px: 2, py: 1, bgcolor: 'grey.50' }}>
              <Typography variant="subtitle2" color="text.secondary">
                Quick Scan Templates
              </Typography>
            </Box>

            {templates.map((template) => (
              <MenuItem
                key={template.id}
                onClick={() => handleTemplateSelect(template)}
                sx={{ py: 1.5 }}
              >
                <ListItemIcon>
                  <Box sx={{ color: `${template.color}.main` }}>
                    {template.icon}
                  </Box>
                </ListItemIcon>
                <ListItemText
                  primary={
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <Typography variant="subtitle2">
                        {template.name}
                      </Typography>
                      {template.isDefault && (
                        <Chip 
                          label="Default" 
                          size="small" 
                          color="primary" 
                          sx={{ height: 18, fontSize: '0.7rem' }}
                        />
                      )}
                    </Box>
                  }
                  secondary={
                    <Box>
                      <Typography variant="caption" color="text.secondary">
                        {template.description}
                      </Typography>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mt: 0.5 }}>
                        <Schedule sx={{ fontSize: 12 }} />
                        <Typography variant="caption" color="text.secondary">
                          {template.estimatedDuration}
                        </Typography>
                        {template.lastUsed && (
                          <Typography variant="caption" color="text.secondary">
                            • Last used {template.lastUsed}
                          </Typography>
                        )}
                      </Box>
                    </Box>
                  }
                />
              </MenuItem>
            ))}

            <Divider />
            
            <MenuItem onClick={handleCustomScan}>
              <ListItemIcon>
                <Settings />
              </ListItemIcon>
              <ListItemText
                primary="Custom Scan"
                secondary="Configure scan options manually"
              />
            </MenuItem>
          </>
        )}
      </Menu>
    </>
  );
};

export default QuickScanMenu;