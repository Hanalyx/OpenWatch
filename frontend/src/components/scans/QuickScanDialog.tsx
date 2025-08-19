import React, { useState, useEffect } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Box,
  Typography,
  Card,
  CardContent,
  Grid,
  Chip,
  RadioGroup,
  FormControlLabel,
  Radio,
  TextField,
  Switch,
  Alert,
  LinearProgress,
  IconButton
} from '@mui/material';
import {
  Security,
  CheckCircle,
  BugReport,
  Settings,
  Schedule,
  PlayArrow,
  Close,
  Info
} from '@mui/icons-material';

interface ScanTemplate {
  id: string;
  name: string;
  description: string;
  icon: React.ReactNode;
  color: 'primary' | 'success' | 'warning' | 'error';
  contentId: number;
  profileId: string;
  estimatedDuration: string;
  ruleCount?: number;
}

interface QuickScanDialogProps {
  open: boolean;
  onClose: () => void;
  hostId: string;
  hostName: string;
  onScanStarted: (scanId: string) => void;
}

const QuickScanDialog: React.FC<QuickScanDialogProps> = ({
  open,
  onClose,
  hostId,
  hostName,
  onScanStarted
}) => {
  const [selectedTemplate, setSelectedTemplate] = useState<string>('');
  const [customName, setCustomName] = useState('');
  const [emailNotify, setEmailNotify] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [templates] = useState<ScanTemplate[]>([
    {
      id: 'quick-compliance',
      name: 'Quick Compliance',
      description: 'Essential compliance checks for regulatory requirements',
      icon: <CheckCircle />,
      color: 'success',
      contentId: 1,
      profileId: 'xccdf_org.ssgproject.content_profile_cui',
      estimatedDuration: '5-10 min',
      ruleCount: 120
    },
    {
      id: 'security-audit',
      name: 'Security Audit',
      description: 'Comprehensive security configuration review',
      icon: <Security />,
      color: 'error',
      contentId: 1,
      profileId: 'xccdf_org.ssgproject.content_profile_stig',
      estimatedDuration: '15-25 min',
      ruleCount: 340
    },
    {
      id: 'vulnerability-scan',
      name: 'Vulnerability Check',
      description: 'Scan for known security vulnerabilities',
      icon: <BugReport />,
      color: 'warning',
      contentId: 1,
      profileId: 'xccdf_org.ssgproject.content_profile_cis',
      estimatedDuration: '10-15 min',
      ruleCount: 200
    }
  ]);

  useEffect(() => {
    if (open) {
      // Auto-select first template
      setSelectedTemplate(templates[0]?.id || '');
      setCustomName(`${templates[0]?.name || 'Scan'} - ${hostName}`);
      setError(null);
    }
  }, [open, hostName, templates]);

  const handleStartScan = async () => {
    if (!selectedTemplate) {
      setError('Please select a scan template');
      return;
    }

    const template = templates.find(t => t.id === selectedTemplate);
    if (!template) {
      setError('Invalid template selected');
      return;
    }

    try {
      setLoading(true);
      setError(null);

      const response = await fetch('/api/scans/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
        },
        body: JSON.stringify({
          name: customName || `${template.name} - ${hostName}`,
          host_id: hostId,
          content_id: template.contentId,
          profile_id: template.profileId,
          scan_options: {
            template_id: template.id,
            quick_scan: true,
            email_notify: emailNotify
          }
        })
      });

      if (response.ok) {
        const data = await response.json();
        onScanStarted(data.scan_id);
        onClose();
      } else {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Failed to start scan');
      }
    } catch (err: any) {
      setError(err.message || 'Failed to start scan');
    } finally {
      setLoading(false);
    }
  };

  const selectedTemplateData = templates.find(t => t.id === selectedTemplate);

  return (
    <Dialog
      open={open}
      onClose={onClose}
      maxWidth="md"
      fullWidth
    >
      <DialogTitle>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <Box>
            <Typography variant="h6">Quick Scan</Typography>
            <Typography variant="body2" color="text.secondary">
              {hostName}
            </Typography>
          </Box>
          <IconButton onClick={onClose} disabled={loading}>
            <Close />
          </IconButton>
        </Box>
      </DialogTitle>

      <DialogContent>
        {error && (
          <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
            {error}
          </Alert>
        )}

        {loading && <LinearProgress sx={{ mb: 2 }} />}

        {/* Template Selection */}
        <Typography variant="subtitle1" gutterBottom sx={{ mt: 1 }}>
          Choose Scan Type
        </Typography>

        <RadioGroup
          value={selectedTemplate}
          onChange={(e) => {
            setSelectedTemplate(e.target.value);
            const template = templates.find(t => t.id === e.target.value);
            if (template) {
              setCustomName(`${template.name} - ${hostName}`);
            }
          }}
        >
          <Grid container spacing={2}>
            {templates.map((template) => (
              <Grid item xs={12} sm={6} md={4} key={template.id}>
                <Card 
                  sx={{ 
                    cursor: 'pointer',
                    border: selectedTemplate === template.id ? 2 : 1,
                    borderColor: selectedTemplate === template.id 
                      ? `${template.color}.main` 
                      : 'divider',
                    '&:hover': {
                      boxShadow: 3
                    }
                  }}
                  onClick={() => {
                    setSelectedTemplate(template.id);
                    setCustomName(`${template.name} - ${hostName}`);
                  }}
                >
                  <CardContent sx={{ p: 2 }}>
                    <FormControlLabel
                      value={template.id}
                      control={<Radio />}
                      label=""
                      sx={{ m: 0, position: 'absolute' }}
                    />
                    
                    <Box sx={{ ml: 4 }}>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                        <Box sx={{ color: `${template.color}.main` }}>
                          {template.icon}
                        </Box>
                        <Typography variant="subtitle2" fontWeight="bold">
                          {template.name}
                        </Typography>
                      </Box>
                      
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                        {template.description}
                      </Typography>
                      
                      <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                        <Chip
                          icon={<Schedule />}
                          label={template.estimatedDuration}
                          size="small"
                          variant="outlined"
                        />
                        {template.ruleCount && (
                          <Chip
                            label={`${template.ruleCount} rules`}
                            size="small"
                            variant="outlined"
                          />
                        )}
                      </Box>
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </RadioGroup>

        {/* Scan Configuration */}
        <Box sx={{ mt: 3 }}>
          <Typography variant="subtitle1" gutterBottom>
            Scan Configuration
          </Typography>
          
          <TextField
            fullWidth
            label="Scan Name"
            value={customName}
            onChange={(e) => setCustomName(e.target.value)}
            margin="normal"
            placeholder={`${selectedTemplateData?.name || 'Scan'} - ${hostName}`}
          />

          <Box sx={{ display: 'flex', alignItems: 'center', mt: 2 }}>
            <FormControlLabel
              control={
                <Switch
                  checked={emailNotify}
                  onChange={(e) => setEmailNotify(e.target.checked)}
                />
              }
              label="Email notification when complete"
            />
            <IconButton size="small" sx={{ ml: 1 }}>
              <Info fontSize="small" />
            </IconButton>
          </Box>
        </Box>

        {/* Selected Template Summary */}
        {selectedTemplateData && (
          <Alert
            severity="info"
            sx={{ mt: 2 }}
            icon={selectedTemplateData.icon}
          >
            <Typography variant="body2">
              <strong>{selectedTemplateData.name}</strong> will run {selectedTemplateData.ruleCount} security checks
              and complete in approximately <strong>{selectedTemplateData.estimatedDuration}</strong>.
            </Typography>
          </Alert>
        )}
      </DialogContent>

      <DialogActions>
        <Button onClick={onClose} disabled={loading}>
          Cancel
        </Button>
        <Button
          variant="contained"
          startIcon={<PlayArrow />}
          onClick={handleStartScan}
          disabled={loading || !selectedTemplate}
        >
          {loading ? 'Starting...' : 'Start Scan'}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default QuickScanDialog;