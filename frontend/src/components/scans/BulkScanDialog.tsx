import React, { useState, useEffect } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Box,
  Typography,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  TextField,
  Switch,
  FormControlLabel,
  Alert,
  Chip,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Card,
  CardContent,
  Grid,
  Slider,
  IconButton,
} from '@mui/material';
import { Computer, PlayArrow, Close, Info, AutoAwesome, Timer } from '@mui/icons-material';

interface Host {
  id: string;
  hostname: string;
  display_name?: string;
  ip_address: string;
  operating_system?: string;
  environment?: string;
  last_scan?: string;
}

interface FeasibilityAnalysis {
  feasible: boolean;
  total_hosts: number;
  estimated_time_minutes: number;
  max_parallel_scans: number;
  os_groups: Record<string, number>;
  environment_groups: Record<string, number>;
  recommendations: string[];
  reason?: string;
}

interface BulkScanDialogProps {
  open: boolean;
  onClose: () => void;
  selectedHosts: Host[];
  onScanStarted: (sessionId: string, sessionName: string) => void;
  onError?: (error: string) => void;
}

const BulkScanDialog: React.FC<BulkScanDialogProps> = ({
  open,
  onClose,
  selectedHosts,
  onScanStarted,
  onError,
}) => {
  const [templateId, setTemplateId] = useState('auto');
  const [namePrefix, setNamePrefix] = useState('Bulk Scan');
  const [priority, setPriority] = useState('normal');
  const [staggerDelay, setStaggerDelay] = useState(30);
  const [emailNotify, setEmailNotify] = useState(false);
  const [loading, setLoading] = useState(false);
  const [feasibilityLoading, setFeasibilityLoading] = useState(false);
  const [feasibility, setFeasibility] = useState<FeasibilityAnalysis | null>(null);
  const [error, setError] = useState<string | null>(null);

  const templates = [
    {
      id: 'auto',
      name: 'Smart Scan (AI-Recommended)',
      description: 'Intelligent profile selection per host',
      icon: '🤖',
    },
    {
      id: 'essential',
      name: 'Essential Security',
      description: 'Quick security baseline',
      icon: '⚡',
    },
    {
      id: 'xccdf_org.ssgproject.content_profile_cui',
      name: 'CUI Compliance',
      description: 'Controlled Unclassified Information',
      icon: '🛡️',
    },
    {
      id: 'xccdf_org.ssgproject.content_profile_stig',
      name: 'STIG Security',
      description: 'Security Technical Implementation Guide',
      icon: '🔒',
    },
    {
      id: 'xccdf_org.ssgproject.content_profile_cis',
      name: 'CIS Benchmark',
      description: 'Center for Internet Security',
      icon: '🎯',
    },
  ];

  useEffect(() => {
    if (open && selectedHosts.length > 0) {
      analyzeFeasibility();
    }
  }, [open, selectedHosts]);

  const analyzeFeasibility = async () => {
    try {
      setFeasibilityLoading(true);
      setError(null);

      // Mock feasibility analysis - in real implementation this would call the API
      const mockAnalysis: FeasibilityAnalysis = {
        feasible: selectedHosts.length <= 50,
        total_hosts: selectedHosts.length,
        estimated_time_minutes: Math.ceil((selectedHosts.length * 10) / 3), // Assuming 3 parallel scans
        max_parallel_scans: Math.min(5, selectedHosts.length),
        os_groups: selectedHosts.reduce(
          (acc, host) => {
            const os = host.operating_system || 'Unknown';
            acc[os] = (acc[os] || 0) + 1;
            return acc;
          },
          {} as Record<string, number>
        ),
        environment_groups: selectedHosts.reduce(
          (acc, host) => {
            const env = host.environment || 'Unknown';
            acc[env] = (acc[env] || 0) + 1;
            return acc;
          },
          {} as Record<string, number>
        ),
        recommendations: [],
      };

      // Add recommendations based on analysis
      if (selectedHosts.length > 20) {
        mockAnalysis.recommendations.push(
          'Large batch detected - consider splitting into smaller groups'
        );
      }

      const osTypes = Object.keys(mockAnalysis.os_groups).length;
      if (osTypes > 3) {
        mockAnalysis.recommendations.push(
          'Multiple OS types detected - scans will be optimized per OS'
        );
      }

      const hasProductionAndOthers =
        mockAnalysis.environment_groups['production'] &&
        Object.keys(mockAnalysis.environment_groups).length > 1;
      if (hasProductionAndOthers) {
        mockAnalysis.recommendations.push(
          'Production and non-production hosts mixed - consider separate scans'
        );
      }

      if (mockAnalysis.recommendations.length === 0) {
        mockAnalysis.recommendations.push('Batch configuration looks optimal');
      }

      if (!mockAnalysis.feasible) {
        mockAnalysis.reason = 'Too many hosts selected. Maximum 50 hosts per bulk scan.';
      }

      setFeasibility(mockAnalysis);
    } catch (err: any) {
      setError(err.message || 'Failed to analyze bulk scan feasibility');
    } finally {
      setFeasibilityLoading(false);
    }
  };

  const handleStartBulkScan = async () => {
    try {
      setLoading(true);
      setError(null);

      const hostIds = selectedHosts.map((host) => host.id);

      const response = await fetch('/api/scans/bulk-scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${localStorage.getItem('auth_token')}`,
        },
        body: JSON.stringify({
          host_ids: hostIds,
          template_id: templateId,
          priority,
          name_prefix: namePrefix,
          stagger_delay: staggerDelay,
        }),
      });

      if (response.ok) {
        const data = await response.json();
        onScanStarted(data.session_id, data.message);
        onClose();
      } else {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Failed to start bulk scan');
      }
    } catch (err: any) {
      const errorMessage = err.message || 'Failed to start bulk scan';
      setError(errorMessage);
      if (onError) {
        onError(errorMessage);
      }
    } finally {
      setLoading(false);
    }
  };

  const formatEstimatedTime = (minutes: number) => {
    if (minutes < 60) {
      return `~${minutes} minutes`;
    } else {
      const hours = Math.floor(minutes / 60);
      const remainingMinutes = minutes % 60;
      return `~${hours}h ${remainingMinutes}m`;
    }
  };

  const canStartScan = feasibility?.feasible && selectedHosts.length > 0 && !loading;

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <Box>
            <Typography variant="h6">Bulk Scan Configuration</Typography>
            <Typography variant="body2" color="text.secondary">
              {selectedHosts.length} hosts selected
            </Typography>
          </Box>
          <IconButton onClick={onClose}>
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

        {/* Feasibility Analysis */}
        {feasibilityLoading ? (
          <Card sx={{ mb: 2 }}>
            <CardContent>
              <Typography>Analyzing scan feasibility...</Typography>
            </CardContent>
          </Card>
        ) : (
          feasibility && (
            <Card sx={{ mb: 2 }}>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                  <AutoAwesome color={feasibility.feasible ? 'success' : 'error'} />
                  <Typography variant="h6">Feasibility Analysis</Typography>
                  <Chip
                    label={feasibility.feasible ? 'Optimal' : 'Issues Found'}
                    color={feasibility.feasible ? 'success' : 'error'}
                    size="small"
                  />
                </Box>

                <Grid container spacing={2}>
                  <Grid item xs={6} sm={3}>
                    <Box sx={{ textAlign: 'center' }}>
                      <Typography variant="h4" color="primary">
                        {feasibility.total_hosts}
                      </Typography>
                      <Typography variant="caption">Total Hosts</Typography>
                    </Box>
                  </Grid>
                  <Grid item xs={6} sm={3}>
                    <Box sx={{ textAlign: 'center' }}>
                      <Typography variant="h4" color="success.main">
                        {feasibility.max_parallel_scans}
                      </Typography>
                      <Typography variant="caption">Parallel Scans</Typography>
                    </Box>
                  </Grid>
                  <Grid item xs={12} sm={6}>
                    <Box sx={{ textAlign: 'center' }}>
                      <Typography variant="h4" color="warning.main">
                        {formatEstimatedTime(feasibility.estimated_time_minutes)}
                      </Typography>
                      <Typography variant="caption">Estimated Duration</Typography>
                    </Box>
                  </Grid>
                </Grid>

                {Object.keys(feasibility.os_groups).length > 1 && (
                  <Box sx={{ mt: 2 }}>
                    <Typography variant="subtitle2" gutterBottom>
                      Operating Systems:
                    </Typography>
                    <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                      {Object.entries(feasibility.os_groups).map(([os, count]) => (
                        <Chip key={os} label={`${os} (${count})`} size="small" variant="outlined" />
                      ))}
                    </Box>
                  </Box>
                )}

                {feasibility.recommendations.length > 0 && (
                  <Box sx={{ mt: 2 }}>
                    <Typography variant="subtitle2" gutterBottom>
                      Recommendations:
                    </Typography>
                    <List dense>
                      {feasibility.recommendations.map((rec, index) => (
                        <ListItem key={index} sx={{ py: 0 }}>
                          <ListItemIcon sx={{ minWidth: 32 }}>
                            <Info fontSize="small" color="info" />
                          </ListItemIcon>
                          <ListItemText primary={<Typography variant="body2">{rec}</Typography>} />
                        </ListItem>
                      ))}
                    </List>
                  </Box>
                )}

                {!feasibility.feasible && (
                  <Alert severity="error" sx={{ mt: 2 }}>
                    {feasibility.reason}
                  </Alert>
                )}
              </CardContent>
            </Card>
          )
        )}

        {/* Scan Configuration */}
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          <FormControl fullWidth>
            <InputLabel>Scan Template</InputLabel>
            <Select
              value={templateId}
              onChange={(e) => setTemplateId(e.target.value)}
              label="Scan Template"
            >
              {templates.map((template) => (
                <MenuItem key={template.id} value={template.id}>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <span>{template.icon}</span>
                    <Box>
                      <Typography variant="body2">{template.name}</Typography>
                      <Typography variant="caption" color="text.secondary">
                        {template.description}
                      </Typography>
                    </Box>
                  </Box>
                </MenuItem>
              ))}
            </Select>
          </FormControl>

          <TextField
            fullWidth
            label="Name Prefix"
            value={namePrefix}
            onChange={(e) => setNamePrefix(e.target.value)}
            helperText="Each scan will be named: [Prefix] - [Hostname]"
          />

          <FormControl fullWidth>
            <InputLabel>Priority</InputLabel>
            <Select value={priority} onChange={(e) => setPriority(e.target.value)} label="Priority">
              <MenuItem value="low">Low</MenuItem>
              <MenuItem value="normal">Normal</MenuItem>
              <MenuItem value="high">High</MenuItem>
            </Select>
          </FormControl>

          <Box>
            <Typography gutterBottom>Stagger Delay: {staggerDelay} seconds</Typography>
            <Slider
              value={staggerDelay}
              onChange={(_, value) => setStaggerDelay(value as number)}
              min={10}
              max={120}
              step={10}
              valueLabelDisplay="auto"
              marks={[
                { value: 10, label: '10s' },
                { value: 30, label: '30s' },
                { value: 60, label: '1m' },
                { value: 120, label: '2m' },
              ]}
            />
            <Typography variant="caption" color="text.secondary">
              Time delay between starting each scan to manage system resources
            </Typography>
          </Box>

          <FormControlLabel
            control={
              <Switch checked={emailNotify} onChange={(e) => setEmailNotify(e.target.checked)} />
            }
            label="Email notification when all scans complete"
          />
        </Box>

        {/* Selected Hosts Preview */}
        <Card sx={{ mt: 2 }}>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Selected Hosts ({selectedHosts.length})
            </Typography>
            <Box sx={{ maxHeight: 200, overflow: 'auto' }}>
              <List dense>
                {selectedHosts.slice(0, 10).map((host) => (
                  <ListItem key={host.id}>
                    <ListItemIcon>
                      <Computer fontSize="small" />
                    </ListItemIcon>
                    <ListItemText
                      primary={host.display_name || host.hostname}
                      secondary={`${host.ip_address} • ${host.operating_system || 'Unknown OS'}`}
                    />
                  </ListItem>
                ))}
                {selectedHosts.length > 10 && (
                  <ListItem>
                    <ListItemText
                      primary={
                        <Typography color="text.secondary">
                          ... and {selectedHosts.length - 10} more hosts
                        </Typography>
                      }
                    />
                  </ListItem>
                )}
              </List>
            </Box>
          </CardContent>
        </Card>
      </DialogContent>

      <DialogActions>
        <Button onClick={onClose} disabled={loading}>
          Cancel
        </Button>
        <Button
          variant="contained"
          startIcon={loading ? <Timer /> : <PlayArrow />}
          onClick={handleStartBulkScan}
          disabled={!canStartScan}
        >
          {loading ? 'Starting...' : `Start Bulk Scan (${selectedHosts.length} hosts)`}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default BulkScanDialog;
