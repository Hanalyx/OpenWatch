import React, { useState, useEffect } from 'react';
import {
  Box,
  Button,
  Container,
  Typography,
  Stepper,
  Step,
  StepLabel,
  Card,
  CardContent,
  Grid,
  Checkbox,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  TextField,
  InputAdornment,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Alert,
  Chip,
  IconButton,
  CircularProgress
} from '@mui/material';
import {
  Group,
  Computer,
  Search,
  ArrowBack,
  ArrowForward,
  CheckCircle
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { api } from '../../services/api';

interface Host {
  id: string;
  hostname: string;
  ip_address: string;
  status: 'online' | 'offline';
  os?: string;
}

interface HostGroup {
  id: string;
  name: string;
  description: string;
  host_count: number;
}

interface ComplianceRule {
  id: string;
  rule_id: string;
  title: string;
  description: string;
  severity: 'high' | 'medium' | 'low';
  framework: string;
}

const ComplianceScans: React.FC = () => {
  const navigate = useNavigate();
  const [activeStep, setActiveStep] = useState(0);
  const [targetType, setTargetType] = useState<'hosts' | 'groups' | null>(null);
  const [selectedHosts, setSelectedHosts] = useState<string[]>([]);
  const [selectedGroups, setSelectedGroups] = useState<string[]>([]);
  const [selectedRules, setSelectedRules] = useState<string[]>([]);
  const [hosts, setHosts] = useState<Host[]>([]);
  const [groups, setGroups] = useState<HostGroup[]>([]);
  const [rules, setRules] = useState<ComplianceRule[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [frameworkFilter, setFrameworkFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [rulesError, setRulesError] = useState(false);

  const steps = ['Select Target', 'Choose Rules', 'Review & Start'];

  useEffect(() => {
    if (targetType === 'hosts') {
      loadHosts();
    } else if (targetType === 'groups') {
      loadGroups();
    }
  }, [targetType]);

  useEffect(() => {
    if (activeStep === 1) {
      loadRules();
    }
  }, [activeStep, frameworkFilter, severityFilter]);

  const loadHosts = async () => {
    try {
      setLoading(true);
      const response = await api.get('/api/hosts/');
      setHosts(response.hosts || []);
    } catch (error) {
      console.error('Failed to load hosts:', error);
      setError('Failed to load hosts');
    } finally {
      setLoading(false);
    }
  };

  const loadGroups = async () => {
    try {
      setLoading(true);
      const response = await api.get('/api/host-groups/');
      setGroups(response.groups || []);
    } catch (error) {
      console.error('Failed to load groups:', error);
      setError('Failed to load host groups');
    } finally {
      setLoading(false);
    }
  };

  const loadRules = async () => {
    try {
      setLoading(true);
      setRulesError(false);
      const params: any = {};
      if (frameworkFilter) params.framework = frameworkFilter;
      if (severityFilter) params.business_impact = severityFilter;
      
      const response = await api.get('/api/compliance/semantic-rules', { params });
      
      // Transform the response to match our interface
      const transformedRules = (response.rules || []).map((rule: any) => ({
        id: rule.id,
        rule_id: rule.scap_rule_id,
        title: rule.title,
        description: rule.compliance_intent,
        severity: rule.risk_level?.toLowerCase() || 'medium',
        framework: rule.frameworks?.[0] || 'unknown'
      }));
      
      setRules(transformedRules);
    } catch (error) {
      console.error('Failed to load rules:', error);
      setRulesError(true);
      setRules([]);
    } finally {
      setLoading(false);
    }
  };

  const handleNext = () => {
    if (activeStep === 0 && !targetType) {
      setError('Please select a target type');
      return;
    }
    if (activeStep === 0 && targetType === 'hosts' && selectedHosts.length === 0) {
      setError('Please select at least one host');
      return;
    }
    if (activeStep === 0 && targetType === 'groups' && selectedGroups.length === 0) {
      setError('Please select at least one group');
      return;
    }
    setError(null);
    setActiveStep(prev => prev + 1);
  };

  const handleBack = () => {
    setActiveStep(prev => prev - 1);
  };

  const handleSelectAllHosts = () => {
    if (selectedHosts.length === hosts.length) {
      setSelectedHosts([]);
    } else {
      setSelectedHosts(hosts.map(h => h.id));
    }
  };

  const handleHostToggle = (hostId: string) => {
    setSelectedHosts(prev => 
      prev.includes(hostId) 
        ? prev.filter(id => id !== hostId)
        : [...prev, hostId]
    );
  };

  const handleStartScan = async () => {
    try {
      setLoading(true);
      
      if (targetType === 'groups') {
        // Use group compliance endpoint for host groups
        for (const groupId of selectedGroups) {
          const response = await api.post(`/api/group-compliance/${groupId}/scan`, {
            rule_ids: selectedRules,
            scan_name: `Compliance Scan - ${new Date().toISOString()}`
          });
          console.log(`Started scan for group ${groupId}:`, response);
        }
        // Navigate to scans list to see all started scans
        navigate('/scans');
      } else {
        // For individual hosts, we need to create individual scans
        // This would require the regular scan endpoint with compliance profile
        setError('Individual host scanning not yet implemented. Please use host groups for now.');
        return;
      }
    } catch (error) {
      console.error('Failed to start scan:', error);
      setError('Failed to start compliance scan');
    } finally {
      setLoading(false);
    }
  };

  const renderSelectTarget = () => (
    <Box>
      <Box sx={{ mb: 4 }}>
        <Typography variant="h5" component="h2" gutterBottom>
          Select Target Type
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Choose whether to scan individual hosts or host groups.
        </Typography>
      </Box>
      
      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Card 
            sx={{ 
              cursor: 'pointer',
              border: targetType === 'groups' ? '2px solid' : '1px solid',
              borderColor: targetType === 'groups' ? 'primary.main' : 'divider',
              transition: 'all 0.3s',
              '&:hover': {
                borderColor: 'primary.main',
                transform: 'translateY(-2px)'
              }
            }}
            onClick={() => setTargetType('groups')}
          >
            <CardContent sx={{ textAlign: 'center', py: 6 }}>
              <Group sx={{ fontSize: 48, color: 'primary.main', mb: 2 }} />
              <Typography variant="h6" gutterBottom>
                Target Groups
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Scan entire host groups at once
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        
        <Grid item xs={12} md={6}>
          <Card 
            sx={{ 
              cursor: 'pointer',
              border: targetType === 'hosts' ? '2px solid' : '1px solid',
              borderColor: targetType === 'hosts' ? 'primary.main' : 'divider',
              transition: 'all 0.3s',
              '&:hover': {
                borderColor: 'primary.main',
                transform: 'translateY(-2px)'
              }
            }}
            onClick={() => setTargetType('hosts')}
          >
            <CardContent sx={{ textAlign: 'center', py: 6 }}>
              <Computer sx={{ fontSize: 48, color: 'primary.main', mb: 2 }} />
              <Typography variant="h6" gutterBottom>
                Target Hosts
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Select individual hosts to scan
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );

  const renderSelectHosts = () => (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 4 }}>
        <Box>
          <Typography variant="h5" component="h2" gutterBottom>
            Select Target Hosts
          </Typography>
          <Typography variant="body1" color="text.secondary">
            Select one or more hosts to scan for compliance.
          </Typography>
        </Box>
        <Button
          variant="text"
          onClick={handleSelectAllHosts}
          disabled={loading}
        >
          {selectedHosts.length === hosts.length ? 'Deselect All' : 'Select All'}
        </Button>
      </Box>

      {loading ? (
        <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', py: 8 }}>
          <CircularProgress />
          <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
            Loading available hosts...
          </Typography>
        </Box>
      ) : hosts.length === 0 ? (
        <Alert severity="info">No hosts available for scanning</Alert>
      ) : (
        <Grid container spacing={2}>
          {hosts.map(host => (
            <Grid item xs={12} md={6} key={host.id}>
              <Card
                sx={{
                  cursor: 'pointer',
                  border: selectedHosts.includes(host.id) ? '2px solid' : '1px solid',
                  borderColor: selectedHosts.includes(host.id) ? 'primary.main' : 'divider',
                  transition: 'all 0.2s',
                  '&:hover': {
                    borderColor: 'primary.main'
                  }
                }}
                onClick={() => handleHostToggle(host.id)}
              >
                <CardContent sx={{ display: 'flex', alignItems: 'center' }}>
                  <Checkbox
                    checked={selectedHosts.includes(host.id)}
                    onChange={() => handleHostToggle(host.id)}
                    onClick={e => e.stopPropagation()}
                  />
                  <Box sx={{ ml: 2, flexGrow: 1 }}>
                    <Typography variant="subtitle1" fontWeight="medium">
                      {host.hostname}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {host.ip_address}
                    </Typography>
                    {host.os && (
                      <Typography variant="caption" color="text.secondary">
                        {host.os}
                      </Typography>
                    )}
                  </Box>
                  <Chip
                    label={host.status}
                    size="small"
                    color={host.status === 'online' ? 'success' : 'default'}
                  />
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      )}
    </Box>
  );

  const renderChooseRules = () => (
    <Box>
      <Box sx={{ mb: 4 }}>
        <Typography variant="h5" component="h2" gutterBottom>
          Choose Compliance Rules
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Select specific compliance rules to check or enable full scan for comprehensive assessment.
        </Typography>
      </Box>

      <Box sx={{ mb: 3 }}>
        <Grid container spacing={2} alignItems="center">
          <Grid item xs={12} md={4}>
            <TextField
              fullWidth
              placeholder="Search rules by title, description, or rule ID..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <Search />
                  </InputAdornment>
                ),
              }}
            />
          </Grid>
          <Grid item xs={12} md={3}>
            <FormControl fullWidth>
              <InputLabel>Framework</InputLabel>
              <Select
                value={frameworkFilter}
                onChange={(e) => setFrameworkFilter(e.target.value)}
                label="Framework"
              >
                <MenuItem value="">All</MenuItem>
                <MenuItem value="nist">NIST</MenuItem>
                <MenuItem value="cis">CIS</MenuItem>
                <MenuItem value="stig">DISA STIG</MenuItem>
              </Select>
            </FormControl>
          </Grid>
          <Grid item xs={12} md={3}>
            <FormControl fullWidth>
              <InputLabel>Severity</InputLabel>
              <Select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                label="Severity"
              >
                <MenuItem value="">All</MenuItem>
                <MenuItem value="high">High</MenuItem>
                <MenuItem value="medium">Medium</MenuItem>
                <MenuItem value="low">Low</MenuItem>
              </Select>
            </FormControl>
          </Grid>
          <Grid item xs={12} md={2} sx={{ textAlign: 'right' }}>
            <Button
              variant="text"
              onClick={() => setSelectedRules(rules.map(r => r.id))}
              disabled={loading || rules.length === 0}
            >
              {selectedRules.length === rules.length ? 'Deselect All' : 'Select All'}
            </Button>
          </Grid>
        </Grid>
      </Box>

      <Box sx={{ mb: 2 }}>
        <Typography variant="body2" color="text.secondary">
          {selectedRules.length} of {rules.length} rules selected
        </Typography>
      </Box>

      {loading ? (
        <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', py: 8 }}>
          <CircularProgress />
          <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
            Loading compliance rules...
          </Typography>
        </Box>
      ) : rulesError ? (
        <Box sx={{ py: 8, textAlign: 'center' }}>
          <Typography variant="h6" gutterBottom>
            No rules found
          </Typography>
          <Typography variant="body2" color="text.secondary" gutterBottom>
            No compliance rules available
          </Typography>
          <Alert severity="error" sx={{ mt: 3, mb: 2 }}>
            We don't see compliance rules here because the MongoDB database failed to connect
            but this is the view for step 4
          </Alert>
          <Button
            variant="outlined"
            onClick={loadRules}
            disabled={loading}
            startIcon={loading ? <CircularProgress size={20} /> : undefined}
          >
            {loading ? 'Retrying...' : 'Retry Loading Rules'}
          </Button>
        </Box>
      ) : rules.length === 0 ? (
        <Alert severity="info">No compliance rules available</Alert>
      ) : (
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell padding="checkbox">
                  <Checkbox
                    checked={selectedRules.length === rules.length}
                    onChange={() => {
                      if (selectedRules.length === rules.length) {
                        setSelectedRules([]);
                      } else {
                        setSelectedRules(rules.map(r => r.id));
                      }
                    }}
                  />
                </TableCell>
                <TableCell>Rule ID</TableCell>
                <TableCell>Title</TableCell>
                <TableCell>Framework</TableCell>
                <TableCell>Severity</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {rules
                .filter(rule => {
                  if (searchQuery && !rule.title.toLowerCase().includes(searchQuery.toLowerCase()) &&
                      !rule.rule_id.toLowerCase().includes(searchQuery.toLowerCase())) {
                    return false;
                  }
                  if (frameworkFilter && rule.framework !== frameworkFilter) {
                    return false;
                  }
                  if (severityFilter && rule.severity !== severityFilter) {
                    return false;
                  }
                  return true;
                })
                .map(rule => (
                  <TableRow
                    key={rule.id}
                    hover
                    onClick={() => {
                      setSelectedRules(prev =>
                        prev.includes(rule.id)
                          ? prev.filter(id => id !== rule.id)
                          : [...prev, rule.id]
                      );
                    }}
                    sx={{ cursor: 'pointer' }}
                  >
                    <TableCell padding="checkbox">
                      <Checkbox
                        checked={selectedRules.includes(rule.id)}
                        onClick={e => e.stopPropagation()}
                      />
                    </TableCell>
                    <TableCell>{rule.rule_id}</TableCell>
                    <TableCell>{rule.title}</TableCell>
                    <TableCell>{rule.framework.toUpperCase()}</TableCell>
                    <TableCell>
                      <Chip
                        label={rule.severity}
                        size="small"
                        color={
                          rule.severity === 'high' ? 'error' :
                          rule.severity === 'medium' ? 'warning' : 'default'
                        }
                      />
                    </TableCell>
                  </TableRow>
                ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}
    </Box>
  );

  const renderReviewAndStart = () => (
    <Box>
      <Box sx={{ mb: 4 }}>
        <Typography variant="h5" component="h2" gutterBottom>
          Review & Start Scan
        </Typography>
      </Box>
      
      <Grid container spacing={3}>
        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Typography variant="subtitle1" fontWeight="medium" gutterBottom>
                Scan Configuration Summary
              </Typography>
              
              <Box sx={{ mt: 2 }}>
                <Typography variant="body2" color="text.secondary">
                  Target Type: <strong>{targetType === 'hosts' ? 'Individual Hosts' : 'Host Groups'}</strong>
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                  Selected Targets: <strong>{targetType === 'hosts' ? selectedHosts.length : selectedGroups.length}</strong>
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                  Compliance Rules: <strong>{selectedRules.length}</strong>
                </Typography>
              </Box>

              <Box sx={{ mt: 3 }}>
                <Button
                  variant="contained"
                  color="primary"
                  size="large"
                  fullWidth
                  onClick={handleStartScan}
                  disabled={loading}
                  startIcon={loading ? <CircularProgress size={20} /> : <CheckCircle />}
                >
                  {loading ? 'Starting Scan...' : 'Start Compliance Scan'}
                </Button>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );

  const getStepContent = () => {
    switch (activeStep) {
      case 0:
        return targetType === null ? renderSelectTarget() : renderSelectHosts();
      case 1:
        return renderChooseRules();
      case 2:
        return renderReviewAndStart();
      default:
        return null;
    }
  };

  return (
    <Container maxWidth="xl">
      {/* Standard Header Pattern */}
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" component="h1" gutterBottom>
          New Compliance Scan
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Create and configure security compliance scans for your infrastructure
        </Typography>
      </Box>

      {/* Stepper in Paper Container */}
      <Paper sx={{ mb: 3, p: 3 }}>
        <Stepper activeStep={activeStep}>
          {steps.map((label, index) => (
            <Step key={label}>
              <StepLabel>{label}</StepLabel>
            </Step>
          ))}
        </Stepper>
      </Paper>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {/* Content in Card */}
      <Card sx={{ mb: 3 }}>
        <CardContent sx={{ p: 3 }}>
          {getStepContent()}
        </CardContent>
      </Card>

      {/* Navigation Actions */}
      <Paper sx={{ p: 3 }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
        <Button
          onClick={() => {
            if (activeStep === 0 && targetType !== null) {
              setTargetType(null);
            } else if (activeStep > 0) {
              handleBack();
            } else {
              navigate('/scans');
            }
          }}
          startIcon={<ArrowBack />}
        >
          Back
        </Button>
        
        {activeStep < steps.length - 1 && (
          <Button
            variant="contained"
            onClick={handleNext}
            endIcon={<ArrowForward />}
            disabled={
              (activeStep === 0 && targetType === null) ||
              (activeStep === 0 && targetType === 'hosts' && selectedHosts.length === 0)
            }
          >
            Next
          </Button>
        )}
        </Box>
      </Paper>
    </Container>
  );
};

export default ComplianceScans;