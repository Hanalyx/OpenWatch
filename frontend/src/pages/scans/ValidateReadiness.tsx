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
  CircularProgress,
  LinearProgress,
} from '@mui/material';
import {
  Group,
  Computer,
  Search,
  ArrowBack,
  CheckCircle,
  FactCheck as FactCheckIcon,
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { api } from '../../services/api';
import ReadinessDialog from '../../components/ReadinessDialog';

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

interface ValidationResult {
  host_id: string;
  hostname: string;
  status: 'ready' | 'not_ready' | 'degraded';
  overall_passed: boolean;
  passed_checks: number;
  failed_checks: number;
  total_checks: number;
}

const ValidateReadiness: React.FC = () => {
  const navigate = useNavigate();
  const [activeStep, setActiveStep] = useState(0);
  const [targetType, setTargetType] = useState<'hosts' | 'groups' | null>(null);
  const [selectedHosts, setSelectedHosts] = useState<string[]>([]);
  const [selectedGroups, setSelectedGroups] = useState<string[]>([]);
  const [hosts, setHosts] = useState<Host[]>([]);
  const [groups, setGroups] = useState<HostGroup[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [validating, setValidating] = useState(false);
  const [validationResults, setValidationResults] = useState<ValidationResult[]>([]);
  const [showResultsDialog, setShowResultsDialog] = useState(false);
  const [selectedResultHostId, setSelectedResultHostId] = useState<string>('');
  const [selectedResultHostname, setSelectedResultHostname] = useState<string>('');

  const steps = ['Select Target', 'Select Hosts/Groups'];

  useEffect(() => {
    if (targetType === 'hosts') {
      loadHosts();
    } else if (targetType === 'groups') {
      loadGroups();
    }
  }, [targetType]);

  const loadHosts = async () => {
    try {
      setLoading(true);
      const response = await api.get('/api/hosts/');
      setHosts(response || []);
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
      setGroups(response || []);
    } catch (error) {
      console.error('Failed to load host groups:', error);
      setError('Failed to load host groups');
    } finally {
      setLoading(false);
    }
  };

  const handleNext = () => {
    if (activeStep === 0 && targetType) {
      setActiveStep(1);
    }
  };

  const handleBack = () => {
    if (activeStep === 1) {
      setActiveStep(0);
      setSelectedHosts([]);
      setSelectedGroups([]);
      setValidationResults([]);
    } else {
      navigate('/scans');
    }
  };

  const handleHostToggle = (hostId: string) => {
    setSelectedHosts((prev) =>
      prev.includes(hostId) ? prev.filter((id) => id !== hostId) : [...prev, hostId]
    );
  };

  const handleGroupToggle = (groupId: string) => {
    setSelectedGroups((prev) =>
      prev.includes(groupId) ? prev.filter((id) => id !== groupId) : [...prev, groupId]
    );
  };

  const handleSelectAll = () => {
    if (targetType === 'hosts') {
      const filteredHostIds = getFilteredHosts().map((h) => h.id);
      setSelectedHosts(filteredHostIds);
    } else if (targetType === 'groups') {
      const filteredGroupIds = getFilteredGroups().map((g) => g.id);
      setSelectedGroups(filteredGroupIds);
    }
  };

  const handleDeselectAll = () => {
    if (targetType === 'hosts') {
      setSelectedHosts([]);
    } else if (targetType === 'groups') {
      setSelectedGroups([]);
    }
  };

  const handleValidate = async () => {
    try {
      setValidating(true);
      setError(null);
      setValidationResults([]);

      let hostIdsToValidate: string[] = [];

      if (targetType === 'hosts') {
        hostIdsToValidate = selectedHosts;
      } else if (targetType === 'groups') {
        // Fetch hosts from selected groups
        for (const groupId of selectedGroups) {
          const groupHosts = await api.get(`/api/host-groups/${groupId}/hosts`);
          hostIdsToValidate.push(...groupHosts.map((h: any) => h.id));
        }
      }

      // Call bulk validation API
      const response = await api.post('/api/v1/scans/readiness/validate-bulk', {
        host_ids: hostIdsToValidate,
        parallel: true,
        use_cache: true,
        cache_ttl_hours: 1,
      });

      setValidationResults(response.hosts || []);
    } catch (error: any) {
      console.error('Validation failed:', error);
      setError(error.message || 'Failed to validate host readiness');
    } finally {
      setValidating(false);
    }
  };

  const handleViewDetails = (hostId: string, hostname: string) => {
    setSelectedResultHostId(hostId);
    setSelectedResultHostname(hostname);
    setShowResultsDialog(true);
  };

  const getFilteredHosts = () => {
    if (!searchQuery) return hosts;
    return hosts.filter(
      (host) =>
        host.hostname.toLowerCase().includes(searchQuery.toLowerCase()) ||
        host.ip_address.includes(searchQuery)
    );
  };

  const getFilteredGroups = () => {
    if (!searchQuery) return groups;
    return groups.filter(
      (group) =>
        group.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        group.description?.toLowerCase().includes(searchQuery.toLowerCase())
    );
  };

  const getStatusColor = (
    status: string
  ): 'success' | 'error' | 'warning' | 'default' | 'primary' | 'secondary' | 'info' => {
    switch (status) {
      case 'ready':
        return 'success';
      case 'not_ready':
        return 'error';
      case 'degraded':
        return 'warning';
      default:
        return 'default';
    }
  };

  const renderSelectTarget = () => (
    <Box>
      <Box sx={{ mb: 4 }}>
        <Typography variant="h5" component="h2" gutterBottom>
          Select Target Type
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Choose whether to validate individual hosts or host groups.
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
                transform: 'translateY(-2px)',
              },
            }}
            onClick={() => setTargetType('groups')}
          >
            <CardContent sx={{ textAlign: 'center', py: 6 }}>
              <Group sx={{ fontSize: 48, color: 'primary.main', mb: 2 }} />
              <Typography variant="h6" gutterBottom>
                Target Groups
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Validate all hosts in selected groups
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
                transform: 'translateY(-2px)',
              },
            }}
            onClick={() => setTargetType('hosts')}
          >
            <CardContent sx={{ textAlign: 'center', py: 6 }}>
              <Computer sx={{ fontSize: 48, color: 'primary.main', mb: 2 }} />
              <Typography variant="h6" gutterBottom>
                Target Hosts
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Validate specific individual hosts
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );

  const renderSelectHosts = () => (
    <Box>
      <Box sx={{ mb: 3, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Box>
          <Typography variant="h5" component="h2" gutterBottom>
            Select {targetType === 'hosts' ? 'Hosts' : 'Groups'} to Validate
          </Typography>
          <Typography variant="body2" color="text.secondary">
            {targetType === 'hosts'
              ? `${selectedHosts.length} host(s) selected`
              : `${selectedGroups.length} group(s) selected`}
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Button size="small" onClick={handleSelectAll}>
            Select All
          </Button>
          <Button size="small" onClick={handleDeselectAll}>
            Deselect All
          </Button>
        </Box>
      </Box>

      <TextField
        fullWidth
        placeholder={
          targetType === 'hosts' ? 'Search hosts by name or IP...' : 'Search groups by name...'
        }
        value={searchQuery}
        onChange={(e) => setSearchQuery(e.target.value)}
        InputProps={{
          startAdornment: (
            <InputAdornment position="start">
              <Search />
            </InputAdornment>
          ),
        }}
        sx={{ mb: 3 }}
      />

      {loading ? (
        <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
          <CircularProgress />
        </Box>
      ) : targetType === 'hosts' ? (
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell padding="checkbox">
                  <Checkbox
                    checked={
                      selectedHosts.length > 0 && selectedHosts.length === getFilteredHosts().length
                    }
                    indeterminate={
                      selectedHosts.length > 0 && selectedHosts.length < getFilteredHosts().length
                    }
                    onChange={() => {
                      if (selectedHosts.length === getFilteredHosts().length) {
                        handleDeselectAll();
                      } else {
                        handleSelectAll();
                      }
                    }}
                  />
                </TableCell>
                <TableCell>Hostname</TableCell>
                <TableCell>IP Address</TableCell>
                <TableCell>OS</TableCell>
                <TableCell>Status</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {getFilteredHosts().map((host) => (
                <TableRow
                  key={host.id}
                  hover
                  onClick={() => handleHostToggle(host.id)}
                  sx={{ cursor: 'pointer' }}
                >
                  <TableCell padding="checkbox">
                    <Checkbox checked={selectedHosts.includes(host.id)} />
                  </TableCell>
                  <TableCell>{host.hostname}</TableCell>
                  <TableCell>{host.ip_address}</TableCell>
                  <TableCell>{host.os || 'Unknown'}</TableCell>
                  <TableCell>
                    <Chip
                      label={host.status}
                      color={host.status === 'online' ? 'success' : 'default'}
                      size="small"
                    />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      ) : (
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell padding="checkbox">
                  <Checkbox
                    checked={
                      selectedGroups.length > 0 &&
                      selectedGroups.length === getFilteredGroups().length
                    }
                    indeterminate={
                      selectedGroups.length > 0 &&
                      selectedGroups.length < getFilteredGroups().length
                    }
                    onChange={() => {
                      if (selectedGroups.length === getFilteredGroups().length) {
                        handleDeselectAll();
                      } else {
                        handleSelectAll();
                      }
                    }}
                  />
                </TableCell>
                <TableCell>Group Name</TableCell>
                <TableCell>Description</TableCell>
                <TableCell>Host Count</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {getFilteredGroups().map((group) => (
                <TableRow
                  key={group.id}
                  hover
                  onClick={() => handleGroupToggle(group.id)}
                  sx={{ cursor: 'pointer' }}
                >
                  <TableCell padding="checkbox">
                    <Checkbox checked={selectedGroups.includes(group.id)} />
                  </TableCell>
                  <TableCell>{group.name}</TableCell>
                  <TableCell>{group.description}</TableCell>
                  <TableCell>{group.host_count}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      {validationResults.length > 0 && (
        <Box sx={{ mt: 4 }}>
          <Typography variant="h6" gutterBottom>
            Validation Results
          </Typography>
          <TableContainer component={Paper}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Hostname</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Passed</TableCell>
                  <TableCell>Failed</TableCell>
                  <TableCell>Total</TableCell>
                  <TableCell>Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {validationResults.map((result) => (
                  <TableRow key={result.host_id}>
                    <TableCell>{result.hostname}</TableCell>
                    <TableCell>
                      <Chip
                        label={result.status.replace('_', ' ').toUpperCase()}
                        color={getStatusColor(result.status)}
                        size="small"
                        icon={result.overall_passed ? <CheckCircle /> : undefined}
                      />
                    </TableCell>
                    <TableCell>
                      <Chip label={result.passed_checks} color="success" size="small" />
                    </TableCell>
                    <TableCell>
                      <Chip label={result.failed_checks} color="error" size="small" />
                    </TableCell>
                    <TableCell>{result.total_checks}</TableCell>
                    <TableCell>
                      <Button
                        size="small"
                        variant="outlined"
                        onClick={() => handleViewDetails(result.host_id, result.hostname)}
                      >
                        View Details
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Box>
      )}
    </Box>
  );

  return (
    <Container maxWidth="lg" sx={{ py: 4 }}>
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" component="h1" gutterBottom>
          Validate Host Readiness
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Ensure hosts meet all requirements for SCAP scanning
        </Typography>
      </Box>

      <Stepper activeStep={activeStep} sx={{ mb: 4 }}>
        {steps.map((label) => (
          <Step key={label}>
            <StepLabel>{label}</StepLabel>
          </Step>
        ))}
      </Stepper>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      <Card>
        <CardContent sx={{ p: 4 }}>
          {activeStep === 0 && renderSelectTarget()}
          {activeStep === 1 && renderSelectHosts()}
        </CardContent>
      </Card>

      <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 3 }}>
        <Button startIcon={<ArrowBack />} onClick={handleBack}>
          {activeStep === 0 ? 'Cancel' : 'Back'}
        </Button>

        <Box sx={{ display: 'flex', gap: 2 }}>
          {activeStep === 0 && (
            <Button variant="contained" onClick={handleNext} disabled={!targetType}>
              Next
            </Button>
          )}

          {activeStep === 1 && (
            <Button
              variant="contained"
              color="primary"
              startIcon={validating ? <CircularProgress size={20} /> : <FactCheckIcon />}
              onClick={handleValidate}
              disabled={
                validating ||
                (targetType === 'hosts' && selectedHosts.length === 0) ||
                (targetType === 'groups' && selectedGroups.length === 0)
              }
            >
              {validating ? 'Validating...' : 'Validate'}
            </Button>
          )}
        </Box>
      </Box>

      {validating && (
        <Box sx={{ mt: 3 }}>
          <Typography variant="body2" color="text.secondary" gutterBottom>
            Running readiness checks...
          </Typography>
          <LinearProgress />
        </Box>
      )}

      {showResultsDialog && (
        <ReadinessDialog
          open={showResultsDialog}
          onClose={() => setShowResultsDialog(false)}
          hostId={selectedResultHostId}
          hostname={selectedResultHostname}
        />
      )}
    </Container>
  );
};

export default ValidateReadiness;
