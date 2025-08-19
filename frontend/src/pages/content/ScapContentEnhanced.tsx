import React, { useState, useEffect } from 'react';
import {
  Box,
  Button,
  Card,
  CardContent,
  Container,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Alert,
  Snackbar,
  IconButton,
  Menu,
  MenuItem,
  LinearProgress,
  Tooltip,
  FormControl,
  InputLabel,
  Select,
  Tabs,
  Tab,
  Grid,
  Switch,
  FormControlLabel,
  Collapse,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  ListItemSecondaryAction,
  Badge,
  ButtonGroup,
  Divider,
  useTheme,
  alpha
} from '@mui/material';
import {
  Upload as UploadIcon,
  Download as DownloadIcon,
  Delete as DeleteIcon,
  MoreVert as MoreVertIcon,
  Security as SecurityIcon,
  CloudUpload as CloudUploadIcon,
  CloudSync as CloudSyncIcon,
  CloudOff as CloudOffIcon,
  Update as UpdateIcon,
  Schedule as ScheduleIcon,
  Storage as StorageIcon,
  Computer as ComputerIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  ExpandMore as ExpandMoreIcon,
  ExpandLess as ExpandLessIcon,
  Sync as SyncIcon,
  SyncDisabled as SyncDisabledIcon,
  Archive as ArchiveIcon,
  Speed as SpeedIcon,
  CleaningServices as CleaningServicesIcon,
} from '@mui/icons-material';

// Enhanced interfaces for enterprise SCAP management
interface SCAPContent {
  id: number;
  name: string;
  filename: string;
  content_type: string;
  description: string;
  version: string;
  profiles: Profile[];
  uploaded_at: string;
  uploaded_by: number;
  has_file: boolean;
  os_family: string;
  os_version: string;
  source: 'repository' | 'manual' | 'imported';
  status: 'current' | 'outdated' | 'deprecated';
  update_available?: boolean;
  compliance_framework?: string;
}

interface Profile {
  id: string;
  title: string;
  description: string;
}

interface RepositoryConfig {
  id: string;
  name: string;
  url?: string;
  type: 'official' | 'custom' | 'mirror';
  enabled: boolean;
  lastSync?: string;
  status: 'healthy' | 'error' | 'syncing';
}

interface EnvironmentInfo {
  type: 'connected' | 'air-gapped' | 'hybrid';
  repositories: RepositoryConfig[];
  autoSyncEnabled: boolean;
  lastGlobalSync?: string;
  nextScheduledSync?: string;
}

const ScapContentEnhanced: React.FC = () => {
  const theme = useTheme();
  const [scapContent, setScapContent] = useState<SCAPContent[]>([]);
  const [loading, setLoading] = useState(false);
  const [selectedTab, setSelectedTab] = useState(0);
  const [environmentInfo, setEnvironmentInfo] = useState<EnvironmentInfo>({
    type: 'connected',
    repositories: [
      {
        id: '1',
        name: 'NIST Official Repository',
        url: 'https://ncp.nist.gov/repository',
        type: 'official',
        enabled: true,
        lastSync: '2025-08-05T20:00:00Z',
        status: 'healthy'
      },
      {
        id: '2', 
        name: 'Red Hat Security Data',
        url: 'https://access.redhat.com/security',
        type: 'official',
        enabled: true,
        lastSync: '2025-08-05T19:30:00Z',
        status: 'healthy'
      }
    ],
    autoSyncEnabled: true,
    lastGlobalSync: '2025-08-05T20:00:00Z',
    nextScheduledSync: '2025-08-06T02:00:00Z'
  });

  // UI state
  const [uploadDialogOpen, setUploadDialogOpen] = useState(false);
  const [repositoryDialogOpen, setRepositoryDialogOpen] = useState(false);
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [uploadName, setUploadName] = useState('');
  const [uploadDescription, setUploadDescription] = useState('');
  const [selectedOsFamily, setSelectedOsFamily] = useState('');
  const [uploading, setUploading] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [expandedGroups, setExpandedGroups] = useState<string[]>(['rhel', 'ubuntu']);
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [selectedContent, setSelectedContent] = useState<SCAPContent | null>(null);
  const [detailsDialogOpen, setDetailsDialogOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [snackbar, setSnackbar] = useState<{
    open: boolean;
    message: string;
    severity: 'success' | 'error' | 'warning' | 'info';
  }>({
    open: false,
    message: '',
    severity: 'info'
  });

  // Mock data for demonstration
  const mockContent: SCAPContent[] = [
    {
      id: 1,
      name: 'RHEL 9 STIG',
      filename: 'rhel9-stig-latest.xml',
      content_type: 'datastream',
      description: 'Red Hat Enterprise Linux 9 Security Technical Implementation Guide',
      version: '1.0.5',
      profiles: [
        { id: 'stig', title: 'STIG Profile', description: 'DoD STIG compliance profile' },
        { id: 'stig-gui', title: 'STIG GUI Profile', description: 'STIG profile for GUI systems' }
      ],
      uploaded_at: '2025-08-05T20:00:00Z',
      uploaded_by: 1,
      has_file: true,
      os_family: 'rhel',
      os_version: '9.3',
      source: 'repository',
      status: 'current',
      compliance_framework: 'STIG'
    },
    {
      id: 2,
      name: 'Ubuntu 22.04 CIS Benchmark',
      filename: 'ubuntu2204-cis-v1.0.0.xml',
      content_type: 'datastream',
      description: 'Center for Internet Security Benchmark for Ubuntu 22.04',
      version: '1.0.0',
      profiles: [
        { id: 'level1-server', title: 'Level 1 Server', description: 'Basic security hardening' },
        { id: 'level2-server', title: 'Level 2 Server', description: 'Enhanced security hardening' }
      ],
      uploaded_at: '2025-08-05T18:30:00Z',
      uploaded_by: 1,
      has_file: true,
      os_family: 'ubuntu',
      os_version: '22.04',
      source: 'repository',
      status: 'current',
      compliance_framework: 'CIS'
    },
    {
      id: 3,
      name: 'RHEL 8 Custom Profile',
      filename: 'rhel8-custom-v2.1.xml',
      content_type: 'xccdf',
      description: 'Custom security profile for RHEL 8 production environment',
      version: '2.1',
      profiles: [
        { id: 'production', title: 'Production Profile', description: 'Production environment hardening' }
      ],
      uploaded_at: '2025-08-04T14:20:00Z',
      uploaded_by: 2,
      has_file: true,
      os_family: 'rhel',
      os_version: '8.8',
      source: 'manual',
      status: 'current',
      compliance_framework: 'Custom'
    }
  ];

  const showSnackbar = (message: string, severity: 'success' | 'error' | 'warning' | 'info' = 'info') => {
    setSnackbar({ open: true, message, severity });
  };

  const fetchScapContent = async () => {
    try {
      setLoading(true);
      const response = await fetch('/api/scap-content/', {
        headers: {
          'Authorization': 'Bearer demo-token'
        }
      });
      
      if (response.ok) {
        const data = await response.json();
        setScapContent(data.scap_content || []);
      } else {
        showSnackbar('Failed to load content', 'error');
        // Fallback to mock data for demo
        setScapContent(mockContent);
      }
    } catch (error) {
      showSnackbar('Failed to load SCAP content', 'error');
      // Fallback to mock data for demo
      setScapContent(mockContent);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScapContent();
  }, []);

  // Group content by OS family and version
  const groupedContent = scapContent.reduce((groups, content) => {
    const key = content.os_family;
    if (!groups[key]) {
      groups[key] = {};
    }
    if (!groups[key][content.os_version]) {
      groups[key][content.os_version] = [];
    }
    groups[key][content.os_version].push(content);
    return groups;
  }, {} as Record<string, Record<string, SCAPContent[]>>);

  // Calculate statistics
  const stats = {
    totalContent: scapContent.length,
    osTypes: Object.keys(groupedContent).length,
    totalProfiles: scapContent.reduce((sum, content) => sum + content.profiles.length, 0),
    outdated: scapContent.filter(c => c.status === 'outdated').length,
    updateAvailable: scapContent.filter(c => c.update_available).length
  };

  const handleSync = async () => {
    setSyncing(true);
    try {
      const response = await fetch('/api/scap-content/repositories/sync', {
        method: 'POST',
        headers: {
          'Authorization': 'Bearer demo-token',
          'Content-Type': 'application/json'
        }
      });
      
      if (response.ok) {
        showSnackbar('Repository sync completed successfully', 'success');
        fetchScapContent();
      } else {
        const error = await response.json();
        showSnackbar(error.detail || 'Sync failed. Please check repository connections.', 'error');
      }
    } catch (error) {
      showSnackbar('Network error during sync. Please check your connection.', 'error');
    } finally {
      setSyncing(false);
    }
  };

  const handleAutoSyncToggle = () => {
    setEnvironmentInfo(prev => ({
      ...prev,
      autoSyncEnabled: !prev.autoSyncEnabled
    }));
    showSnackbar(
      `Auto-sync ${!environmentInfo.autoSyncEnabled ? 'enabled' : 'disabled'}`,
      'info'
    );
  };

  const getOSIcon = (osFamily: string) => {
    switch (osFamily.toLowerCase()) {
      case 'rhel':
      case 'centos':
        return '🎩';
      case 'ubuntu':
      case 'debian':
        return '🐧';
      case 'suse':
      case 'opensuse':
        return '🦎';
      case 'windows':
        return '🪟';
      default:
        return '💻';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'current':
        return 'success';
      case 'outdated':
        return 'warning';
      case 'deprecated':
        return 'error';
      default:
        return 'default';
    }
  };

  const getFrameworkColor = (framework?: string) => {
    switch (framework?.toLowerCase()) {
      case 'stig':
        return 'error';
      case 'cis':
        return 'info';
      case 'pci-dss':
        return 'warning';
      case 'nist':
        return 'primary';
      case 'custom':
        return 'secondary';
      default:
        return 'default';
    }
  };

  const formatRelativeTime = (dateString: string) => {
    const date = new Date(dateString);
    const now = new Date();
    const diffHours = Math.floor((now.getTime() - date.getTime()) / (1000 * 60 * 60));
    
    if (diffHours < 1) return 'Just now';
    if (diffHours < 24) return `${diffHours}h ago`;
    
    const diffDays = Math.floor(diffHours / 24);
    return `${diffDays}d ago`;
  };

  const toggleGroupExpansion = (groupKey: string) => {
    setExpandedGroups(prev => 
      prev.includes(groupKey) 
        ? prev.filter(k => k !== groupKey)
        : [...prev, groupKey]
    );
  };

  const handleDownload = async (content: SCAPContent) => {
    console.log('handleDownload called with:', content);
    try {
      const token = localStorage.getItem('auth_token');
      const url = `/api/scap-content/${content.id}/download`;
      console.log('Downloading from URL:', url);
      
      const response = await fetch(url, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
          'X-Requested-With': 'XMLHttpRequest'
        }
      });

      console.log('Download response status:', response.status);
      
      if (response.ok) {
        const blob = await response.blob();
        const downloadUrl = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = downloadUrl;
        a.download = content.filename;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(downloadUrl);
        document.body.removeChild(a);
        showSnackbar(`Downloaded ${content.filename}`, 'success');
      } else {
        console.log('Download failed with status:', response.status);
        const errorText = await response.text();
        showSnackbar(`Failed to download content: ${response.statusText}`, 'error');
      }
    } catch (error) {
      console.error('Download error:', error);
      showSnackbar('Network error during download', 'error');
    }
  };

  const handleDelete = async () => {
    if (!selectedContent) return;
    console.log('handleDelete called for:', selectedContent);

    try {
      const token = localStorage.getItem('auth_token');
      const url = `/api/scap-content/${selectedContent.id}`;
      console.log('Deleting from URL:', url);
      
      const response = await fetch(url, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${token}`,
          'X-Requested-With': 'XMLHttpRequest'
        }
      });

      console.log('Delete response status:', response.status);

      if (response.ok) {
        showSnackbar(`Deleted ${selectedContent.name}`, 'success');
        setDeleteDialogOpen(false);
        setSelectedContent(null);
        fetchScapContent();
      } else {
        console.log('Delete failed with status:', response.status);
        try {
          const error = await response.json();
          showSnackbar(error.detail || `Delete failed: ${response.statusText}`, 'error');
        } catch {
          showSnackbar(`Delete failed: ${response.statusText}`, 'error');
        }
      }
    } catch (error) {
      console.error('Delete error:', error);
      showSnackbar('Network error during deletion', 'error');
    }
  };

  return (
    <Container maxWidth="xl" sx={{ py: 2 }}>



      {/* Main Content Area */}
      <Card>
        <CardContent>
          <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
            <Typography variant="h6">
              Content Library
            </Typography>
            <Box display="flex" gap={1} alignItems="center">
              <ButtonGroup variant="contained" size="small" sx={{ mr: 2 }}>
                <Button
                  startIcon={<UploadIcon />}
                  onClick={() => setUploadDialogOpen(true)}
                >
                  Upload Content
                </Button>
                <Button
                  startIcon={<CloudSyncIcon />}
                  onClick={handleSync}
                  disabled={syncing || environmentInfo.type === 'air-gapped'}
                >
                  {syncing ? 'Syncing...' : 'Sync Repository'}
                </Button>
              </ButtonGroup>
              <Tooltip title="Health Check">
                <IconButton size="small">
                  <SpeedIcon />
                </IconButton>
              </Tooltip>
              <Tooltip title="Clean Cache">
                <IconButton size="small">
                  <CleaningServicesIcon />
                </IconButton>
              </Tooltip>
              <Tooltip title="Repository Settings">
                <IconButton 
                  size="small"
                  onClick={() => setRepositoryDialogOpen(true)}
                >
                  <StorageIcon />
                </IconButton>
              </Tooltip>
            </Box>
          </Box>

          {loading && <LinearProgress sx={{ mb: 2 }} />}

          {/* OS-Based Content Organization */}
          <Box>
            {Object.entries(groupedContent).map(([osFamily, versions]) => {
              const isExpanded = expandedGroups.includes(osFamily);
              const contentCount = Object.values(versions).flat().length;
              const hasUpdates = Object.values(versions).flat().some(c => c.update_available);

              return (
                <Card key={osFamily} variant="outlined" sx={{ mb: 2 }}>
                  <CardContent sx={{ pb: 1 }}>
                    <Box 
                      display="flex" 
                      alignItems="center" 
                      justifyContent="space-between"
                      sx={{ cursor: 'pointer' }}
                      onClick={() => toggleGroupExpansion(osFamily)}
                    >
                      <Box display="flex" alignItems="center" gap={2}>
                        <Box sx={{ fontSize: '1.5rem' }}>
                          {getOSIcon(osFamily)}
                        </Box>
                        <Box>
                          <Typography variant="h6" sx={{ textTransform: 'uppercase' }}>
                            {osFamily} Family
                          </Typography>
                          <Typography variant="body2" color="text.secondary">
                            {contentCount} content items, {Object.keys(versions).length} versions
                          </Typography>
                        </Box>
                      </Box>
                      <Box display="flex" alignItems="center" gap={1}>
                        {hasUpdates && (
                          <Badge badgeContent="!" color="warning">
                            <UpdateIcon color="warning" />
                          </Badge>
                        )}
                        {isExpanded ? <ExpandLessIcon /> : <ExpandMoreIcon />}
                      </Box>
                    </Box>

                    <Collapse in={isExpanded}>
                      <Box sx={{ mt: 2 }}>
                        {Object.entries(versions).map(([version, contents]) => (
                          <Box key={version} sx={{ mb: 2 }}>
                            <Typography variant="subtitle1" color="primary" sx={{ mb: 1 }}>
                              {osFamily.toUpperCase()} {version}
                            </Typography>
                            <List dense>
                              {contents.map((content) => (
                                <ListItem key={content.id} sx={{ pl: 0 }}>
                                  <ListItemIcon>
                                    <SecurityIcon color="action" />
                                  </ListItemIcon>
                                  <ListItemText
                                    primary={
                                      <Box display="flex" alignItems="center" gap={1}>
                                        <Typography variant="body2" fontWeight="medium">
                                          {content.name}
                                        </Typography>
                                        <Chip
                                          label={content.compliance_framework}
                                          size="small"
                                          color={getFrameworkColor(content.compliance_framework)}
                                        />
                                        <Chip
                                          label={content.status}
                                          size="small"
                                          color={getStatusColor(content.status)}
                                          variant="outlined"
                                        />
                                      </Box>
                                    }
                                    secondary={
                                      <Box>
                                        <Typography variant="caption" color="text.secondary">
                                          {content.description}
                                        </Typography>
                                        <br />
                                        <Typography variant="caption" color="text.secondary">
                                          {content.profiles.length} profiles • v{content.version} • 
                                          {content.source === 'repository' ? ' 🔄 Auto' : ' 📦 Manual'} • 
                                          {formatRelativeTime(content.uploaded_at)}
                                        </Typography>
                                      </Box>
                                    }
                                  />
                                  <ListItemSecondaryAction>
                                    <IconButton
                                      size="small"
                                      onClick={(e) => {
                                        setSelectedContent(content);
                                        setAnchorEl(e.currentTarget);
                                      }}
                                    >
                                      <MoreVertIcon />
                                    </IconButton>
                                  </ListItemSecondaryAction>
                                </ListItem>
                              ))}
                            </List>
                          </Box>
                        ))}
                      </Box>
                    </Collapse>
                  </CardContent>
                </Card>
              );
            })}

            {Object.keys(groupedContent).length === 0 && !loading && (
              <Paper sx={{ p: 4, textAlign: 'center', bgcolor: alpha(theme.palette.primary.main, 0.05) }}>
                <SecurityIcon sx={{ fontSize: 48, color: 'text.secondary', mb: 2 }} />
                <Typography variant="h6" color="text.secondary" gutterBottom>
                  No Content Available
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
                  {environmentInfo.type === 'connected' 
                    ? 'Sync with repositories or upload content to get started'
                    : 'Upload content files to get started'
                  }
                </Typography>
                <ButtonGroup>
                  <Button
                    variant="outlined"
                    startIcon={<UploadIcon />}
                    onClick={() => setUploadDialogOpen(true)}
                  >
                    Upload Content
                  </Button>
                  {environmentInfo.type === 'connected' && (
                    <Button
                      variant="contained"
                      startIcon={<CloudSyncIcon />}
                      onClick={handleSync}
                      disabled={syncing}
                    >
                      Sync Repository
                    </Button>
                  )}
                </ButtonGroup>
              </Paper>
            )}
          </Box>
        </CardContent>
      </Card>

      {/* Upload Dialog - Enhanced with OS Selection */}
      <Dialog 
        open={uploadDialogOpen} 
        onClose={() => setUploadDialogOpen(false)} 
        maxWidth="md" 
        fullWidth
      >
        <DialogTitle>Upload Content</DialogTitle>
        <DialogContent>
          <Box sx={{ pt: 1 }}>
            <input
              accept=".xml,.zip"
              style={{ display: 'none' }}
              id="file-upload"
              type="file"
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (file) {
                  setUploadFile(file);
                  setUploadName(file.name.replace(/\.[^/.]+$/, ""));
                }
              }}
            />
            <label htmlFor="file-upload">
              <Button
                variant="outlined"
                component="span"
                startIcon={<CloudUploadIcon />}
                fullWidth
                sx={{ mb: 2, py: 2 }}
              >
                {uploadFile ? uploadFile.name : 'Select Content File (XML or ZIP)'}
              </Button>
            </label>
            
            <Grid container spacing={2}>
              <Grid item xs={12} sm={6}>
                <TextField
                  fullWidth
                  label="Content Name"
                  value={uploadName}
                  onChange={(e) => setUploadName(e.target.value)}
                  required
                  helperText="Descriptive name for this content"
                />
              </Grid>
              <Grid item xs={12} sm={6}>
                <FormControl fullWidth>
                  <InputLabel>Operating System</InputLabel>
                  <Select
                    value={selectedOsFamily}
                    onChange={(e) => setSelectedOsFamily(e.target.value)}
                    label="Operating System"
                  >
                    <MenuItem value="rhel">Red Hat Enterprise Linux</MenuItem>
                    <MenuItem value="ubuntu">Ubuntu</MenuItem>
                    <MenuItem value="debian">Debian</MenuItem>
                    <MenuItem value="centos">CentOS</MenuItem>
                    <MenuItem value="suse">SUSE Linux</MenuItem>
                    <MenuItem value="windows">Windows</MenuItem>
                    <MenuItem value="other">Other</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
            </Grid>
            
            <TextField
              fullWidth
              label="Description"
              value={uploadDescription}
              onChange={(e) => setUploadDescription(e.target.value)}
              margin="normal"
              multiline
              rows={3}
              helperText="Optional description and version information"
            />
            
            {uploading && (
              <Box sx={{ mt: 2 }}>
                <LinearProgress variant="indeterminate" />
                <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                  Uploading and validating content...
                </Typography>
              </Box>
            )}
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setUploadDialogOpen(false)} disabled={uploading}>
            Cancel
          </Button>
          <Button 
            onClick={async () => {
              if (!uploadFile || !uploadName.trim()) {
                showSnackbar('Please select a file and provide a name', 'error');
                return;
              }

              try {
                setUploading(true);

                const formData = new FormData();
                formData.append('file', uploadFile);
                formData.append('name', uploadName.trim());
                formData.append('description', uploadDescription.trim());

                const response = await fetch('/api/scap-content/upload', {
                  method: 'POST',
                  headers: {
                    'Authorization': 'Bearer demo-token'
                  },
                  body: formData
                });

                if (response.ok) {
                  const result = await response.json();
                  showSnackbar(`Content uploaded successfully. Found ${result.profiles?.length || 0} profiles.`, 'success');
                  setUploadDialogOpen(false);
                  setUploadFile(null);
                  setUploadName('');
                  setUploadDescription('');
                  fetchScapContent();
                } else {
                  const error = await response.json();
                  showSnackbar(error.detail || 'Upload failed', 'error');
                }
              } catch (error) {
                showSnackbar('Network error during upload', 'error');
              } finally {
                setUploading(false);
              }
            }} 
            variant="contained" 
            disabled={uploading || !uploadFile}
          >
            Upload
          </Button>
        </DialogActions>
      </Dialog>

      {/* Repository Configuration Dialog */}
      <Dialog
        open={repositoryDialogOpen}
        onClose={() => setRepositoryDialogOpen(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>Repository Configuration</DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Configure content repositories for automatic updates
          </Typography>
          
          <List>
            {environmentInfo.repositories.map((repo) => (
              <ListItem key={repo.id}>
                <ListItemIcon>
                  <StorageIcon color={repo.enabled ? 'primary' : 'disabled'} />
                </ListItemIcon>
                <ListItemText
                  primary={repo.name}
                  secondary={
                    <Box>
                      <Typography variant="caption" color="text.secondary">
                        {repo.url || 'Local repository'}
                      </Typography>
                      <br />
                      <Chip
                        label={repo.status}
                        size="small"
                        color={repo.status === 'healthy' ? 'success' : 'error'}
                        sx={{ mr: 1 }}
                      />
                      <Typography variant="caption" color="text.secondary">
                        Last sync: {repo.lastSync ? formatRelativeTime(repo.lastSync) : 'Never'}
                      </Typography>
                    </Box>
                  }
                />
                <ListItemSecondaryAction>
                  <Switch
                    checked={repo.enabled}
                    disabled={environmentInfo.type === 'air-gapped'}
                  />
                </ListItemSecondaryAction>
              </ListItem>
            ))}
          </List>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setRepositoryDialogOpen(false)}>
            Close
          </Button>
          <Button variant="contained">
            Save Changes
          </Button>
        </DialogActions>
      </Dialog>

      {/* Context Menu */}
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={() => setAnchorEl(null)}
      >
        <MenuItem onClick={() => {
          console.log('Download clicked for:', selectedContent);
          if (selectedContent) {
            handleDownload(selectedContent);
          }
          setAnchorEl(null);
        }}>
          <DownloadIcon sx={{ mr: 2 }} />
          Download
        </MenuItem>
        <MenuItem onClick={() => {
          console.log('View Details clicked for:', selectedContent);
          setDetailsDialogOpen(true);
          setAnchorEl(null);
        }}>
          <InfoIcon sx={{ mr: 2 }} />
          View Details
        </MenuItem>
        <Divider />
        <MenuItem onClick={() => {
          console.log('Delete clicked for:', selectedContent);
          setDeleteDialogOpen(true);
          setAnchorEl(null);
        }} sx={{ color: 'error.main' }}>
          <DeleteIcon sx={{ mr: 2 }} />
          Delete
        </MenuItem>
      </Menu>

      {/* View Details Dialog */}
      <Dialog
        open={detailsDialogOpen}
        onClose={() => setDetailsDialogOpen(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>
          <Box display="flex" alignItems="center" gap={1}>
            <InfoIcon color="primary" />
            Content Details
          </Box>
        </DialogTitle>
        <DialogContent>
          {selectedContent && (
            <Box>
              <Grid container spacing={2} sx={{ mb: 3 }}>
                <Grid item xs={12} sm={6}>
                  <Typography variant="subtitle2" color="text.secondary">Name</Typography>
                  <Typography variant="body1" fontWeight="medium">{selectedContent.name}</Typography>
                </Grid>
                <Grid item xs={12} sm={6}>
                  <Typography variant="subtitle2" color="text.secondary">Version</Typography>
                  <Typography variant="body1">{selectedContent.version}</Typography>
                </Grid>
                <Grid item xs={12} sm={6}>
                  <Typography variant="subtitle2" color="text.secondary">Operating System</Typography>
                  <Typography variant="body1">
                    {selectedContent.os_family.toUpperCase()} {selectedContent.os_version}
                  </Typography>
                </Grid>
                <Grid item xs={12} sm={6}>
                  <Typography variant="subtitle2" color="text.secondary">Content Type</Typography>
                  <Typography variant="body1">{selectedContent.content_type}</Typography>
                </Grid>
                <Grid item xs={12} sm={6}>
                  <Typography variant="subtitle2" color="text.secondary">Framework</Typography>
                  <Chip
                    label={selectedContent.compliance_framework}
                    color={getFrameworkColor(selectedContent.compliance_framework)}
                    size="small"
                  />
                </Grid>
                <Grid item xs={12} sm={6}>
                  <Typography variant="subtitle2" color="text.secondary">Status</Typography>
                  <Chip
                    label={selectedContent.status}
                    color={getStatusColor(selectedContent.status)}
                    size="small"
                  />
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="subtitle2" color="text.secondary">Description</Typography>
                  <Typography variant="body1">{selectedContent.description}</Typography>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="subtitle2" color="text.secondary">Filename</Typography>
                  <Typography variant="body1" sx={{ fontFamily: 'monospace' }}>
                    {selectedContent.filename}
                  </Typography>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="subtitle2" color="text.secondary">Uploaded</Typography>
                  <Typography variant="body1">
                    {new Date(selectedContent.uploaded_at).toLocaleString()} ({formatRelativeTime(selectedContent.uploaded_at)})
                  </Typography>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="subtitle2" color="text.secondary">Source</Typography>
                  <Typography variant="body1">
                    {selectedContent.source === 'repository' ? '🔄 Repository' : '📦 Manual Upload'}
                  </Typography>
                </Grid>
              </Grid>

              <Divider sx={{ mb: 2 }} />

              <Typography variant="h6" gutterBottom>
                Profiles ({selectedContent.profiles.length})
              </Typography>
              <List dense>
                {selectedContent.profiles.map((profile) => (
                  <ListItem key={profile.id}>
                    <ListItemIcon>
                      <SecurityIcon color="action" />
                    </ListItemIcon>
                    <ListItemText
                      primary={profile.title}
                      secondary={profile.description}
                    />
                  </ListItem>
                ))}
              </List>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDetailsDialogOpen(false)}>
            Close
          </Button>
          <Button 
            variant="contained" 
            startIcon={<DownloadIcon />}
            onClick={() => {
              if (selectedContent) {
                handleDownload(selectedContent);
                setDetailsDialogOpen(false);
              }
            }}
          >
            Download
          </Button>
        </DialogActions>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <Dialog
        open={deleteDialogOpen}
        onClose={() => setDeleteDialogOpen(false)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>Confirm Deletion</DialogTitle>
        <DialogContent>
          <Alert severity="warning" sx={{ mb: 2 }}>
            This action cannot be undone. Deleting content will also remove all associated scan results.
          </Alert>
          {selectedContent && (
            <Box>
              <Typography variant="body1">
                Are you sure you want to delete the following content?
              </Typography>
              <Box sx={{ mt: 2, p: 2, bgcolor: 'grey.100', borderRadius: 1 }}>
                <Typography variant="subtitle1" fontWeight="medium">
                  {selectedContent.name}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {selectedContent.filename} • Version {selectedContent.version}
                </Typography>
              </Box>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteDialogOpen(false)}>
            Cancel
          </Button>
          <Button 
            variant="contained" 
            color="error"
            startIcon={<DeleteIcon />}
            onClick={handleDelete}
          >
            Delete
          </Button>
        </DialogActions>
      </Dialog>

      {/* Snackbar */}
      <Snackbar
        open={snackbar.open}
        autoHideDuration={6000}
        onClose={() => setSnackbar({ ...snackbar, open: false })}
      >
        <Alert 
          onClose={() => setSnackbar({ ...snackbar, open: false })} 
          severity={snackbar.severity}
          sx={{ width: '100%' }}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Container>
  );
};

export default ScapContentEnhanced;