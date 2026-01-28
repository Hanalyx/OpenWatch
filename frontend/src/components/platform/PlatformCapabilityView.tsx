import React, { useState, useCallback } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Button,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Chip,
  Stack,
  Paper,
  LinearProgress,
  Alert,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  IconButton,
  Tooltip,
  useTheme,
  alpha,
  CircularProgress,
  Badge,
} from '@mui/material';
import Grid from '@mui/material/GridLegacy';
import {
  Computer as ComputerIcon,
  Storage as StorageIcon,
  Security as SecurityIcon,
  Build as BuildIcon,
  CheckCircle as CheckIcon,
  Cancel as CancelIcon,
  Warning as WarningIcon,
  Refresh as RefreshIcon,
  ExpandMore as ExpandMoreIcon,
  Search as SearchIcon,
  Assessment as AssessmentIcon,
} from '@mui/icons-material';
import { ruleService } from '../../services/ruleService';
import { type PlatformCapability } from '../../store/slices/ruleSlice';

interface PlatformCapabilityViewProps {
  onRuleFilterChange?: (platform: string, capabilities: string[]) => void;
}

interface DetectionResult {
  platform: string;
  version: string;
  capabilities: PlatformCapability | null;
  timestamp: string;
  isLoading: boolean;
  error: string | null;
}

interface CapabilityFilter {
  search: string;
  status: 'all' | 'detected' | 'missing' | 'matched';
  category: string;
}

/**
 * Individual capability item (package, service, etc.)
 * Represents a detected platform capability with its state
 */
interface CapabilityItem {
  installed?: boolean;
  enabled?: boolean;
  state?: string;
  version?: string;
}

/**
 * Category data structure from PlatformCapability results
 * Groups related capabilities (packages, services, etc.)
 */
interface CategoryData {
  detected: boolean;
  results: Record<string, CapabilityItem>;
}

const PlatformCapabilityView: React.FC<PlatformCapabilityViewProps> = ({ onRuleFilterChange }) => {
  const theme = useTheme();

  // Detection state
  const [targetHost, setTargetHost] = useState('localhost');
  const [selectedPlatform, setSelectedPlatform] = useState('rhel');
  const [selectedVersion, setSelectedVersion] = useState('8');
  const [detectionResults, setDetectionResults] = useState<DetectionResult[]>([]);
  const [isDetecting, setIsDetecting] = useState(false);

  // UI state
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set(['overview']));
  const [filter, setFilter] = useState<CapabilityFilter>({
    search: '',
    status: 'all',
    category: 'all',
  });

  // Available platforms and versions
  const platforms = [
    { id: 'rhel', name: 'Red Hat Enterprise Linux', versions: ['7', '8', '9'] },
    { id: 'ubuntu', name: 'Ubuntu', versions: ['18.04', '20.04', '22.04'] },
    { id: 'centos', name: 'CentOS', versions: ['7', '8'] },
    { id: 'debian', name: 'Debian', versions: ['10', '11', '12'] },
  ];

  const currentPlatform = platforms.find((p) => p.id === selectedPlatform);

  // Run platform capability detection
  const handleDetection = useCallback(async () => {
    setIsDetecting(true);

    const newResult: DetectionResult = {
      platform: selectedPlatform,
      version: selectedVersion,
      capabilities: null,
      timestamp: new Date().toISOString(),
      isLoading: true,
      error: null,
    };

    setDetectionResults((prev) => [newResult, ...prev.slice(0, 9)]); // Keep last 10 results

    try {
      const response = await ruleService.detectPlatformCapabilities({
        platform: selectedPlatform,
        platformVersion: selectedVersion,
        targetHost,
        compareBaseline: true,
        capabilityTypes: ['package', 'service', 'security', 'configuration'],
      });

      if (response.success) {
        setDetectionResults((prev) =>
          prev.map((result, index) =>
            index === 0
              ? {
                  ...result,
                  capabilities: response.data,
                  isLoading: false,
                }
              : result
          )
        );
      } else {
        throw new Error('Detection failed');
      }
    } catch {
      setDetectionResults((prev) =>
        prev.map((result, index) =>
          index === 0
            ? {
                ...result,
                isLoading: false,
                error: 'Failed to detect platform capabilities',
              }
            : result
        )
      );
    } finally {
      setIsDetecting(false);
    }
  }, [selectedPlatform, selectedVersion, targetHost]);

  // Toggle section expansion
  const toggleSection = (section: string) => {
    const newExpanded = new Set(expandedSections);
    if (newExpanded.has(section)) {
      newExpanded.delete(section);
    } else {
      newExpanded.add(section);
    }
    setExpandedSections(newExpanded);
  };

  // Get status icon and color
  const getStatusInfo = (detected: boolean, matched?: boolean) => {
    if (detected && matched) {
      return {
        icon: <CheckIcon />,
        color: theme.palette.success.main,
        label: 'Detected & Matched',
      };
    } else if (detected) {
      return { icon: <CheckIcon />, color: theme.palette.info.main, label: 'Detected' };
    } else if (matched === false) {
      return { icon: <CancelIcon />, color: theme.palette.error.main, label: 'Missing' };
    } else {
      return { icon: <WarningIcon />, color: theme.palette.warning.main, label: 'Unknown' };
    }
  };

  // Filter capabilities based on current filter
  const filterCapabilities = (capabilities: PlatformCapability) => {
    const { search, status, category } = filter;
    // Filtered results grouped by category (packages, services, etc.)
    const filtered: Record<string, CategoryData> = {};

    Object.entries(capabilities.capabilities).forEach(([categoryName, categoryData]) => {
      if (category !== 'all' && category !== categoryName) return;

      // Filtered capability items within this category
      const categoryResults: Record<string, CapabilityItem> = {};
      Object.entries(categoryData.results as Record<string, CapabilityItem>).forEach(
        ([itemName, itemData]) => {
          const matchesSearch = !search || itemName.toLowerCase().includes(search.toLowerCase());

          const matchesStatus =
            status === 'all' ||
            (status === 'detected' && itemData.installed) ||
            (status === 'missing' && !itemData.installed) ||
            (status === 'matched' && capabilities.baseline_comparison?.matched?.includes(itemName));

          if (matchesSearch && matchesStatus) {
            categoryResults[itemName] = itemData;
          }
        }
      );

      if (Object.keys(categoryResults).length > 0) {
        filtered[categoryName] = {
          ...categoryData,
          results: categoryResults,
        };
      }
    });

    return filtered;
  };

  // Render capability category
  const renderCapabilityCategory = (
    categoryName: string,
    categoryData: CategoryData,
    capabilities: PlatformCapability
  ) => {
    const items = Object.entries(categoryData.results);
    const detectedCount = items.filter(([_, data]) => data.installed || data.enabled).length;
    const matchedItems = capabilities.baseline_comparison?.matched || [];
    const missingItems = capabilities.baseline_comparison?.missing || [];

    return (
      <Accordion
        key={categoryName}
        expanded={expandedSections.has(categoryName)}
        onChange={() => toggleSection(categoryName)}
      >
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Box display="flex" alignItems="center" justifyContent="space-between" width="100%">
            <Box display="flex" alignItems="center" gap={2}>
              <Box sx={{ color: theme.palette.primary.main }}>
                {categoryName === 'package' && <StorageIcon />}
                {categoryName === 'service' && <BuildIcon />}
                {categoryName === 'security' && <SecurityIcon />}
                {categoryName === 'configuration' && <ComputerIcon />}
              </Box>
              <Typography variant="subtitle1" fontWeight="medium">
                {categoryName.charAt(0).toUpperCase() + categoryName.slice(1)}
              </Typography>
            </Box>

            <Box display="flex" alignItems="center" gap={1} onClick={(e) => e.stopPropagation()}>
              <Badge badgeContent={detectedCount} color="success">
                <Chip label={`${items.length} items`} size="small" />
              </Badge>
              {categoryData.detected && <CheckIcon fontSize="small" color="success" />}
            </Box>
          </Box>
        </AccordionSummary>

        <AccordionDetails>
          <List dense>
            {items.map(([itemName, itemData]) => {
              const isMatched = matchedItems.includes(itemName);
              const isMissing = missingItems.includes(itemName);
              const statusInfo = getStatusInfo(
                itemData.installed || itemData.enabled || itemData.state === 'enabled',
                isMatched ? true : isMissing ? false : undefined
              );

              return (
                <ListItem
                  key={itemName}
                  sx={{
                    borderRadius: 1,
                    mb: 0.5,
                    backgroundColor: isMatched
                      ? alpha(theme.palette.success.main, 0.05)
                      : isMissing
                        ? alpha(theme.palette.error.main, 0.05)
                        : 'transparent',
                  }}
                >
                  <ListItemIcon>
                    <Box sx={{ color: statusInfo.color }}>{statusInfo.icon}</Box>
                  </ListItemIcon>
                  <ListItemText
                    primary={
                      <Box display="flex" alignItems="center" gap={1}>
                        <Typography variant="body2" fontWeight="medium">
                          {itemName}
                        </Typography>
                        {itemData.version && (
                          <Chip label={itemData.version} size="small" variant="outlined" />
                        )}
                      </Box>
                    }
                    secondary={
                      <Box display="flex" alignItems="center" gap={1} mt={0.5}>
                        <Chip
                          label={statusInfo.label}
                          size="small"
                          sx={{
                            backgroundColor: alpha(statusInfo.color, 0.1),
                            color: statusInfo.color,
                          }}
                        />
                        {itemData.state && (
                          <Chip
                            label={`State: ${itemData.state}`}
                            size="small"
                            variant="outlined"
                          />
                        )}
                      </Box>
                    }
                  />

                  {onRuleFilterChange && (
                    <Tooltip title="Filter rules for this capability">
                      <IconButton
                        size="small"
                        onClick={() => onRuleFilterChange(selectedPlatform, [itemName])}
                      >
                        <SearchIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                  )}
                </ListItem>
              );
            })}
          </List>
        </AccordionDetails>
      </Accordion>
    );
  };

  // Render detection results overview
  const renderOverview = (result: DetectionResult) => {
    if (!result.capabilities) return null;

    const capabilities = result.capabilities;
    const baseline = capabilities.baseline_comparison;

    return (
      <Grid container spacing={2}>
        <Grid item xs={12} md={4}>
          <Card sx={{ textAlign: 'center' }}>
            <CardContent>
              <Typography variant="h4" color="success.main" gutterBottom>
                {baseline?.matched?.length || 0}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Baseline Matches
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={4}>
          <Card sx={{ textAlign: 'center' }}>
            <CardContent>
              <Typography variant="h4" color="error.main" gutterBottom>
                {baseline?.missing?.length || 0}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Missing Items
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={4}>
          <Card sx={{ textAlign: 'center' }}>
            <CardContent>
              <Typography variant="h4" color="primary.main" gutterBottom>
                {(baseline?.analysis?.baseline_coverage || 0 * 100).toFixed(0)}%
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Baseline Coverage
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Typography variant="subtitle2" gutterBottom>
                Platform Health Assessment
              </Typography>
              <Box display="flex" alignItems="center" gap={2}>
                <LinearProgress
                  variant="determinate"
                  value={(baseline?.analysis?.baseline_coverage || 0) * 100}
                  sx={{ flex: 1, height: 8, borderRadius: 4 }}
                  color={
                    (baseline?.analysis?.baseline_coverage || 0) > 0.8
                      ? 'success'
                      : (baseline?.analysis?.baseline_coverage || 0) > 0.6
                        ? 'warning'
                        : 'error'
                  }
                />
                <Chip
                  label={baseline?.analysis?.platform_health || 'unknown'}
                  color={
                    baseline?.analysis?.platform_health === 'good'
                      ? 'success'
                      : baseline?.analysis?.platform_health === 'fair'
                        ? 'warning'
                        : 'error'
                  }
                />
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    );
  };

  const latestResult = detectionResults[0];
  const filteredCapabilities = latestResult?.capabilities
    ? filterCapabilities(latestResult.capabilities)
    : {};

  return (
    <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      {/* Header and Detection Controls */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h5" gutterBottom display="flex" alignItems="center" gap={1}>
          <ComputerIcon color="primary" />
          Platform Capability Detection
        </Typography>
        <Typography variant="body2" color="text.secondary" paragraph>
          Detect platform-specific capabilities and compare against security baselines
        </Typography>

        <Grid container spacing={2} alignItems="end">
          <Grid item xs={12} sm={6} md={3}>
            <TextField
              label="Target Host"
              value={targetHost}
              onChange={(e) => setTargetHost(e.target.value)}
              fullWidth
              size="small"
            />
          </Grid>

          <Grid item xs={12} sm={6} md={3}>
            <FormControl fullWidth size="small">
              <InputLabel>Platform</InputLabel>
              <Select
                value={selectedPlatform}
                label="Platform"
                onChange={(e) => setSelectedPlatform(e.target.value)}
              >
                {platforms.map((platform) => (
                  <MenuItem key={platform.id} value={platform.id}>
                    {platform.name}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>

          <Grid item xs={12} sm={6} md={3}>
            <FormControl fullWidth size="small">
              <InputLabel>Version</InputLabel>
              <Select
                value={selectedVersion}
                label="Version"
                onChange={(e) => setSelectedVersion(e.target.value)}
              >
                {currentPlatform?.versions.map((version) => (
                  <MenuItem key={version} value={version}>
                    {version}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>

          <Grid item xs={12} sm={6} md={3}>
            <Button
              variant="contained"
              onClick={handleDetection}
              disabled={isDetecting}
              startIcon={isDetecting ? <CircularProgress size={16} /> : <RefreshIcon />}
              fullWidth
            >
              {isDetecting ? 'Detecting...' : 'Detect'}
            </Button>
          </Grid>
        </Grid>
      </Paper>

      {/* Results */}
      {detectionResults.length > 0 && (
        <Box flex={1}>
          {latestResult.error ? (
            <Alert severity="error" sx={{ mb: 2 }}>
              {latestResult.error}
              <Button size="small" onClick={handleDetection} sx={{ ml: 1 }}>
                Retry
              </Button>
            </Alert>
          ) : latestResult.isLoading ? (
            <Box display="flex" justifyContent="center" alignItems="center" minHeight={200}>
              <CircularProgress />
              <Typography variant="body2" sx={{ ml: 2 }}>
                Detecting platform capabilities...
              </Typography>
            </Box>
          ) : (
            latestResult.capabilities && (
              <Stack spacing={3}>
                {/* Overview */}
                <Card>
                  <CardContent>
                    <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
                      <Typography variant="h6">
                        Detection Results - {currentPlatform?.name} {selectedVersion}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {new Date(latestResult.timestamp).toLocaleString()}
                      </Typography>
                    </Box>
                    {renderOverview(latestResult)}
                  </CardContent>
                </Card>

                {/* Filters */}
                <Paper sx={{ p: 2 }}>
                  <Grid container spacing={2} alignItems="center">
                    <Grid item xs={12} sm={6} md={4}>
                      <TextField
                        label="Search capabilities"
                        value={filter.search}
                        onChange={(e) => setFilter((prev) => ({ ...prev, search: e.target.value }))}
                        size="small"
                        fullWidth
                      />
                    </Grid>

                    <Grid item xs={12} sm={3} md={2}>
                      <FormControl fullWidth size="small">
                        <InputLabel>Status</InputLabel>
                        <Select
                          value={filter.status}
                          label="Status"
                          onChange={(e) =>
                            setFilter((prev) => ({
                              ...prev,
                              status: e.target.value as CapabilityFilter['status'],
                            }))
                          }
                        >
                          <MenuItem value="all">All</MenuItem>
                          <MenuItem value="detected">Detected</MenuItem>
                          <MenuItem value="missing">Missing</MenuItem>
                          <MenuItem value="matched">Matched</MenuItem>
                        </Select>
                      </FormControl>
                    </Grid>

                    <Grid item xs={12} sm={3} md={2}>
                      <FormControl fullWidth size="small">
                        <InputLabel>Category</InputLabel>
                        <Select
                          value={filter.category}
                          label="Category"
                          onChange={(e) =>
                            setFilter((prev) => ({ ...prev, category: e.target.value }))
                          }
                        >
                          <MenuItem value="all">All</MenuItem>
                          <MenuItem value="package">Packages</MenuItem>
                          <MenuItem value="service">Services</MenuItem>
                          <MenuItem value="security">Security</MenuItem>
                          <MenuItem value="configuration">Config</MenuItem>
                        </Select>
                      </FormControl>
                    </Grid>
                  </Grid>
                </Paper>

                {/* Capability Details */}
                <Box>
                  {Object.keys(filteredCapabilities).length > 0 ? (
                    Object.entries(filteredCapabilities).map(([categoryName, categoryData]) =>
                      renderCapabilityCategory(
                        categoryName,
                        categoryData,
                        latestResult.capabilities!
                      )
                    )
                  ) : (
                    <Alert severity="info">No capabilities match the current filters.</Alert>
                  )}
                </Box>
              </Stack>
            )
          )}
        </Box>
      )}

      {detectionResults.length === 0 && (
        <Box
          display="flex"
          flexDirection="column"
          alignItems="center"
          justifyContent="center"
          flex={1}
          textAlign="center"
        >
          <AssessmentIcon sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />
          <Typography variant="h6" gutterBottom>
            Platform Capability Detection
          </Typography>
          <Typography variant="body2" color="text.secondary" paragraph>
            Detect and analyze platform-specific capabilities to optimize rule selection and ensure
            security baseline compliance.
          </Typography>
          <Button
            variant="contained"
            onClick={handleDetection}
            disabled={isDetecting}
            startIcon={<RefreshIcon />}
          >
            Run Detection
          </Button>
        </Box>
      )}
    </Box>
  );
};

export default PlatformCapabilityView;
