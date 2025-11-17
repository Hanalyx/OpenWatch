import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Button,
  Grid,
  Card,
  CardContent,
  FormControl,
  Select,
  MenuItem,
  Chip,
  Alert,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  IconButton,
} from '@mui/material';
import {
  ArrowForward as ArrowIcon,
  CheckCircle as CheckIcon,
  ArrowBack as BackIcon,
  ExpandMore as ExpandMoreIcon,
  Clear as ClearIcon,
  AutoFixHigh as AutoIcon,
} from '@mui/icons-material';

interface FieldMapperProps {
  analysis: CSVAnalysis | null;
  initialMappings: FieldMapping[];
  onMappingComplete: (mappings: FieldMapping[]) => void;
  onBack: () => void;
}

interface CSVAnalysis {
  total_rows: number;
  total_columns: number;
  headers: string[];
  field_analyses: FieldAnalysis[];
  auto_mappings: Record<string, string>;
  template_matches: string[];
}

interface FieldAnalysis {
  column_name: string;
  detected_type: string;
  confidence: number;
  sample_values: string[];
  unique_count: number;
  null_count: number;
  suggestions: string[];
}

interface FieldMapping {
  source_column: string;
  target_field: string;
  transform_function?: string;
}

const TARGET_FIELDS = [
  { value: 'hostname', label: 'Hostname', required: true, description: 'System hostname or name' },
  { value: 'ip_address', label: 'IP Address', required: true, description: 'IPv4 or IPv6 address' },
  {
    value: 'display_name',
    label: 'Display Name',
    required: false,
    description: 'Friendly display name',
  },
  {
    value: 'operating_system',
    label: 'Operating System',
    required: false,
    description: 'OS type (RHEL, CentOS, etc.)',
  },
  {
    value: 'port',
    label: 'SSH Port',
    required: false,
    description: 'SSH connection port (default: 22)',
  },
  { value: 'username', label: 'Username', required: false, description: 'SSH username' },
  {
    value: 'auth_method',
    label: 'Auth Method',
    required: false,
    description: 'Authentication method',
  },
  {
    value: 'environment',
    label: 'Environment',
    required: false,
    description: 'Environment (prod, staging, dev)',
  },
  { value: 'tags', label: 'Tags', required: false, description: 'Comma-separated tags' },
  { value: 'owner', label: 'Owner', required: false, description: 'Responsible person or team' },
];

const FieldMapper: React.FC<FieldMapperProps> = ({
  analysis,
  initialMappings,
  onMappingComplete,
  onBack,
}) => {
  const [mappings, setMappings] = useState<FieldMapping[]>(initialMappings);
  const [hoveredTarget, setHoveredTarget] = useState<string | null>(null);

  useEffect(() => {
    setMappings(initialMappings);
  }, [initialMappings]);

  const handleMappingChange = (sourceColumn: string, targetField: string) => {
    setMappings((prev) => {
      // Remove any existing mapping for this source column
      const filtered = prev.filter((m) => m.source_column !== sourceColumn);

      // Add new mapping if target is not empty
      if (targetField) {
        // Also remove any existing mapping to this target field
        const finalFiltered = filtered.filter((m) => m.target_field !== targetField);
        return [...finalFiltered, { source_column: sourceColumn, target_field: targetField }];
      }

      return filtered;
    });
  };

  const clearMapping = (sourceColumn: string) => {
    setMappings((prev) => prev.filter((m) => m.source_column !== sourceColumn));
  };

  const applyAutoMappings = () => {
    if (!analysis) return;

    const autoMappings: FieldMapping[] = Object.entries(analysis.auto_mappings).map(
      ([source, target]) => ({
        source_column: source,
        target_field: target,
      })
    );
    setMappings(autoMappings);
  };

  const clearAllMappings = () => {
    setMappings([]);
  };

  const getMappedTargets = () => {
    return new Set(mappings.map((m) => m.target_field));
  };

  const getMappingForColumn = (columnName: string) => {
    return mappings.find((m) => m.source_column === columnName);
  };

  const getFieldAnalysis = (columnName: string) => {
    return analysis?.field_analyses.find((f) => f.column_name === columnName);
  };

  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 0.8) return 'success';
    if (confidence >= 0.5) return 'warning';
    return 'error';
  };

  const requiredFieldsMapped = () => {
    const mappedTargets = getMappedTargets();
    return TARGET_FIELDS.filter((f) => f.required).every((f) => mappedTargets.has(f.value));
  };

  const handleContinue = () => {
    onMappingComplete(mappings);
  };

  if (!analysis) {
    return <Alert severity="error">No analysis data available</Alert>;
  }

  return (
    <Box>
      <Box display="flex" alignItems="center" justifyContent="space-between" mb={3}>
        <Box display="flex" alignItems="center" gap={2}>
          <SettingsIcon color="primary" />
          <Typography variant="h6">Field Mapping</Typography>
        </Box>

        <Box display="flex" gap={1}>
          <Button
            variant="outlined"
            size="small"
            startIcon={<AutoIcon />}
            onClick={applyAutoMappings}
          >
            Apply Auto-Mapping
          </Button>
          <Button
            variant="outlined"
            size="small"
            startIcon={<ClearIcon />}
            onClick={clearAllMappings}
          >
            Clear All
          </Button>
        </Box>
      </Box>

      <Alert severity="info" sx={{ mb: 3 }}>
        Map your CSV columns to SecureOps fields. Required fields (hostname and IP address) must be
        mapped to proceed.
      </Alert>

      <Grid container spacing={3}>
        {/* Source Columns */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Your CSV Columns ({analysis.headers.length})
              </Typography>

              <List dense>
                {analysis.headers.map((header, index) => {
                  const fieldAnalysis = getFieldAnalysis(header);
                  const mapping = getMappingForColumn(header);

                  return (
                    <ListItem key={index}>
                      <Box sx={{ width: '100%' }}>
                        <Box
                          display="flex"
                          alignItems="center"
                          justifyContent="space-between"
                          mb={1}
                        >
                          <Typography variant="body2" fontWeight="medium">
                            {header}
                          </Typography>
                          {mapping && (
                            <IconButton
                              size="small"
                              onClick={() => clearMapping(header)}
                              sx={{ ml: 1 }}
                            >
                              <ClearIcon fontSize="small" />
                            </IconButton>
                          )}
                        </Box>

                        {fieldAnalysis && (
                          <Box display="flex" alignItems="center" gap={1} mb={1}>
                            <Chip
                              label={fieldAnalysis.detected_type.replace('_', ' ')}
                              size="small"
                              color={getConfidenceColor(fieldAnalysis.confidence)}
                            />
                            <Typography variant="caption" color="text.secondary">
                              {Math.round(fieldAnalysis.confidence * 100)}% confidence
                            </Typography>
                          </Box>
                        )}

                        <FormControl fullWidth size="small">
                          <Select
                            value={mapping?.target_field || ''}
                            onChange={(e) => handleMappingChange(header, e.target.value)}
                            displayEmpty
                          >
                            <MenuItem value="">
                              <em>Not mapped</em>
                            </MenuItem>
                            {TARGET_FIELDS.map((field) => {
                              const isAlreadyMapped =
                                getMappedTargets().has(field.value) &&
                                mapping?.target_field !== field.value;
                              return (
                                <MenuItem
                                  key={field.value}
                                  value={field.value}
                                  disabled={isAlreadyMapped}
                                >
                                  <Box display="flex" alignItems="center" gap={1}>
                                    {field.label}
                                    {field.required && (
                                      <Chip label="Required" size="small" color="error" />
                                    )}
                                    {isAlreadyMapped && <Chip label="Mapped" size="small" />}
                                  </Box>
                                </MenuItem>
                              );
                            })}
                          </Select>
                        </FormControl>

                        {fieldAnalysis && fieldAnalysis.sample_values.length > 0 && (
                          <Typography
                            variant="caption"
                            color="text.secondary"
                            sx={{ mt: 0.5, display: 'block' }}
                          >
                            Sample: {fieldAnalysis.sample_values.slice(0, 2).join(', ')}
                          </Typography>
                        )}
                      </Box>
                    </ListItem>
                  );
                })}
              </List>
            </CardContent>
          </Card>
        </Grid>

        {/* Target Fields */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                SecureOps Fields
              </Typography>

              <List dense>
                {TARGET_FIELDS.map((field) => {
                  const isAlreadyMapped = getMappedTargets().has(field.value);
                  const mappingForField = mappings.find((m) => m.target_field === field.value);

                  return (
                    <ListItem key={field.value}>
                      <Box sx={{ width: '100%' }}>
                        <Box display="flex" alignItems="center" justifyContent="between" mb={1}>
                          <Box display="flex" alignItems="center" gap={1}>
                            <Typography variant="body2" fontWeight="medium">
                              {field.label}
                            </Typography>
                            {field.required && <Chip label="Required" size="small" color="error" />}
                          </Box>

                          {isAlreadyMapped && (
                            <Box display="flex" alignItems="center" gap={1}>
                              <ArrowIcon color="success" fontSize="small" />
                              <Chip
                                label={mappingForField?.source_column}
                                size="small"
                                color="success"
                                variant="outlined"
                              />
                            </Box>
                          )}
                        </Box>

                        <Typography variant="caption" color="text.secondary">
                          {field.description}
                        </Typography>
                      </Box>
                    </ListItem>
                  );
                })}
              </List>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Mapping Summary */}
      <Accordion sx={{ mt: 3 }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography variant="h6">Mapping Summary ({mappings.length} mapped)</Typography>
        </AccordionSummary>
        <AccordionDetails>
          {mappings.length > 0 ? (
            <List dense>
              {mappings.map((mapping, index) => {
                const targetField = TARGET_FIELDS.find((f) => f.value === mapping.target_field);
                return (
                  <ListItem key={index}>
                    <ListItemIcon>
                      <ArrowIcon color="success" />
                    </ListItemIcon>
                    <ListItemText
                      primary={
                        <Box display="flex" alignItems="center" gap={1}>
                          <Typography variant="body2" fontWeight="medium">
                            {mapping.source_column}
                          </Typography>
                          <ArrowIcon fontSize="small" />
                          <Typography variant="body2" color="primary">
                            {targetField?.label}
                          </Typography>
                        </Box>
                      }
                      secondary={targetField?.description}
                    />
                  </ListItem>
                );
              })}
            </List>
          ) : (
            <Typography color="text.secondary">No fields mapped yet</Typography>
          )}
        </AccordionDetails>
      </Accordion>

      {/* Validation Status */}
      {!requiredFieldsMapped() && (
        <Alert severity="warning" sx={{ mt: 2 }}>
          Please map the required fields (hostname and IP address) to continue.
        </Alert>
      )}

      {/* Navigation */}
      <Box sx={{ mt: 3, display: 'flex', justifyContent: 'space-between' }}>
        <Button variant="outlined" startIcon={<BackIcon />} onClick={onBack}>
          Back to Analysis
        </Button>

        <Button
          variant="contained"
          onClick={handleContinue}
          disabled={!requiredFieldsMapped()}
          startIcon={<CheckIcon />}
          size="large"
        >
          Continue to Preview ({mappings.length} fields mapped)
        </Button>
      </Box>
    </Box>
  );
};

export default FieldMapper;
