import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Alert,
  AlertTitle,
  FormControlLabel,
  Checkbox,
  Chip,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Card,
  CardContent,
} from '@mui/material';
import Grid from '@mui/material/Grid';
import {
  ArrowBack as BackIcon,
  PlayArrow as ImportIcon,
  Preview as PreviewIcon,
  CheckCircle as SuccessIcon,
  Warning as WarningIcon,
  ExpandMore as ExpandMoreIcon,
  Info as InfoIcon,
} from '@mui/icons-material';

interface DataPreviewProps {
  csvData: string;
  fieldMappings: FieldMapping[];
  analysis: CSVAnalysis | null;
  onImport: (
    mappings: FieldMapping[],
    options: { updateExisting: boolean; dryRun: boolean }
  ) => void;
  onBack: () => void;
  importing: boolean;
  importResult: ImportResult | null;
  updateExisting: boolean;
  setUpdateExisting: (value: boolean) => void;
  dryRun: boolean;
  setDryRun: (value: boolean) => void;
}

interface FieldMapping {
  source_column: string;
  target_field: string;
  transform_function?: string;
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

interface ImportResult {
  total_processed: number;
  successful_imports: number;
  failed_imports: number;
  skipped_duplicates: number;
  errors: Array<{
    row: number;
    hostname: string;
    error: string;
    action?: string;
  }>;
  imported_hosts: Array<{
    hostname: string;
    ip_address: string;
    action: string;
  }>;
}

const DataPreview: React.FC<DataPreviewProps> = ({
  csvData,
  fieldMappings,
  analysis,
  onImport,
  onBack,
  importing,
  importResult,
  updateExisting,
  setUpdateExisting,
  dryRun,
  setDryRun,
}) => {
  // CSV rows mapped to target host fields (field names as keys, CSV values as values)
  const [previewData, setPreviewData] = useState<Record<string, string | number>[]>([]);
  const [showErrors, setShowErrors] = useState(true);
  const [validationWarnings, setValidationWarnings] = useState<string[]>([]);

  // Generate preview when CSV data or field mappings change
  // ESLint disable: generatePreview function is not memoized to avoid complex dependency chain
  useEffect(() => {
    generatePreview();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [csvData, fieldMappings]);

  const generatePreview = () => {
    try {
      // Parse CSV data
      const lines = csvData.trim().split('\n');
      const headers = lines[0].split(',').map((h) => h.trim().replace(/"/g, ''));

      // Create field mapping lookup
      const fieldMap = fieldMappings.reduce(
        (acc, mapping) => {
          acc[mapping.source_column] = mapping.target_field;
          return acc;
        },
        {} as Record<string, string>
      );

      // Process first 5 rows for preview
      const preview = [];
      const warnings = [];

      for (let i = 1; i < Math.min(6, lines.length); i++) {
        const values = lines[i].split(',').map((v) => v.trim().replace(/"/g, ''));
        // Mapped row - dynamically built from CSV using field mappings
        const mappedRow: Record<string, string | number> = {};

        // Apply field mappings
        headers.forEach((header, index) => {
          const targetField = fieldMap[header];
          if (targetField && values[index]) {
            mappedRow[targetField] = values[index];
          }
        });

        // Apply defaults
        if (!mappedRow.environment) mappedRow.environment = 'production';
        if (!mappedRow.port) mappedRow.port = 22;
        if (!mappedRow.auth_method) mappedRow.auth_method = 'ssh_key';
        if (!mappedRow.display_name && mappedRow.hostname) {
          mappedRow.display_name = mappedRow.hostname;
        }

        // Validate required fields
        if (!mappedRow.hostname) {
          warnings.push(`Row ${i}: Missing hostname`);
        }
        if (!mappedRow.ip_address) {
          warnings.push(`Row ${i}: Missing IP address`);
        }

        preview.push({ ...mappedRow, _row: i });
      }

      setPreviewData(preview);
      setValidationWarnings(warnings);
    } catch (error) {
      console.error('Preview generation error:', error);
      setValidationWarnings(['Failed to generate preview']);
    }
  };

  const handleImport = () => {
    onImport(fieldMappings, { updateExisting, dryRun });
  };

  const getMappedFields = () => {
    return fieldMappings.map((m) => m.target_field);
  };

  const getUnmappedRequiredFields = () => {
    const mapped = getMappedFields();
    const required = ['hostname', 'ip_address'];
    return required.filter((field) => !mapped.includes(field));
  };

  if (importResult) {
    return (
      <Box>
        <Box display="flex" alignItems="center" gap={2} mb={3}>
          <PreviewIcon color="primary" />
          <Typography variant="h6">{dryRun ? 'Validation Complete' : 'Import Complete'}</Typography>
        </Box>

        <Alert severity={importResult.failed_imports > 0 ? 'warning' : 'success'} sx={{ mb: 3 }}>
          <AlertTitle>{dryRun ? 'Validation Results' : 'Import Results'}</AlertTitle>
          <Grid container spacing={2}>
            <Grid size={{ xs: 6, sm: 3 }}>
              <Typography variant="body2">
                <strong>Total Processed:</strong> {importResult.total_processed}
              </Typography>
            </Grid>
            <Grid size={{ xs: 6, sm: 3 }}>
              <Typography variant="body2">
                <strong>Successful:</strong> {importResult.successful_imports}
              </Typography>
            </Grid>
            {importResult.failed_imports > 0 && (
              <Grid size={{ xs: 6, sm: 3 }}>
                <Typography variant="body2">
                  <strong>Failed:</strong> {importResult.failed_imports}
                </Typography>
              </Grid>
            )}
            {importResult.skipped_duplicates > 0 && (
              <Grid size={{ xs: 6, sm: 3 }}>
                <Typography variant="body2">
                  <strong>Skipped:</strong> {importResult.skipped_duplicates}
                </Typography>
              </Grid>
            )}
          </Grid>
        </Alert>

        {importResult.errors.length > 0 && (
          <Accordion sx={{ mb: 2 }}>
            <AccordionSummary
              expandIcon={<ExpandMoreIcon />}
              onClick={() => setShowErrors(!showErrors)}
            >
              <Typography variant="h6">Errors ({importResult.errors.length})</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <TableContainer component={Paper} variant="outlined">
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Row</TableCell>
                      <TableCell>Hostname</TableCell>
                      <TableCell>Error</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {importResult.errors.map((error, index) => (
                      <TableRow key={index}>
                        <TableCell>{error.row}</TableCell>
                        <TableCell>{error.hostname}</TableCell>
                        <TableCell>
                          <Typography variant="body2" color="error">
                            {error.error}
                          </Typography>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </AccordionDetails>
          </Accordion>
        )}

        {importResult.imported_hosts.length > 0 && (
          <Accordion defaultExpanded>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography variant="h6">
                {dryRun ? 'Would Import' : 'Imported Hosts'} ({importResult.imported_hosts.length})
              </Typography>
            </AccordionSummary>
            <AccordionDetails>
              <List dense>
                {importResult.imported_hosts.slice(0, 10).map((host, index) => (
                  <ListItem key={index}>
                    <ListItemIcon>
                      <SuccessIcon color="success" fontSize="small" />
                    </ListItemIcon>
                    <ListItemText
                      primary={host.hostname}
                      secondary={`${host.ip_address} - ${host.action}`}
                    />
                  </ListItem>
                ))}
                {importResult.imported_hosts.length > 10 && (
                  <ListItem>
                    <ListItemText
                      secondary={`... and ${importResult.imported_hosts.length - 10} more`}
                    />
                  </ListItem>
                )}
              </List>
            </AccordionDetails>
          </Accordion>
        )}

        {dryRun && importResult.failed_imports === 0 && (
          <Box sx={{ mt: 3, display: 'flex', justifyContent: 'center' }}>
            <Button
              variant="contained"
              color="primary"
              onClick={() => {
                setDryRun(false);
                handleImport();
              }}
              startIcon={<ImportIcon />}
              size="large"
            >
              Proceed with Actual Import
            </Button>
          </Box>
        )}
      </Box>
    );
  }

  return (
    <Box>
      <Box display="flex" alignItems="center" gap={2} mb={3}>
        <PreviewIcon color="primary" />
        <Typography variant="h6">Data Preview & Import</Typography>
      </Box>

      {validationWarnings.length > 0 && (
        <Alert severity="warning" sx={{ mb: 3 }}>
          <AlertTitle>Validation Warnings</AlertTitle>
          <List dense>
            {validationWarnings.map((warning, index) => (
              <ListItem key={index}>
                <ListItemIcon>
                  <WarningIcon fontSize="small" />
                </ListItemIcon>
                <ListItemText primary={warning} />
              </ListItem>
            ))}
          </List>
        </Alert>
      )}

      {/* Import Options */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Import Options
          </Typography>
          <Box>
            <FormControlLabel
              control={
                <Checkbox
                  checked={updateExisting}
                  onChange={(e) => setUpdateExisting(e.target.checked)}
                />
              }
              label="Update existing hosts instead of skipping duplicates"
            />
            <FormControlLabel
              control={<Checkbox checked={dryRun} onChange={(e) => setDryRun(e.target.checked)} />}
              label="Dry run (validate data without importing)"
            />
          </Box>
        </CardContent>
      </Card>

      {/* Preview Table */}
      <Accordion defaultExpanded sx={{ mb: 3 }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography variant="h6">
            Data Preview (first 5 rows of {analysis?.total_rows || 0})
          </Typography>
        </AccordionSummary>
        <AccordionDetails>
          <TableContainer component={Paper} variant="outlined">
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Row</TableCell>
                  {getMappedFields().map((field) => (
                    <TableCell key={field}>
                      <Box display="flex" alignItems="center" gap={1}>
                        {field.replace('_', ' ')}
                        {['hostname', 'ip_address'].includes(field) && (
                          <Chip label="Required" size="small" color="error" />
                        )}
                      </Box>
                    </TableCell>
                  ))}
                </TableRow>
              </TableHead>
              <TableBody>
                {previewData.map((row, index) => (
                  <TableRow key={index}>
                    <TableCell>{row._row}</TableCell>
                    {getMappedFields().map((field) => (
                      <TableCell key={field}>
                        <Typography
                          variant="body2"
                          sx={{
                            fontFamily: 'monospace',
                            color: row[field] ? 'text.primary' : 'text.secondary',
                          }}
                        >
                          {row[field] || <em>default</em>}
                        </Typography>
                      </TableCell>
                    ))}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </AccordionDetails>
      </Accordion>

      {/* Field Mapping Summary */}
      <Accordion sx={{ mb: 3 }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography variant="h6">Applied Mappings ({fieldMappings.length})</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <List dense>
            {fieldMappings.map((mapping, index) => (
              <ListItem key={index}>
                <ListItemIcon>
                  <InfoIcon fontSize="small" color="primary" />
                </ListItemIcon>
                <ListItemText
                  primary={`${mapping.source_column} → ${mapping.target_field}`}
                  secondary={`Maps CSV column to SecureOps field`}
                />
              </ListItem>
            ))}
          </List>
        </AccordionDetails>
      </Accordion>

      {/* Navigation */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Button variant="outlined" startIcon={<BackIcon />} onClick={onBack} disabled={importing}>
          Back to Mapping
        </Button>

        <Box display="flex" gap={2}>
          {!dryRun && (
            <Button
              variant="outlined"
              onClick={() => {
                setDryRun(true);
                handleImport();
              }}
              disabled={importing || getUnmappedRequiredFields().length > 0}
            >
              Validate First
            </Button>
          )}

          <Button
            variant="contained"
            onClick={handleImport}
            disabled={importing || getUnmappedRequiredFields().length > 0}
            startIcon={<ImportIcon />}
            size="large"
          >
            {dryRun ? 'Validate Data' : 'Import Hosts'} ({analysis?.total_rows || 0} rows)
          </Button>
        </Box>
      </Box>

      {getUnmappedRequiredFields().length > 0 && (
        <Alert severity="error" sx={{ mt: 2 }}>
          Required fields not mapped: {getUnmappedRequiredFields().join(', ')}
        </Alert>
      )}
    </Box>
  );
};

export default DataPreview;
