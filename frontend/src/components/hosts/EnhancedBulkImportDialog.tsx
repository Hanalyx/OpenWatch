import React, { useState, useCallback, useEffect } from 'react';
import { storageGet, StorageKeys } from '../../services/storage';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Box,
  Typography,
  Stepper,
  Step,
  StepLabel,
  IconButton,
  Alert,
  LinearProgress,
} from '@mui/material';
import {
  Close as CloseIcon,
  CloudUpload as UploadIcon,
  Settings as MappingIcon,
  Preview as PreviewIcon,
  Check as CheckIcon,
} from '@mui/icons-material';

import CSVAnalyzer from './CSVAnalyzer';
import FieldMapper from './FieldMapper';
import DataPreview from './DataPreview';

interface EnhancedBulkImportDialogProps {
  open: boolean;
  onClose: () => void;
  onImportComplete: () => void;
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

const steps = ['Upload & Analyze', 'Map Fields', 'Preview & Import'];

const EnhancedBulkImportDialog: React.FC<EnhancedBulkImportDialogProps> = ({
  open,
  onClose,
  onImportComplete,
}) => {
  const [activeStep, setActiveStep] = useState(0);
  const [_csvFile, setCsvFile] = useState<File | null>(null);
  const [csvData, setCsvData] = useState<string>('');
  const [analysis, setAnalysis] = useState<CSVAnalysis | null>(null);
  const [fieldMappings, setFieldMappings] = useState<FieldMapping[]>([]);
  const [importing, setImporting] = useState(false);
  const [importResult, setImportResult] = useState<ImportResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [updateExisting, setUpdateExisting] = useState(false);
  const [dryRun, setDryRun] = useState(false);

  const resetDialog = useCallback(() => {
    setActiveStep(0);
    setCsvFile(null);
    setCsvData('');
    setAnalysis(null);
    setFieldMappings([]);
    setImportResult(null);
    setError(null);
    setImporting(false);
    setUpdateExisting(false);
    setDryRun(false);
  }, []);

  useEffect(() => {
    if (open) {
      resetDialog();
    }
  }, [open, resetDialog]);

  const handleNext = () => {
    setActiveStep((prevStep) => prevStep + 1);
  };

  const handleBack = () => {
    setActiveStep((prevStep) => prevStep - 1);
  };

  const handleClose = () => {
    resetDialog();
    onClose();
  };

  const handleFileAnalyzed = (file: File, csvContent: string, analysisResult: CSVAnalysis) => {
    setCsvFile(file);
    setCsvData(csvContent);
    setAnalysis(analysisResult);

    // Initialize field mappings from auto-mappings
    const mappings: FieldMapping[] = Object.entries(analysisResult.auto_mappings).map(
      ([source, target]) => ({
        source_column: source,
        target_field: target,
      })
    );
    setFieldMappings(mappings);

    setError(null);
    handleNext();
  };

  const handleMappingComplete = (mappings: FieldMapping[]) => {
    setFieldMappings(mappings);
    handleNext();
  };

  const handleImport = async (
    finalMappings: FieldMapping[],
    options: { updateExisting: boolean; dryRun: boolean }
  ) => {
    setImporting(true);
    setError(null);

    try {
      const token = storageGet(StorageKeys.AUTH_TOKEN);
      if (!token) {
        throw new Error('Authentication required');
      }

      const response = await fetch('/api/bulk/hosts/import-with-mapping', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          csv_data: csvData,
          field_mappings: finalMappings,
          update_existing: options.updateExisting,
          dry_run: options.dryRun,
          default_values: {
            environment: 'production',
            port: 22,
            auth_method: 'ssh_key',
          },
        }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ detail: 'Import failed' }));
        throw new Error(errorData.detail || 'Import failed');
      }

      const result = await response.json();
      setImportResult(result);

      if (!options.dryRun && result.successful_imports > 0) {
        onImportComplete();
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Import failed');
    } finally {
      setImporting(false);
    }
  };

  const getStepContent = (step: number) => {
    switch (step) {
      case 0:
        return <CSVAnalyzer onAnalysisComplete={handleFileAnalyzed} onError={setError} />;
      case 1:
        return (
          <FieldMapper
            analysis={analysis}
            initialMappings={fieldMappings}
            onMappingComplete={handleMappingComplete}
            onBack={handleBack}
          />
        );
      case 2:
        return (
          <DataPreview
            csvData={csvData}
            fieldMappings={fieldMappings}
            analysis={analysis}
            onImport={handleImport}
            onBack={handleBack}
            importing={importing}
            importResult={importResult}
            updateExisting={updateExisting}
            setUpdateExisting={setUpdateExisting}
            dryRun={dryRun}
            setDryRun={setDryRun}
          />
        );
      default:
        return null;
    }
  };

  return (
    <Dialog open={open} onClose={handleClose} maxWidth="lg" fullWidth>
      <DialogTitle>
        <Box display="flex" alignItems="center" justifyContent="space-between">
          <Box display="flex" alignItems="center" gap={2}>
            <UploadIcon color="primary" />
            <Typography variant="h6">Enhanced Bulk Import</Typography>
          </Box>
          <IconButton onClick={handleClose} size="small">
            <CloseIcon />
          </IconButton>
        </Box>
      </DialogTitle>

      <DialogContent dividers>
        {error && (
          <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
            {error}
          </Alert>
        )}

        <Box sx={{ mb: 3 }}>
          <Stepper activeStep={activeStep} alternativeLabel>
            {steps.map((label, index) => (
              <Step key={label}>
                <StepLabel
                  StepIconComponent={({ active, completed }) => {
                    const icons = [UploadIcon, MappingIcon, PreviewIcon];
                    const Icon = icons[index];
                    return (
                      <Box
                        sx={{
                          width: 40,
                          height: 40,
                          borderRadius: '50%',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          bgcolor: completed
                            ? 'success.main'
                            : active
                              ? 'primary.main'
                              : 'grey.300',
                          color: completed || active ? 'white' : 'grey.600',
                        }}
                      >
                        {completed ? <CheckIcon /> : <Icon />}
                      </Box>
                    );
                  }}
                >
                  {label}
                </StepLabel>
              </Step>
            ))}
          </Stepper>
        </Box>

        {importing && (
          <Box sx={{ mb: 2 }}>
            <LinearProgress />
            <Typography variant="body2" color="text.secondary" align="center" sx={{ mt: 1 }}>
              {dryRun ? 'Validating data...' : 'Importing hosts...'}
            </Typography>
          </Box>
        )}

        <Box sx={{ minHeight: 400 }}>{getStepContent(activeStep)}</Box>
      </DialogContent>

      <DialogActions>
        <Button onClick={handleClose} disabled={importing}>
          {importResult ? 'Close' : 'Cancel'}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default EnhancedBulkImportDialog;
