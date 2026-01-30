import React, { useState, useCallback } from 'react';
import { storageGet, StorageKeys } from '../../services/storage';
import {
  Box,
  Typography,
  Button,
  Card,
  CardContent,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Alert,
  LinearProgress,
  Accordion,
  AccordionSummary,
  AccordionDetails,
} from '@mui/material';
import Grid from '@mui/material/GridLegacy';
import {
  CloudUpload as UploadIcon,
  CheckCircle as CheckIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  ExpandMore as ExpandMoreIcon,
  Analytics as AnalyticsIcon,
} from '@mui/icons-material';
import { useDropzone } from 'react-dropzone';

interface CSVAnalyzerProps {
  onAnalysisComplete: (file: File, csvContent: string, analysis: CSVAnalysis) => void;
  onError: (error: string) => void;
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

const CSVAnalyzer: React.FC<CSVAnalyzerProps> = ({ onAnalysisComplete, onError }) => {
  const [file, setFile] = useState<File | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [analysis, setAnalysis] = useState<CSVAnalysis | null>(null);
  const [csvContent, setCsvContent] = useState<string>('');

  const onDrop = useCallback(
    async (acceptedFiles: File[]) => {
      if (acceptedFiles.length === 0) return;

      const uploadedFile = acceptedFiles[0];
      setFile(uploadedFile);
      setAnalyzing(true);
      onError('');

      try {
        // Read file content
        const content = await uploadedFile.text();
        setCsvContent(content);

        // Send to backend for analysis
        const token = storageGet(StorageKeys.AUTH_TOKEN);
        if (!token) {
          throw new Error('Authentication required');
        }

        const formData = new FormData();
        formData.append('file', uploadedFile);

        const response = await fetch('/api/bulk/hosts/analyze-csv', {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${token}`,
          },
          body: formData,
        });

        if (!response.ok) {
          const errorData = await response.json().catch(() => ({ detail: 'Analysis failed' }));
          throw new Error(errorData.detail || 'Failed to analyze CSV');
        }

        const analysisResult = await response.json();
        setAnalysis(analysisResult);
      } catch (error) {
        onError(error instanceof Error ? error.message : 'Failed to analyze CSV');
      } finally {
        setAnalyzing(false);
      }
    },
    [onError]
  );

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'text/csv': ['.csv'],
    },
    maxFiles: 1,
    disabled: analyzing,
  });

  const handleContinue = () => {
    if (file && csvContent && analysis) {
      onAnalysisComplete(file, csvContent, analysis);
    }
  };

  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 0.8) return 'success';
    if (confidence >= 0.5) return 'warning';
    return 'error';
  };

  const getConfidenceIcon = (confidence: number) => {
    if (confidence >= 0.8) return <CheckIcon fontSize="small" />;
    if (confidence >= 0.5) return <WarningIcon fontSize="small" />;
    return <InfoIcon fontSize="small" />;
  };

  if (!file) {
    return (
      <Box
        {...getRootProps()}
        sx={{
          border: '2px dashed',
          borderColor: isDragActive ? 'primary.main' : 'grey.400',
          borderRadius: 2,
          p: 6,
          textAlign: 'center',
          cursor: 'pointer',
          bgcolor: isDragActive ? 'action.hover' : 'background.paper',
          transition: 'all 0.2s ease',
          minHeight: 300,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
        }}
      >
        <input {...getInputProps()} />
        <UploadIcon sx={{ fontSize: 80, color: 'text.secondary', mb: 2 }} />

        <Typography variant="h5" gutterBottom>
          {isDragActive ? 'Drop your CSV file here' : 'Upload Any CSV File'}
        </Typography>

        <Typography variant="body1" color="text.secondary" sx={{ mb: 3, maxWidth: 600 }}>
          Upload CSV files from any source - VMware vCenter, Red Hat Satellite, AWS, Azure, or
          custom exports. Our intelligent analysis will automatically detect and suggest field
          mappings.
        </Typography>

        <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', justifyContent: 'center' }}>
          <Chip label="VMware vCenter" size="small" variant="outlined" />
          <Chip label="Red Hat Satellite" size="small" variant="outlined" />
          <Chip label="AWS EC2" size="small" variant="outlined" />
          <Chip label="Azure VMs" size="small" variant="outlined" />
          <Chip label="Custom Exports" size="small" variant="outlined" />
        </Box>

        <Button variant="outlined" startIcon={<UploadIcon />} sx={{ mt: 3 }} disabled={analyzing}>
          Choose CSV File
        </Button>
      </Box>
    );
  }

  return (
    <Box>
      {analyzing && (
        <Box sx={{ mb: 3 }}>
          <LinearProgress />
          <Typography variant="body2" color="text.secondary" align="center" sx={{ mt: 1 }}>
            Analyzing CSV structure and content...
          </Typography>
        </Box>
      )}

      {file && !analyzing && (
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Box display="flex" alignItems="center" gap={2} mb={2}>
              <AnalyticsIcon color="primary" />
              <Typography variant="h6">File Analysis Complete</Typography>
            </Box>

            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" gutterBottom>
                  File Information
                </Typography>
                <Typography variant="body2">Name: {file.name}</Typography>
                <Typography variant="body2">Size: {(file.size / 1024).toFixed(2)} KB</Typography>
                {analysis && (
                  <>
                    <Typography variant="body2">Rows: {analysis.total_rows}</Typography>
                    <Typography variant="body2">Columns: {analysis.total_columns}</Typography>
                  </>
                )}
              </Grid>

              {analysis && analysis.template_matches.length > 0 && (
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>
                    Detected Templates
                  </Typography>
                  <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                    {analysis.template_matches.map((template, index) => (
                      <Chip
                        key={index}
                        label={template}
                        color="primary"
                        size="small"
                        icon={<CheckIcon />}
                      />
                    ))}
                  </Box>
                </Grid>
              )}
            </Grid>
          </CardContent>
        </Card>
      )}

      {analysis && (
        <>
          <Accordion defaultExpanded>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography variant="h6">Field Analysis & Auto-Mapping</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <TableContainer component={Paper} variant="outlined">
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Column</TableCell>
                      <TableCell>Detected Type</TableCell>
                      <TableCell>Confidence</TableCell>
                      <TableCell>Sample Data</TableCell>
                      <TableCell>Auto-Mapped</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {analysis.field_analyses.map((field, index) => (
                      <TableRow key={index}>
                        <TableCell>
                          <Typography variant="body2" fontWeight="medium">
                            {field.column_name}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={field.detected_type.replace('_', ' ')}
                            size="small"
                            color={getConfidenceColor(field.confidence)}
                            icon={getConfidenceIcon(field.confidence)}
                          />
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2">
                            {Math.round(field.confidence * 100)}%
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography
                            variant="body2"
                            sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}
                          >
                            {field.sample_values.slice(0, 2).join(', ')}
                            {field.sample_values.length > 2 && '...'}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          {analysis.auto_mappings[field.column_name] ? (
                            <Chip
                              label={analysis.auto_mappings[field.column_name]}
                              size="small"
                              color="success"
                              variant="outlined"
                            />
                          ) : (
                            <Typography variant="body2" color="text.secondary">
                              Manual mapping required
                            </Typography>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>

              {Object.keys(analysis.auto_mappings).length > 0 && (
                <Alert severity="success" sx={{ mt: 2 }}>
                  <Typography variant="body2">
                    <strong>Great!</strong> We automatically mapped{' '}
                    {Object.keys(analysis.auto_mappings).length} out of {analysis.total_columns}{' '}
                    fields. You can review and adjust these mappings in the next step.
                  </Typography>
                </Alert>
              )}
            </AccordionDetails>
          </Accordion>

          <Box
            sx={{ mt: 3, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}
          >
            <Button
              variant="outlined"
              onClick={() => {
                setFile(null);
                setAnalysis(null);
                setCsvContent('');
              }}
            >
              Choose Different File
            </Button>

            <Button
              variant="contained"
              onClick={handleContinue}
              startIcon={<CheckIcon />}
              size="large"
            >
              Continue to Field Mapping
            </Button>
          </Box>
        </>
      )}
    </Box>
  );
};

export default CSVAnalyzer;
