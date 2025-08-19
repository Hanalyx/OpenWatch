import React, { useState, useEffect } from 'react';
import {
  Box,
  Button,
  Card,
  CardContent,
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
  Select
} from '@mui/material';
import {
  Upload as UploadIcon,
  Download as DownloadIcon,
  Delete as DeleteIcon,
  MoreVert as MoreVertIcon,
  Description as DescriptionIcon,
  Security as SecurityIcon,
  CloudUpload as CloudUploadIcon
} from '@mui/icons-material';

interface ScapContent {
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
}

interface Profile {
  id: string;
  title: string;
  description: string;
}

const ScapContent: React.FC = () => {
  const [scapContent, setScapContent] = useState<ScapContent[]>([]);
  const [loading, setLoading] = useState(false);
  const [uploadDialogOpen, setUploadDialogOpen] = useState(false);
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [uploadName, setUploadName] = useState('');
  const [uploadDescription, setUploadDescription] = useState('');
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [selectedContent, setSelectedContent] = useState<ScapContent | null>(null);
  const [snackbar, setSnackbar] = useState<{
    open: boolean;
    message: string;
    severity: 'success' | 'error' | 'warning' | 'info';
  }>({
    open: false,
    message: '',
    severity: 'info'
  });

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
        showSnackbar('Failed to load SCAP content', 'error');
      }
    } catch (error) {
      showSnackbar('Network error loading SCAP content', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScapContent();
  }, []);

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      // Validate file type
      const allowedTypes = ['.xml', '.zip'];
      const fileExtension = '.' + file.name.split('.').pop()?.toLowerCase();
      
      if (!allowedTypes.includes(fileExtension)) {
        showSnackbar('Invalid file type. Please upload XML or ZIP files only.', 'error');
        return;
      }
      
      // Validate file size (max 50MB)
      const maxSize = 50 * 1024 * 1024;
      if (file.size > maxSize) {
        showSnackbar('File size too large. Maximum size is 50MB.', 'error');
        return;
      }
      
      setUploadFile(file);
      setUploadName(file.name.replace(/\.[^/.]+$/, ""));
    }
  };

  const handleUpload = async () => {
    if (!uploadFile || !uploadName.trim()) {
      showSnackbar('Please select a file and provide a name', 'error');
      return;
    }

    try {
      setUploading(true);
      setUploadProgress(0);

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
        showSnackbar(`SCAP content uploaded successfully. Found ${result.profiles?.length || 0} profiles.`, 'success');
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
      setUploadProgress(0);
    }
  };

  const handleMenuClick = (event: React.MouseEvent<HTMLElement>, content: ScapContent) => {
    event.stopPropagation();
    setAnchorEl(event.currentTarget);
    setSelectedContent(content);
  };

  const handleMenuClose = () => {
    setAnchorEl(null);
    setSelectedContent(null);
  };

  const handleDownload = async () => {
    if (!selectedContent) return;
    
    try {
      const response = await fetch(`/api/scap-content/${selectedContent.id}/download`, {
        headers: {
          'Authorization': 'Bearer demo-token'
        }
      });
      
      if (response.ok) {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = selectedContent.filename;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
        showSnackbar('Download started', 'success');
      } else {
        showSnackbar('Download failed', 'error');
      }
    } catch (error) {
      showSnackbar('Network error during download', 'error');
    }
    handleMenuClose();
  };

  const handleDelete = async () => {
    if (!selectedContent) return;
    
    if (!window.confirm(`Are you sure you want to delete "${selectedContent.name}"? This action cannot be undone.`)) {
      handleMenuClose();
      return;
    }
    
    try {
      const response = await fetch(`/api/scap-content/${selectedContent.id}`, {
        method: 'DELETE',
        headers: {
          'Authorization': 'Bearer demo-token'
        }
      });
      
      if (response.ok) {
        showSnackbar('SCAP content deleted successfully', 'success');
        fetchScapContent();
      } else {
        const error = await response.json();
        showSnackbar(error.detail || 'Delete failed', 'error');
      }
    } catch (error) {
      showSnackbar('Network error during deletion', 'error');
    }
    handleMenuClose();
  };

  const getContentTypeColor = (type: string) => {
    switch (type.toLowerCase()) {
      case 'datastream':
        return 'primary';
      case 'xccdf':
        return 'secondary';
      case 'oval':
        return 'success';
      default:
        return 'default';
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  return (
    <Box sx={{ p: 3 }}>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h4" component="h1">
          SCAP Content Management
        </Typography>
        <Button
          variant="contained"
          startIcon={<UploadIcon />}
          onClick={() => setUploadDialogOpen(true)}
        >
          Upload Content
        </Button>
      </Box>

      <Card>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Available SCAP Content
          </Typography>
          
          {loading && <LinearProgress sx={{ mb: 2 }} />}
          
          <TableContainer component={Paper} variant="outlined">
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Name</TableCell>
                  <TableCell>Type</TableCell>
                  <TableCell>Version</TableCell>
                  <TableCell>Profiles</TableCell>
                  <TableCell>Uploaded</TableCell>
                  <TableCell>Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {scapContent.length === 0 && !loading ? (
                  <TableRow>
                    <TableCell colSpan={6} align="center" sx={{ py: 4 }}>
                      <Typography variant="body2" color="text.secondary">
                        No SCAP content available. Upload content to get started.
                      </Typography>
                    </TableCell>
                  </TableRow>
                ) : (
                  scapContent.map((content) => (
                    <TableRow key={content.id} hover>
                      <TableCell>
                        <Box display="flex" alignItems="center" gap={1}>
                          <SecurityIcon color="action" />
                          <Box>
                            <Typography variant="body2" fontWeight="medium">
                              {content.name}
                            </Typography>
                            <Typography variant="caption" color="text.secondary">
                              {content.filename}
                            </Typography>
                            {content.description && (
                              <Typography variant="caption" display="block" color="text.secondary">
                                {content.description}
                              </Typography>
                            )}
                          </Box>
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={content.content_type.toUpperCase()}
                          color={getContentTypeColor(content.content_type)}
                          size="small"
                        />
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2">
                          {content.version || 'N/A'}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={`${content.profiles.length} profiles`}
                          variant="outlined"
                          size="small"
                        />
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2">
                          {formatDate(content.uploaded_at)}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <IconButton
                          onClick={(e) => handleMenuClick(e, content)}
                          size="small"
                        >
                          <MoreVertIcon />
                        </IconButton>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </TableContainer>
        </CardContent>
      </Card>

      {/* Upload Dialog */}
      <Dialog open={uploadDialogOpen} onClose={() => setUploadDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Upload SCAP Content</DialogTitle>
        <DialogContent>
          <Box sx={{ pt: 1 }}>
            <input
              accept=".xml,.zip"
              style={{ display: 'none' }}
              id="file-upload"
              type="file"
              onChange={handleFileUpload}
            />
            <label htmlFor="file-upload">
              <Button
                variant="outlined"
                component="span"
                startIcon={<CloudUploadIcon />}
                fullWidth
                sx={{ mb: 2, py: 2 }}
              >
                {uploadFile ? uploadFile.name : 'Select SCAP File (XML or ZIP)'}
              </Button>
            </label>
            
            <TextField
              fullWidth
              label="Content Name"
              value={uploadName}
              onChange={(e) => setUploadName(e.target.value)}
              margin="normal"
              required
              helperText="A descriptive name for this SCAP content"
            />
            
            <TextField
              fullWidth
              label="Description"
              value={uploadDescription}
              onChange={(e) => setUploadDescription(e.target.value)}
              margin="normal"
              multiline
              rows={3}
              helperText="Optional description of the content"
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
          <Button onClick={handleUpload} variant="contained" disabled={uploading || !uploadFile}>
            Upload
          </Button>
        </DialogActions>
      </Dialog>

      {/* Context Menu */}
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleMenuClose}
      >
        <MenuItem onClick={handleDownload}>
          <DownloadIcon sx={{ mr: 2 }} />
          Download
        </MenuItem>
        <MenuItem onClick={handleDelete} sx={{ color: 'error.main' }}>
          <DeleteIcon sx={{ mr: 2 }} />
          Delete
        </MenuItem>
      </Menu>

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
    </Box>
  );
};

export default ScapContent;