import React, { useState, useEffect, useRef } from 'react';
import {
  Box,
  Button,
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
  LinearProgress,
  IconButton,
  Alert,
  CircularProgress
} from '@mui/material';
import {
  Add as AddIcon,
  MoreVert as MoreVertIcon
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { api } from '../../services/api';

interface Scan {
  id: string;
  name: string;
  host_name: string;
  content_name: string;
  profile_id: string;
  status: string;
  progress: number;
  started_at: string;
  completed_at?: string;
}

const Scans: React.FC = () => {
  const navigate = useNavigate();
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const scansRef = useRef<Scan[]>([]);

  const fetchScans = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await api.get<{scans: Scan[]}>('/api/scans/');
      const newScans = data.scans || [];
      setScans(newScans);
      scansRef.current = newScans;
    } catch (error: any) {
      console.error('Failed to load scans:', error);
      
      // Show user-friendly error message
      if (error.isNetworkError) {
        setError('Network error: Unable to connect to server');
      } else if (error.status === 401) {
        setError('Authentication required');
      } else {
        setError('Failed to load scans data');
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();
    
    // Set up periodic refresh for running scans using ref to avoid infinite loop
    const interval = setInterval(() => {
      if (scansRef.current.some(scan => scan.status === 'running')) {
        fetchScans();
      }
    }, 10000); // Refresh every 10 seconds if there are running scans
    
    return () => clearInterval(interval);
  }, []); // Empty dependency array - only run once

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed':
        return 'success';
      case 'running':
        return 'primary';
      case 'failed':
        return 'error';
      case 'pending':
        return 'warning';
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
    <Container maxWidth="xl">
      {/* Header */}
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" component="h1" gutterBottom>
          Compliance Scans
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Monitor and manage security compliance scans across your infrastructure
        </Typography>
      </Box>

      {/* Actions Bar */}
      <Box sx={{ mb: 3, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Button
          variant="contained"
          startIcon={<AddIcon />}
          onClick={() => navigate('/scans/compliance')}
          size="large"
        >
          New Scan
        </Button>
        <Button
          variant="text"
          disabled
          sx={{ color: 'text.secondary' }}
        >
          Start All Pending
        </Button>
      </Box>

      {/* Error Display */}
      {error && (
        <Alert 
          severity="error" 
          sx={{ mb: 3 }}
          action={
            <Button
              color="inherit"
              size="small"
              onClick={fetchScans}
              disabled={loading}
              startIcon={loading ? <CircularProgress size={16} /> : undefined}
            >
              {loading ? 'Retrying...' : 'Retry'}
            </Button>
          }
          onClose={() => setError(null)}
        >
          {error}
        </Alert>
      )}

      {/* Scans Table */}
      <Paper>
        <TableContainer>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Name</TableCell>
                <TableCell>Host</TableCell>
                <TableCell>Content</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Progress</TableCell>
                <TableCell>Started</TableCell>
                <TableCell>Completed</TableCell>
                <TableCell>Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {loading ? (
                <TableRow>
                  <TableCell colSpan={8}>
                    <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', py: 4 }}>
                      <LinearProgress sx={{ width: '100%' }} />
                    </Box>
                  </TableCell>
                </TableRow>
              ) : scans.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={8}>
                    <Box sx={{ textAlign: 'center', py: 4 }}>
                      <Typography variant="body1" color="text.secondary" gutterBottom>
                        No scans found
                      </Typography>
                      <Button
                        variant="contained"
                        startIcon={<AddIcon />}
                        onClick={() => navigate('/scans/compliance')}
                      >
                        Create Your First Scan
                      </Button>
                    </Box>
                  </TableCell>
                </TableRow>
              ) : (
                scans.map((scan) => (
                  <TableRow key={scan.id} hover>
                    <TableCell>
                      <Typography variant="subtitle2" fontWeight="medium">
                        {scan.name}
                      </Typography>
                    </TableCell>
                    <TableCell>{scan.host_name}</TableCell>
                    <TableCell>{scan.content_name}</TableCell>
                    <TableCell>
                      <Chip
                        label={scan.status}
                        color={getStatusColor(scan.status)}
                        size="small"
                        variant="filled"
                      />
                    </TableCell>
                    <TableCell>
                      {scan.status === 'running' && (
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <LinearProgress
                            variant="determinate"
                            value={scan.progress}
                            sx={{ flexGrow: 1 }}
                          />
                          <Typography variant="caption">
                            {scan.progress}%
                          </Typography>
                        </Box>
                      )}
                    </TableCell>
                    <TableCell>{formatDate(scan.started_at)}</TableCell>
                    <TableCell>
                      {scan.completed_at ? formatDate(scan.completed_at) : '-'}
                    </TableCell>
                    <TableCell>
                      <IconButton size="small">
                        <MoreVertIcon />
                      </IconButton>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </TableContainer>
      </Paper>
    </Container>
  );
};

export default Scans;